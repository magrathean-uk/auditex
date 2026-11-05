"""Internal ScubaGear export adapter: parsing, projection, proof and surface checks."""
from __future__ import annotations

from copy import deepcopy
from contextlib import nullcontext
from hashlib import sha256
import ast
import importlib.util
import inspect
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys

import pytest

from auditex.model_serving import ModelConfig, assess_scubagear_export, policy_catalogue
from auditex.scuba_projection import (
    PACK_ENUM_DOMAINS, PACK_SHAPE_DIGESTS, SCUBA_CAP_EXCLUSION_POLICIES,
    SCUBA_ROLE_EXCLUSION_POLICIES, _json, _seen_shape, policy_section, rule_policy_section,
)
from auditex.scubagear_export import (
    CA_RESTRICTION_NAMES, NOT_ASSESSED_REASONS, SECTION_LEDGERS, UNMAPPABLE_REGO_POLICIES, VERDICT_MAP,
    build_baseline, canonicalise_privileged_users, load_export, project_export, prune_section,
    qualifier_check, redaction_salt, resolve_output_directory,
)
from auditex.scubagear_prune_proof import (
    GATE_DIGEST, PINNED_REVISION, PRUNE_PROOF, PRUNE_REASONS, PROOF_VERSION, REGO_SHA256,
    shape_paths, verdict_of,
)
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.model_evidence import NOT_COLLECTED

ROOT = Path(__file__).resolve().parents[1]
IGNORED_OPTIONS_WARNING = ("Warning: legacy model options are ignored for assessment; the model layer is parked "
                           "and redaction stays enabled.")
FIXTURES = ROOT / "tests/fixtures/scubagear-export"
PROVIDER = FIXTURES / "mocktenant-provider-export.json"
REAL = FIXTURES / "mocktenant-realformat-export.json"
RESULTS = FIXTURES / "mocktenant-scubaresults.json"
SENTINEL = "SENTINEL-NOT-A-SECRET-0001"
EXPECTED_VERDICTS = {section: "prunable" for section in (
    "SPO_tenant", "accepted_domains", "authorization_policies", "conditional_access_policies",
    "dkim_config", "dkim_records", "dmarc_records", "meeting_policies", "org_config",
    "privileged_roles", "service_plans", "spf_records", "transport_config")}
EXPECTED_READS = {
    "accepted_domains": ("[].DomainName",),
    "service_plans": ("[].ServicePlanId", "[].ServicePlanName"),
    "dkim_config": ("[].Domain", "[].Enabled"),
    "dkim_records": ("[].domain", "[].rdata"),
    "dmarc_records": ("[].domain", "[].rdata"),
    "transport_config": ("[].Name", "[].SmtpClientAuthenticationDisabled"),
}


def _save(tmp_path, value, name="export.json"):
    path = tmp_path / name
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


def _dry(tmp_path, source=PROVIDER, **kwargs):
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "assessment"
    result = assess_scubagear_export(source, out, ModelConfig(model_name="test-model"), dry_run=True, **kwargs)
    sidecar = json.loads((out / "scubagear_adapter_report.json").read_text())
    prompts = [json.loads(line) for line in (out / "model_assessment_prompts.jsonl").read_text().splitlines()]
    return result, sidecar, prompts


def test_fixture_ceiling_and_policy_disposition(tmp_path):
    catalogue = policy_catalogue()["policies"]
    assert len(catalogue) == 102
    assert set(SECTION_LEDGERS) == {s for p in catalogue.values() for s in p["sections"]} - {"scuba_config"}
    assert len({pid for pid, p in catalogue.items() if "scuba_config" in p["sections"]}) == 19
    assert set(UNMAPPABLE_REGO_POLICIES).isdisjoint(catalogue)
    for source, disposition_file, expected in ((PROVIDER, "policy-disposition.json", 44),
                                               (REAL, "policy-disposition-realformat.json", 43)):
        result, sidecar, prompts = _dry(tmp_path / source.stem, source)
        assert result["prompts"] == len(catalogue) == len(prompts)
        assert {p["policy_id"] for p in prompts} == set(catalogue)
        assert sidecar["disposition"] == json.loads((FIXTURES / disposition_file).read_text())["disposition"]
        assert sidecar["ceiling"]["overall"] == {"assessed": expected, "total": len(catalogue)}
        if source == PROVIDER:
            assert {pid for pid, row in sidecar["disposition"].items() if row["status"] == "assessed"} == {
                pid for pid, item in catalogue.items() if all(section in PACK_SHAPE_DIGESTS for section in item["sections"])}
        assert sidecar["pruning"]["totals"]["pruned_keys"] == sum(
            row["pruned_keys"] for row in sidecar["pruning"]["sections"].values())
        assert set(sidecar["unmappable"]["ids"]) >= set(UNMAPPABLE_REGO_POLICIES)
    clean = {p["policy_id"]: p["prompt_sha256"] for p in _dry(tmp_path / "clean-prompts")[2]}
    real = {p["policy_id"]: p["prompt_sha256"] for p in _dry(tmp_path / "real-prompts", REAL)[2]}
    assert {pid for pid in clean if clean[pid] != real[pid]} == {
        "MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1", "MS.EXO.13.1v1"}


def test_provider_and_raw_wrapper_same_projection_and_prompts(tmp_path):
    _, provider_report, provider_prompts = _dry(tmp_path / "provider")
    _, wrapper_report, wrapper_prompts = _dry(tmp_path / "wrapper", RESULTS)
    assert {p["policy_id"]: p["prompt_sha256"] for p in provider_prompts} == {
        p["policy_id"]: p["prompt_sha256"] for p in wrapper_prompts}
    for key in ("canonicalised", "pruning", "disposition", "ceiling"):
        assert provider_report[key] == wrapper_report[key]
    assert provider_report["input"]["kind"] == "provider_export"
    assert wrapper_report["input"]["kind"] == "scubaresults"


def test_real_scubaresults_group_lists_and_unreadable_baselines(tmp_path):
    wrapper = json.loads(RESULTS.read_text())
    assert isinstance(wrapper["Results"]["AAD"], list)
    assert {"GroupName", "GroupNumber", "GroupReferenceURL", "Controls"} <= set(wrapper["Results"]["AAD"][0])
    _, sidecar, _ = _dry(tmp_path / "real-list", RESULTS)
    assert sidecar["verdicts"]["state"] == "readable"
    assert sidecar["verdicts"]["counts"] == {"pass": 1, "fail": 2, "not_assessed": 2}
    invented = deepcopy(wrapper)
    invented["Results"]["AAD"] = {"Mock": invented["Results"]["AAD"][0]}
    _, unreadable, _ = _dry(tmp_path / "wrong-layout", _save(tmp_path, invented))
    assert unreadable["verdicts"]["source"] == "embedded"
    assert unreadable["verdicts"]["state"] == "unreadable_layout"
    assert unreadable["verdicts"]["counts"] == {}
    malformed_group = deepcopy(wrapper)
    malformed_group["Results"]["AAD"].append({"GroupName": "Broken", "Controls": "not-a-list"})
    _, malformed_report, _ = _dry(tmp_path / "malformed-group", _save(tmp_path, malformed_group))
    assert malformed_report["verdicts"]["state"] == "unreadable_layout"
    assert malformed_report["verdicts"]["counts"] == {}
    empty = deepcopy(wrapper)
    empty["Results"]["AAD"] = []
    _, empty_report, _ = _dry(tmp_path / "empty-results", _save(tmp_path, empty))
    assert empty_report["verdicts"]["state"] == "empty"
    malformed = tmp_path / "malformed-results.json"
    malformed.write_text("{this is not JSON}")
    _, unreadable_file, _ = _dry(tmp_path / "unreadable-file", PROVIDER, results_path=malformed)
    assert unreadable_file["verdicts"]["source"] == "results_file"
    assert unreadable_file["verdicts"]["state"] == "unreadable_file"
    assert unreadable_file["verdicts"]["counts"] == {}
    single = json.loads((FIXTURES / "mocktenant-testresults.json").read_text())[0]
    from auditex.scubagear_export import load_results
    assert load_results(_save(tmp_path, single, "single-result.json")) == ([single], "testresults")
    repaired_results = RESULTS.read_text().replace('"Result": "Pass"', '"Result": ', 1)
    _, repaired_report, _ = _dry(tmp_path / "repaired-results", _save_text(tmp_path, repaired_results))
    assert repaired_report["verdicts"]["state"] == "unreadable_repaired"
    assert repaired_report["verdicts"]["counts"] == {}


def test_nested_repairs_withhold_enclosing_section_and_string_matches_refuse(tmp_path):
    text = PROVIDER.read_text()
    assert '"ExcludeUsers": []' in text
    loaded = load_export(_save_text(tmp_path, text.replace('"ExcludeUsers": []', '"ExcludeUsers": ', 1)))
    assert "conditional_access_policies" in loaded.repaired_keys
    projection, _ = project_export(loaded, policy_catalogue()["policies"])
    assert projection.report["sections"]["conditional_access_policies"]["status"] == "not_collected"
    assert projection["conditional_access_policies"] == NOT_COLLECTED
    hostile_raw = json.loads(text)
    hostile_raw["conditional_access_policies"][0]["DisplayName"] = 'Mock": , block'
    hostile = json.dumps(hostile_raw).replace('"tenant_id":', '"zz_broken": , "tenant_id":', 1)
    with pytest.raises(ValueError, match="^Invalid ScubaGear export$"):
        load_export(_save_text(tmp_path, hostile))
    raw = json.loads(text)
    raw["dkim_config"][0]["non.identifier"] = []
    masked_text = json.dumps(raw).replace('"non.identifier": []', '"non.identifier": ', 1)
    masked = load_export(_save_text(tmp_path, masked_text))
    assert masked.repaired_masked_count == 1 and "dkim_config" in masked.repaired_keys
    _, sidecar, _ = _dry(tmp_path / "masked-repair", _save_text(tmp_path, masked_text))
    assert sidecar["parse"]["masked_repaired_keys"] == 1


def test_repair_after_sidecar_cap_still_withholds_provider(tmp_path):
    from auditex.scubagear_export import _SAFE_REPAIRED_KEYS

    wrapper = json.loads(RESULTS.read_text())
    holes = sorted(_SAFE_REPAIRED_KEYS - {"meeting_policies", "teams_successful_commands"})
    assert len(holes) == 70 and "teams_unsuccessful_commands" in holes[64:]
    for key in holes:
        if key != "Results":
            wrapper["Raw"][key] = []
    wrapper["Results"] = []
    content = json.dumps(wrapper)
    for key in holes:
        needle = '"' + key + '": []'
        assert needle in content
        content = content.replace(needle, '"' + key + '": ', 1)
    loaded = load_export(_save_text(tmp_path, content))
    assert len(loaded.repaired_keys) == 70
    assert "teams_unsuccessful_commands" in loaded.repaired_keys
    projection, _ = project_export(loaded, policy_catalogue()["policies"])
    assert projection.report["sections"]["meeting_policies"]["status"] == "not_collected"
    baseline, reasons, _ = build_baseline(
        {"TEAMS": [{"Controls": [{"Control ID": "MS.TEAMS.1.1v1", "Result": "Pass"}]}]},
        loaded.raw, kind="scubaresults", repaired_keys=loaded.repaired_keys,
    )
    assert baseline["MS.TEAMS.1.1v1"] == "not_assessed"
    assert reasons["MS.TEAMS.1.1v1"] == "ledger_unavailable"
    _, sidecar, _ = _dry(tmp_path / "capped-report", _save_text(tmp_path, content))
    assert len(sidecar["parse"]["repaired_keys"]) == 64


def test_repaired_export_keys_never_reach_sidecar_or_diagnostics(tmp_path, caplog, capsys):
    hostile = ("a1b2c3d4e5f64a7b8c9d0e1f2a3b4c5d", "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
               "NiajMockAdmin", "SENTINELNOTASECRET0001")
    raw = json.loads(PROVIDER.read_text())
    raw["tenant_details"]["Nested"] = {name: [] for name in hostile}
    content = json.dumps(raw)
    for name in hostile:
        content = content.replace('"' + name + '": []', '"' + name + '": ', 1)
    with caplog.at_level("DEBUG"):
        _, sidecar, _ = _dry(tmp_path / "repaired-private", _save_text(tmp_path, content))
        assert sidecar["parse"]["masked_repaired_keys"] >= len(hostile)
        assert not any(name in sidecar["parse"]["repaired_keys"] for name in hostile)
        refused = content.replace('"tenant_id":', '"' + hostile[1] + '": 0, "' + hostile[1] + '": 1, "tenant_id":', 1)
        with pytest.raises(ValueError) as error:
            load_export(_save_text(tmp_path, refused))
    output = json.dumps(sidecar) + str(error.value) + caplog.text
    captured = capsys.readouterr()
    output += captured.out + captured.err
    assert all(name not in output for name in hostile)


def test_repair_scan_is_linear_for_many_matches_after_large_string(tmp_path):
    from time import perf_counter
    raw = json.loads(PROVIDER.read_text())
    raw["tenant_details"]["Padding"] = "x" * 3_000_000
    raw["tenant_details"]["Nested"] = {f"Field{i}": [] for i in range(800)}
    content = json.dumps(raw)
    for i in range(800):
        content = content.replace(f'"Field{i}": []', f'"Field{i}": ', 1)
    start = perf_counter()
    loaded = load_export(_save_text(tmp_path, content))
    assert loaded.repaired and loaded.repaired_masked_count >= 800
    assert perf_counter() - start < 12


def test_non_string_ca_state_withholds_only_ca(tmp_path):
    for state in ([], {}):
        raw = json.loads(PROVIDER.read_text())
        raw["conditional_access_policies"][0]["State"] = state
        assert qualifier_check("conditional_access_policies", raw["conditional_access_policies"]) is None
        projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()["policies"])
        assert projection.report["sections"]["conditional_access_policies"]["status"] == "not_collected"
        assert projection.report["sections"]["dkim_config"]["status"] == "projected"


def test_whole_export_salt_is_canonical_and_file_hash_is_bytes(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    source = _save(tmp_path, raw, "first.json")
    loaded = load_export(source)
    shuffled = {key: value for key, value in reversed(list(raw.items()))}
    shuffled["tenant_details"] = {"Other": {"b": 2, "a": 1}, **shuffled["tenant_details"]}
    alternate = _save(tmp_path, shuffled, "alternate.json")
    assert load_export(alternate).whole_digest != loaded.whole_digest
    del shuffled["tenant_details"]["Other"]
    reordered = _save(tmp_path, shuffled, "reordered.json")
    assert load_export(reordered).whole_digest == loaded.whole_digest
    assert load_export(reordered).sha256 != loaded.sha256
    a, _, _ = _dry(tmp_path / "salt-a", source)
    b, _, _ = _dry(tmp_path / "salt-b", alternate)
    assert a["prompts"] == b["prompts"] == 102
    first = (tmp_path / "salt-a/assessment/model_assessment_prompts.jsonl").read_text()
    second = (tmp_path / "salt-b/assessment/model_assessment_prompts.jsonl").read_text()
    assert first != second


def test_distinct_fixture_exports_have_distinct_salts_and_pseudonyms(tmp_path):
    assert load_export(PROVIDER).whole_digest != load_export(REAL).whole_digest
    clean = _dry(tmp_path / "clean", PROVIDER)[2]
    real = _dry(tmp_path / "real", REAL)[2]
    for policy_id in ("MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1"):
        a = next(row for row in clean if row["policy_id"] == policy_id)
        b = next(row for row in real if row["policy_id"] == policy_id)
        assert a["prompt_sha256"] != b["prompt_sha256"]
        def names(row):
            case = json.loads(row["messages"][1]["content"])
            observed = next(item["observed"] for item in case["evidence"]
                            if item["section"] == "privileged_users")
            return {entry["DisplayName"] for entry in observed.values()}
        assert names(a) != names(b)


def test_parse_fail_closed_and_repairs(tmp_path, capsys):
    original = PROVIDER.read_text()
    for value in ({}, {"unlisted_export_key": "sentinel"}, {"Raw": {}, "MetaData": {}}):
        with pytest.raises(ValueError, match="^Invalid ScubaGear export$"):
            load_export(_save(tmp_path, value))
    for text in ("{} trailing", '{"a": NaN}', '{"a": Infinity}', '{"a": 1e999}',
                 '{"a": "\\ud800"}', '{"\\ud800": 1}', '{"a": True}',
                 '{"a": "' + SENTINEL + '", "b": } junk', '[' * 5000 + '0' + ']' * 5000):
        path = tmp_path / "bad.json"
        path.write_text(text)
        with pytest.raises(ValueError) as err:
            load_export(path)
        assert str(err.value) == "Invalid ScubaGear export"
    assert SENTINEL not in capsys.readouterr().out
    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + PROVIDER.read_bytes())
    assert load_export(bom).raw["tenant_id"] == "11111111-1111-4111-8111-111111111111"
    for source_key in ("exo_unsuccessful_commands", "exo_successful_commands", "accepted_domains"):
        bad = original.replace('"' + source_key + '": [],', '"' + source_key + '": ,', 1)
        if bad == original:
            bad = original.replace('"' + source_key + '": [', '"' + source_key + '": , "discard": [', 1)
        path = tmp_path / "repaired.json"
        path.write_text(bad)
        loaded = load_export(path)
        assert loaded.repaired and source_key in loaded.repaired_keys
    over = tmp_path / "oversize.json"
    over.write_bytes(b"{}")
    import auditex.scubagear_export as adapter
    old = adapter._MAX_EXPORT_BYTES
    adapter._MAX_EXPORT_BYTES = 1
    try:
        with pytest.raises(ValueError, match="Invalid ScubaGear export"):
            load_export(over)
    finally:
        adapter._MAX_EXPORT_BYTES = old


def test_generic_parse_errors_hide_keys_and_huge_integers(tmp_path, caplog, capsys):
    text = PROVIDER.read_text()
    hostile = text.replace('"tenant_id":', '"SENTINEL-NOT-A-SECRET-0001": 1, '
                           '"SENTINEL-NOT-A-SECRET-0001": 2, "tenant_id":', 1)
    for content in (hostile,
                    text.replace('"tenant_id":', '"huge": ' + '9' * 5000 + ', "tenant_id":', 1)):
        with caplog.at_level("DEBUG"):
            with pytest.raises(ValueError) as error:
                load_export(_save_text(tmp_path, content))
        assert str(error.value) == "Invalid ScubaGear export"
    captured = capsys.readouterr()
    assert SENTINEL not in captured.out + captured.err + caplog.text


def test_duplicate_accepted_domains_and_other_keys(tmp_path):
    text = PROVIDER.read_text()
    needle = '"accepted_domains": '
    start = text.index(needle)
    value = json.loads(text)["accepted_domains"]
    equal = text[:start] + '"accepted_domains": ' + json.dumps(value) + ',\n  ' + text[start:]
    loaded = load_export(_save_text(tmp_path, equal))
    assert loaded.duplicate_keys == ["accepted_domains"] and not loaded.differing_accepted_domains
    assert loaded.whole_digest != load_export(_save_text(tmp_path, text)).whole_digest
    different = text[:start] + '"accepted_domains": [],\n  ' + text[start:]
    assert load_export(_save_text(tmp_path, different)).differing_accepted_domains
    for bad in (text[:start] + '"tenant_id": "mock",\n  ' + text[start:],
                '{"nested":{"a":1,"a":2}}'):
        with pytest.raises(ValueError, match="Invalid ScubaGear export"):
            load_export(_save_text(tmp_path, bad))


def _save_text(tmp_path, text):
    path = tmp_path / "source.json"
    path.write_text(text)
    return path


@pytest.mark.parametrize("mutation", [
    "extra", "missing_immutable", "missing_name", "missing_roles", "name_null", "immutable_int",
    "roles_string", "roles_empty", "roles_bad", "id_bad", "id_other", "mixed", "email_key",
    "brace_key", "urn_key", "unhyphenated_key", "empty_map", "empty_entry", "list", "null",
    "entry_list", "one_bad",
])
def test_canonicaliser_rejects_partial_and_unseen_shapes(mutation):
    users = deepcopy(json.loads(PROVIDER.read_text())["privileged_users"])
    first = next(iter(users))
    if mutation == "extra": users[first]["ServicePrincipalId"] = "mock"
    if mutation == "missing_immutable": del users[first]["OnPremisesImmutableId"]
    if mutation == "missing_name": del users[first]["DisplayName"]
    if mutation == "missing_roles": del users[first]["roles"]
    if mutation == "name_null": users[first]["DisplayName"] = None
    if mutation == "immutable_int": users[first]["OnPremisesImmutableId"] = 1
    if mutation == "roles_string": users[first]["roles"] = "Global Administrator"
    if mutation == "roles_empty": users[first]["roles"] = []
    if mutation == "roles_bad": users[first]["roles"] = [None]
    if mutation == "id_bad": users[first]["id"] = 1
    if mutation == "id_other": users[first]["id"] = "other"
    if mutation in {"mixed", "email_key", "brace_key", "urn_key", "unhyphenated_key"}:
        key = {"mixed": "User1", "email_key": "user1@mocktenant.invalid", "brace_key": "{" + first + "}",
               "urn_key": "urn:uuid:" + first, "unhyphenated_key": first.replace("-", "")}[mutation]
        users[key] = users.pop(first) if mutation != "mixed" else deepcopy(users[first])
    if mutation == "empty_map": users = {}
    if mutation == "empty_entry": users[first] = {}
    if mutation == "list": users = []
    if mutation == "null": users = None
    if mutation == "entry_list": users[first] = []
    if mutation == "one_bad": users[first]["AppId"] = "mock"
    converted, applied, object_ids = canonicalise_privileged_users(users)
    assert not applied and object_ids is None and converted == users
    with pytest.raises(Exception):
        _seen_shape("privileged_users", converted)


def test_canonicaliser_salt_determinism_and_gate(tmp_path):
    original = json.loads(PROVIDER.read_text())
    users = original["privileged_users"]
    converted, applied, ids = canonicalise_privileged_users(users)
    assert applied and len(converted) == len(users) and len(ids) == len(users)
    _seen_shape("privileged_users", converted)
    assert len(PACK_SHAPE_DIGESTS) == 16 and sum(map(len, PACK_SHAPE_DIGESTS.values())) == 410
    expected_salt = redaction_salt(converted, ids)
    randomizer = random.Random(20261104)
    for _ in range(20):
        shuffled = list(users.items())
        randomizer.shuffle(shuffled)
        value = {key: {k: deepcopy(v) for k, v in randomizer.sample(list(entry.items()), len(entry))}
                 for key, entry in shuffled}
        for entry in value.values():
            randomizer.shuffle(entry["roles"])
        actual, yes, object_ids = canonicalise_privileged_users(value)
        assert yes and actual == converted and object_ids == ids
        assert redaction_salt(actual, object_ids) == expected_salt
    numbered = {f"User{i}": deepcopy(v) for i, v in enumerate(reversed(list(converted.values())), 1)}
    assert canonicalise_privileged_users(numbered) == (numbered, False, None)
    assert redaction_salt(numbered) == redaction_salt(converted)
    assert redaction_salt(converted, ids) != redaction_salt(numbered)
    changed = deepcopy(users)
    key = next(iter(changed))
    changed[key]["DisplayName"] += " changed"
    assert redaction_salt(*_salt_inputs(changed)) != expected_salt
    changed = deepcopy(users)
    new = "00000000-0000-4000-8000-000000000099"
    changed[new] = changed.pop(key)
    changed[new]["id"] = new
    assert redaction_salt(*_salt_inputs(changed)) != expected_salt


def test_redaction_salt_blocks_output_only_name_dictionary(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    raw["privileged_users"] = dict(list(raw["privileged_users"].items())[:2])
    raw.pop("privileged_roles")
    source = _save(tmp_path, raw)
    _, _, prompts = _dry(tmp_path / "attack", source)
    selected = next(row for row in prompts if row["policy_id"] == "MS.AAD.7.1v1")
    case = json.loads(selected["messages"][1]["content"])
    observed = next(item["observed"] for item in case["evidence"] if item["section"] == "privileged_users")
    pseudonyms = {entry["DisplayName"] for entry in observed.values()}
    assert len(pseudonyms) == 2
    assert all(key not in (tmp_path / "attack/assessment/model_assessment_prompts.jsonl").read_text()
               for key in raw["privileged_users"])
    roles = [entry["roles"] for entry in raw["privileged_users"].values()]
    names = [entry["DisplayName"] for entry in raw["privileged_users"].values()]
    candidates = names + [f"Synthetic Name {index}" for index in range(98)]
    def guesses(a, b, object_ids=None, whole_digest=None):
        entries = [{"DisplayName": name, "OnPremisesImmutableId": None, "roles": role}
                   for name, role in ((a, roles[0]), (b, roles[1]))]
        basis = {"purpose": "scubagear-adapter-redaction-v1",
                 "privileged_users": {"entries": sorted(_json(entry) for entry in entries), "object_ids": object_ids},
                 "whole_export": whole_digest}
        salt = sha256(_json(basis).encode()).hexdigest()
        return {"User " + sha256((salt + "\0" + name).encode()).hexdigest()[:16] for name in (a, b)}
    assert guesses(*names) != pseudonyms
    assert all(guesses(a, b) != pseudonyms for a in candidates for b in candidates if a != b)
    known_ids = sorted(raw["privileged_users"])
    known_digest = load_export(source).whole_digest
    assert all(guesses(a, b, known_ids, None) != pseudonyms
               for a in candidates for b in candidates if a != b)
    assert any(guesses(a, b, known_ids, known_digest) == pseudonyms
               for a in candidates for b in candidates if a != b)


@pytest.mark.parametrize("clear", [False, True])
def test_user_entries_guard_withholds_mixed_missing_immutable(tmp_path, clear):
    raw = json.loads(PROVIDER.read_text())
    users = dict(list(raw["privileged_users"].items())[:2])
    numbered = canonicalise_privileged_users(users)[0]
    del numbered["User1"]["OnPremisesImmutableId"]
    _seen_shape("privileged_users", numbered)
    names = [entry["DisplayName"] for entry in numbered.values()]
    raw["privileged_users"] = numbered
    source = _save(tmp_path, raw)
    result = assess_scubagear_export(source, tmp_path / "output", ModelConfig(model_name="test-model"),
                                     policies=["MS.AAD.3.3v2"], no_redaction=clear)
    validate_assessment(result)
    row = result["projection"]["sections"]["privileged_users"]
    assert row["reason"] == "incomplete_shape" and row["detail"] == {
        "field": "User1.OnPremisesImmutableId", "kind": "missing_field"}
    written = (tmp_path / "output/model_assessment.json").read_text() + (
        tmp_path / "output/scubagear_adapter_report.json").read_text()
    assert all(name not in written for name in names)


def _salt_inputs(users):
    converted, _, ids = canonicalise_privileged_users(users)
    return converted, ids


def test_projection_fail_closed_and_ledger_repair(tmp_path):
    original = json.loads(PROVIDER.read_text())
    cases = [
        (lambda v: v.pop("accepted_domains"), "accepted_domains", "missing_artifact", None),
        (lambda v: v.pop("exo_successful_commands"), "dkim_config", "incomplete_shape", "unseen_shape"),
        (lambda v: v["exo_unsuccessful_commands"].append("Get-Mock"), "dkim_config", "collector_error", None),
        (lambda v: v["dkim_config"][0].update(Enabled="bad"), "dkim_config", "incomplete_shape", "unseen_shape"),
    ]
    for index, (mutate, section, reason, kind) in enumerate(cases):
        raw = deepcopy(original)
        mutate(raw)
        projection, _ = project_export(load_export(_save(tmp_path, raw, f"case-{index}.json")),
                                       policy_catalogue()["policies"])
        row = projection.report["sections"][section]
        assert row["reason"] == reason
        if kind: assert row["detail"]["kind"] == kind
    raw = deepcopy(original)
    raw["tenant_id"] = SENTINEL
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()["policies"])
    assert projection["tenant_id"] == NOT_COLLECTED
    assert projection.report["sections"]["tenant_id"]["reason"] == "incomplete_shape"
    raw = deepcopy(original)
    del raw["scuba_config"]
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()["policies"])
    assert projection.report["sections"]["scuba_config"] == {"status": "not_collected", "reason": "missing_artifact", "source": []}
    text = PROVIDER.read_text().replace('"exo_unsuccessful_commands": [],', '"exo_unsuccessful_commands": ,', 1)
    loaded = load_export(_save_text(tmp_path, text))
    projection, _ = project_export(loaded, policy_catalogue()["policies"])
    assert all(projection.report["sections"][s]["reason"] == "incomplete_shape"
               for s in SECTION_LEDGERS if "exo" in SECTION_LEDGERS[s] and s in loaded.raw)


def test_service_plan_budget_and_config_outcomes(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    template = raw["service_plans"][0]
    for count, status in ((40, "projected"), (41, "not_collected")):
        candidate = deepcopy(raw)
        candidate["service_plans"] = [deepcopy(template) for _ in range(count)]
        projection, _ = project_export(load_export(_save(tmp_path, candidate, f"plans-{count}.json")),
                                       policy_catalogue()["policies"])
        assert projection.report["sections"]["service_plans"]["status"] == status
        if count == 41:
            assert projection.report["sections"]["service_plans"]["reason"] == "oversize"
    projection, _ = project_export(load_export(PROVIDER), policy_catalogue()["policies"])
    readers = {pid for pid, entry in policy_catalogue()["policies"].items() if "scuba_config" in entry["sections"]}
    assert set(projection.report["sections"]["scuba_config"]["synthesis"]["policies"]) == readers
    candidate = deepcopy(raw)
    candidate["scuba_config"]["CapExclusions"] = {"Applications": [], "Groups": [],
                                                   "GuestUserTypes": [], "Users": ["mock"]}
    projection, _ = project_export(load_export(_save(tmp_path, candidate, "exclusion.json")),
                                   policy_catalogue()["policies"])
    outcomes = projection.report["sections"]["scuba_config"]["synthesis"]["policies"]
    expected = SCUBA_CAP_EXCLUSION_POLICIES | SCUBA_ROLE_EXCLUSION_POLICIES
    assert {pid for pid, outcome in outcomes.items() if outcome == "break_glass_unresolved"} == expected
    candidate = deepcopy(raw)
    candidate["scuba_config"]["M365Environment"] = "gcc"
    projection, _ = project_export(load_export(_save(tmp_path, candidate, "gcc.json")),
                                   policy_catalogue()["policies"])
    outcomes = projection.report["sections"]["scuba_config"]["synthesis"]["policies"]
    for pid in ("MS.AAD.9.1v1", "MS.TEAMS.2.2v2", "MS.TEAMS.2.3v2", "MS.TEAMS.4.1v1"):
        assert outcomes[pid] == "environment_ambiguous"
        assert policy_section(projection, pid, "scuba_config") == NOT_COLLECTED
        assert rule_policy_section(projection, pid, "scuba_config")["M365Environment"] == "gcc"


def test_baselines_map_and_reasons():
    assert VERDICT_MAP == {"Pass": "pass", "Fail": "fail", "Warning": "fail", "N/A": "not_assessed"}
    raw = json.loads(PROVIDER.read_text())
    wrapper = json.loads(RESULTS.read_text())
    baseline, reasons, _ = build_baseline(wrapper["Results"], raw, kind="scubaresults")
    assert [baseline[pid] for pid in ("MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1", "MS.AAD.7.4v1")] == [
        "pass", "fail", "fail", "not_assessed"]
    assert reasons["MS.AAD.7.4v1"] == "manual" and reasons["MS.AAD.1.1v1"] == "error"
    rows = json.loads((FIXTURES / "mocktenant-testresults.json").read_text())
    actual, reasons, _ = build_baseline(rows, raw, kind="testresults")
    assert actual["MS.AAD.7.1v1"] == "pass" and actual["MS.AAD.7.3v1"] == "fail"
    assert actual["MS.AAD.7.4v1"] == "not_assessed" and reasons["MS.AAD.7.4v1"] == "not_implemented"
    switched = {**VERDICT_MAP, "Warning": "not_assessed", "N/A": "fail"}
    changed, changed_reasons, _ = build_baseline(rows, raw, kind="testresults", verdict_map=switched)
    assert {pid for pid in actual if actual[pid] != changed[pid]} == {"MS.AAD.7.3v1", "MS.AAD.7.4v1", "MS.AAD.1.1v1"}
    assert changed_reasons["MS.AAD.7.3v1"] == "warning"
    assert all(v in NOT_ASSESSED_REASONS for v in reasons.values())
    for invalid in ({"Pass": "pass"}, {**VERDICT_MAP, "Other": "pass"}, {**VERDICT_MAP, "Warning": "maybe"}):
        with pytest.raises(ValueError):
            build_baseline(rows, raw, kind="testresults", verdict_map=invalid)


def test_verdict_precedence_and_dropped_criticality(tmp_path):
    _, embedded, _ = _dry(tmp_path / "embedded", RESULTS)
    _, overridden, _ = _dry(tmp_path / "overridden", RESULTS,
                            results_path=FIXTURES / "mocktenant-testresults.json")
    _, absent, _ = _dry(tmp_path / "absent")
    assert embedded["verdicts"]["source"] == "embedded"
    assert overridden["verdicts"]["source"] == "results_file"
    assert absent["verdicts"]["source"] == "none" and absent["verdicts"]["counts"] == {}
    assert embedded["verdicts"]["not_assessed_reasons"] != overridden["verdicts"]["not_assessed_reasons"]
    assert not any("Should" in str(value) or "Shall" in str(value) for value in overridden.values())
    assert SENTINEL not in json.dumps(overridden)
    raw = json.loads(PROVIDER.read_text())
    ids = ["MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1", "MS.AAD.7.4v1", "MS.AAD.1.1v1"]
    rows = [
        {"PolicyId": ids[0], "Criticality": "Should", "Commandlet": ["Get-Mock"], "RequirementMet": False},
        {"PolicyId": ids[1], "Criticality": "Shall", "Commandlet": ["Get-Mock"], "RequirementMet": False},
        {"PolicyId": ids[2], "Criticality": "Should/3rd Party", "Commandlet": ["Get-Mock"], "RequirementMet": False},
        {"PolicyId": ids[3], "Criticality": "Shall/Not-Implemented", "Commandlet": ["Get-Mock"], "RequirementMet": False},
        {"PolicyId": ids[4], "Criticality": "Shall", "Commandlet": ["Get-Failed"], "RequirementMet": True},
    ]
    verdicts, reasons, _ = build_baseline(rows, raw, kind="testresults")
    assert verdicts == {ids[0]: "fail", ids[1]: "fail", ids[2]: "not_assessed",
                        ids[3]: "not_assessed", ids[4]: "not_assessed"}
    assert reasons == {ids[2]: "third_party", ids[3]: "not_implemented", ids[4]: "error"}
    repaired, repaired_reasons, _ = build_baseline(rows, raw, kind="testresults",
                                                   repaired_keys=["aad_successful_commands"])
    assert set(repaired.values()) == {"not_assessed"}
    assert set(repaired_reasons.values()) == {"ledger_unavailable"}
    raw.pop("aad_successful_commands")
    absent_ledger, reasons, _ = build_baseline(rows, raw, kind="testresults")
    assert set(absent_ledger.values()) == {"not_assessed"} and set(reasons.values()) == {"ledger_unavailable"}


def test_scubaresults_other_labels_and_testresults_criticalities():
    raw = json.loads(PROVIDER.read_text())
    ids = ["MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1", "MS.AAD.7.4v1"]
    for label in ("Omitted", "Incorrect result", "-", "unexpected", "Error - Test results missing"):
        rows = {"AAD": [{"GroupName": "Mock", "Controls": [{"Control ID": ids[0], "Result": label}]}]}
        baseline, reasons, _ = build_baseline(rows, raw, kind="scubaresults")
        assert baseline == {ids[0]: "not_assessed"} and reasons == {ids[0]: "other"}
    rows = [{"PolicyId": pid, "RequirementMet": False, "Criticality": criticality,
             "Commandlet": ["Get-Mock"]} for pid, criticality in zip(ids, (
                 "Should", "Shall", "Should/Not-Implemented", "Shall/3rd Party"))]
    baseline, reasons, _ = build_baseline(rows, raw, kind="testresults")
    assert [baseline[pid] for pid in ids] == ["fail", "fail", "not_assessed", "not_assessed"]
    assert reasons == {ids[2]: "not_implemented", ids[3]: "third_party"}


def test_warning_and_fail_comparisons_have_identical_semantics():
    from auditex.model_serving import _comparison
    raw = json.loads(PROVIDER.read_text())
    records = [{"claims": [{"id": "requirement_met", "status": "confirmed", "value": False}],
                "validation_status": "valid"} for _ in range(4)]
    ids = ("MS.AAD.7.1v1", "MS.AAD.7.2v1", "MS.AAD.7.3v1", "MS.AAD.7.4v1")
    scuba_rows = {"AAD": [{"Controls": [{"Control ID": ids[0], "Result": "Warning"},
                                         {"Control ID": ids[1], "Result": "Fail"}]}]}
    test_rows = [{"PolicyId": pid, "RequirementMet": False, "Criticality": criticality,
                  "Commandlet": ["Get-Mock"]} for pid, criticality in zip(ids[2:], ("Should", "Shall"))]
    baseline = {**build_baseline(scuba_rows, raw, kind="scubaresults")[0],
                **build_baseline(test_rows, raw, kind="testresults")[0]}
    assert set(baseline) == set(ids) and set(baseline.values()) == {"fail"}
    assert len({_json(_comparison(pid, row, baseline)) for pid, row in zip(ids, records)}) == 1


def test_warning_and_na_switches_are_independent_and_keep_ledger_failures():
    raw = json.loads(PROVIDER.read_text())
    rows = json.loads((FIXTURES / "mocktenant-testresults.json").read_text())
    default, _, _ = build_baseline(rows, raw, kind="testresults")
    for changed_key in ("Warning", "N/A"):
        replacement = "not_assessed" if changed_key == "Warning" else "fail"
        changed, reasons, _ = build_baseline(rows, raw, kind="testresults",
                                             verdict_map={**VERDICT_MAP, changed_key: replacement})
        assert {pid for pid in changed if changed[pid] != default[pid]} == (
            {"MS.AAD.7.3v1"} if changed_key == "Warning" else {"MS.AAD.7.4v1", "MS.AAD.1.1v1"})
        assert all(reason in NOT_ASSESSED_REASONS for reason in reasons.values())
        raw_failed = deepcopy(raw)
        raw_failed.pop("aad_successful_commands")
        failed, failed_reasons, _ = build_baseline(rows, raw_failed, kind="testresults",
                                                  verdict_map={**VERDICT_MAP, changed_key: replacement})
        assert set(failed.values()) == {"not_assessed"}
        assert set(failed_reasons.values()) == {"ledger_unavailable"}
    wrapper = json.loads(RESULTS.read_text())["Results"]
    default_scuba, _, _ = build_baseline(wrapper, raw, kind="scubaresults")
    for changed_key, expected in (("Warning", {"MS.AAD.7.3v1"}),
                                  ("N/A", {"MS.AAD.7.4v1"})):
        replacement = "not_assessed" if changed_key == "Warning" else "fail"
        changed, _, _ = build_baseline(wrapper, raw, kind="scubaresults",
                                       verdict_map={**VERDICT_MAP, changed_key: replacement})
        assert {pid for pid in changed if changed[pid] != default_scuba[pid]} == expected
        raw_failed = deepcopy(raw)
        raw_failed.pop("aad_successful_commands")
        failed, failed_reasons, _ = build_baseline(wrapper, raw_failed, kind="scubaresults",
                                                  verdict_map={**VERDICT_MAP, changed_key: replacement})
        assert set(failed.values()) == {"not_assessed"}
        assert set(failed_reasons.values()) == {"ledger_unavailable"}


def test_hostile_report_uuid_never_becomes_run_id(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    raw["report_uuid"] = SENTINEL
    result = assess_scubagear_export(_save(tmp_path, raw), tmp_path / "hostile",
                                     ModelConfig(model_name="test-model"), policies=["MS.AAD.3.3v2"])
    validate_assessment(result)
    assert re.fullmatch(r"scubagear-[0-9a-f]{16}", result["run_id"])
    assert SENTINEL not in json.dumps(result) + (tmp_path / "hostile/scubagear_adapter_report.json").read_text()
    raw["report_uuid"] = "3F2504E0-4F89-41D3-9A0C-0305E82C3301"
    canonical = assess_scubagear_export(_save(tmp_path, raw, "uuid.json"), tmp_path / "uuid",
                                        ModelConfig(model_name="test-model"), policies=["MS.AAD.3.3v2"])
    assert canonical["run_id"] == "scubagear-3f2504e0-4f89-41d3-9a0c-0305e82c3301"


def test_pruning_proof_shape_and_witness_roundtrip():
    assert PROOF_VERSION == 1 and PINNED_REVISION == "2446ad723b7f55031cc02c8aca244d731d468cba"
    assert len(REGO_SHA256) == 12 and set(PRUNE_PROOF) == set(EXPECTED_VERDICTS)
    assert {s: row["verdict"] for s, row in PRUNE_PROOF.items()} == EXPECTED_VERDICTS
    assert {s: PRUNE_PROOF[s]["rego_read"] for s in EXPECTED_READS} == EXPECTED_READS
    assert all(row["reason"] in ("", *PRUNE_REASONS) and row["verdict"] == verdict_of(row)
               and all(tuple(values) == tuple(sorted(set(values))) for values in (
                   row["rego_read"], row["validated"], row["evidence"], row["adjudicated"]))
               for row in PRUNE_PROOF.values())
    assert GATE_DIGEST == sha256("\n".join(sorted(d for s in PRUNE_PROOF for d in PACK_SHAPE_DIGESTS[s])).encode()).hexdigest()
    fixture = json.loads((ROOT / "tests/fixtures/scuba-projection-shapes-v7.json").read_text())
    total = 0
    for section, row in PRUNE_PROOF.items():
        descriptors = [d for d in fixture["sections"][section]
                       if sha256(_json(d).encode()).hexdigest() in PACK_SHAPE_DIGESTS[section]]
        assert set(row["validated"]) == {p for d in descriptors for p in shape_paths(d)}
        total += len(descriptors)
        for descriptor in descriptors:
            witness = _shape_witness(descriptor, section)
            _seen_shape(section, witness)
            injected = deepcopy(witness)
            _inject_extra(injected)
            if injected != witness:
                with pytest.raises(Exception):
                    _seen_shape(section, injected)
            assert prune_section(section, injected)[0] == witness
            _seen_shape(section, prune_section(section, injected)[0])
    assert total == 305


def test_proof_verdict_cases_and_inline_rego_scan():
    _require_pinned_opa()
    row = {"rego_read": ("[].Name",), "validated": ("[].Name",), "adjudicated": ()}
    assert verdict_of(row) == "prunable"
    for change in ({"rego_read": ("[].Other",)}, {"adjudicated": ("whole_object:Test.rego:1",)},
                   {"adjudicated": ("unresolved:Test.rego:1",)}, {"rego_read": ()}):
        assert verdict_of({**row, **change}) == "withheld"
    script = ROOT / "scripts/derive-scubagear-prune-table.py"
    spec = importlib.util.spec_from_file_location("derive_inline", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    validated = {section: ("[].Name", "[].Nested", "[].Nested.Field", "[].RoleTemplateId")
                 for section in module.SECTIONS}
    kinds = {section: {"": {"array"}, "[]": {"object"}, "[].Nested": {"object"},
                       "[].Name": {"leaf"}, "[].RoleTemplateId": {"leaf"}}
             for section in module.SECTIONS}
    snippets = [
        ("some X in input.org_config\n    X.Name == \"mock\"", "prunable", "[].Name"),
        ("X := input.org_config[_]\n    X.Name == \"mock\"", "prunable", "[].Name"),
        ("every X in input.org_config { X.Name == \"mock\" }", "prunable", "[].Name"),
        ("every K, V in input.org_config { V.Name == \"mock\" }", "withheld", "[].Name"),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    object.keys(X)", "withheld", "[].Name"),
        ("some K, X in input.org_config\n    X.Name == \"mock\"", "withheld", "[].Name"),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    X[K]", "withheld", "[].Name"),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    X == Y", "withheld", "[].Name"),
        ("some X in input.org_config\n    X != null\n    X.Name == \"mock\"", "prunable", "[].Name"),
        ("some X in input.org_config\n    count(X) > 0\n    X.Name == \"mock\"", "prunable", "[].Name"),
        ("some X in input.org_config\n    startswith(X.Name, \"m\")", "prunable", "[].Name"),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    sprintf(\"%v\", [X]) == \"x\"", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    X == {\"Name\": \"mock\"}", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    some V in X.Nested", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    object.get(X, K, null) == false", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    count([v | some v in X]) > 3", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    json.marshal(X.Nested) == \"{}\"", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    custom_builtin(X.Nested)", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    X.Nested == {}", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    walk(input.org_config, [p, v])", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    input.org_config == []", "withheld", None),
        ("some X in input.org_config\n    X.Name == \"mock\"\n    bar with input.org_config as []", "withheld", None),
    ]
    for index, (code, expected, read) in enumerate(snippets):
        if index in (3, 4, 5, 6, 7):
            code = 'some R in input.org_config\n    R.Name == "mock"\n    ' + code
        source = "package exo\nimport rego.v1\nfoo if {\n    " + code + "\n}\n"
        actual = module.scan_rego({"Test.rego": source}, validated, kinds)["org_config"]
        assert actual["verdict"] == expected, (code, actual)
        if read:
            assert read in actual["rego_read"]
        if expected == "withheld":
            assert actual["reason"] != "no_rego_reader", (code, actual)
            if index in (3, 4, 5, 6, 7):
                assert actual["reason"] == (
                    "unresolved_reference" if index == 6 else "whole_object_use"), (code, actual)
    alias = "package exo\nimport rego.v1\nAlias := input.org_config[0]\nfoo if {\n    Alias.Name == \"mock\"\n}\n"
    assert "[].Name" in module.scan_rego({"Test.rego": alias}, validated)["org_config"]["rego_read"]
    helper = ("package exo\nimport rego.v1\nHelper(Item) if { Item.Name == \"mock\" }\n"
              "foo if { some X in input.org_config; Helper(X) }\n")
    assert "[].Name" in module.scan_rego({"Test.rego": helper}, validated)["org_config"]["rego_read"]
    object_get = ("package exo\nimport rego.v1\nAlias := object.get(input, \"org_config\", [{}])[0]\n"
                  "foo if { object.get(Alias, \"Name\", null) == \"mock\" }\n")
    assert "[].Name" in module.scan_rego({"Test.rego": object_get}, validated)["org_config"]["rego_read"]
    wrapped = ('package exo\nimport rego.v1\nfoo := {"ActualValue": sprintf("%v", [input.org_config])} '
               'if { some X in input.org_config; X.Name == "mock" }\n')
    assert module.scan_rego({"Test.rego": wrapped}, validated, kinds)["org_config"]["verdict"] == "withheld"
    report_only = ('package exo\nimport rego.v1\nfoo := {"ActualValue": input.org_config} '
                   'if { some X in input.org_config; X.Name == "mock" }\n')
    assert module.scan_rego({"Test.rego": report_only}, validated, kinds)["org_config"]["verdict"] == "prunable"
    empty_kinds = deepcopy(kinds)
    empty_kinds["org_config"]["[]"] = {"object", "empty_object"}
    emptiness = ('package exo\nimport rego.v1\nfoo if { some X in input.org_config; X.Name == "mock"; '
                 'count(X) == 0 }\n')
    assert module.scan_rego({"Test.rego": emptiness}, validated, kinds)["org_config"]["verdict"] == "prunable"
    assert module.scan_rego({"Test.rego": emptiness}, validated, empty_kinds)["org_config"]["verdict"] == "withheld"
    computed_literal = ('package exo\nimport rego.v1\nGetField(Item, Key) := Item[Key]\n'
                        'foo if { some X in input.org_config; X.Name == "mock"; '
                        'GetField(X, "Name") == "mock" }\n')
    assert module.scan_rego({"Test.rego": computed_literal}, validated, kinds)["org_config"]["verdict"] == "prunable"
    computed_unknown = ('package exo\nimport rego.v1\nGetField(Item, Key) := object.get(Item, Key, null)\n'
                        'foo if { some X in input.org_config; X.Name == "mock"; '
                        'GetField(X, K) == false }\n')
    assert module.scan_rego({"Test.rego": computed_unknown}, validated, kinds)["org_config"]["verdict"] == "withheld"
    chain = 'package exo\nimport rego.v1\n' + '\n'.join(
        f'H{i}(Item) if {{ H{i + 1}(Item) }}' for i in range(9)) + '\nH9(Item) if { Item.Name == "mock" }\n' + \
        'foo if { some X in input.org_config; X.Name == "mock"; H0(X) }\n'
    deep = module.scan_rego({"Test.rego": chain}, validated, kinds)["org_config"]
    assert deep["verdict"] == "withheld" and deep["reason"] == "unresolved_reference"
    assert any(entry.startswith("unresolved:Test.rego:") for entry in deep["adjudicated"])
    hazards = [
        ('some X in input.org_config; X.Name == "mock"; contains(sprintf("%v", [X]), "x")', "whole_object_use"),
        ('some X in input.org_config; X.Name == "mock"; {"Name":"mock"} in input.org_config', "whole_object_use"),
        ('some X in input.org_config; X.Name == "mock"; input.org_config != [{"Name":"x"}]', "whole_object_use"),
        ('some X in input.org_config; X.Name == "mock"; json.marshal(input.org_config[_]) != "{}"', "whole_object_use"),
        ('some X in input.org_config; X.Name == "mock"; X.Nested', "whole_object_use"),
        ('some X in input.org_config; X.Name == "mock"; S := "org_config"; some O in input[S]', "unresolved_reference"),
    ]
    for body, reason in hazards:
        source = "package exo\nimport rego.v1\nfoo if { " + body + " }\n"
        result = module.scan_rego({"Test.rego": source}, validated, kinds)["org_config"]
        assert result["verdict"] == "withheld" and result["reason"] == reason, (body, result)
        assert "[].Name" in result["rego_read"]
    mixed_head = ('package exo\nimport rego.v1\n'
                  'foo := {"ActualValue": input.org_config, "RequirementMet": input.org_config == []} '
                  'if { some X in input.org_config; X.Name == "mock" }\n')
    result = module.scan_rego({"Test.rego": mixed_head}, validated, kinds)["org_config"]
    assert result["verdict"] == "withheld" and result["reason"] == "whole_object_use", result
    assert "[].Name" in result["rego_read"]
    first_org = ('package exo\nimport rego.v1\nFirstOrg(Arr) := Arr[0]\n'
                 'foo if { some X in input.org_config; X.Name == "mock"; '
                 'O := FirstOrg(input.org_config); O.HybridMode == "Restricted" }\n')
    result = module.scan_rego({"Test.rego": first_org}, validated, kinds)["org_config"]
    assert result["verdict"] == "withheld" and result["reason"] == "whole_object_use", result
    assert "[].Name" in result["rego_read"]
    variable_key = ('package exo\nimport rego.v1\nGetField(Item, Key) := Item[Key]\n'
                    'foo if { some X in input.org_config; X.Name == "mock"; '
                    'GetField(X, "Name") == "mock"; K := "IsHidden"; GetField(X, K) == true }\n')
    result = module.scan_rego({"Test.rego": variable_key}, validated, kinds)["org_config"]
    assert result["verdict"] == "withheld" and result["reason"] == "unresolved_reference", result
    alias_hazards = (
        'contains(sprintf("%v", [Alias]), "x")',
        'json.marshal(Alias[_]) != "{}"',
        'json.marshal(Alias[0]) != "{}"',
        '{"Name":"mock"} in Alias',
        'Alias != [{"Name":"mock"}]',
    )
    for expression in alias_hazards:
        source = ('package exo\nimport rego.v1\nAlias := input.org_config\n'
                  'foo if { some X in input.org_config; X.Name == "mock"; ' + expression + ' }\n')
        result = module.scan_rego({"Test.rego": source}, validated, kinds)["org_config"]
        assert result["verdict"] == "withheld" and result["reason"] == "whole_object_use", (expression, result)
        assert "[].Name" in result["rego_read"]
    array_kinds = deepcopy(kinds)
    array_kinds["privileged_roles"] = {"": {"array"}, "[]": {"object"}, "[].Rules": {"array"},
                                       "[].Rules[]": {"object"}}
    array_source = ('package aad\nimport rego.v1\nfoo if { '
                    'some Role in input.privileged_roles; Role.RoleTemplateId == "mock"; '
                    'sprintf("%v", [Role.Rules]) == "x" }\n')
    array_validated = {**validated, "privileged_roles": (*validated["privileged_roles"], "[].Rules")}
    result = module.scan_rego({"Test.rego": array_source}, array_validated, array_kinds)["privileged_roles"]
    assert result["verdict"] == "withheld" and result["reason"] == "whole_object_use", result
    mutation_cases = (
        ("M1", "conditional_access_policies", 'some P in input.conditional_access_policies; '
         'P.DisplayName == "mock"; P.Conditions.Unvalidated == true', "reads_unvalidated_field"),
        ("M2", "org_config", 'some X in input.org_config; X.Name == "mock"; '
         'sprintf("%v", [input.org_config]) == "x"', "whole_object_use"),
        ("M3", "org_config", 'some X in input.org_config; X.Name == "mock"; '
         'X.HybridConfigurationStatus == false', "reads_unvalidated_field"),
        ("M4", "org_config", 'some X in input.org_config; X.Name == "mock"; '
         'input.org_config == []', "whole_object_use"),
    )
    mutation_validated = {**validated, "conditional_access_policies": ("[].DisplayName", "[].Conditions")}
    mutation_kinds = {**kinds, "conditional_access_policies": {"": {"array"}, "[]": {"object"},
                                                       "[].DisplayName": {"leaf"}, "[].Conditions": {"object"}}}
    for mutation_id, section, body, reason in mutation_cases:
        source = 'package exo\nimport rego.v1\nfoo if { ' + body + ' }\n'
        result = module.scan_rego({"Test.rego": source}, mutation_validated, mutation_kinds)[section]
        assert result["verdict"] == "withheld" and result["reason"] == reason, (mutation_id, result)
    module.ADJUDICATIONS["Test.rego:1"] = ("leaf", "stale")
    with pytest.raises(ValueError, match="Unused ScubaGear adjudication"):
        module.scan_rego({"Test.rego": "package exo\nfoo if { true }\n"}, validated)


def _require_pinned_opa():
    opa = os.environ.get("AUDITEX_TEST_OPA")
    if not opa or not Path(opa).is_file():
        pytest.skip("export AUDITEX_TEST_OPA (pinned OPA 1.20.2)")
    version = subprocess.run([opa, "version"], capture_output=True, text=True, check=False)
    if version.returncode or "Version: 1.20.2" not in version.stdout:
        pytest.skip("AUDITEX_TEST_OPA is not pinned OPA 1.20.2")


@pytest.mark.parametrize("case,source,reason", [
    ("N11", 'ModeIs(O, M) if { upper(O.HybridMode) == M }\n'
     'foo if { some O in input.org_config; O.Name == "mock"; ModeIs(O, upper("restricted")) }',
     "reads_unvalidated_field"),
    ("N12", 'import input.org_config as orgs\n'
     'foo if { some X in input.org_config; X.Name == "mock"; '
     'some O in orgs; O.HybridMode == "Restricted" }', "reads_unvalidated_field"),
    ("N13", 'foo if { some X in input.org_config; X.Name == "mock"; '
     'I := input; some O in I.org_config; O.HybridMode == "Restricted" }', "unresolved_reference"),
    ("N15", 'foo if { some X in input.org_config; X.Name == "mock"; '
     'some O in input[ "org_config" ]; O.HybridMode == "Restricted" }', "reads_unvalidated_field"),
    ("N16", 'foo if { some O in input.org_config; O.Name == "mock"; '
     'X := `#`; O.HybridMode == "Restricted" }', "reads_unvalidated_field"),
    ("N17", 'foo if { some O in input.org_config; O.Name == "mock"; '
     'O[\n"HybridMode"\n] == "Restricted" }', "reads_unvalidated_field"),
    ("N19", 'Check(Inp) if { some O in Inp.org_config; O.HybridMode == "Restricted" }\n'
     'foo if { some X in input.org_config; X.Name == "mock"; Check(input) }', "unresolved_reference"),
    ("N23", 'foo if { some O in input.org_config; O.Name == "mock"; '
     'X := `"`; contains(json.marshal(O), "Restricted") }', "whole_object_use"),
    ("N26", 'foo if {\n    some O in input.org_config\n    O.Name == "mock"\n'
     'Junk := 1\n    O.HybridMode == "Restricted"\n}', "reads_unvalidated_field"),
])
def test_ast_review_constructs_withhold(case, source, reason):
    _require_pinned_opa()
    script = ROOT / "scripts/derive-scubagear-prune-table.py"
    spec = importlib.util.spec_from_file_location("derive_ast_review", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rego = "package exo\nimport rego.v1\n" + source + "\n"
    validated = {section: ("[].Name",) for section in module.SECTIONS}
    kinds = {section: {"": {"array"}, "[]": {"object"}, "[].Name": {"leaf"}}
             for section in module.SECTIONS}
    result = module.scan_rego({"Test.rego": rego}, validated, kinds)["org_config"]
    assert result["verdict"] == "withheld" and result["reason"] == reason, (case, result)
    assert "[].Name" in result["rego_read"], (case, result)


def test_computed_input_in_separate_rule_withholds_all_sections():
    _require_pinned_opa()
    spec = importlib.util.spec_from_file_location("derive_ast_two_rule", ROOT / "scripts/derive-scubagear-prune-table.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = ('package exo\nimport rego.v1\n'
              'reader if { some X in input.org_config; X.Name == "mock" }\n'
              'computed if { S := "org_config"; some O in input[S] }\n')
    validated = {section: ("[].Name",) for section in module.SECTIONS}
    kinds = {section: {"": {"array"}, "[]": {"object"}, "[].Name": {"leaf"}}
             for section in module.SECTIONS}
    result = module.scan_rego({"Test.rego": source}, validated, kinds)["org_config"]
    assert result["rego_read"] == ("[].Name",)
    assert result["verdict"] == "withheld" and result["reason"] == "unresolved_reference"


@pytest.mark.parametrize("case,section,source,reason", [
    ("M1", "conditional_access_policies",
     'foo if { some P in input.conditional_access_policies; P.DisplayName == "mock"; '
     'not P.Conditions.Platforms }', "reads_unvalidated_field"),
    ("M2", "org_config",
     'OrgConfig := input.org_config\n'
     'foo if { some X in input.org_config; X.Name == "mock"; '
     'count([v | some v in OrgConfig]) > 3 }', "whole_object_use"),
    ("M3", "org_config",
     'foo if { some OrgConfig in input.org_config; OrgConfig.Name == "mock"; '
     'OrgConfig.HybridConfigurationStatus == false }', "reads_unvalidated_field"),
    ("M4", "org_config",
     'foo if { some OrgConfig in input.org_config; OrgConfig.Name == "mock"; '
     'some K in ["HybridConfigurationStatus"]; object.get(OrgConfig, K, true) == false }',
     "whole_object_use"),
    ("FirstOrg", "org_config",
     'FirstOrg(Arr) := Arr[0]\n'
     'foo if { some X in input.org_config; X.Name == "mock"; '
     'O := FirstOrg(input.org_config); O.HybridMode == "Restricted" }', "whole_object_use"),
])
def test_ast_mutation_constructs_withhold(case, section, source, reason):
    _require_pinned_opa()
    spec = importlib.util.spec_from_file_location("derive_ast_mutation", ROOT / "scripts/derive-scubagear-prune-table.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    validated = {name: ("[].DisplayName", "[].Conditions") if name == "conditional_access_policies"
                 else ("[].Name",) for name in module.SECTIONS}
    kinds = {name: {"": {"array"}, "[]": {"object"}, "[].Name": {"leaf"},
                    "[].DisplayName": {"leaf"}, "[].Conditions": {"object"}}
             for name in module.SECTIONS}
    row = module.scan_rego({"Test.rego": "package exo\nimport rego.v1\n" + source + "\n"}, validated, kinds)[section]
    assert row["verdict"] == "withheld" and row["reason"] == reason, (case, row)
    assert ("[].DisplayName" if case == "M1" else "[].Name") in row["rego_read"]


def _shape_witness(node, section, path=""):
    if isinstance(node, str) and node[:1] in '{["':
        try:
            return _shape_witness(json.loads(node), section, path)
        except json.JSONDecodeError:
            pass
    if isinstance(node, dict) and set(node) == {"object"}:
        return {key: _shape_witness(child, section, path + "." + key) for key, child in node["object"].items()}
    if isinstance(node, dict) and set(node) == {"array"}:
        return [_shape_witness(child, section, path + "[]") for child in node["array"]]
    if node == "NoneType":
        return None
    for encoded in PACK_ENUM_DOMAINS.get(section, {}).get(path.removesuffix("[]"), []):
        value = json.loads(encoded)
        if node == "str" and isinstance(value, str) or node == "int" and type(value) is int or \
                node == "bool" and type(value) is bool:
            return value
    return {"str": "mock", "int": 0, "bool": False, "float": 0.0}[node]


def _inject_extra(value):
    if isinstance(value, list):
        for item in value:
            _inject_extra(item)
    elif isinstance(value, dict):
        for item in list(value.values()):
            _inject_extra(item)
        value["UnvalidatedScalar"] = "mock"
        value["UnvalidatedObject"] = {"Nested": "mock"}


def test_prune_section_does_not_trust_hand_edited_verdict():
    raw = json.loads(REAL.read_text())["dkim_config"]
    clean, count = prune_section("dkim_config", raw)
    assert count and clean != raw
    _seen_shape("dkim_config", clean)
    assert prune_section("dkim_config", clean) == (clean, 0)
    bad = deepcopy(PRUNE_PROOF)
    bad["dkim_config"]["rego_read"] += ("[].Selector1CNAME",)
    assert verdict_of(bad["dkim_config"]) == "withheld"
    assert prune_section("dkim_config", raw, bad) == (raw, 0)
    bad["dkim_config"]["verdict"] = "withheld"
    assert prune_section("dkim_config", raw, bad) == (raw, 0)


def test_unseen_shapes_after_pruning_are_withheld_without_ignored_fields(tmp_path):
    base = json.loads(REAL.read_text())
    mutations = [
        ("dkim_config", lambda r: r["dkim_config"][0].update(Enabled="true")),
        ("spf_records", lambda r: r["spf_records"][0].update(rdata=[])),
        ("spf_records", lambda r: r["spf_records"][0].update(rdata=None)),
        ("authorization_policies", lambda r: r["authorization_policies"][0].update(AllowInvitesFrom="everyone")),
        ("dkim_config", lambda r: r.update(dkim_config=[{"Extra": "mock"}])),
    ]
    for index, (section, mutate) in enumerate(mutations):
        raw = deepcopy(base)
        mutate(raw)
        projection, extras = project_export(load_export(_save(tmp_path, raw, f"shape-{index}.json")),
                                            policy_catalogue()["policies"])
        row = projection.report["sections"][section]
        assert row["status"] == "not_collected", (section, row)
        assert "ignored_fields" not in row
        assert extras["pruning"][section]["outcome"] == "withheld"
        assert extras["pruning"][section]["pruned_keys"] > 0


def test_twenty_key_order_shuffles_keep_prompt_hashes_and_pruning_blocks(tmp_path):
    original = json.loads(REAL.read_text())
    _, baseline, prompts = _dry(tmp_path / "baseline", REAL)
    hashes = [row["prompt_sha256"] for row in prompts]
    randomizer = random.Random(20261104)
    def shuffle(value, path=""):
        if isinstance(value, dict):
            return {key: shuffle(child, key) for key, child in randomizer.sample(list(value.items()), len(value))}
        if isinstance(value, list):
            children = randomizer.sample(value, len(value)) if path == "roles" else value
            return [shuffle(child) for child in children]
        return value
    for index in range(20):
        source = _save(tmp_path, shuffle(original), f"shuffle-{index}.json")
        _, sidecar, rows = _dry(tmp_path / f"shuffle-{index}", source)
        assert [row["prompt_sha256"] for row in rows] == hashes
        assert sidecar["pruning"] == baseline["pruning"]
        assert sidecar["canonicalised"] == baseline["canonicalised"]
        assert sidecar["disposition"] == baseline["disposition"]
        assert sidecar["ceiling"] == baseline["ceiling"]


def test_empty_pruning_proof_is_identity_on_clean_fixture(tmp_path):
    loaded = load_export(PROVIDER)
    default, _ = project_export(loaded, policy_catalogue()["policies"])
    identity, _ = project_export(loaded, policy_catalogue()["policies"], proof={})
    assert dict(default) == dict(identity)
    assert default.report["sections"] == identity.report["sections"]


def test_replacing_every_privileged_guid_keeps_unrelated_prompt_bytes(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    original = _dry(tmp_path / "original-guid")[2]
    replaced = {}
    for index, (old, entry) in enumerate(raw["privileged_users"].items(), 1):
        new = f"3f2504e0-4f89-41d3-9a0c-{index:012x}"
        replaced[new] = {**entry, "id": new}
    raw["privileged_users"] = replaced
    changed = _dry(tmp_path / "changed-guid", _save(tmp_path, raw))[2]
    users_readers = {pid for pid, item in policy_catalogue()["policies"].items()
                     if "privileged_users" in item["sections"]}
    assert users_readers
    before = {row["policy_id"]: row["prompt_sha256"] for row in original}
    after = {row["policy_id"]: row["prompt_sha256"] for row in changed}
    assert all(before[pid] == after[pid] for pid in before if pid not in users_readers)
    assert any(before[pid] != after[pid] for pid in users_readers)


@pytest.mark.parametrize("clear", [False, True])
def test_removed_values_and_invalid_key_names_do_not_leak(tmp_path, caplog, capsys, clear):
    raw = json.loads(REAL.read_text())
    for row in raw["dkim_config"]:
        row["PrunedSecret"] = SENTINEL
        row["non.identifier.key"] = SENTINEL
        row["@odata.type"] = SENTINEL
    source = _save(tmp_path, raw)
    with caplog.at_level("DEBUG"):
        _, sidecar, prompts = _dry(tmp_path / "out", source, no_redaction=clear)
    loaded = load_export(source)
    projection, _ = project_export(loaded, policy_catalogue()["policies"], redact=not clear)
    report = projection.report["sections"]["dkim_config"]
    assert report["status"] == "projected"
    assert "PrunedSecret" in report["ignored_fields"]
    assert "unrecognisedField" in report["ignored_fields"]
    assert "non.identifier.key" not in repr(report)
    assert "@odata." not in repr(report)
    written = (tmp_path / "out/assessment/model_assessment_prompts.jsonl").read_text() + (
        tmp_path / "out/assessment/scubagear_adapter_report.json").read_text()
    assert SENTINEL not in written + repr(sidecar) + repr(projection.report) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("clear", [False, True])
def test_sensitive_unlisted_export_and_result_fields_never_reach_outputs(tmp_path, caplog, capsys, clear):
    raw = json.loads(PROVIDER.read_text())
    raw["scuba_config"].update(AppID=SENTINEL, CertificateThumbprint=SENTINEL)
    raw["tenant_details"]["Ignored"] = SENTINEL
    raw["cap_table_data"] = {"secret": SENTINEL}
    raw["unlisted_export_key"] = SENTINEL
    raw["module_version"] = SENTINEL
    raw["privileged_users"][next(iter(raw["privileged_users"]))]["DisplayName"] = "mock.user@mocktenant.invalid"
    results = json.loads(RESULTS.read_text())
    control = results["Results"]["AAD"][0]["Controls"][0]
    control.update(Details=SENTINEL, ReportDetails=SENTINEL, ErrorDetails=SENTINEL,
                   Requirement=SENTINEL)
    result_path = _save(tmp_path, results, "results.json")
    with caplog.at_level("DEBUG"):
        _, sidecar, prompts = _dry(tmp_path / "leak", _save(tmp_path, raw),
                                   results_path=result_path, no_redaction=clear)
    output = (tmp_path / "leak/assessment/model_assessment_prompts.jsonl").read_text() + json.dumps(sidecar)
    assert SENTINEL not in output + repr(prompts) + caplog.text + str(capsys.readouterr())
    assessed = assess_scubagear_export(_save(tmp_path, raw, "assessment-source.json"),
                                       tmp_path / "leak-envelope", ModelConfig(model_name="test-model"),
                                       results_path=result_path, policies=["MS.AAD.3.3v2"], no_redaction=clear)
    validate_assessment(assessed)
    assert SENTINEL not in json.dumps(assessed) + (tmp_path / "leak-envelope/scubagear_adapter_report.json").read_text()
    assert "mocktenant.invalid" in output
    if not clear:
        assert "mock.user@mocktenant.invalid" not in output


@pytest.mark.parametrize("clear", [False, True])
def test_guid_key_and_id_forms_never_leak_even_on_rejection(tmp_path, caplog, capsys, clear):
    guid = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
    raw = json.loads(PROVIDER.read_text())
    old, entry = next(iter(raw["privileged_users"].items()))
    del raw["privileged_users"][old]
    entry["id"] = guid
    raw["privileged_users"][guid] = entry
    source = _save(tmp_path, raw)
    forms = {guid, guid.upper(), guid.replace("-", ""), guid.replace("-", "").upper()}
    with caplog.at_level("DEBUG"):
        result, sidecar, prompts = _dry(tmp_path / "valid", source, no_redaction=clear)
    text = json.dumps(result) + json.dumps(sidecar) + repr(prompts)
    assert all(form not in text + caplog.text + str(capsys.readouterr()) for form in forms)
    envelope = assess_scubagear_export(source, tmp_path / "valid-envelope", ModelConfig(model_name="test-model"),
                                       policies=["MS.AAD.3.3v2"], no_redaction=clear)
    validate_assessment(envelope)
    assert all(form not in json.dumps(envelope) for form in forms)
    raw["privileged_users"][guid]["Extra"] = SENTINEL
    rejected = _save(tmp_path, raw, "rejected.json")
    with caplog.at_level("DEBUG"):
        result, sidecar, prompts = _dry(tmp_path / "rejected", rejected, no_redaction=clear)
    text = json.dumps(result) + json.dumps(sidecar) + repr(prompts)
    assert all(form not in text + caplog.text + str(capsys.readouterr()) for form in forms)
    assert sidecar["disposition"]["MS.AAD.7.1v1"]["status"] == "withheld"
    for index, malformed_id in enumerate((guid.upper(), guid.replace("-", "").upper())):
        changed = deepcopy(raw)
        changed["privileged_users"][guid]["id"] = malformed_id
        result, sidecar, prompts = _dry(tmp_path / f"malformed-id-{index}",
                                        _save(tmp_path, changed, f"malformed-id-{index}.json"),
                                        no_redaction=clear)
        text = json.dumps(result) + json.dumps(sidecar) + repr(prompts)
        assert all(form not in text for form in forms)
    assert all("PrunedSecret" not in json.dumps(row) for row in sidecar["pruning"]["sections"].values())


def test_qualifier_checks_ca_and_roles():
    raw = json.loads(REAL.read_text())
    ca = deepcopy(raw["conditional_access_policies"])
    ca[0]["Conditions"]["Locations"] = {"IncludeLocations": ["All"]}
    assert qualifier_check("conditional_access_policies", ca) == {"field": "$", "kind": "unexpected_field"}
    ca[0]["State"] = "disabled"
    assert qualifier_check("conditional_access_policies", ca) is None
    role = deepcopy(raw["privileged_roles"])
    role[0]["Assignments"][0]["MemberType"] = "Direct"
    assert qualifier_check("privileged_roles", role) == {"field": "$", "kind": "unexpected_field"}
    del role[0]["Assignments"][0]["MemberType"]
    role[0]["Rules"][0]["Id"] = "Unknown_Mock"
    assert qualifier_check("privileged_roles", role) == {"field": "Rules.Id", "kind": "unseen_enum_value"}
    assert len(CA_RESTRICTION_NAMES) == 16


def _camel(value):
    if isinstance(value, dict):
        return {key[:1].lower() + key[1:]: _camel(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_camel(item) for item in value]
    return value


def _bundle_ca_decision(rows):
    from auditex.scuba_projection import Bundle, Unavailable, _ca
    class Example(Bundle):
        def operation(self, *_args):
            return _camel(rows)
    try:
        _ca(Example(Path("."), 1, 1, 1))
        return None
    except Unavailable as exc:
        return exc.detail if exc.detail.get("kind") == "unexpected_field" else None


def _bundle_role_decision(rows):
    from auditex.scuba_projection import Bundle, Unavailable, _roles
    class Example(Bundle):
        def collector_health(self, *_args):
            pass
        def normalised(self, *_args):
            return rows
    try:
        _roles(Example(Path("."), 1, 1, 1))
        return None
    except Unavailable as exc:
        return exc.detail if exc.detail.get("kind") in {"unexpected_field", "unseen_enum_value"} else None


def _spec_paths(node, base=""):
    paths = set()
    if isinstance(node, ast.DictComp):
        assert len(node.generators) == 1 and isinstance(node.generators[0].iter, ast.Tuple)
        for item in node.generators[0].iter.elts:
            field = ast.literal_eval(item)
            paths.add(base + "." + field if base else field)
        return paths
    if not isinstance(node, ast.Dict):
        return paths
    for key, child in zip(node.keys, node.values):
        if key is None:
            assert isinstance(child, ast.DictComp)
            assert len(child.generators) == 1 and isinstance(child.generators[0].iter, ast.Tuple)
            for item in child.generators[0].iter.elts:
                field = ast.literal_eval(item)
                paths.add(base + "." + field if base else field)
        else:
            field = ast.literal_eval(key)
            path = base + "." + field if base else field
            paths.add(path)
            paths.update(_spec_paths(child, path))
    return paths


def test_qualifier_mirrors_drift_guards():
    import auditex.scuba_projection as bundle_module
    ca_ast = ast.parse(inspect.getsource(bundle_module._ca))
    restriction = next(node.value for node in ast.walk(ca_ast) if isinstance(node, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == "restriction_names" for t in node.targets))
    assert CA_RESTRICTION_NAMES == set(ast.literal_eval(restriction))
    spec = next(node.value for node in ast.walk(ca_ast) if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "spec" for t in node.targets))
    assert {"[]." + path for path in _spec_paths(spec)} == set(PRUNE_PROOF["conditional_access_policies"]["validated"])
    base = json.loads(PROVIDER.read_text())
    ca_cases = []
    for path, value in [
        (("Conditions", "Locations"), {"IncludeLocations": ["mock"]}),
        (("Conditions", "Platforms"), {"IncludePlatforms": ["mock"]}),
        (("Conditions", "Devices"), {"IncludeDevices": ["mock"]}),
        (("SessionControls",), {"mock": True}),
        (("Conditions", "Users", "IncludeGroups"), ["mock"]),
        (("Conditions", "Users", "IncludeGuestsOrExternalUsers"), {"mock": True}),
        (("Conditions", "UnknownRestriction"), "mock"),
        (("Conditions", "Nested", "id"), "mock"),
        (("Conditions", "Locations"), None),
        (("Conditions", "Locations"), {}),
        (("Conditions", "Locations"), {"IncludeLocations": []}),
        (("Id",), "mock"), (("CreatedDateTime",), "mock"),
        (("TemplateId",), "mock"), (("@odata.type",), "mock"),
    ]:
        rows = deepcopy(base["conditional_access_policies"])
        node = rows[0]
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = value
        ca_cases.append(rows)
    for state in ("disabled", "enabledForReportingButNotEnforced"):
        rows = deepcopy(ca_cases[0])
        rows[0]["State"] = state
        ca_cases.append(rows)
    for rows in ca_cases:
        expected = _bundle_ca_decision(rows)
        actual = qualifier_check("conditional_access_policies", rows)
        assert (expected is not None) == (actual is not None)
    roles = base["privileged_roles"]
    role_cases = []
    for key, value in [
        ("MemberType", "Direct"), ("AssignmentType", "Direct"), ("Status", "active"),
        ("AppScopeId", "mock"), ("DirectoryScopeId", "/unit"), ("DirectoryScopeId", "/"),
        ("ExtraNull", None), ("ExtraEmpty", ""), ("RoleDefinitionId", "other"),
    ]:
        rows = deepcopy(roles)
        rows[0]["Assignments"][0][key] = value
        role_cases.append(rows)
    for key, value in [("Target", {"Caller": "other", "Level": "other"}),
                       ("NotificationLevel", "mock"), ("RecipientType", "other")]:
        rows = deepcopy(roles)
        rows[0]["Rules"][0][key] = value
        role_cases.append(rows)
    rows = deepcopy(roles)
    rows[0]["Rules"][0]["Id"] = "Unknown_Mock"
    role_cases.append(rows)
    for rows in role_cases:
        expected = _bundle_role_decision(rows)
        actual = qualifier_check("privileged_roles", rows)
        assert (expected is not None) == (actual is not None), (expected, actual)
        if expected and expected.get("field") == "Rules.Id":
            assert actual == expected


def test_scope_raw_branch_keeps_restrictions(tmp_path):
    raw = json.loads(REAL.read_text())
    raw["conditional_access_policies"][0]["Conditions"]["Locations"] = {
        "IncludeLocations": ["00000000-0000-4000-8000-000000000030"]}
    raw["conditional_access_policies"][0]["DisplayName"] = "user1@mocktenant.invalid scope"
    source = _save(tmp_path, raw)
    loaded = load_export(source)
    projection, extra = project_export(loaded, policy_catalogue()["policies"])
    from auditex.scubagear_export import scope_from_export
    summary = scope_from_export(projection, extra["raw_ca"], redact=True, max_items=40).summary
    assert projection.report["sections"]["conditional_access_policies"]["detail"]["kind"] == "unexpected_field"
    assert summary["status"] == "evaluated" and summary["source"] == "raw" and summary["count"] >= 1
    assert "***@mocktenant.invalid" in json.dumps(summary)
    assert "user1@" not in json.dumps(summary)


def test_projected_scope_summary_and_bad_raw_scope_is_not_evaluated(tmp_path):
    from auditex.scubagear_export import scope_from_export
    raw = json.loads(PROVIDER.read_text())
    raw["conditional_access_policies"][0]["GrantControls"]["BuiltInControls"] = ["mfa"]
    projection, extras = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()["policies"])
    scope = scope_from_export(projection, extras["raw_ca"], redact=True, max_items=40)
    assert scope.summary["source"] == "projection" and scope.summary["count"] == 1
    assert scope.summary["policies"] == [{"name": raw["conditional_access_policies"][0]["DisplayName"],
                                           "conditions": ["conditions.clientAppTypes"]}]
    raw["conditional_access_policies"][0]["DisplayName"] = []
    projection, extras = project_export(load_export(_save(tmp_path, raw, "bad-scope.json")),
                                        policy_catalogue()["policies"])
    bad = scope_from_export(projection, extras["raw_ca"], redact=True, max_items=40)
    assert bad.summary["status"] == "not_evaluated" and bad.summary["source"] is None


@pytest.mark.parametrize("variant,expected_source,expected_reason", [
    ("projected", "projection", None), ("restriction", "raw", None),
    ("unseen_shape", None, "incomplete_shape"), ("unseen_enum", "raw", None),
    ("unseen_shape_valid", "raw", None),
    ("oversize", "raw", None), ("absent", None, "missing_artifact"),
    ("repaired", None, "incomplete_shape"),
    ("ledger_absent", None, "incomplete_shape"), ("ledger_failed", None, "incomplete_shape"),
    ("not_list", None, "incomplete_shape"),
])
def test_scope_branches_validate_envelope(tmp_path, variant, expected_source, expected_reason):
    raw = json.loads(PROVIDER.read_text())
    if variant == "restriction":
        raw["conditional_access_policies"][0]["Conditions"]["Locations"] = {
            "IncludeLocations": ["00000000-0000-4000-8000-000000000030"]}
    elif variant == "unseen_shape":
        raw["conditional_access_policies"][0]["State"] = 1
    elif variant == "unseen_enum":
        raw["conditional_access_policies"][0]["Conditions"]["ClientAppTypes"] = ["unseen"]
    elif variant == "unseen_shape_valid":
        raw["conditional_access_policies"][0]["GrantControls"]["Operator"] = 5
    elif variant == "absent":
        del raw["conditional_access_policies"]
    elif variant == "ledger_absent":
        del raw["aad_successful_commands"]
    elif variant == "ledger_failed":
        raw["aad_unsuccessful_commands"].append("Get-Mock")
    elif variant == "not_list":
        raw["conditional_access_policies"] = {}
    if variant == "repaired":
        content = json.dumps(raw)
        content = content.replace('"conditional_access_policies": ' + json.dumps(raw["conditional_access_policies"]),
                                  '"conditional_access_policies": ')
        source = _save_text(tmp_path, content)
    else:
        source = _save(tmp_path, raw)
    bound = 2 if variant == "oversize" else 40
    result = assess_scubagear_export(source, tmp_path / "output", ModelConfig(model_name="test-model"),
                                     policies=["MS.AAD.3.3v2"], projection_max_items=bound)
    validate_assessment(result)
    summary = result["scope_post_check"]
    assert summary["source"] == expected_source
    assert summary["reason"] == expected_reason
    assert summary["status"] == ("evaluated" if expected_source else "not_evaluated")


def test_scope_oversize_inside_raw_read_is_not_evaluated(tmp_path, monkeypatch):
    import azure_tenant_audit.scuba_scope as scuba_scope
    from auditex.scubagear_export import scope_from_export
    raw = json.loads(PROVIDER.read_text())
    raw["conditional_access_policies"][0]["Conditions"]["Locations"] = {"IncludeLocations": ["mock"]}
    projection, extra = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()["policies"])
    assert projection.report["sections"]["conditional_access_policies"]["status"] != "projected"
    monkeypatch.setattr(scuba_scope, "MAX_ENTRIES", 0)
    summary = scope_from_export(projection, extra["raw_ca"], redact=True, max_items=40).summary
    assert summary["status"] == "not_evaluated" and summary["reason"] == "oversize"


def test_dry_run_no_network_or_process_and_refusal_no_output(tmp_path, monkeypatch):
    import shutil
    import socket
    def forbidden(*_args, **_kwargs):
        raise AssertionError("no network or process call is permitted")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    result, _, _ = _dry(tmp_path / "offline")
    assert result["prompts"] == len(policy_catalogue()["policies"])
    bad = _save(tmp_path, {"Raw": [], "MetaData": {}}, "invalid-shape.json")
    target = tmp_path / "absent"
    with pytest.raises(ValueError, match="Invalid ScubaGear export"):
        assess_scubagear_export(bad, target, ModelConfig(model_name="test-model"), dry_run=True)
    assert not target.exists()


def test_output_dir_and_private_files(tmp_path):
    from auditex.cli import _model_output_directory
    target = tmp_path / "new"
    assert resolve_output_directory(target) == target
    assert _model_output_directory(str(target)) == str(target)
    target.mkdir()
    (target / "occupied").write_text("x")
    with pytest.raises(ValueError): resolve_output_directory(target)
    (tmp_path / "link").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError): resolve_output_directory(tmp_path / "link")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "run-manifest.json").write_text("{}")
    for value in (bundle / "nested", bundle.parent if False else bundle / "nested" / "deeper"):
        with pytest.raises(ValueError): resolve_output_directory(value)
        with pytest.raises(ValueError): _model_output_directory(str(value))
    result, _, _ = _dry(tmp_path / "normal")
    out = Path(result["path"]).parent
    assert {p.name for p in out.iterdir()} == {"model_assessment_prompts.jsonl", "scubagear_adapter_report.json"}
    assert out.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in out.iterdir())


def test_existing_empty_output_dir_becomes_private_and_validation_fails_without_writes(tmp_path):
    target = tmp_path / "empty"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    assess_scubagear_export(PROVIDER, target, ModelConfig(model_name="test-model"), dry_run=True)
    assert target.stat().st_mode & 0o777 == 0o700
    bad = _save(tmp_path, {"Raw": [], "MetaData": {}}, "invalid-export.json")
    refused = tmp_path / "refused-output"
    with pytest.raises(ValueError, match="Invalid ScubaGear export"):
        assess_scubagear_export(bad, refused, ModelConfig(model_name="test-model"))
    assert not refused.exists()


def test_assessment_validation_failure_creates_no_directory(tmp_path, monkeypatch):
    import azure_tenant_audit.model_assessment as assessment
    import auditex.model_serving as serving
    target = tmp_path / "invalid-assessment"
    def reject(_result):
        raise ValueError("synthetic validation failure")
    monkeypatch.setattr(assessment, "validate_assessment", reject)
    monkeypatch.setattr(serving, "_assess_policies", lambda *_args, **_kwargs: ([], []))
    with pytest.raises(ValueError, match="synthetic validation failure"):
        assess_scubagear_export(PROVIDER, target, ModelConfig(model_name="test-model"))
    assert not target.exists()


def test_output_directory_rechecked_after_assessment(tmp_path, monkeypatch):
    import auditex.model_serving as serving
    original = serving._assess_policies
    target = tmp_path / "raced"
    def insert_file(*args, **kwargs):
        target.mkdir()
        (target / "occupied").write_text("keep")
        return original(*args, **kwargs)
    monkeypatch.setattr(serving, "_assess_policies", insert_file)
    with pytest.raises(ValueError, match="new or empty"):
        assess_scubagear_export(PROVIDER, target, ModelConfig(model_name="test-model"), dry_run=True)
    assert (target / "occupied").read_text() == "keep"


def test_tilde_script_path_uses_resolved_output(tmp_path, monkeypatch, capsys):
    script = ROOT / "scripts/assess-scubagear-export.py"
    spec = importlib.util.spec_from_file_location("scubagear_tilde_script", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(Path, "expanduser", lambda self: tmp_path / str(self)[2:]
                        if str(self).startswith("~/") else self)
    monkeypatch.setattr(sys, "argv", [str(script), str(PROVIDER), "--output-dir", "~/tilde-output",
                                  "--dry-run", "--model", "test-model"])
    assert module.main() == 0
    summary = json.loads(capsys.readouterr().out)
    assert Path(summary["sidecar_path"]) == tmp_path / "tilde-output/scubagear_adapter_report.json"
    assert Path(summary["assessment_path"]).is_file()


def test_internal_script_and_surface(tmp_path, monkeypatch, capsys):
    module_path = ROOT / "scripts/assess-scubagear-export.py"
    spec = importlib.util.spec_from_file_location("scubagear_script", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", [str(module_path), "--help"])
    with pytest.raises(SystemExit) as help_exit:
        module.main()
    assert help_exit.value.code == 0
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", [str(module_path), str(PROVIDER), "--output-dir", str(tmp_path / "script"),
                                  "--dry-run", "--model", "test-model"])
    assert module.main() == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["assessed"] == 44 and SENTINEL not in json.dumps(summary)
    import tomllib
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert set(project["project"]["scripts"]) == {"azure-tenant-audit", "auditex", "auditex-mcp"}
    assert not any("scubagear" in str(value).lower() or "scripts/" in str(value)
                   for value in project["tool"]["setuptools"]["data-files"].values())
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "file").write_text("x")
    monkeypatch.setattr(sys, "argv", [str(module_path), str(PROVIDER), "--output-dir", str(occupied),
                                  "--dry-run", "--model", "test-model"])
    assert module.main() == 2
    warning, failure = capsys.readouterr().err.splitlines()
    assert warning == IGNORED_OPTIONS_WARNING and failure.startswith("ScubaGear assessment failed: ")
    invalid = _save(tmp_path, {"Raw": [], "MetaData": {}}, "invalid.json")
    refused = tmp_path / "refused"
    monkeypatch.setattr(sys, "argv", [str(module_path), str(invalid), "--output-dir", str(refused),
                                  "--dry-run", "--model", "test-model"])
    assert module.main() == 2
    warning, failure = capsys.readouterr().err.splitlines()
    assert warning == IGNORED_OPTIONS_WARNING and failure.startswith("ScubaGear assessment failed: Invalid ScubaGear export")
    assert not refused.exists()


def test_no_public_cli_mcp_or_customer_document_surface(monkeypatch):
    from auditex import cli, mcp_registry
    for response in (None, "1"):
        if response is None:
            monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)
        else:
            monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", response)
        root_help = cli._build_root_parser().format_help().lower()
        model_help = cli._build_model_parser().format_help().lower()
        assert "assess-scubagear" not in root_help + model_help
        assert "scubagear" not in root_help + model_help
        specs = mcp_registry.iter_tool_specs(include_response=bool(response))
        names = {item["name"].lower() for item in specs}
        assert all("assess-scubagear" not in name and "scubagear" not in name for name in names)
        assert "assess-scubagear-export" not in json.dumps(specs).lower()
    for args in ((), ("model",)):
        proc = subprocess.run([str(ROOT / ".venv/bin/auditex"), *args, "--help"],
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0
        assert "assess-scubagear" not in proc.stdout.lower() and "scubagear" not in proc.stdout.lower()
    for folder in ("docs/guides", "docs/reference", "docs/provenance"):
        for path in (ROOT / folder).rglob("*"):
            if path.is_file() and path.suffix in {".md", ".txt"}:
                text = path.read_text(encoding="utf-8", errors="replace")
                assert "scubagear_export" not in text and "assess-scubagear-export" not in text
    for name in ("README.md", "docs/index.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "scubagear_export" not in text and "assess-scubagear-export" not in text


def test_non_dry_run_validates_without_model_request(tmp_path):
    result = assess_scubagear_export(PROVIDER, tmp_path / "result", ModelConfig(model_name="test-model"),
                                     policies=["MS.AAD.3.3v2"])
    validate_assessment(result)
    assert (tmp_path / "result/model_assessment.json").is_file()
    assert result["scope_post_check"]["source"] == "projection"
    assert SENTINEL not in (tmp_path / "result/model_assessment.json").read_text()
    result2 = assess_scubagear_export(PROVIDER, tmp_path / "clear", ModelConfig(model_name="test-model"),
                                      policies=["MS.AAD.3.3v2"], no_redaction=True)
    validate_assessment(result2)
    remote = assess_scubagear_export(PROVIDER, tmp_path / "remote", ModelConfig(endpoint="https://example.invalid/v1",
                                     model_name="test-model"), no_redaction=True)
    assert remote["projection"]["redaction"]["enabled"] and remote["endpoint_host"] == "none"
    validate_assessment(remote)


@pytest.mark.parametrize('section,value', [
    ('powerbi_tenant_settings', [{'settingName': 'synthetic', 'enabled': True}] * 41),
    ('authentication_method', [{'state': 'enabled'}]),
    ('remote_domains', [{'DomainName': 'example.invalid'}]),
    ('dlp_policies', [{'name': 'synthetic'}]),
    ('environment_creation', [{'name': 'synthetic'}]),
    ('environment_list', [{'name': 'synthetic'}]),
    ('tenant_isolation', [{'properties': {'isDisabled': False}}]),
    ('anti_malware_rules', [{'Priority': 7}]),
    ('safe_attachment_rules', [{'Priority': 3}]),
])
def test_digestless_export_sections_reach_only_private_rule_view(tmp_path, section, value):
    raw = json.loads(PROVIDER.read_text())
    raw[section] = value
    for prefix in SECTION_LEDGERS[section]:
        raw[prefix + '_successful_commands'] = []
        raw[prefix + '_unsuccessful_commands'] = []
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections[section] == value
    assert projection[section] == NOT_COLLECTED


def test_export_rule_view_preserves_log_null_and_absent_and_withholds_qualifiers(tmp_path):
    raw = json.loads(REAL.read_text())
    raw['spf_records'][0]['log'] = 'synthetic DNS log'
    raw['privileged_roles'][0]['Assignments'][0]['EndDateTime'] = None
    raw['privileged_roles'][0]['Assignments'][0].pop('StartDateTime', None)
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections['spf_records'][0]['log'] == 'synthetic DNS log'
    assignment = projection.rule_sections['privileged_roles'][0]['Assignments'][0]
    assert assignment['EndDateTime'] is None and 'StartDateTime' not in assignment
    assert projection.rule_views['MS.SECURITYSUITE.2.1v1']['scuba_config'] == NOT_COLLECTED
    assert rule_policy_section(projection, 'MS.SECURITYSUITE.2.1v1', 'scuba_config') == NOT_COLLECTED
    assert policy_section(projection, 'MS.SECURITYSUITE.2.1v1', 'scuba_config') == NOT_COLLECTED
    raw['conditional_access_policies'][0]['Conditions']['Locations'] = {'IncludeLocations': ['All']}
    withheld, _ = project_export(load_export(_save(tmp_path, raw, 'restricted.json')),
                                 policy_catalogue()['policies'])
    assert withheld.rule_sections['conditional_access_policies'] == NOT_COLLECTED
    raw['securitysuite_unsuccessful_commands'] = ['Get-SyntheticFailure']
    failed, _ = project_export(load_export(_save(tmp_path, raw, 'failed.json')),
                               policy_catalogue()['policies'])
    assert failed.rule_sections['safe_links_policies'] == NOT_COLLECTED


def test_rule_view_canaries_never_enter_outputs_or_logs(tmp_path, caplog, capsys):
    canary_email = 'rule-view-canary@example.invalid'
    canary_name = 'Rule View Canary DisplayName'
    raw = json.loads(PROVIDER.read_text())
    # The shipped Power BI value rule reads these settings; the canaries reach
    # that input while the model shape gate withholds the section.
    raw['powerbi_access_denied_reason'] = ''
    raw['powerbi_license_found'] = True
    raw['powerbi_tenant_settings'] = [{'settingName': 'PublishToWeb', 'enabled': canary_name,
                                       'Sender': canary_email}]
    source = _save(tmp_path, raw)
    projection, _ = project_export(load_export(source), policy_catalogue()['policies'])
    assert canary_email in repr(projection.rule_sections['powerbi_tenant_settings'])
    assert canary_name in repr(projection.rule_sections['powerbi_tenant_settings'])
    assert projection['powerbi_tenant_settings'] == NOT_COLLECTED
    with caplog.at_level('DEBUG'):
        _dry(tmp_path / 'dry', source)
        assess_scubagear_export(source, tmp_path / 'assessed', ModelConfig(model_name='test-model'),
                                policies=['MS.POWERBI.1.1v1'])
    written = ''.join(path.read_text() for folder in ('dry/assessment', 'assessed')
                      for path in (tmp_path / folder).iterdir() if path.is_file())
    assert canary_email not in written + caplog.text + str(capsys.readouterr())
    assert canary_name not in written + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize('section', ['defender_license', 'defender_dlp_license'])
@pytest.mark.parametrize('value', [True, False, None, 'unreadable'])
def test_defender_licence_flags_reach_rules_without_coercion(tmp_path, section, value):
    raw = json.loads(PROVIDER.read_text())
    raw[section] = value
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections[section] == value
    assert projection[section] == NOT_COLLECTED


@pytest.mark.parametrize('failed', [[], ['Get-EOPProtectionPolicyRule'], ['Get-HostedContentFilterRule'],
                                   ['Get-ATPProtectionPolicyRule']])
def test_securitysuite_failure_ledger_reaches_rules_and_still_withholds_provider_sections(tmp_path, failed):
    raw = json.loads(PROVIDER.read_text())
    raw['securitysuite_unsuccessful_commands'] = failed
    raw['defender_license'] = True
    raw['atp_policy_rules'] = []
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections['securitysuite_unsuccessful_commands'] == failed
    assert 'securitysuite_unsuccessful_commands' not in projection
    if failed:
        for section in ('atp_policy_rules', 'defender_license', 'safe_links_policies'):
            assert projection.rule_sections[section] == NOT_COLLECTED
            assert projection.report['sections'][section]['reason'] == 'collector_error'
    else:
        assert projection.rule_sections['atp_policy_rules'] == []
        assert projection.rule_sections['defender_license'] is True


@pytest.mark.parametrize('bad', [None, 'Get-Mock', [None], {'error': 'private'}])
def test_unusable_securitysuite_ledger_is_not_an_empty_success(tmp_path, bad):
    raw = json.loads(PROVIDER.read_text())
    raw['securitysuite_unsuccessful_commands'] = bad
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections['securitysuite_unsuccessful_commands'] == NOT_COLLECTED
    assert projection.rule_sections['safe_links_policies'] == NOT_COLLECTED


def test_repaired_or_missing_securitysuite_ledger_is_not_trusted(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    raw.pop('securitysuite_unsuccessful_commands')
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections['securitysuite_unsuccessful_commands'] == NOT_COLLECTED
    raw['securitysuite_unsuccessful_commands'] = []
    source = _save(tmp_path, raw)
    source.write_text(source.read_text().replace('"securitysuite_unsuccessful_commands": []',
                                               '"securitysuite_unsuccessful_commands": '))
    projection, _ = project_export(load_export(source), policy_catalogue()['policies'])
    assert projection.rule_sections['securitysuite_unsuccessful_commands'] == NOT_COLLECTED


@pytest.mark.parametrize('pid', [f'MS.SECURITYSUITE.{number}v1' for number in ('2.1', '2.2', '2.3', '7.1', '7.2', '7.3')])
def test_atp_preset_rule_scope_reaches_each_private_policy_reader(tmp_path, pid):
    raw = json.loads(PROVIDER.read_text())
    atp = [{'Identity': 'Standard Preset Security Policy', 'State': 'Enabled',
            'SentTo': ['atp-recipient@example.invalid'], 'SentToMemberOf': ['Synthetic Group'],
            'RecipientDomainIs': ['example.invalid'], 'ExceptIfSentTo': ['except@example.invalid'],
            'ExceptIfSentToMemberOf': [], 'ExceptIfRecipientDomainIs': []}]
    raw['atp_policy_rules'] = atp
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert rule_policy_section(projection, pid, 'atp_policy_rules') == atp
    assert projection['atp_policy_rules'] == NOT_COLLECTED


@pytest.mark.parametrize('redact', [True, False])
@pytest.mark.parametrize('failed_ledger', [False, True])
def test_atp_recipients_and_ledger_never_enter_persisted_outputs(
        tmp_path, monkeypatch, caplog, capsys, redact, failed_ledger):
    from azure_tenant_audit import value_rules
    from azure_tenant_audit.value_rules import catalogue
    canary = 'atp-private-canary@example.invalid'
    ledger_canary = 'John-Smith'
    raw = json.loads(PROVIDER.read_text())
    raw['securitysuite_unsuccessful_commands'] = [ledger_canary] if failed_ledger else []
    raw['securitysuite_successful_commands'].append(ledger_canary)
    raw['atp_policy_rules'] = [{'Identity': 'Standard Preset Security Policy', 'State': 'Enabled',
                               'SentTo': [canary], 'ExceptIfSentTo': [], 'SentToMemberOf': [],
                               'RecipientDomainIs': [], 'ExceptIfSentToMemberOf': [], 'ExceptIfRecipientDomainIs': []}]
    raw['powerbi_access_denied_reason'] = ''
    raw['powerbi_license_found'] = True
    raw['powerbi_tenant_settings'] = [{'settingName': 'PublishToWeb', 'enabled': True}]
    source = _save(tmp_path, raw)
    original_row, original_assess = catalogue.row_for, value_rules.assess
    seen = []

    # The Defender kinds land in later stages. Exercise today's serving read-set boundary with a shipped rule.
    def with_atp_read_set(pid):
        row = original_row(pid)
        return {**row, 'sections': [*row['sections'], 'atp_policy_rules',
                                   'securitysuite_unsuccessful_commands']} if row else row

    def reading_rule(pid, sections):
        seen.append((sections['atp_policy_rules'], sections['securitysuite_unsuccessful_commands']))
        # Keep the shipped rule's result contract while exercising an additional private input.
        with monkeypatch.context() as context:
            context.setattr(catalogue, 'row_for', original_row)
            record = original_assess(pid, sections)
        return {**record, 'cited_sections': original_row(pid)['sections']}

    monkeypatch.setattr(catalogue, 'row_for', with_atp_read_set)
    monkeypatch.setattr(value_rules, 'assess', reading_rule)
    with caplog.at_level('DEBUG'):
        _, sidecar, _ = _dry(tmp_path / 'dry', source, no_redaction=not redact)
        assess_scubagear_export(source, tmp_path / 'assessed', ModelConfig(model_name='test-model'),
                                policies=['MS.POWERBI.1.1v1'], no_redaction=not redact)
    # The serving read-set passes the failed ledger privately while withholding its provider sections.
    assert seen == [(NOT_COLLECTED if failed_ledger else raw['atp_policy_rules'],
                     [ledger_canary] if failed_ledger else [])]
    projection, _ = project_export(load_export(source), policy_catalogue()['policies'])
    assert projection.rule_sections['securitysuite_unsuccessful_commands'] == (
        [ledger_canary] if failed_ledger else [])
    assert projection.rule_sections['atp_policy_rules'] == (NOT_COLLECTED if failed_ledger else raw['atp_policy_rules'])
    assert sidecar['ledger']['securitysuite'] == {'unsuccessful_count': int(failed_ledger)}
    assert all(set(row) == {'unsuccessful_count'} for row in sidecar['ledger'].values())
    written = ''.join(path.read_text() for folder in ('dry/assessment', 'assessed')
                      for path in (tmp_path / folder).rglob('*') if path.is_file())
    emitted = written + caplog.text + str(capsys.readouterr())
    assert canary not in emitted
    assert ledger_canary not in emitted


@pytest.mark.parametrize('section', ['spf_records', 'dkim_records', 'dmarc_records'])
def test_export_dns_log_stays_private_after_capture(tmp_path, section):
    raw = json.loads(REAL.read_text())
    canary = 'export-dns-log-canary@example.invalid'
    raw[section][0]['log'] = [{'query_result': 'No answers returned.', 'detail': canary}]
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections[section][0]['log'] == raw[section][0]['log']
    assert canary not in json.dumps(projection) + json.dumps(projection.report)


@pytest.mark.parametrize('key', ['EndDateTime', 'StartDateTime'])
def test_export_role_dates_distinguish_null_from_absent(tmp_path, key):
    raw = json.loads(PROVIDER.read_text())
    first = raw['privileged_roles'][0]['Assignments'][0]
    first[key] = None
    absent = {k: v for k, v in first.items() if k != key}
    raw['privileged_roles'][0]['Assignments'] = [first, absent]
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assignments = projection.rule_sections['privileged_roles'][0]['Assignments']
    assert assignments[0][key] is None and key not in assignments[1]


@pytest.mark.parametrize('environment', ['commercial', 'gcc', 'gcchigh', 'dod', 'GCC', None, [], 'unknown'])
def test_export_environment_is_retained_only_when_recognised(tmp_path, environment):
    raw = json.loads(PROVIDER.read_text())
    raw['scuba_config']['M365Environment'] = environment
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    for pid in ('MS.AAD.9.1v1', 'MS.TEAMS.2.2v2', 'MS.TEAMS.2.3v2', 'MS.TEAMS.4.1v1'):
        view = rule_policy_section(projection, pid, 'scuba_config')
        if isinstance(environment, str) and environment in {'commercial', 'gcc', 'gcchigh', 'dod'}:
            assert view['M365Environment'] == environment
        else:
            assert view == NOT_COLLECTED


# Retaining recognised rule-view environments lets the commercial-only Teams gates fire.
# Compare with the same export under the previous environment branch; unrelated rule additions
# must not invalidate this regression, and model prompts must remain byte-identical.
@pytest.mark.parametrize('source', [PROVIDER, REAL], ids=['provider', 'realformat'])
@pytest.mark.parametrize('environment', ['gcc', 'gcchigh', 'dod'])
@pytest.mark.parametrize('redact', [True, False])
def test_noncommercial_export_model_prompts_and_prechecks_match_committed_behaviour(
        tmp_path, monkeypatch, source, environment, redact):
    from auditex import scubagear_export
    from auditex.model_precheck import precheck_case
    from auditex.model_serving import ModelClient, ModelEndpointError, build_case
    from azure_tenant_audit.value_rules.catalogue import row_for

    monkeypatch.delenv('AUDITEX_DISABLE_VALUE_RULES', raising=False)
    raw = json.loads(source.read_text())
    raw['scuba_config']['M365Environment'] = environment
    export = _save(tmp_path, raw)

    def signatures(label):
        projection, _ = project_export(load_export(export), policy_catalogue()['policies'], redact=redact)
        prompts = _dry(tmp_path / label, export, no_redaction=not redact)[2]
        assert len(prompts) == 102
        prechecks = {}
        for prompt in prompts:
            pid = prompt['policy_id']
            row = row_for(pid)
            rule_input = {s: deepcopy(rule_policy_section(projection, pid, s)) for s in row['sections']} if row else None
            precheck = precheck_case(build_case(pid, projection, 'unused'), absent_fields=True, empty_lists=True,
                                     value_rules=True, rule_projection=rule_input)
            prechecks[pid] = precheck['rule_precheck'] if precheck else None
        return projection, {p['policy_id']: p['prompt_sha256'] for p in prompts}, prechecks

    projection, prompts, prechecks = signatures('current')
    config_view = scubagear_export._config_view

    def without_environment_retention(raw, catalogue, max_items, max_chars, *, rule_view=False):
        # Only rule_view's recognised-environment set differs here. Replaying this same export
        # through the old branch gives a baseline independent of unrelated rules added on main.
        return config_view(raw, catalogue, max_items, max_chars, rule_view=False)

    with monkeypatch.context() as baseline_patch:
        baseline_patch.setattr(scubagear_export, '_config_view', without_environment_retention)
        baseline_projection, baseline_prompts, baseline_prechecks = signatures('baseline')
    assert prompts == baseline_prompts
    changed = {pid for pid in prechecks if prechecks[pid] != baseline_prechecks[pid]}
    teams = {'MS.TEAMS.2.2v2', 'MS.TEAMS.2.3v2', 'MS.TEAMS.4.1v1'}
    assert changed == teams | {'MS.AAD.9.1v1'}
    for pid in changed:
        assert prechecks[pid]['class'] == 'value_rule'
        assert rule_policy_section(baseline_projection, pid, 'scuba_config') == NOT_COLLECTED
        assert baseline_prechecks[pid]['cell'] == 'section_not_collected'
    closed = teams | ({'MS.AAD.9.1v1'} if environment in {'gcchigh', 'dod'} else set())
    for pid in closed:
        # A closed gate wins even though other rule dependencies may be unavailable.
        assert prechecks[pid]['cell'] == 'closed_gate'
        assert prechecks[pid]['reason_code'] == 'policy_not_applicable_environment'
    for pid in changed:
        assert policy_section(projection, pid, 'scuba_config') == NOT_COLLECTED
        assert rule_policy_section(projection, pid, 'scuba_config')['M365Environment'] == environment
    if environment == 'gcc':
        # GCC leaves AAD 9.1 applicable; the fixtures have no P2 service plan.
        assert prechecks['MS.AAD.9.1v1']['cell'] == 'licence_not_detected'
        assert prechecks['MS.AAD.9.1v1']['reason_code'] == 'data_unavailable_no_licence'
        assert prechecks['MS.AAD.9.1v1']['section'] == ['service_plans']

    calls = []
    original_assess = ModelClient.assess

    def guarded_assess(client, case):
        pid = case['policy_id']
        assert prechecks[pid] is None, f'{pid} must retain its committed precheck'
        calls.append(pid)
        return original_assess(client, case)

    def unavailable(*args, **kwargs):
        raise ModelEndpointError('Synthetic endpoint unavailable')

    monkeypatch.setattr(ModelClient, 'assess', guarded_assess)
    monkeypatch.setattr(ModelClient, '_request', unavailable)
    result = assess_scubagear_export(export, tmp_path / 'assessed', ModelConfig(model_name='test-model'),
                                     no_redaction=not redact)
    assert not calls
    assert {row['policy_id']: row.get('rule_precheck') for row in result['policies']} == {
        pid: detail if row_for(pid) else None for pid, detail in prechecks.items()}


@pytest.mark.parametrize('operator', ['AND', 'OR', None])
def test_export_ca_operator_is_retained_in_private_view(tmp_path, operator):
    raw = json.loads(PROVIDER.read_text())
    raw['conditional_access_policies'][0]['GrantControls']['Operator'] = operator
    projection, _ = project_export(load_export(_save(tmp_path, raw)), policy_catalogue()['policies'])
    assert projection.rule_sections['conditional_access_policies'][0]['GrantControls']['Operator'] == operator


def test_bad_guid_keyed_user_is_shape_withheld_before_user_detail(tmp_path):
    raw = json.loads(PROVIDER.read_text())
    guid = next(iter(raw['privileged_users']))
    del raw['privileged_users'][guid]['DisplayName']
    source = _save(tmp_path, raw)
    projection, _ = project_export(load_export(source), policy_catalogue()['policies'])
    assert projection.rule_sections['privileged_users'] == NOT_COLLECTED
    result = assess_scubagear_export(source, tmp_path / 'assessed', ModelConfig(model_name='test-model'),
                                     policies=['MS.POWERBI.1.1v1'])
    assert result['projection']['sections']['privileged_users']['detail'] == {
        'field': '$', 'kind': 'unseen_shape'}
    assert (tmp_path / 'assessed/model_assessment.json').is_file()
    assert guid not in ''.join(p.read_text() for p in (tmp_path / 'assessed').iterdir() if p.is_file())


def test_one_rule_cannot_mutate_later_policy_evidence(tmp_path, monkeypatch):
    from azure_tenant_audit import value_rules
    raw = json.loads(PROVIDER.read_text())
    raw['powerbi_access_denied_reason'] = ''
    raw['powerbi_license_found'] = True
    raw['powerbi_tenant_settings'] = [{'settingName': 'PublishToWeb', 'enabled': True}]
    source = _save(tmp_path, raw)
    original = value_rules.assess
    seen = []
    def mutating_rule(policy_id, sections):
        seen.append(len(sections['powerbi_tenant_settings']))
        sections['powerbi_tenant_settings'].append({'settingName': 'injected', 'enabled': False})
        return original(policy_id, sections)
    monkeypatch.setattr(value_rules, 'assess', mutating_rule)
    assess_scubagear_export(source, tmp_path / 'assessed', ModelConfig(model_name='test-model'),
                            policies=['MS.POWERBI.1.1v1', 'MS.POWERBI.2.1v1'])
    assert seen == [1, 1]


def test_rule_exception_text_never_reaches_export_artifacts_or_stderr(tmp_path, monkeypatch, capsys):
    from azure_tenant_audit import value_rules
    secret = 'canary.person@example.invalid'
    def broken_rule(*args):
        raise RuntimeError(secret)
    monkeypatch.setattr(value_rules, 'assess', broken_rule)
    result = assess_scubagear_export(PROVIDER, tmp_path / 'assessed', ModelConfig(model_name='test-model'),
                                     policies=['MS.POWERBI.1.1v1'])
    row = result['policies'][0]
    assert row['rule_precheck']['cell'] == 'rule_evaluation_failed'
    assert row['recommendations'] == ['report_product_fault'] and row['limitations'] == []
    persisted = ''.join(p.read_text() for p in (tmp_path / 'assessed').iterdir() if p.is_file())
    assert secret not in persisted + str(capsys.readouterr())


@pytest.mark.parametrize('source,expected', [
    (PROVIDER, 'c8e526c5e27692b2884a9215389428a309571e6b8683a3e3558c75c36da2ef14'),
    (REAL, '12b876594566f27bdebf3cc688ada165c809efb250adf539cbc474243a534cdb'),
])
def test_unaffected_export_prompt_hashes_match_pre_rule_view_fixture(tmp_path, source, expected):
    changed_by_m5 = {'MS.SECURITYSUITE.2.1v1', 'MS.SECURITYSUITE.2.3v1', 'MS.SECURITYSUITE.3.2v1'}
    prompts = _dry(tmp_path / source.stem, source)[2]
    assert len(prompts) == 102
    hashes = {row['policy_id']: row['prompt_sha256'] for row in prompts
              if row['policy_id'] not in changed_by_m5}
    assert len(hashes) == 99
    assert sha256(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == expected


@pytest.mark.parametrize("baseline_status,expected", [("pass", "agree"), ("fail", "disagree")])
def test_rule_export_comparisons_without_model(tmp_path, monkeypatch, baseline_status, expected):
    from auditex.model_serving import ModelClient
    monkeypatch.setattr(ModelClient, '__init__', lambda *args: pytest.fail('No assessment model client'))
    pid = "MS.EXO.13.1v1"
    raw = json.loads(PROVIDER.read_text())
    raw['org_config'] = [{'Name': 'Synthetic', 'AuditDisabled': False}]
    source = _save(tmp_path, raw)
    results = tmp_path / 'verdicts.json'
    results.write_text(json.dumps([{'PolicyId': pid, 'RequirementMet': baseline_status == 'pass',
                                  'Criticality': 'Shall', 'Commandlet': ['Get-Mock']}]))
    result = assess_scubagear_export(source, tmp_path / 'assessment', results_path=results, policies=[pid])
    row = result['policies'][0]
    assert row['reason'] == 'rule_precheck' and row['attempts'] == 0
    assert row['comparison']['result'] == expected
    validate_assessment(result)


FORMERLY_HELD = ['MS.SECURITYSUITE.1.1v1', 'MS.SECURITYSUITE.6.1v1', 'MS.SECURITYSUITE.6.2v1']


def test_export_formerly_held_policies_are_rule_rows_without_model(tmp_path, monkeypatch):
    from auditex.model_serving import ModelClient
    monkeypatch.setattr(ModelClient, '__init__', lambda *args: pytest.fail('No assessment model client'))
    result = assess_scubagear_export(PROVIDER, tmp_path / 'assessment', results_path=RESULTS, policies=FORMERLY_HELD)
    assert [row['policy_id'] for row in result['policies']] == FORMERLY_HELD
    assert all(row['reason'] == 'rule_precheck' and row['rule_precheck']['class'] == 'value_rule'
               and row['attempts'] == 0 for row in result['policies'])
    validate_assessment(result)


def test_export_policy_without_a_rule_is_uncovered_without_model(tmp_path, monkeypatch):
    from auditex.model_serving import ModelClient
    from azure_tenant_audit.value_rules import catalogue as rule_catalogue
    monkeypatch.setattr(ModelClient, '__init__', lambda *args: pytest.fail('No assessment model client'))
    # Every catalogue policy has a rule today: withdraw one to reach the uncovered path through the export flow.
    original, withdrawn = rule_catalogue.row_for, FORMERLY_HELD[0]
    monkeypatch.setattr(rule_catalogue, 'row_for', lambda pid: None if pid == withdrawn else original(pid))
    result = assess_scubagear_export(PROVIDER, tmp_path / 'assessment', results_path=RESULTS, policies=FORMERLY_HELD)
    rows = {row['policy_id']: row for row in result['policies']}
    assert rows[withdrawn]['reason'] == 'rule_not_implemented'
    assert rows[withdrawn]['comparison']['result'] == 'not_assessed'
    assert all(rows[pid]['reason'] == 'rule_precheck' for pid in FORMERLY_HELD[1:])
    assert (result['endpoint_host'], result['model_name']) == ('none', 'rules-only') and 'serving' not in result
    validate_assessment(result)


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


SCUBA = _env_path("AUDITEX_TEST_SCUBAGEAR")


@pytest.mark.skipif(not (SCUBA and (SCUBA / "Rego").is_dir()),
                    reason="export AUDITEX_TEST_SCUBAGEAR (PowerShell/ScubaGear at the pinned commit)")
def test_proof_matches_pinned_rego():
    _require_pinned_opa()
    rego = SCUBA / "Rego"
    if any(not (rego / name).is_file() or sha256((rego / name).read_bytes()).hexdigest() != digest
           for name, digest in REGO_SHA256.items()):
        pytest.skip("AUDITEX_TEST_SCUBAGEAR/Rego is not the pinned revision 2446ad72")
    script = ROOT / "scripts/derive-scubagear-prune-table.py"
    spec = importlib.util.spec_from_file_location("derive_scubagear", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.derive(rego, ROOT / "tests/fixtures/scuba-projection-shapes-v7.json") == (
        ROOT / "src/auditex/scubagear_prune_proof.py").read_text()
