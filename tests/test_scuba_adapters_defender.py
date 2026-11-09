"""Offline run-path contract for Defender's in-memory rule evidence."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import importlib
import json
from pathlib import Path

import pytest

from auditex.rule_assessment import canonical
from auditex.scuba_adapters_defender import ADAPTERS, DEFENDER_ADAPTERS, SECTION_KEYS
from auditex.scuba_projection import Bundle, NOT_COLLECTED, PACK_SHAPE_DIGESTS, project_run


SCOPE = (
    "SentTo", "SentToMemberOf", "RecipientDomainIs",
    "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs",
)
CONTRACT = {
    "protection_policy_rules": ("eopProtectionPolicyRules", ("Identity", "State", *SCOPE)),
    "atp_policy_rules": ("atpProtectionPolicyRules", ("Identity", "State", *SCOPE)),
    "built_in_protection_rules": ("atpBuiltInProtectionRules", (
        "Identity", "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")),
    "atp_policy_for_o365": ("atpPolicyForO365", ("Identity", "EnableATPForSPOTeamsODB")),
    "anti_malware_policies": ("malwareFilterPolicy", ("Identity", "EnableFileFilter", "FileTypes", "ZapEnabled")),
    "anti_malware_rules": ("malwareFilterRules", ("Identity", "State", "Priority", "MalwareFilterPolicy", *SCOPE)),
    "safe_attachment_policies": ("safeAttachmentPolicies", ("Identity", "Action")),
    "safe_attachment_rules": ("safeAttachmentRules", ("Identity", "State", "Priority", "SafeAttachmentPolicy", *SCOPE)),
    "anti_phish_policies": ("antiPhishPolicies", (
        "Identity", "Name", "IsDefault", "Enabled", "EnableTargetedUserProtection", "TargetedUserProtectionAction",
        "EnableOrganizationDomainsProtection", "TargetedDomainProtectionAction", "EnableTargetedDomainsProtection",
        "TargetedDomainsToProtect", "EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips",
        "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips", "EnableViaTag", "EnableUnauthenticatedSender")),
    "anti_phish_rules": ("antiPhishRules", ("Identity", "State", "AntiPhishPolicy", *SCOPE)),
    "hosted_content_filter_policies": ("hostedContentFilterPolicies", (
        "Identity", "IsDefault", "RecommendedPolicyType", "SpamAction", "HighConfidenceSpamAction",
        "PhishSpamAction", "HighConfidencePhishAction", "AllowedSenderDomains")),
    "hosted_content_filter_rules": ("hostedContentFilterRules", ("Identity", "State", "HostedContentFilterPolicy", *SCOPE)),
    "safe_links_policies": ("safeLinksPolicies", (
        "Identity", "EnableSafeLinksForEmail", "EnableSafeLinksForTeams", "EnableSafeLinksForOffice",
        "EnableForInternalSenders", "ScanUrls", "DeliverMessageAfterScan", "TrackClicks")),
    "safe_links_rules": ("safeLinksRules", ("Identity", "State", "Priority", "SafeLinksPolicy", *SCOPE)),
    "conn_filter": ("hostedConnectionFilterPolicy", ("Name", "IPAllowList", "EnableSafeList")),
    "admin_audit_log_config": ("adminAuditLogConfig", ("Identity", "UnifiedAuditLogIngestionEnabled")),
}
LIST_SECTIONS = tuple(CONTRACT)
UNOBSERVED = {"version": 1, "state": "not_collected"}


def rule_rows(section, rows):
    """Projected rule rows: anti-phish rows also carry a private TargetedUsersCoverage (absent: not_collected)."""
    if section != "anti_phish_policies":
        return rows
    return [{**row, "TargetedUsersCoverage": UNOBSERVED} for row in rows]
RULE_SECTIONS = tuple(section for section, (_, keys) in CONTRACT.items() if "ExceptIfSentTo" in keys)
ATP_SECTIONS = ("atp_policy_for_o365", "atp_policy_rules")


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def operation(root, name, rows, **metadata):
    path = root / "raw/exchange_policy.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {"value": rows, "status": "ok", **metadata}
    write(root, "raw/exchange_policy.json", payload)


@pytest.fixture(scope="module")
def fixture_document():
    return json.loads((Path(__file__).parent / "fixtures/defender/exchange-defender-ops.json").read_text())


@pytest.fixture(scope="module")
def cases(fixture_document):
    # Store only verbatim, traceable vector objects. Adapter edge cases are local
    # constructions, so they cannot accidentally copy an unidentified pack row.
    result = {}
    for name, payload in fixture_document.items():
        if name == "_meta":
            continue
        good = deepcopy(payload["good"])
        absent = deepcopy(good[:1])
        absent[0].pop("ExceptIfSentTo", None)
        integer = deepcopy(good[:1])
        if "State" in integer[0]:
            integer[0]["State"] = 1
        result[name] = {
            "good": good,
            "empty": [],
            "absent_exceptif": absent,
            "enum_as_int": integer,
            "error_row": [{"error": "Synthetic failure", "error_class": "command_error"}],
        }
    return result


def test_fixture_provenance_covers_every_stored_row(fixture_document, cases):
    meta = fixture_document["_meta"]
    assert meta["provenance"] == (
        "constructed rows and pack train and validation rows from v3.9.1; "
        "held-out test and pilot rows excluded"
    )
    assert meta["spec_version"] == "v3.9.1 FINAL"
    assert meta["source"] == "value-rules-v391/vectors.jsonl"
    assert len(meta["source_sha256"]) == 64
    assert set(meta["rows"]) == set(cases) == set(meta["before"]["rows"])
    counts = Counter()
    before_counts = Counter()
    for section, (name, _) in CONTRACT.items():
        assert set(fixture_document[name]) == {"good"}
        rows = fixture_document[name]["good"]
        origins = meta["rows"][name]
        before = meta["before"]["rows"][name]
        assert len(origins) == len(rows) == len(before["good"])
        assert set(before) == set(cases[name])
        for variant, originals in before.items():
            assert len(originals) == len(cases[name][variant])
            before_counts.update(record["source_kind"] for record in originals)
        for row, origin in zip(rows, origins, strict=True):
            kind = origin["source_kind"]
            assert kind in {"constructed", "pack-train", "pack-validation", "packlic-train"}
            assert origin["vector_id"].startswith(f"{kind}:")
            if kind == "constructed":
                assert origin["source_file"] == "constructed by build_vectors.py"
                assert "split" not in origin
            else:
                assert origin["source_file"].startswith("20261030-oracle-pack-v10/")
                assert origin["split"] == ("validation" if kind == "pack-validation" else "train")
            assert origin["section"] == section
            assert type(origin["section_row"]) is int and origin["section_row"] >= 0
            assert origin["policy"].startswith("MS.SECURITYSUITE.")
            assert origin["rule_cell"] and origin["rule_reason_code"]
            content = json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
            assert sha256(content).hexdigest() == origin["row_sha256"]
            counts[kind] += 1
    assert counts == meta["after_by_source_kind"]
    assert sum(counts.values()) == 30
    assert before_counts == meta["before"]["by_source_kind"]
    assert sum(len(rows) for variants in cases.values() for rows in variants.values()) == 78


@pytest.fixture
def bundle(tmp_path, cases):
    write(tmp_path, "run-manifest.json", {"run_id": "synthetic-defender", "platform": "m365"})
    for name, rows in cases.items():
        operation(tmp_path, name, rows["good"])
    return tmp_path


def test_registration_and_exact_collector_field_contract(cases):
    module = importlib.import_module("auditex.scuba_adapters_defender")
    assert "defender_license" in module.ADAPTERS
    assert DEFENDER_ADAPTERS is ADAPTERS
    assert SECTION_KEYS == CONTRACT
    assert set(ADAPTERS) == set(CONTRACT) | {"defender_license"}
    assert len(ADAPTERS) == 17
    assert not set(ADAPTERS) & PACK_SHAPE_DIGESTS.keys()
    assert "accepted_domains" not in ADAPTERS
    assert len({name for name, _ in CONTRACT.values()}) == 16
    assert set(cases) == {name for name, _ in CONTRACT.values()}
    for name, keys in CONTRACT.values():
        assert set(cases[name]) == {"good", "empty", "absent_exceptif", "enum_as_int", "error_row"}
        assert cases[name]["good"]
        assert all(set(row) <= set(keys) for row in cases[name]["good"])


@pytest.mark.parametrize("section", LIST_SECTIONS)
def test_round_trip_preserves_rule_rows_and_withholds_model_view(bundle, cases, section):
    name, keys = CONTRACT[section]
    rows = cases[name]["good"]
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == rule_rows(section, [{key: row[key] for key in keys if key in row} for row in rows])
    assert p[section] == NOT_COLLECTED
    assert p.report["sections"][section]["reason"] == "incomplete_shape"


@pytest.mark.parametrize("section", RULE_SECTIONS)
def test_absent_keys_stay_absent_and_null_stays_null(bundle, cases, section):
    name, keys = CONTRACT[section]
    absent = deepcopy(cases[name]["absent_exceptif"])
    assert "ExceptIfSentTo" not in absent[0]
    operation(bundle, name, absent)
    assert project_run(bundle, redact=False).rule_sections[section] == rule_rows(section, absent)
    null_row = {key: None for key in keys}
    operation(bundle, name, [null_row])
    assert project_run(bundle, redact=False).rule_sections[section] == rule_rows(section, [null_row])


@pytest.mark.parametrize("section", LIST_SECTIONS)
def test_values_are_not_defaulted_coerced_trimmed_sorted_or_filtered(bundle, section):
    name, keys = CONTRACT[section]
    values = [None, False, 1, " Disabled ", ["z", "a", "z", None], {"nested": [3, 1]}]
    rows = [{key: deepcopy(values[index % len(values)]) for index, key in enumerate(keys)}, {}]
    operation(bundle, name, rows)
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == rule_rows(section, rows)
    assert canonical(p.rule_sections[section]) == canonical(rule_rows(section, rows))  # Includes JSON boolean versus number types.


@pytest.mark.parametrize("section", [s for s in LIST_SECTIONS if "State" in CONTRACT[s][1]])
def test_integer_enum_reaches_rules_unchanged(bundle, cases, section):
    name, _ = CONTRACT[section]
    rows = cases[name]["enum_as_int"]
    operation(bundle, name, rows)
    p = project_run(bundle, redact=False)
    assert p.rule_sections[section] == rows
    assert type(p.rule_sections[section][0]["State"]) is int
    assert p[section] == NOT_COLLECTED


def test_explicit_empty_operations_are_decisive(bundle):
    for name, _ in CONTRACT.values():
        operation(bundle, name, [], item_count=0)
    p = project_run(bundle)
    for section in LIST_SECTIONS:
        assert p.rule_sections[section] == []
        assert p[section] == NOT_COLLECTED
    assert p.rule_sections["defender_license"] is True


@pytest.mark.parametrize("section", LIST_SECTIONS)
def test_failed_coverage_never_makes_an_empty_answer(bundle, section):
    name, _ = CONTRACT[section]
    operation(bundle, name, [], item_count=0)
    write(bundle, "coverage.json", [{"collector": "exchange_policy", "name": name, "status": "failed"}])
    p = project_run(bundle)
    assert p.rule_sections[section] == NOT_COLLECTED
    if section in ATP_SECTIONS:
        assert p.rule_sections["defender_license"] == NOT_COLLECTED
    other = "conn_filter" if section == "admin_audit_log_config" else "admin_audit_log_config"
    assert p.rule_sections[other] != NOT_COLLECTED
    assert f"exchange_policy.{name}" in p.report["sections"][other]["ignored_failures"]


@pytest.mark.parametrize("marker", [
    {"error": "Synthetic failure"},
    {"read_state": "blocked"},
    {"collection_status": "not_collected"},
])
def test_failed_row_with_stale_fields_withholds_its_section_only(bundle, cases, marker):
    name = "safeLinksRules"
    operation(bundle, name, [{**cases[name]["good"][0], **marker}])
    p = project_run(bundle)
    assert p.rule_sections["safe_links_rules"] == NOT_COLLECTED
    assert p.rule_sections["admin_audit_log_config"] == cases["adminAuditLogConfig"]["good"]


@pytest.mark.parametrize("section", LIST_SECTIONS)
def test_error_rows_and_non_objects_are_unavailable(bundle, cases, section):
    name, _ = CONTRACT[section]
    for rows in (cases[name]["error_row"], [None]):
        operation(bundle, name, rows)
        p = project_run(bundle)
        assert p.rule_sections[section] == NOT_COLLECTED
        other = "conn_filter" if section == "admin_audit_log_config" else "admin_audit_log_config"
        assert p.rule_sections[other] != NOT_COLLECTED


def test_missing_operation_is_a_gap(bundle):
    write(bundle, "raw/exchange_policy.json", {})
    p = project_run(bundle)
    for section in ADAPTERS:
        assert p.rule_sections[section] == NOT_COLLECTED
        assert p.report["sections"][section]["reason"] == "missing_artifact"


def test_healthy_atp_reads_mean_licence_true(bundle):
    p = project_run(bundle)
    assert p.rule_sections["defender_license"] is True
    assert p["defender_license"] == NOT_COLLECTED


def test_missing_collector_cannot_establish_a_licence(bundle):
    (bundle / "raw/exchange_policy.json").unlink()
    p = project_run(bundle)
    assert p.rule_sections["defender_license"] == NOT_COLLECTED
    assert p.report["sections"]["defender_license"]["reason"] == "missing_artifact"


@pytest.mark.parametrize("section", ATP_SECTIONS)
def test_explicit_empty_licence_refusal_means_false(bundle, cases, section):
    name, _ = CONTRACT[section]
    operation(bundle, name, [], status="error", error="Synthetic licence refusal",
              error_class="license_required", item_count=0)
    p = project_run(bundle)
    assert p.rule_sections["defender_license"] is False
    assert p.rule_sections[section] == NOT_COLLECTED
    other = next(s for s in ATP_SECTIONS if s != section)
    assert p.rule_sections[other] == cases[CONTRACT[other][0]]["good"]
    assert f"exchange_policy.{name}" in p.report["sections"]["defender_license"]["ignored_failures"]


@pytest.mark.parametrize("section", ATP_SECTIONS)
@pytest.mark.parametrize("error_class", ["command_error", "command_not_authenticated"])
def test_real_atp_failure_never_means_licence_false(bundle, section, error_class):
    name, _ = CONTRACT[section]
    operation(bundle, name, [], status="error", error="Synthetic failure", error_class=error_class, item_count=0)
    p = project_run(bundle)
    assert p.rule_sections["defender_license"] == NOT_COLLECTED
    assert p.report["sections"]["defender_license"]["reason"] == "collector_error"


@pytest.mark.parametrize("inferred_sections", [ATP_SECTIONS, ATP_SECTIONS[:1], ATP_SECTIONS[1:]])
def test_inferred_atp_licence_refusal_withholds_like_plain_failure(bundle, inferred_sections):
    for section in ATP_SECTIONS:
        name, _ = CONTRACT[section]
        operation(bundle, name, [], status="failed", error_class="command_error")
    plain_failure = project_run(bundle)

    for section in ATP_SECTIONS:
        name, _ = CONTRACT[section]
        metadata = {"licence_inferred": True} if section in inferred_sections else {}
        operation(bundle, name, [], status="failed", error_class="license_required", **metadata)
    inferred_refusal = project_run(bundle)

    for section in (*ATP_SECTIONS, "defender_license"):
        assert plain_failure.rule_sections[section] == NOT_COLLECTED
        assert inferred_refusal.rule_sections[section] == NOT_COLLECTED
        assert inferred_refusal[section] == NOT_COLLECTED
        assert plain_failure.report["sections"][section]["reason"] == "collector_error"
        assert inferred_refusal.report["sections"][section]["reason"] == "collector_error"


@pytest.mark.parametrize("section", ATP_SECTIONS)
def test_missing_atp_operation_never_means_licence_true_or_false(bundle, section):
    path = bundle / "raw/exchange_policy.json"
    payload = json.loads(path.read_text())
    del payload[CONTRACT[section][0]]
    write(bundle, "raw/exchange_policy.json", payload)
    p = project_run(bundle)
    assert p.rule_sections["defender_license"] == NOT_COLLECTED
    assert p.report["sections"]["defender_license"]["reason"] == "missing_artifact"


@pytest.mark.parametrize("metadata", [
    {"value": [{"Identity": "example.invalid"}], "item_count": 1},
    {"item_count": 1},
    {"chunk_files": ["raw/exchange_policy/atpPolicyForO365/part.jsonl"]},
])
def test_licence_refusal_with_rows_counts_or_chunks_is_not_a_false_flag(bundle, metadata):
    rows = metadata.get("value", [])
    operation(bundle, "atpPolicyForO365", rows, error="Synthetic refusal", error_class="license_required",
              **{key: value for key, value in metadata.items() if key != "value"})
    assert project_run(bundle).rule_sections["defender_license"] == NOT_COLLECTED


def test_licence_refusal_does_not_hide_a_real_failure_of_the_other_read(bundle):
    operation(bundle, "atpPolicyForO365", [], error="Synthetic refusal", error_class="license_required", item_count=0)
    operation(bundle, "atpProtectionPolicyRules", [], error="Synthetic failure", error_class="command_error")
    assert project_run(bundle).rule_sections["defender_license"] == NOT_COLLECTED


def test_unrelated_operation_failure_does_not_withhold_licence(bundle):
    operation(bundle, "safeLinksRules", [], error="Synthetic failure", error_class="command_error")
    p = project_run(bundle)
    assert p.rule_sections["defender_license"] is True
    assert "exchange_policy.safeLinksRules" in p.report["sections"]["defender_license"]["ignored_failures"]


@pytest.mark.parametrize("redact", [False, True])
def test_rule_addresses_never_reach_model_report_or_new_files(bundle, cases, redact):
    leak = "leak@example.invalid"
    row = {**cases["atpProtectionPolicyRules"]["good"][0], "Identity": leak,
           "SentTo": ["recipient"], "FreeField": leak, "TargetedUsersToProtect": [leak]}
    operation(bundle, "atpProtectionPolicyRules", [row])
    before = {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob("*") if p.is_file()}
    p = project_run(bundle, redact=redact)
    assert p.rule_sections["atp_policy_rules"][0]["Identity"] == leak
    assert "FreeField" not in p.rule_sections["atp_policy_rules"][0]
    assert "TargetedUsersToProtect" not in p.rule_sections["atp_policy_rules"][0]
    assert leak not in canonical(p)
    assert leak not in json.dumps(p.report)
    assert "recipient" not in canonical(p)
    assert "recipient" not in json.dumps(p.report)
    assert {p.relative_to(bundle): p.read_bytes() for p in bundle.rglob("*") if p.is_file()} == before


def test_adapter_copies_nested_values_and_drops_unselected_fields(tmp_path, monkeypatch):
    rows = [{"Identity": "example.invalid", "FileTypes": ["exe", "cmd"],
             "source_name": "malwareFilterPolicy", "key": "example.invalid", "kind": "policy",
             "FreeField": "leak@example.invalid"}]
    bundle = Bundle(tmp_path, 100, 10000, 10)
    monkeypatch.setattr(bundle, "operation", lambda collector, name: rows)
    projected = ADAPTERS["anti_malware_policies"](bundle)
    projected[0]["FileTypes"].append("vbe")
    assert rows[0]["FileTypes"] == ["exe", "cmd"]
    assert set(projected[0]) == {"Identity", "FileTypes"}
    assert bundle.ignored_fields == {"FreeField"}


def test_anti_phish_adapter_keeps_settings_binds_the_summary_and_never_the_target_list(tmp_path, monkeypatch):
    from auditex.scuba_projection import PrivateSnapshot
    from azure_tenant_audit.value_rules.defender_targeted_users import COVERAGE_KEY, SensitiveUsersBinding

    leak = "target-leak@example.invalid"
    digest = "ab" * 32
    known = {"version": 1, "state": "known", "input_hmac_sha256": digest, "input_count": 2,
             "protected_nonempty": True, "missing_count": 0}
    rows = [{"Identity": "Default", "IsDefault": True, "EnableTargetedDomainsProtection": True,
             "TargetedDomainsToProtect": ["partner.invalid"], "TargetedUsersToProtect": [leak],
             COVERAGE_KEY: {"version": 1, "state": "unusable", "echo": leak}},
            {"Identity": "Second", "IsDefault": False, COVERAGE_KEY: known}]
    bundle = Bundle(tmp_path, 100, 10000, 10)
    monkeypatch.setattr(bundle, "operation", lambda collector, name: rows)
    projected = ADAPTERS["anti_phish_policies"](bundle)
    # SS 2.2-2.4 keep their settings; SS 2.1 gets a minimal unusable proof, never the offending value.
    assert projected[0] == {"Identity": "Default", "IsDefault": True, "EnableTargetedDomainsProtection": True,
                            "TargetedDomainsToProtect": ["partner.invalid"], COVERAGE_KEY: {"version": 1, "state": "unusable"}}
    assert projected[1][COVERAGE_KEY] == {"version": 1, "state": "unusable"}      # nothing verified: unbound
    assert leak not in repr(projected)
    assert bundle.ignored_fields == {"TargetedUsersToProtect"}
    projected[0]["TargetedDomainsToProtect"].append("x")
    assert rows[0]["TargetedDomainsToProtect"] == ["partner.invalid"]
    bundle.sensitive_users = PrivateSnapshot(("a@example.invalid", "b@example.invalid"), SensitiveUsersBinding(2, digest), None)
    bundle.reset()
    bound = ADAPTERS["anti_phish_policies"](bundle)[1][COVERAGE_KEY]
    assert bound == known and bound is not known
    bundle.sensitive_users = PrivateSnapshot(("a@example.invalid", "b@example.invalid"), SensitiveUsersBinding(2, "cd" * 32), None)
    assert ADAPTERS["anti_phish_policies"](bundle)[1][COVERAGE_KEY] == {"version": 1, "state": "unusable"}
