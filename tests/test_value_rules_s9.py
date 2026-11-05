"""Stage-9 AAD pilot vectors, rule-view shapes, privacy and pinned oracle."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
from time import perf_counter

import pytest

from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for
from azure_tenant_audit.value_rules.catalogue import row_for
from azure_tenant_audit.value_rules.record import evidence_kind
from test_value_rules_oracle import _outcome_v3, pinned  # noqa: F401 - shared pytest fixture
from test_value_rules_vectors import _rows, _strip_names, STAGE9_POLICIES

FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-s9.jsonl.xz"
MANIFEST = FIXTURE.with_name("manifest-s9.json")
A2_OVERRIDES = FIXTURE.with_name("label-overrides-a2-s9.jsonl")


def _apply_a2_overrides(vectors, overrides):
    """Copy gold and change only exact, precondition-checked A2 claim citations."""
    by_id = {v["vector_id"]: v for v in vectors}
    effective = {vid: deepcopy(v.get("gold_response")) for vid, v in by_id.items()}
    seen = set()
    for entry in overrides:
        vid = entry["vector_id"]
        if vid in seen or vid not in by_id:
            raise ValueError("Duplicate or unknown A2 override")
        seen.add(vid)
        vector = by_id[vid]
        if (entry["policy"] != "MS.AAD.3.3v2" or vector["policy"] != entry["policy"]
                or vector["source_kind"] not in {"constructed", "pack-train", "pack-validation"}
                or entry["claim_id"] != "requirement_met"
                or entry["evidence_section_order"] != ["authentication_method"]
                or entry["new_cited"] != ["e0", "e1"]
                or vector.get("disagreement") is not None or effective[vid] is None):
            raise ValueError("A2 override precondition mismatch")
        claims = [c for c in effective[vid]["claims"] if c["id"] == "requirement_met"]
        if len(claims) != 1 or claims[0]["evidence_ids"] != entry["old_cited"]:
            raise ValueError("A2 override old ids mismatch")
        claims[0]["evidence_ids"] = deepcopy(entry["new_cited"])
    return effective


@pytest.fixture(scope="module")
def a2_overrides():
    return [json.loads(line) for line in A2_OVERRIDES.read_text().splitlines()]


def test_a2_overlay_manifest_is_exact_and_excludes_held_out(rows, a2_overrides):
    assert sha256(A2_OVERRIDES.read_bytes()).hexdigest() == "5ec93e854ed2d93449e015e93d920c0db23e14616cc4c6c6db54dad97d3cdd6f"
    assert len(a2_overrides) == 128
    ids = {entry["vector_id"] for entry in a2_overrides}
    assert len(ids) == 128
    assert Counter(vid.split(":")[0] for vid in ids) == {"pack-train": 125, "pack-validation": 3}
    affected = set()
    for vector in rows:
        if (vector["policy"] == "MS.AAD.3.3v2" and vector.get("gold_response") is not None
                and vector.get("disagreement") is None):
            claim = next(c for c in vector["gold_response"]["claims"] if c["id"] == "requirement_met")
            if any(e not in {"e0", "e1"} for e in claim["evidence_ids"]):
                affected.add(vector["vector_id"])
    assert ids == affected  # Every stale label and no unrelated label.
    before = deepcopy(rows)
    effective = _apply_a2_overrides(rows, a2_overrides)
    assert rows == before
    for vector in rows:
        vid = vector["vector_id"]
        restored = deepcopy(effective[vid])
        if vid in ids:
            old = next(c for c in vector["gold_response"]["claims"] if c["id"] == "requirement_met")
            next(c for c in restored["claims"] if c["id"] == "requirement_met")["evidence_ids"] = old["evidence_ids"]
        assert restored == vector.get("gold_response")


@pytest.mark.parametrize("mutation", ["duplicate", "unknown", "policy", "claim", "order", "old", "new"])
def test_a2_overrides_reject_bad_manifest_entries(rows, a2_overrides, mutation):
    entries = [deepcopy(a2_overrides[0])]
    if mutation == "duplicate":
        entries *= 2
    else:
        key, value = {"unknown": ("vector_id", "unknown"), "policy": ("policy", "MS.AAD.3.5v2"),
                      "claim": ("claim_id", "policy_criticality"),
                      "order": ("evidence_section_order", ["scuba_config"]),
                      "old": ("old_cited", ["e0", "e1"]),
                      "new": ("new_cited", ["e0"])}[mutation]
        entries[0][key] = value
    before = deepcopy(rows)
    with pytest.raises(ValueError, match="A2 override"):
        _apply_a2_overrides(rows, entries)
    assert rows == before


@pytest.fixture(scope="module")
def rows():
    return list(_rows(FIXTURE))


def _check_vector(vector):
    policy, sections = vector["policy"], vector["sections"]
    rule = row_for(policy)
    before = deepcopy(sections)
    record = assess(policy, sections)
    expected = (vector["rule_verdict"], vector["rule_cell"], vector["rule_reason_code"],
                vector["rule_reason_text"], vector["rule_cited_sections"] or rule["sections"])
    assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
            record["cited_sections"] or rule["sections"]) == expected, vector["vector_id"]
    detail = precheck_policy(policy, sections, list(sections), value_rules=True, absent_fields=True, empty_lists=True)
    assert detail["class"] == "value_rule" and detail["rule_id"] == rule["rule_id"]
    assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == expected[1:]
    criticality = vector.get("criticality") or json.loads(open_text_resource("configs/scuba-policy-sections.json"))[
        "policies"][policy]["policy_item"]["criticality"]
    response = precheck_response(detail, {"policy_id": policy, "criticality": criticality}, list(sections),
                                 named_limitations=False)
    assert response == as_pack_response(record, criticality, list(sections), legacy=True)
    assert vector.get("disagreement") is None or vector["disagreement"].startswith("expected:")
    assert (vector.get("disagreement") is None) is (vector["rule_verdict"] == vector["gold_verdict"])
    assert record["detail"] == {}
    assert sections == before
    assert assess(policy, _strip_names(sections)) == record
    return record["cell"]


@pytest.mark.parametrize("policy", sorted(STAGE9_POLICIES))
def test_vectors_match_reference_and_reach_every_cell(policy, rows):
    reached = {_check_vector(vector) for vector in rows if vector["policy"] == policy}
    assert reached == set(cells_for(policy))


def test_manifest_and_split_exclusions(rows):
    manifest = json.loads(MANIFEST.read_text())[FIXTURE.name]
    assert sha256(FIXTURE.read_bytes()).hexdigest() == manifest["sha256"]
    assert manifest["spec_version"] == "v3.9.1" and manifest["stage"] == 9
    assert len(rows) == manifest["rows"] == 1609
    assert len({row["vector_id"] for row in rows}) == len(rows)
    assert dict(Counter(row["policy"] for row in rows)) == manifest["by_policy"]
    assert set(manifest["by_policy"]) == STAGE9_POLICIES
    assert dict(Counter(f"{row['policy']}:{row['rule_cell']}" for row in rows)) == manifest["by_cell"]
    assert len(manifest["by_cell"]) == 72
    assert dict(Counter(row["rule_verdict"] for row in rows)) == manifest["by_verdict"]
    assert dict(Counter(row["source_kind"] for row in rows)) == manifest["by_source"]
    assert set(manifest["by_source"]) <= {"constructed", "pack-train", "pack-validation", "packlic-train"}
    assert all(not row["source_kind"].startswith("aad-") for row in rows)
    assert all(not row["source_kind"].endswith("test") for row in rows)


def test_builder_reuses_shared_split_filter(tmp_path, rows):
    path = Path(__file__).parents[1] / "scripts/build-value-rule-fixture-s9.py"
    spec = importlib.util.spec_from_file_location("stage9_fixture", path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    keep = {**next(row for row in rows if row["source_kind"] == "constructed"),
            "origin": "constructed", "source_file": "constructed by build_vectors.py", "split": None}
    held_out = {**keep, "vector_id": "held-out", "source_kind": "pack-test", "split": "test",
                "source_file": "20261030-oracle-pack-v10/test.jsonl"}
    sealed = {**keep, "vector_id": "sealed", "source_kind": "aad-frozen", "split": "test"}
    source, target = tmp_path / "source.jsonl", tmp_path / "out.jsonl.xz"
    source.write_text("".join(json.dumps(row) + "\n" for row in (keep, held_out, sealed)))
    manifest = builder.build(source, target)
    assert manifest["rows"] == 1
    assert [row["vector_id"] for row in _rows(target)] == [keep["vector_id"]]
    assert manifest["source_sha256"] == sha256(source.read_bytes()).hexdigest()
    source.write_text(json.dumps({**keep, "disagreement": "UNEXPECTED"}) + "\n")
    with pytest.raises(ValueError, match="UNEXPECTED"):
        builder.build(source, target)


@pytest.mark.parametrize("policy", sorted(STAGE9_POLICIES))
def test_agreeing_pack_response_parity(policy, rows, a2_overrides):
    agreeing = [v for v in rows if v["policy"] == policy and v["source_kind"].startswith("pack-")
                and v.get("gold_response") is not None and v.get("disagreement") is None]
    effective = _apply_a2_overrides(rows, a2_overrides)
    s2_only = set()
    for vector in agreeing:
        sections = vector["sections"]
        if policy == "MS.AAD.3.3v2":
            # A2 uses the current read set without mutating frozen source sections.
            sections = {"authentication_method": deepcopy(sections["authentication_method"])}
        record = assess(policy, sections)
        assert record == assess(policy, vector["sections"])
        gold = effective[vector["vector_id"]]
        response = as_pack_response(record, vector["criticality"], list(sections),
                                    legacy=policy != "MS.AAD.3.3v2")
        if response != gold:
            # A2 retains S2 only for an exact legacy-vocabulary match on unusable evidence.
            assert policy == "MS.AAD.3.3v2" and record["verdict"] == "not_assessed", vector["vector_id"]
            assert evidence_kind(record["reason_code"]) is not None
            assert as_pack_response(record, vector["criticality"], list(sections), legacy=True) == gold, vector["vector_id"]
            s2_only.add(vector["vector_id"])
    if policy == "MS.AAD.3.3v2":
        assert s2_only == {"pack-train:scuba-aad-ms-aad-3-3v2-3fb3d8c6fb",
                           "pack-train:scuba-aad-ms-aad-3-3v2-e66d9b7294"}


def test_optional_full_stage9_vectors():
    source = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS")
    if not source:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS unset")
    reached = defaultdict(set)
    count = 0
    for vector in _rows(Path(source)):
        if vector["policy"] in STAGE9_POLICIES:
            reached[vector["policy"]].add(_check_vector(vector))
            count += 1
    assert count == 2554
    assert set(reached) == STAGE9_POLICIES
    assert all(reached[policy] == set(cells_for(policy)) for policy in STAGE9_POLICIES)


@pytest.mark.skipif(not (os.getenv("AUDITEX_TEST_OPA") and os.getenv("AUDITEX_TEST_SCUBAGEAR")),
                    reason="set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
def test_stage9_cells_against_pinned_opa(rows, tmp_path, pinned):
    groups = defaultdict(list)
    for row in rows:
        if row.get("gold_source") == "opa-replay":
            groups[(row["policy"], row["rule_cell"])].append(row)
    assert {policy for policy, _ in groups} == STAGE9_POLICIES
    assert set(groups) == {(policy, cell) for policy in STAGE9_POLICIES for cell in cells_for(policy)
                           if cell != "section_not_collected"}
    selected = [sorted(group, key=lambda row: row["vector_id"])[0] for _, group in sorted(groups.items())]
    extra = int(os.getenv("AUDITEX_TEST_VALUE_RULE_SAMPLE", "0"))
    remaining = sorted((row for group in groups.values() for row in sorted(group, key=lambda r: r["vector_id"])[1:]),
                       key=lambda row: row["vector_id"])
    selected.extend(remaining[:max(extra, 0)])
    for row in selected:
        sections = row["sections"]
        if row["source_kind"] != "constructed":
            sections = {name: value for name, value in sections.items() if value is not None}
        path = tmp_path / "input.json"
        path.write_text(json.dumps(sections))
        process = subprocess.run([os.environ["AUDITEX_TEST_OPA"], "eval", "-f", "json",
                                  "-d", str(pinned / "AADConfig.rego"), "-d", str(pinned / "Utils"),
                                  "-i", str(path), "data.aad.tests"],
                                 capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(process.stdout)
        except ValueError:
            result = {"errors": [process.stderr[:200]]}
        assert _outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        actual = assess(row["policy"], row["sections"])["verdict"]
        assert (actual == row["gold_verdict"]) is (row.get("disagreement") is None), row["vector_id"]


def _canary_sections(unusable=False):
    from azure_tenant_audit.value_rules.aad_pilot import APP_SCOPES, ALL_APPS, G_LOW

    canary, display = "stage9.person@example.invalid", "Stage Nine Canary Display Name"
    context = {"State": "enabled", "IncludeTarget": {"Id": "all_users"},
               "ExcludeTarget": {"Id": ""}, "DisplayName": display}
    methods = [{"Id": name, "State": "disabled", "DisplayName": display} for name in ("Sms", "Voice", "Email")]
    methods.append({"Id": "MicrosoftAuthenticator", "State": "enabled", "IsSoftwareOathEnabled": False,
                    "FeatureSettings": {"DisplayAppInformationRequiredState": deepcopy(context),
                                        "DisplayLocationInformationRequiredState": deepcopy(context)},
                    "Owner": canary})
    policy = {"DisplayName": display, "Id": canary}
    for scope in APP_SCOPES:
        policy[scope] = {"PasswordCredentials": [
            {"RestrictionType": "passwordAddition", "State": "disabled",
             "RestrictForAppsCreatedAfterDateTime": ALL_APPS[0]},
            {"RestrictionType": "passwordLifetime", "State": "enabled", "MaxLifetime": "P181D",
             "RestrictForAppsCreatedAfterDateTime": ALL_APPS[1]}],
            "KeyCredentials": [{"RestrictionType": "asymmetricKeyLifetime", "State": "enabled",
                                "MaxLifetime": "P366D", "RestrictForAppsCreatedAfterDateTime": ALL_APPS[0]}]}
    sections = {
        "authentication_method": [{"authentication_method_feature_settings": methods, "Owner": canary}],
        "authorization_policies": [{"Id": canary, "PermissionGrantPolicyIdsAssignedToDefaultUserRole": [G_LOW]}],
        "risky_delegated_permission_classifications": [{"RiskyPermClassifications": [canary], "DisplayName": display}],
        "directory_settings": [{"DisplayName": display, "Values": [
            {"Name": "EnableAdminConsentRequests", "Value": "TrUe", "Owner": canary}]}],
        "default_app_management_policy": [policy],
        "app_management_policies": [{"IsEnabled": True, "DisplayName": display, "Restrictions": {
            "PasswordCredentials": [{"RestrictionType": "passwordLifetime", "State": "enabled",
                                     "MaxLifetime": "P123457D", "AppliesTo": [canary],
                                     "RestrictForAppsCreatedAfterDateTime": ALL_APPS[0]}]}}],
        "domain_settings": [{"Id": canary, "IsVerified": True, "AuthenticationType": "Managed",
                             "IsRoot": True, "PasswordValidityPeriodInDays": 90, "DisplayName": display}],
    }
    if unusable:
        for method in methods:
            method["State"] = canary
        sections["authorization_policies"][0]["PermissionGrantPolicyIdsAssignedToDefaultUserRole"] = [canary]
        sections["directory_settings"][0]["Values"][0]["Value"] = canary
        sections["domain_settings"][0]["PasswordValidityPeriodInDays"] = canary
        sections["app_management_policies"][0]["IsEnabled"] = False
        for scope in APP_SCOPES:
            for entries in policy[scope].values():
                for entry in entries:
                    entry["State"] = canary
    return sections, canary, display


@pytest.mark.parametrize("unusable", [False, True])
def test_served_outputs_and_logs_do_not_contain_any_section_evidence(tmp_path, monkeypatch, caplog, unusable):
    from auditex.model_serving import ModelClient, ModelConfig, assess_run
    from azure_tenant_audit.model_assessment import validate_assessment
    from test_model_serving import fake_projection

    sections, canary, display = _canary_sections(unusable)
    assert set(sections) == {name for policy in STAGE9_POLICIES for name in row_for(policy)["sections"]}
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage9"}')

    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update(deepcopy(sections))
        return projection

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.model_serving.project_run", projected)
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("AAD pilot called the model"))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=sorted(STAGE9_POLICIES))
    validate_assessment(result)
    assert len(result["policies"]) == 8
    assert all(row["rule_precheck"]["class"] == "value_rule" for row in result["policies"])
    if unusable:
        assert all(row["rule_precheck"]["reason_code"].startswith("data_unusable_") for row in result["policies"])
        assert all(row["recommendations"] == ["recollect_unusable_evidence"] for row in result["policies"])
    outputs = [json.dumps(result), caplog.text]
    outputs.extend(path.read_text() for path in tmp_path.rglob("*") if path.is_file())
    outputs.extend(json.dumps(assess(policy, sections)) for policy in sorted(STAGE9_POLICIES))
    assert all(canary not in output and display not in output and "123457" not in output for output in outputs)


@pytest.mark.parametrize("policy", sorted(STAGE9_POLICIES))
def test_uncollected_markers_precede_values(policy):
    for section in row_for(policy)["sections"]:
        sections = {name: None for name in row_for(policy)["sections"]}
        sections[section] = NOT_COLLECTED
        record = assess(policy, sections)
        assert record["cell"] == "section_not_collected"
        assert record["cited_sections"] == [section]


def test_authenticator_context_ignores_conditional_access_and_disabled_gate_wins():
    sections, _, _ = _canary_sections()
    original = assess("MS.AAD.3.3v2", sections)
    assert original["cell"] == "config_met"
    sections["conditional_access_policies"] = NOT_COLLECTED
    sections["scuba_config"] = NOT_COLLECTED
    assert assess("MS.AAD.3.3v2", sections) == original
    methods = sections["authentication_method"][0]["authentication_method_feature_settings"]
    methods[-1]["State"] = "disabled"
    methods[-1].pop("FeatureSettings")
    assert assess("MS.AAD.3.3v2", sections)["cell"] == "closed_gate"
    methods.append(deepcopy(methods[-1]))
    assert assess("MS.AAD.3.3v2", sections)["cell"] == "authenticator_duplicated"


def test_all_three_unusable_method_states_are_a_closed_text():
    sections = {"authentication_method": [{"authentication_method_feature_settings": [
        {"Id": name, "State": "canary@example.invalid"} for name in ("Sms", "Voice", "Email")]}]}
    record = assess("MS.AAD.3.5v2", sections)
    assert record["cell"] == "method_state_unusable"
    assert record["reason_text"] == ("Data unusable: the state of Sms, Voice, Email authentication is not enabled "
                                     "or disabled; the policy was not assessed.")


def test_authenticator_bare_policy_object_is_unusable_evidence():
    sections = {"authentication_method": {"authentication_method_feature_settings": [
        {"Id": "MicrosoftAuthenticator", "State": "disabled"}]}}
    record = assess("MS.AAD.3.3v2", sections)
    assert (record["verdict"], record["cell"], record["reason_code"]) == (
        "not_assessed", "section_shape_unusable", "data_unusable_section_shape")
    assert record["cited_sections"] == ["authentication_method"]
    response = as_pack_response(record, "Shall", ["authentication_method"])
    assert response["limitations"] == ["evidence_unusable"]
    assert response["recommendations"] == ["recollect_unusable_evidence"]


@pytest.mark.parametrize("section,closes", [
    (None, False), ([], False), ([None], False), ([{}], False),
    ([{"authentication_method_feature_settings": {"Id": "MicrosoftAuthenticator", "State": "disabled"}}], False),
    *[([{"authentication_method_feature_settings": entries}], closes) for entries, closes in [
        ([], False), ([None, "disabled"], False),
        ([{"Id": "MicrosoftAuthenticator", "State": "disabled"}], True),
        ([None, {"Id": "MicrosoftAuthenticator", "State": "disabled"}], True),
        ([{"Id": "microsoftauthenticator", "State": "disabled"}], False),
        ([{"Id": "MicrosoftAuthenticator", "State": "Disabled"}], False),
        ([{"Id": "MicrosoftAuthenticator", "State": ["disabled"]}], False),
        ([{"Id": "MicrosoftAuthenticator", "State": "enabled"}], False),
        ([{"Id": "MicrosoftAuthenticator", "State": "disabled"}] * 2, False),
        ([{"Id": "MicrosoftAuthenticator", "State": "disabled"},
          {"Id": "MicrosoftAuthenticator", "State": "enabled"}], False),
    ]],
    ([{"authentication_method_feature_settings": [{"Id": "MicrosoftAuthenticator", "State": "disabled"}]}] * 2, False),
])
def test_authenticator_gate_reference_shapes_duplicates_and_case(section, closes):
    from azure_tenant_audit.value_rules.gates import closed_gate

    sections = {"authentication_method": section}
    assert (closed_gate("MS.AAD.3.3v2", sections) is not None) is closes
    assert (assess("MS.AAD.3.3v2", sections)["cell"] == "closed_gate") is closes


@pytest.mark.parametrize("environment", ["gcc", "gcchigh", "dod", "commercial", "GCC", None, 0, "other"])
@pytest.mark.parametrize("shape", ["object", "singleton", "duplicate", "nested"])
def test_environment_gates_reference_shapes_and_case(environment, shape):
    from azure_tenant_audit.scuba_precheck import rule_catalogue
    from azure_tenant_audit.value_rules.gates import closed_gate

    config = {"M365Environment": environment}
    config = {"object": config, "singleton": [config], "duplicate": [config, config],
              "nested": [[config]]}[shape]
    for rule in rule_catalogue()["rules"]:
        if rule["section"] != "scuba_config":
            continue
        closed = ("gcchigh", "dod") if rule["policy_id"] == "MS.AAD.9.1v1" else ("gcc", "gcchigh", "dod")
        expected = shape == "object" and environment in closed
        assert (closed_gate(rule["policy_id"], {"scuba_config": config}) is not None) is expected


@pytest.mark.parametrize("slider", [0, 1, 2, 3, 0.0, 1.0, 0.5, True, False, "0", "Disabled", None,
                                  float("nan"), float("inf"), -1, 4])
@pytest.mark.parametrize("shape", ["object", "singleton", "duplicate", "nested"])
def test_sharepoint_gates_reference_shapes_duplicates_and_case(slider, shape):
    from azure_tenant_audit.value_rules.gates import closed_gate

    tenant = {"SharingCapability": slider}
    section = {"object": tenant, "singleton": [tenant], "duplicate": [tenant, tenant],
               "nested": [[tenant]]}[shape]
    for policy, closed in {"MS.SHAREPOINT.1.3v1": (0, 3), "MS.SHAREPOINT.3.1v1": (0, 1, 3),
                           "MS.SHAREPOINT.3.2v1": (0, 1, 3), "MS.SHAREPOINT.3.3v2": (0,)}.items():
        expected = shape in ("object", "singleton") and type(slider) in (int, float) and slider in closed
        assert (closed_gate(policy, {"SPO_tenant": section}) is not None) is expected


class _ScanningDomainRoots:
    """Straightforward pre-fix root scan, also used for orphan diagnostics."""

    def __init__(self, roots, *, lower=False):
        self.roots = [(root["Id"].lower() if lower else root["Id"], root) for root in roots]

    def longest(self, name, *, boundary=True):
        matches = [(key, root) for key, root in self.roots
                   if (name == key or name.endswith("." + key))] if boundary else [
                       (key, root) for key, root in self.roots if name.endswith(key)]
        return max(matches, key=lambda item: len(item[0]))[1] if matches else None


def _domain(name, *, root=True, validity=None):
    return {"Id": name, "IsVerified": True, "AuthenticationType": "Managed", "IsRoot": root,
            "PasswordValidityPeriodInDays": validity}


def test_domain_suffix_lookup_matches_straightforward_scan_on_random_small_inputs(monkeypatch):
    from azure_tenant_audit.value_rules import aad_pilot

    rng = random.Random(91061)
    indexed = aad_pilot._DomainRoots
    labels = ["", "a", "ba", "A", "example", "EXAMPLE", "com", "net", "\u0130", "i\u0307"]
    for _ in range(1000):
        names = [".".join(rng.choices(labels, k=rng.randrange(1, 5))) for _ in range(rng.randrange(1, 9))]
        roots = [_domain(name, validity=rng.choice([None, 2147483647, 90, 0, True, "unknown"])) for name in names]
        # Duplicate ids deliberately disagree; the first exported root must win ties.
        roots.append({**rng.choice(roots), "PasswordValidityPeriodInDays": rng.choice([None, 90])})
        children = [rng.choice(["", "x.", "x", "X.", "."]) + rng.choice(names + ["orphan.invalid"])
                    for _ in range(rng.randrange(1, 11))]
        for lower in (False, True):
            index, scan = indexed(roots, lower=lower), _ScanningDomainRoots(roots, lower=lower)
            for child in children:
                name = child.lower() if lower else child
                for boundary in (False, True):
                    assert index.longest(name, boundary=boundary) is scan.longest(name, boundary=boundary)
        domains = roots + [_domain(child, root=False, validity=90) for child in children]
        domains += [None, _domain("ignored.invalid", root=False) | {"IsVerified": False}]
        rng.shuffle(domains)
        with monkeypatch.context() as patch:
            patch.setattr(aad_pilot, "_DomainRoots", _ScanningDomainRoots)
            expected = assess("MS.AAD.6.1v1", {"domain_settings": domains})
        actual = assess("MS.AAD.6.1v1", {"domain_settings": domains})
        assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)


@pytest.mark.parametrize("mode,cell,code", [
    ("inherited", "passwords_never_expire", "passwords_never_expire"),
    ("orphan", "orphan_sub_domain", "data_unusable_sub_domain_without_root"),
    ("case_only", "orphan_sub_domain", "data_unusable_sub_domain_root_case"),
    ("collision", "orphan_sub_domain", "data_unusable_sub_domain_without_root"),
])
def test_domain_inheritance_10000_roots_and_10000_subdomains_within_five_seconds(mode, cell, code):
    roots = [_domain(f"root{i}.example") for i in range(10000)]
    names = {"inherited": lambda i: f"child.root{i}.example", "orphan": lambda i: f"child{i}.invalid",
             "case_only": lambda i: f"child.ROOT{i}.example", "collision": lambda i: f"evilroot{i}.example"}
    domains = roots + [_domain(names[mode](i), root=False) for i in range(10000)]
    start = perf_counter()
    record = assess("MS.AAD.6.1v1", {"domain_settings": domains})
    elapsed = perf_counter() - start
    assert (record["cell"], record["reason_code"]) == (cell, code)
    assert elapsed < 5, f"{mode}: {elapsed:.3f}s for 10,000 roots and 10,000 sub-domains"


def test_rule_exceptions_use_existing_failure_handler(tmp_path, monkeypatch, caplog):
    from auditex.model_serving import ModelClient, ModelConfig, assess_run
    from azure_tenant_audit import value_rules
    from azure_tenant_audit.model_assessment import validate_assessment
    from test_model_serving import fake_projection

    sections, canary, display = _canary_sections()
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage9-exceptions"}')

    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update(deepcopy(sections))
        return projection

    def broken(*args):
        raise ValueError(canary)

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.model_serving.project_run", projected)
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("A failing rule called the model"))
    registry = dict(value_rules._registry())
    registry.update({row_for(policy)["kind"]: broken for policy in STAGE9_POLICIES})
    monkeypatch.setattr(value_rules, "_REGISTRY", registry)
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=sorted(STAGE9_POLICIES))
    validate_assessment(result)
    assert all(row["rule_precheck"]["cell"] == "rule_evaluation_failed" for row in result["policies"])
    assert all(row["recommendations"] == ["report_product_fault"] for row in result["policies"])
    outputs = [json.dumps(result), caplog.text]
    outputs.extend(path.read_text() for path in tmp_path.rglob("*") if path.is_file())
    assert all(canary not in output and display not in output for output in outputs)
