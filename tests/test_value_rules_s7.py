"""v3.9.1 FINAL privileged roles and Conditional Access, synthetic evidence only."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from time import monotonic

import pytest

from azure_tenant_audit.scuba_assessment import validate_assessment
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for
from azure_tenant_audit.value_rules.catalogue import catalogue
from test_value_rules_contract import assessment, assessment_for  # noqa: F401 - shared pytest fixture
from test_value_rules_vectors import STAGE7_POLICIES, _grouped, _rows

FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-s7.jsonl.xz"


@pytest.fixture(scope="module")
def rows_s7():
    return _grouped(FIXTURE)


def _check_rows(policy, rows):
    rule = catalogue()["policies"][policy]
    reached = set()
    for row in rows:
        sections = row["sections"]
        before = deepcopy(sections)
        record = assess(policy, sections)
        assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
                record["cited_sections"]) == (
            row["rule_verdict"], row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"],
            row["rule_cited_sections"]), row["vector_id"]
        detail = precheck_policy(policy, sections, list(sections), value_rules=True,
                                 absent_fields=True, empty_lists=True)
        assert detail["class"] == "value_rule", row["vector_id"]
        assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == (
            record["cell"], record["reason_code"], record["reason_text"],
            record["cited_sections"] or rule["sections"]), row["vector_id"]
        for legacy in (True, False):
            response = as_pack_response(record, row["criticality"], list(sections), legacy=legacy)
            assert precheck_response(detail, {"policy_id": policy, "criticality": row["criticality"]},
                                     list(sections), named_limitations=False, legacy=legacy) == response
            if legacy and row.get("gold_response") is not None and row.get("disagreement") is None:
                assert response == row["gold_response"], row["vector_id"]
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:"), row["vector_id"]
        assert (row.get("disagreement") is None) is (record["verdict"] == row["gold_verdict"]), row["vector_id"]
        assert record["detail"] == {}
        assert sections == before
        reached.add(record["cell"])
    assert reached == set(cells_for(policy))


@pytest.mark.parametrize("policy", sorted(STAGE7_POLICIES))
def test_final_vectors(policy, rows_s7):
    _check_rows(policy, rows_s7[policy])


def test_manifest_and_every_cell(rows_s7):
    manifest = json.loads(FIXTURE.with_name("manifest-s7.json").read_text())[FIXTURE.name]
    rows = [row for group in rows_s7.values() for row in group]
    assert sha256(FIXTURE.read_bytes()).hexdigest() == manifest["sha256"]
    assert manifest["spec_version"] == "v3.9.1"
    assert manifest["rows"] == len(rows) == 7955
    assert set(rows_s7) == STAGE7_POLICIES
    assert manifest["by_policy"] == {p: len(group) for p, group in rows_s7.items()}
    assert manifest["by_cell"] == dict(Counter(f"{r['policy']}:{r['rule_cell']}" for r in rows))
    assert len(manifest["by_cell"]) == sum(len(cells_for(p)) for p in STAGE7_POLICIES)
    assert manifest["by_source"] == dict(Counter(r["source_kind"] for r in rows)) == {
        "constructed": 5705, "pack-train": 2188, "pack-validation": 62}
    assert manifest["by_origin"] == dict(Counter(r["origin"] for r in rows)) == manifest["by_source"]
    for row in rows:
        assert row["vector_id"] and row["origin"] in {"constructed", "pack-train", "pack-validation"}
        assert row["source_origin"] in {"v3.7 vectors-base", "v3.8 constructed", "v3.9 constructed", "v3.9.1 constructed"}
        assert row["source_file"]
        assert row["split"] == {"constructed": None, "pack-train": "train", "pack-validation": "validation"}[row["origin"]]
    assert manifest["by_verdict"] == dict(Counter(r["rule_verdict"] for r in rows))


def test_optional_full_final_source():
    source = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS_V391")
    if not source:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS_V391 unset")
    from azure_tenant_audit.resources import open_text_resource
    items = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    grouped = _grouped(Path(source))
    assert sum(len(grouped[p]) for p in STAGE7_POLICIES) == 8126
    for policy in sorted(STAGE7_POLICIES):
        _check_rows(policy, [{"criticality": items[policy]["policy_item"]["criticality"], **r}
                             for r in grouped[policy]])


@pytest.mark.parametrize("policy", sorted(STAGE7_POLICIES))
def test_every_cell_validates_and_s2_is_distinct(policy, rows_s7, assessment):  # noqa: F811 - shared pytest fixture injected by name
    from auditex.rule_assessment import _comparison
    samples = {r["rule_cell"]: r for r in rows_s7[policy]}
    for cell, row in samples.items():
        record = assess(policy, row["sections"])
        for legacy in (False, True):
            result = assessment_for(assessment, {**record, "cited_sections":
                record["cited_sections"] or catalogue()["policies"][policy]["sections"]}, legacy=legacy)
            result["policies"][0]["comparison"] = _comparison(policy, result["policies"][0], {})
            unknown = record["verdict"] == "not_assessed"
            result["totals"].update(answered=int(not unknown), unknown=int(unknown))
            validate_assessment(result)
        response = as_pack_response(record, "Shall", catalogue()["policies"][policy]["sections"])
        if record["verdict"] == "not_assessed":
            if cell == "section_not_collected":
                assert response["limitations"] == ["required_evidence_section_not_collected"]
                assert response["recommendations"] == ["collect_missing_evidence_section"]
            else:
                assert response["limitations"] == ["evidence_unusable"]
                assert response["recommendations"] != ["collect_missing_evidence_section"]


def _sample(rows, cell):
    matches = [r for r in rows if r["rule_cell"] == cell]
    # Prefer a constructed singleton so a targeted mutation has one deciding object.
    row = min(matches, key=lambda r: (r["source_kind"] != "constructed",
              len(r["sections"].get("conditional_access_policies", [])) != 1))
    return deepcopy(row["sections"])


@pytest.mark.parametrize("field,value,cell", [
    ("Platforms", {"IncludePlatforms": ["android", "iOS"]}, "restricted_policy_only"),
    ("Platforms", {"IncludePlatforms": ["all"]}, "met_policy_clean"),
    ("Platforms", {"ExcludePlatforms": ["windows"]}, "restricted_policy_only"),
    ("Locations", {"IncludeLocations": ["synthetic-location"]}, "restricted_policy_only"),
    ("Locations", {"IncludeLocations": ["All"]}, "met_policy_clean"),
    ("Devices", {"DeviceFilter": {"Mode": "include", "Rule": "synthetic-filter"}}, "restricted_policy_only"),
    ("Devices", {"DeviceFilter": {"Mode": None, "Rule": None}}, "met_policy_clean"),
    ("DeviceStates", {"IncludeStates": ["synthetic-state"]}, "restricted_policy_only"),
    ("ClientApplications", {"IncludeServicePrincipals": ["All"]}, "restricted_policy_only"),
    ("ClientAppTypes", "all", "policy_field_unusable"),
    ("AuthenticationFlows", "deviceCodeFlow", "policy_field_unusable"),
    ("AuthenticationFlows", ["deviceCodeFlow"], "policy_field_unusable"),
])
def test_n1_and_f2_no_restricted_or_unreadable_pass(field, value, cell, rows_s7):
    p = "MS.AAD.3.2v2"
    sections = _sample(rows_s7[p], "met_policy_clean")
    sections["conditional_access_policies"][0]["Conditions"][field] = value
    assert assess(p, sections)["cell"] == cell


@pytest.mark.parametrize("policy,control", [("MS.AAD.3.2v2", "mfa"), ("MS.AAD.3.7v1", "compliantDevice"),
                                            ("MS.AAD.3.8v1", "compliantDevice")])
@pytest.mark.parametrize("strength", ["absent", "bad", {}, {"AllowedCombinations": [7]}])
@pytest.mark.parametrize("operator,cell", [("OR", "policy_field_unusable"), ("AND", "met_policy_clean"),
                                          (None, "policy_field_unusable")])
def test_f1_unknown_strength_is_not_no_strength(policy, control, strength, operator, cell, rows_s7):
    sections = _sample(rows_s7[policy], "met_policy_clean")
    grant = {"BuiltInControls": [control], "Operator": operator}
    if strength != "absent":
        grant["AuthenticationStrength"] = strength
    sections["conditional_access_policies"][0]["GrantControls"] = grant
    assert assess(policy, sections)["cell"] == cell


def test_union_is_not_a_pass_and_managed_device_and_is_stricter(rows_s7):
    p = "MS.AAD.1.1v1"
    sections = _sample(rows_s7[p], "met_policy_clean")
    obj = sections["conditional_access_policies"][0]
    obj["Conditions"]["Users"]["IncludeUsers"] = ["synthetic-user-one"]
    other = deepcopy(obj)
    other["Conditions"]["Users"]["IncludeUsers"] = ["synthetic-user-two"]
    sections["conditional_access_policies"].append(other)
    record = assess(p, sections)
    assert (record["cell"], record["verdict"]) == ("union_possible", "not_assessed")
    p = "MS.AAD.3.7v1"
    sections = _sample(rows_s7[p], "met_policy_clean")
    grant = {"BuiltInControls": ["compliantDevice", "mfa"], "AuthenticationStrength": None, "Operator": "AND"}
    sections["conditional_access_policies"][0]["GrantControls"] = grant
    assert assess(p, sections)["cell"] == "met_policy_clean"
    grant["Operator"] = "OR"
    assert assess(p, sections)["cell"] == "no_policy_meets"


@pytest.mark.parametrize("policy", sorted(p for p in STAGE7_POLICIES
                                          if "service_plans" in catalogue()["policies"][p]["sections"]))
def test_p2_precedes_substantive_values(policy, rows_s7):
    for cell in ("met_policy_clean", "no_policy_meets") if ".7." not in policy else ("all_clear", "role_flagged"):
        sections = _sample(rows_s7[policy], cell)
        sections["service_plans"] = [{"ServicePlanName": "AAD_PREMIUM_P2"}]
        assert assess(policy, sections)["cell"] == "licence_not_detected"
        sections["service_plans"] = "bad"
        record = assess(policy, sections)
        assert record["cell"] == "section_not_a_list" and record["cited_sections"] == ["service_plans"]


@pytest.mark.parametrize("policy,key", [("MS.AAD.7.4v1", "EndDateTime"), ("MS.AAD.7.5v1", "StartDateTime")])
def test_absent_date_and_explicit_null(policy, key, rows_s7):
    sections = _sample(rows_s7[policy], "all_clear")
    sections["privileged_roles"] = [{"DisplayName": "Synthetic Role", "Assignments": [{
        "PrincipalId": "synthetic-id", key: None}]}]
    if "scuba_config" in sections:
        sections["scuba_config"] = {"Aad": None}
    assert assess(policy, sections)["cell"] == "role_flagged"
    del sections["privileged_roles"][0]["Assignments"][0][key]
    assert assess(policy, sections)["cell"] == "role_field_unusable"


@pytest.mark.parametrize("environment,cell", [("commercial", "met_policy_clean"), ("gcc", "met_policy_clean"),
                                             ("gcchigh", "closed_gate"), ("dod", "closed_gate"),
                                             (None, "environment_unknown"), ("GCC", "environment_unknown")])
def test_aad91_environment(environment, cell, rows_s7):
    sections = _sample(rows_s7["MS.AAD.9.1v1"], "met_policy_clean")
    sections["scuba_config"]["M365Environment"] = environment
    assert assess("MS.AAD.9.1v1", sections)["cell"] == cell
    if cell == "closed_gate":
        assert assess("MS.AAD.9.1v1", {"scuba_config": {"M365Environment": environment}})["cell"] == cell


def test_32_exemptions_use_v1_entry(rows_s7):
    p = "MS.AAD.3.2v2"
    sections = _sample(rows_s7[p], "met_policy_clean")
    obj = sections["conditional_access_policies"][0]
    obj["Conditions"]["Users"]["ExcludeUsers"] = ["synthetic-exempt-id"]
    sections["scuba_config"] = {"Aad": {"MS.AAD.3.2v1": {"CapExclusions": {"Users": ["synthetic-exempt-id"]}}}}
    assert assess(p, sections)["cell"] == "met_policy_declared_exclusions"
    sections["scuba_config"]["Aad"][p] = sections["scuba_config"]["Aad"].pop("MS.AAD.3.2v1")
    assert assess(p, sections)["cell"] == "exemption_key_ambiguous"


def test_export_declared_exclusions_stay_not_collected(tmp_path):
    from auditex.rule_assessment import policy_catalogue
    from auditex.scubagear_export import load_export, project_export
    from auditex.scuba_projection import rule_policy_section
    source = Path(__file__).parent / "fixtures/scubagear-export/mocktenant-provider-export.json"
    raw = json.loads(source.read_text())
    raw["scuba_config"]["CapExclusions"] = {"Applications": [], "Groups": [], "GuestUserTypes": [], "Users": ["mock"]}
    path = tmp_path / "mocktenant.json"
    path.write_text(json.dumps(raw))
    projection, _ = project_export(load_export(path), policy_catalogue()["policies"])
    for p in STAGE7_POLICIES:
        if catalogue()["policies"][p]["kind"] != "ca_exists":
            continue
        if p == "MS.AAD.9.1v1":
            continue  # 9.1 reads application exemptions only; the separate regression covers those.
        sections = {s: rule_policy_section(projection, p, s) for s in catalogue()["policies"][p]["sections"]}
        assert sections["scuba_config"] == NOT_COLLECTED
        assert assess(p, sections)["cell"] == "section_not_collected"


def test_export_aad91_declared_application_exemption_stays_unresolved(tmp_path, rows_s7):
    """Scope blocker: stage 2 omits 9.1 from its exclusion-reader policy set."""
    from auditex.rule_assessment import policy_catalogue
    from auditex.scubagear_export import load_export, project_export
    from auditex.scuba_projection import rule_policy_section
    p = "MS.AAD.9.1v1"
    source = Path(__file__).parent / "fixtures/scubagear-export/mocktenant-provider-export.json"
    raw = json.loads(source.read_text())
    raw.update(_sample(rows_s7[p], "met_policy_clean"))
    raw["conditional_access_policies"][0]["Conditions"]["Applications"]["ExcludeApplications"] = ["synthetic-app"]
    raw["scuba_config"] = {"M365Environment": "commercial", "Aad": {
        p: {"CapExclusions": {"Applications": ["synthetic-app"]}}}}
    assert assess(p, raw)["cell"] == "met_policy_declared_exclusions"
    path = tmp_path / "mocktenant.json"
    path.write_text(json.dumps(raw))
    projection, _ = project_export(load_export(path), policy_catalogue()["policies"])
    sections = {s: rule_policy_section(projection, p, s) for s in catalogue()["policies"][p]["sections"]}
    record = assess(p, sections)
    assert record["cell"] == "section_not_collected", record["cell"]


CANARY_EMAIL = "stage7-private@example.invalid"
CANARY_NAME = "Stage Seven Private Display Name"
CANARY_ID = "stage7-private-object-id"


def _canary_sections(policy, rows):
    """Reach a substantive met branch with linked private identifiers, not just extra keys."""
    role_policy = ".7." in policy
    sections = _sample(rows, "all_clear" if role_policy else "met_policy_clean")
    for role in sections.get("privileged_roles", []):
        if role.get("DisplayName") != "Global Administrator" or policy not in {"MS.AAD.7.6v1", "MS.AAD.7.8v1"}:
            role["DisplayName"] = CANARY_NAME
        old = role.get("RoleTemplateId")
        role["RoleTemplateId"] = CANARY_ID
        for obj in sections.get("conditional_access_policies", []):
            users = obj["Conditions"]["Users"]
            users["IncludeRoles"] = [CANARY_ID if x == old else x for x in users.get("IncludeRoles") or []]
        for assignment in role.get("Assignments", []):
            assignment["PrincipalId"] = assignment["UserPrincipalName"] = CANARY_EMAIL
        for rule in role.get("Rules", []):
            rule["RuleSource"], rule["RuleSourceType"] = CANARY_NAME, CANARY_ID
            rule["NotificationRecipients"] = [CANARY_EMAIL]
    if policy == "MS.AAD.7.4v1":
        for role in sections["privileged_roles"]:
            for assignment in role["Assignments"]:
                assignment["EndDateTime"] = None
        sections["scuba_config"] = {"Aad": {policy: {"RoleExclusions": {
            "Users": [CANARY_EMAIL], "Groups": [CANARY_ID]}}}}
    if not role_policy:
        ca = catalogue()["policies"][policy]["params"]["ca"]
        exclusions = {}
        for obj in sections["conditional_access_policies"]:
            obj["DisplayName"], obj["Id"] = CANARY_NAME, CANARY_ID
            users, apps = obj["Conditions"]["Users"], obj["Conditions"]["Applications"]
            for kind in ca["ex"]:
                if kind == "guests":
                    users["ExcludeGuestsOrExternalUsers"] = {"GuestOrExternalUserTypes": CANARY_ID}
                    exclusions["GuestUserTypes"] = [CANARY_ID]
                else:
                    container, field, key = {"users": (users, "ExcludeUsers", "Users"),
                                             "groups": (users, "ExcludeGroups", "Groups"),
                                             "apps": (apps, "ExcludeApplications", "Applications")}[kind]
                    value = CANARY_EMAIL if kind == "users" else CANARY_ID
                    container[field], exclusions[key] = [value], [value]
        sections["scuba_config"]["Aad"] = {ca["key"]: {"CapExclusions": exclusions}}
    # These names must also stay private when the service-plan gate is open.
    for plan in sections.get("service_plans", []):
        if isinstance(plan, dict):
            plan["DisplayName"], plan["UserPrincipalName"] = CANARY_NAME, CANARY_EMAIL
    expected = "all_clear" if role_policy else "met_policy_declared_exclusions"
    assert assess(policy, sections)["cell"] == expected
    return sections


def _scalar_paths(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _scalar_paths(item, (*path, key))
    elif isinstance(value, list) and value:
        for index, item in enumerate(value):
            yield from _scalar_paths(item, (*path, index))
    else:
        yield path, value


def _canary_cases(policy, rows):
    sections = _canary_sections(policy, rows)
    yield "linked-identifiers", sections
    violation = deepcopy(sections)
    if ".7." in policy:
        for role in violation["privileged_roles"]:
            if policy == "MS.AAD.7.4v1":
                violation["scuba_config"]["Aad"][policy]["RoleExclusions"] = {"Users": [], "Groups": []}
            elif policy == "MS.AAD.7.5v1":
                for assignment in role["Assignments"]:
                    assignment["StartDateTime"] = None
            else:
                for rule in role["Rules"]:
                    if policy == "MS.AAD.7.6v1":
                        rule["Setting"]["IsApprovalRequired"] = False
                    else:
                        rule["NotificationRecipients"] = []
        assert assess(policy, violation)["cell"] == "role_flagged"
    else:
        ca = catalogue()["policies"][policy]["params"]["ca"]
        violation["scuba_config"]["Aad"][ca["key"]]["CapExclusions"] = {}
        assert assess(policy, violation)["cell"] == "near_miss_exclusions"
    yield "violation-with-private-labels", violation
    if ".7." not in policy:
        # The clean fixture omits restriction containers; exercise their actual
        # ID/filter fields as well, through the same persistence path.
        for field, value in {
            "Platforms": {"IncludePlatforms": [CANARY_ID], "ExcludePlatforms": [CANARY_ID]},
            "Locations": {"IncludeLocations": [CANARY_ID], "ExcludeLocations": [CANARY_ID]},
            "Devices": {"DeviceFilter": {"Mode": "include", "Rule": CANARY_EMAIL}},
            "DeviceStates": {"IncludeStates": [CANARY_ID]},
            "ClientApplications": {"IncludeServicePrincipals": [CANARY_ID],
                                   "IncludeAgentIdServicePrincipals": [CANARY_ID]},
            "ServicePrincipalRiskLevels": [CANARY_EMAIL],
            "InsiderRiskLevels": [CANARY_EMAIL],
            "AgentIdRiskLevels": [CANARY_EMAIL],
        }.items():
            restricted = deepcopy(sections)
            restricted["conditional_access_policies"][0]["Conditions"][field] = value
            yield field, restricted
        for field, value in {"ApplicationFilter": {"Mode": "include", "Rule": CANARY_EMAIL},
                             "IncludeAuthenticationContextClassReferences": [CANARY_ID]}.items():
            restricted = deepcopy(sections)
            restricted["conditional_access_policies"][0]["Conditions"]["Applications"][field] = value
            yield field, restricted
    # Mutate every scalar field, including closed selectors such as GA, rule Id,
    # ServicePlanId, grant values and M365Environment. Keep identifier links intact.
    for path, value in _scalar_paths(sections):
        mutated = deepcopy(sections)
        target = mutated
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = [CANARY_EMAIL] if isinstance(value, list) else CANARY_EMAIL
        if isinstance(value, str) and value in {CANARY_ID, CANARY_NAME}:
            def relink(item):
                if isinstance(item, dict):
                    return {k: relink(v) for k, v in item.items()}
                if isinstance(item, list):
                    return [relink(v) for v in item]
                return CANARY_EMAIL if item == value else item
            mutated = relink(mutated)
        yield str(path), mutated


@pytest.mark.parametrize("policy", sorted(STAGE7_POLICIES))
def test_every_read_field_has_canaries(policy, rows_s7, caplog):
    caplog.set_level("DEBUG")
    for label, sections in _canary_cases(policy, rows_s7[policy]):
        assert CANARY_EMAIL in json.dumps(sections), label
        record = assess(policy, sections)
        assert record["cell"] != "section_not_collected", label
        detail = precheck_policy(policy, sections, list(sections), value_rules=True)
        assert detail["cell"] == record["cell"], label
        response = precheck_response(detail, {"policy_id": policy, "criticality": "Shall"}, list(sections))
        output = json.dumps([record, detail, response]) + caplog.text
        assert all(c not in output for c in (CANARY_EMAIL, CANARY_NAME, CANARY_ID)), label


@pytest.mark.parametrize("policy", sorted(STAGE7_POLICIES))
def test_canaries_never_persist_or_log(policy, rows_s7, tmp_path, monkeypatch, caplog):
    from auditex.rule_assessment import assess_run
    from auditex.scuba_projection import rule_policy_section
    from test_model_serving import fake_projection
    caplog.set_level("DEBUG")
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage7"}')
    projection = fake_projection(tmp_path, {})
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.rule_assessment.project_run", lambda *a, **kw: projection)
    for label, sections in _canary_cases(policy, rows_s7[policy]):
        projection.rule_sections = {k: v for k, v in sections.items() if k != "scuba_config"}
        projection.rule_views = {policy: {"scuba_config": sections["scuba_config"]}} if "scuba_config" in sections else {}
        for name, value in sections.items():
            assert rule_policy_section(projection, policy, name) == value
        expected = assess(policy, sections)
        result = assess_run(tmp_path, policies=[policy])
        validate_assessment(result)
        detail = result["policies"][0]["rule_precheck"]
        assert detail["class"] == "value_rule" and detail["cell"] == expected["cell"] != "section_not_collected", label
        outputs = [json.dumps(result), caplog.text, *(p.read_text() for p in tmp_path.rglob("*") if p.is_file())]
        assert all(c not in output for output in outputs for c in (CANARY_EMAIL, CANARY_NAME, CANARY_ID)), label


def test_builder_excludes_held_out_and_unknown_origins(tmp_path, rows_s7):
    spec = importlib.util.spec_from_file_location(
        "fixture_s7", Path(__file__).parents[1] / "scripts/build-value-rule-fixture-s7.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    assert builder.POLICIES == STAGE7_POLICIES
    row = rows_s7["MS.AAD.1.1v1"][0]
    def vector(kind, file, split):
        return {**row, "vector_id": kind, "origin": "v3.9.1 constructed", "source_kind": kind,
                "source_file": file, "split": split}
    rows = [vector("constructed", "constructed by v391_vectors.py", None),
            vector("pack-train", "20261030-oracle-pack-v10/train.jsonl", "train"),
            vector("pack-validation", "20261030-oracle-pack-v10/validation.jsonl", "validation"),
            vector("pack-test", "20261030-oracle-pack-v10/test.jsonl", "test")]
    rows += [vector(f"{p}-{k}", "sealed pilot", "test")
             for p in ("aad", "pbi", "ss6") for k in ("frozen", "diagnostic", "dropped")]
    source, target = tmp_path / "source.jsonl", tmp_path / "fixture.jsonl.xz"
    source.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert builder.build(source, target)["rows"] == 3
    emitted = list(_rows(target))
    assert {r["vector_id"] for r in emitted} == {"constructed", "pack-train", "pack-validation"}
    for row in emitted:
        source_row = next(r for r in rows if r["vector_id"] == row["vector_id"])
        assert row["origin"] == row["source_kind"]
        assert row["source_origin"] == source_row["origin"]
        assert all(row[k] == source_row[k] for k in ("source_file", "split"))
    before = target.read_bytes()
    for key, value in (("source_file", "unknown"), ("split", "test"), ("disagreement", "UNEXPECTED"),
                       ("gold_verdict", None), ("origin", "unknown"), ("origin", None), ("origin", []), ("source_kind", "unknown")):
        source.write_text(json.dumps({**rows[0], key: value}) + "\n")
        with pytest.raises(ValueError):
            builder.build(source, target)
        assert target.read_bytes() == before
    missing = dict(rows[0])
    del missing["origin"]
    source.write_text(json.dumps(missing) + "\n")
    with pytest.raises(ValueError):
        builder.build(source, target)
    assert target.read_bytes() == before


def test_stratified_stage7_cells_against_pinned_rego(rows_s7, tmp_path):
    from test_value_rules_oracle import OPA, SCUBA, REGO_SHA256, _outcome_v3
    if not (OPA and OPA.is_file() and SCUBA and (SCUBA / "Rego").is_dir()):
        pytest.skip("set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
    version = subprocess.run([str(OPA), "version"], capture_output=True, text=True, timeout=30)
    assert version.returncode == 0 and "Version: 1.20.2" in version.stdout.splitlines()
    rego = SCUBA / "Rego"
    assert all(sha256((rego / n).read_bytes()).hexdigest() == d for n, d in REGO_SHA256.items())
    groups = defaultdict(list)
    for policy, rows in rows_s7.items():
        for row in rows:
            if row.get("gold_source") == "opa-replay":
                groups[(policy, row["rule_cell"])].append(row)
    assert {p for p, _ in groups} == STAGE7_POLICIES
    for _, rows in sorted(groups.items()):
        row = min(rows, key=lambda r: r["vector_id"])
        path = tmp_path / "input.json"
        path.write_text(json.dumps(row["sections"]))
        proc = subprocess.run([str(OPA), "eval", "-f", "json", "-d", str(rego / "AADConfig.rego"),
                               "-d", str(rego / "Utils"), "-i", str(path), "data.aad.tests"],
                              capture_output=True, text=True, timeout=120)
        result = json.loads(proc.stdout) if proc.stdout else {"errors": [proc.stderr[:200]]}
        assert _outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        actual = assess(row["policy"], row["sections"])["verdict"]
        assert (actual == row["gold_verdict"]) is (row.get("disagreement") is None), row["vector_id"]
    print(f"stage 7 OPA: {len(groups)} cells across {len(STAGE7_POLICIES)} policies")


def _straight_roles_cover(p, sections, inventory=None):
    """Pre-optimisation reference, deliberately using list membership."""
    from azure_tenant_audit.value_rules.helpers import _lst
    roles = sections.get("privileged_roles")
    if not isinstance(roles, list):
        return "u", None
    ids = [r.get("RoleTemplateId") for r in roles if isinstance(r, dict)]
    inc = _lst(p, "Conditions", "Users", "IncludeRoles")
    if not ids or any(type(i) is not str for i in ids):
        known = [i for i in ids if type(i) is str]
        return ("f" if inc is not None and any(i not in inc for i in known) else "u"), None
    return ("u" if inc is None else "t" if all(i in inc for i in ids) else "f"), None


@pytest.mark.parametrize("roles", [None, {}, [], [None, 1], [{}], [{"RoleTemplateId": None}],
    [{"RoleTemplateId": x} for x in ("Role", "role", " Role ", "Role")],
    [{"RoleTemplateId": "known"}, {"RoleTemplateId": []}],
    [{"RoleTemplateId": "known"}, {"RoleTemplateId": {}}],
    [{"RoleTemplateId": "known"}, {"RoleTemplateId": True}],
    [{"RoleTemplateId": str(i)} for i in range(50)]])
@pytest.mark.parametrize("include", ["absent", None, [], ["known"], ["Role", "role", " Role ", "Role"],
    ["ROLE"], ["Role "], [None], [True], [[]], [{}], [str(i) for i in range(50)]])
def test_roles_cover_matches_straightforward(roles, include):
    from azure_tenant_audit.value_rules.conditional_access import _roles_cover, _role_inventory
    p = {"Conditions": {"Users": {} if include == "absent" else {"IncludeRoles": include}}}
    sections = {"privileged_roles": roles}
    expected = _straight_roles_cover(p, sections)
    assert _roles_cover(p, sections) == expected
    assert _roles_cover(p, sections, _role_inventory(sections)) == expected


def test_roles_cover_complete_records_match_straightforward(rows_s7, monkeypatch):
    from azure_tenant_audit.value_rules import conditional_access as ca
    rows = rows_s7["MS.AAD.3.6v1"]
    actual = [json.dumps(assess(row["policy"], row["sections"]), sort_keys=True) for row in rows]
    monkeypatch.setattr(ca, "_roles_cover", _straight_roles_cover)
    expected = [json.dumps(assess(row["policy"], row["sections"]), sort_keys=True) for row in rows]
    assert actual == expected


@pytest.mark.parametrize("objects", [1, 5000])
def test_role_coverage_scale(objects, rows_s7, monkeypatch):
    from azure_tenant_audit.value_rules import conditional_access as ca
    p = "MS.AAD.3.6v1"
    sections = _sample(rows_s7[p], "met_policy_clean")
    ids = [f"role-{i}" for i in range(5000)]
    sections["privileged_roles"] = [{"RoleTemplateId": i} for i in ids]
    obj = sections["conditional_access_policies"][0]
    users = obj["Conditions"]["Users"]
    users["IncludeRoles"] = ids if objects == 1 else [ids[0]]
    if objects > 1:
        # Policy cardinality independently of include-list cardinality: All users
        # covers the inventory (D93), while each object still reads roles_cover.
        users["IncludeUsers"] = ["All"]
    sections["conditional_access_policies"] = [obj] * objects
    calls = []
    original = ca._role_inventory
    def inventory(sections):
        calls.append(None)
        return original(sections)
    monkeypatch.setattr(ca, "_role_inventory", inventory)
    start = monotonic()
    record = assess(p, sections)
    elapsed = monotonic() - start
    assert record["cell"] == "met_policy_clean"
    assert len(calls) == 1
    assert elapsed < 5, elapsed
    print(f"role scale: 5000 roles x {objects} CA objects, IncludeRoles={len(users['IncludeRoles'])}: {elapsed:.3f}s")


def test_configured_exemptions_prepared_once(rows_s7, monkeypatch):
    from azure_tenant_audit.value_rules import conditional_access as ca
    p = "MS.AAD.3.2v2"
    sections = _sample(rows_s7[p], "met_policy_clean")
    obj = sections["conditional_access_policies"][0]
    obj["Conditions"]["Users"]["ExcludeUsers"] = ["user-4999"]
    sections["scuba_config"] = {"Aad": {"MS.AAD.3.2v1": {"CapExclusions": {
        "Users": [f"user-{i}" for i in range(5000)]}}}}
    sections["conditional_access_policies"] = [obj] * 5000
    calls = []
    original = ca._allowed_exemptions
    def allowed(*args):
        calls.append(args[-1])
        return original(*args)
    monkeypatch.setattr(ca, "_allowed_exemptions", allowed)
    start = monotonic()
    assert assess(p, sections)["cell"] == "met_policy_declared_exclusions"
    elapsed = monotonic() - start
    assert calls == ["Users"]
    assert elapsed < 5, elapsed
    print(f"exemption scale: 5000 configured users x 5000 CA objects: {elapsed:.3f}s")


def test_role_exclusions_scale(rows_s7):
    p = "MS.AAD.7.4v1"
    sections = _sample(rows_s7[p], "all_clear")
    sections["privileged_roles"] = [{"DisplayName": f"role-{i}", "Assignments": [
        {"EndDateTime": None, "PrincipalId": f"user-{i}"}]} for i in range(5000)]
    sections["scuba_config"] = {"Aad": {p: {"RoleExclusions": {
        "Users": [f"user-{i}" for i in range(5000)], "Groups": []}}}}
    start = monotonic()
    assert assess(p, sections)["cell"] == "all_clear"
    elapsed = monotonic() - start
    assert elapsed < 5, elapsed
    print(f"role exclusion scale: 5000 exclusions x 5000 roles: {elapsed:.3f}s")
