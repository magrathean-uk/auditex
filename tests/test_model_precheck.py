from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path

import jsonschema
import pytest

from auditex.cli import main
from support import RunBundleBuilder, make_contract_valid
from auditex.rule_assessment import precheck_case
from auditex.rule_assessment import assess_run
from auditex.rule_assessment import build_case, canonical
from azure_tenant_audit.scuba_assessment import validate_assessment
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import check_fields, check_gate, field_name, policy_rule, precheck_policy, rule_catalogue

ROOT = Path(__file__).resolve().parents[1]
SP = "MS.SHAREPOINT.3.1v1"


@pytest.mark.parametrize("pid,closed", [(SP, {0, 1, 3}), ("MS.SHAREPOINT.3.2v1", {0, 1, 3}),
                                      ("MS.SHAREPOINT.3.3v2", {0}), ("MS.SHAREPOINT.1.3v1", {0, 3})])
@pytest.mark.parametrize("value", [0, 1, 2, 3, 0.0, 3.0])
@pytest.mark.parametrize("wrapped", [False, True])
def test_every_sharepoint_gate_value(pid, closed, value, wrapped):
    observed = {"SharingCapability": value, "SharingCapability_name": "untrusted annotation"}
    projection = {"SPO_tenant": [observed] if wrapped else observed}
    before = deepcopy(projection)
    result = precheck_policy(pid, projection, ["SPO_tenant"])
    if value in closed:
        assert result["class"] == "closed_gate" and result["value"] == int(value)
    else:
        assert result is None
    assert projection == before


@pytest.mark.parametrize("value", [-1, 4, 1.5, True, False, "0", None, {}, [], float("inf"), float("nan")])
def test_unusable_gate_values_never_close(value):
    result = check_gate(SP, {"SPO_tenant": [{"SharingCapability": value}]})
    assert result["class"] == "absent_section" and result["value"] is None


@pytest.mark.parametrize("observed", [{}, [], None, [{}], [{"SharingCapability": 0}, {"SharingCapability": 0}]])
def test_missing_or_ambiguous_gate_is_unknown(observed):
    result = precheck_case(build_case(SP, {"SPO_tenant": observed}, "unused"))
    assert result["claims"][0]["status"] == "unknown"
    assert result["rule_precheck"]["field"] == "SharingCapability"
    assert result["limitations"] == ["required_evidence_section_not_collected",
                                     "required_evidence_section_not_collected:SPO_tenant.SharingCapability"]


def test_rule_evidence_ids_follow_case_order_when_rule_sections_differ(tmp_path, monkeypatch):
    from azure_tenant_audit import value_rules
    from azure_tenant_audit.value_rules import catalogue as value_catalogue
    policy_id = "MS.POWERBI.1.1v1"
    data = deepcopy(value_catalogue.catalogue())
    row = data["policies"][policy_id]
    row["sections"] = list(reversed(row["sections"]))
    for entry in row["cells"].values():
        entry["cited"] = [name for name in row["sections"] if name in entry["cited"]]
    text = "Data unavailable: required evidence section(s) not collected: " + ", ".join(row["sections"]) + "."
    row["cells"]["section_not_collected"]["reason_texts"] = [text]
    monkeypatch.setattr(value_catalogue, "catalogue", lambda: data)
    failure = data["shared_reasons"]["rule_evaluation_failed"]
    # The rule fails, so the product-fault answer is built from the patched row and must still pass the validator.
    monkeypatch.setattr(value_rules, "assess", lambda *args: (_ for _ in ()).throw(RuntimeError("boom")))
    case = build_case(policy_id, {}, "unused")
    record = precheck_case(case, value_rules=True, rule_projection={})
    case_sections = [item["section"] for item in case["evidence"][1:]]
    ids = {name: f"e{index}" for index, name in enumerate(case_sections, 1)}
    assert record["claims"][0]["evidence_ids"] == ["e0"] + [ids[name] for name in row["sections"] if name in ids]
    # End to end: the served envelope, built from the same patched row, validates.
    (tmp_path / "run-manifest.json").write_text('{"run_id":"precheck-test"}')
    from test_model_serving import fake_projection
    monkeypatch.setattr("auditex.rule_assessment.project_run", lambda root, **kw: fake_projection(root, {}))
    result = assess_run(tmp_path, policies=[policy_id])
    served = result["policies"][0]
    assert served["reason"] == "rule_precheck" and served["rule_precheck"]["cell"] is None
    assert served["rule_precheck"]["reason_code"] == "rule_evaluation_failed"
    assert served["rule_precheck"]["reason_text"] == failure["reason_text"]
    assert served["rule_precheck"]["section"] == row["sections"]
    assert served["limitations"] == [] and served["recommendations"] == ["report_product_fault"]
    validate_assessment(result)


def test_rule_exception_is_a_constant_not_assessed_answer(monkeypatch, capsys, caplog):
    from azure_tenant_audit import value_rules
    secret = "canary.person@example.invalid"
    def broken(*args):
        raise RuntimeError(secret)
    monkeypatch.setattr(value_rules, "assess", broken)
    policy_id = "MS.POWERBI.1.1v1"
    case = build_case(policy_id, {}, "unused")
    with caplog.at_level("DEBUG"):
        record = precheck_case(case, value_rules=True, rule_projection={})
    detail = record["rule_precheck"]
    assert (detail["cell"], detail["reason_code"], detail["reason_text"]) == (
        None, "rule_evaluation_failed",
        "Not assessed: Auditex could not evaluate this policy on the collected evidence. "
        "This is a product fault, not a tenant setting.")
    assert record["claims"][0] == {"id": "requirement_met", "status": "unknown", "value": None,
                                   "evidence_ids": ["e0", "e1", "e2", "e3"]}
    assert record["limitations"] == [] and record["recommendations"] == ["report_product_fault"]
    assert secret not in json.dumps(record) + str(capsys.readouterr())
    # One line per failure: the rule id and the class name, never the message, evidence or repr.
    lines = [item for item in caplog.records if item.name == "auditex.rule_assessment"]
    assert len(lines) == 1 and lines[0].exc_info is None
    text = lines[0].getMessage()
    assert "MS.POWERBI.1.1v1" in text
    assert "RuntimeError" in text and secret not in text and secret not in caplog.text
    assert secret not in repr(lines[0].__dict__)


def test_rule_memory_error_is_not_swallowed(monkeypatch, caplog):
    from azure_tenant_audit import value_rules
    def exhausted(*args):
        raise MemoryError
    monkeypatch.setattr(value_rules, "assess", exhausted)
    case = build_case("MS.POWERBI.1.1v1", {}, "unused")
    with pytest.raises(MemoryError):
        precheck_case(case, value_rules=True, rule_projection={})
    assert not caplog.records


def test_every_rule_catalogue_has_the_full_section_fallback_text():
    from azure_tenant_audit.value_rules.catalogue import catalogue
    for policy_id, row in catalogue()["policies"].items():
        text = ("Data unavailable: required evidence section(s) not collected: "
                + ", ".join(row["sections"]) + ".")
        cell = row["cells"].get("section_not_collected")
        assert cell is not None, policy_id
        assert text in cell["reason_texts"], policy_id


@pytest.mark.parametrize("pid", ["MS.TEAMS.2.2v2", "MS.TEAMS.2.3v2", "MS.TEAMS.4.1v1"])
@pytest.mark.parametrize("value,expected", [("gcc", "closed_gate"), ("gcchigh", "closed_gate"),
    ("dod", "closed_gate"), ("commercial", None), ("GCC", "absent_section"),
    ("other", "absent_section"), (None, "absent_section"), (0, "absent_section")])
def test_teams_environment_gates(pid, value, expected):
    result = check_gate(pid, {"scuba_config": {"M365Environment": value}})
    assert (result["class"] if result else None) == expected


@pytest.mark.parametrize("state,expected", [("disabled", "closed_gate"), ("enabled", None),
                                          ("unknown", "absent_section"), (None, "absent_section")])
def test_authenticator_selects_the_named_method(state, expected):
    observed = [{"authentication_method_feature_settings": [
        {"Id": "Sms", "State": "disabled"}, {"Id": "MicrosoftAuthenticator", "State": state}]}]
    result = check_gate("MS.AAD.3.3v2", {"authentication_method": observed})
    assert (result["class"] if result else None) == expected
    observed[0]["authentication_method_feature_settings"].append({"Id": "MicrosoftAuthenticator", "State": "disabled"})
    assert check_gate("MS.AAD.3.3v2", {"authentication_method": observed})["class"] == "absent_section"


@pytest.mark.parametrize("projection", [{}, {"SPO_tenant": NOT_COLLECTED},
    {"SPO_tenant": {**NOT_COLLECTED, "diagnostic": "unavailable"}},
    {"SPO_tenant": {**NOT_COLLECTED, "SharingCapability": 0}}, {"unrelated": {}}])
def test_marker_missing_key_and_strict_empty_projection(projection):
    result = precheck_policy(SP, projection, ["SPO_tenant"])
    assert result == {"class": "absent_section", "rule_id": "required_sections_present",
                      "section": ["SPO_tenant"], "field": None, "value": None}


@pytest.mark.parametrize("missing", [True, False])
def test_closed_gate_takes_priority_over_missing_or_marked_dependency(missing):
    pid = "MS.TEAMS.2.2v2"
    projection = {"scuba_config": {"M365Environment": "gcc"}}
    if not missing:
        projection["federation_configuration"] = NOT_COLLECTED
    case = build_case(pid, projection, "unused")
    result = precheck_case(case)
    assert result["rule_precheck"]["class"] == "closed_gate"
    assert result["claims"][0] == {"id": "requirement_met", "status": "inferred", "value": True,
                                   "evidence_ids": ["e0", "e1", "e2"]}
    assert result["limitations"] == ["policy_not_applicable"]
    assert result["recommendations"] == []


@pytest.mark.parametrize("projection,suffix", [
    ({"federation_configuration": {}}, "scuba_config"),
    ({"federation_configuration": {}, "scuba_config": {}}, "scuba_config.M365Environment"),
    ({"federation_configuration": {}, "scuba_config": {"M365Environment": "invalid"}}, "scuba_config.M365Environment"),
    ({"scuba_config": {"M365Environment": "commercial"}}, "federation_configuration"),
])
def test_gate_absence_or_unusable_field_and_open_gate_with_missing_dependency_are_unknown(projection, suffix):
    result = precheck_case(build_case("MS.TEAMS.2.2v2", projection, "unused"))
    assert result["rule_precheck"]["class"] == "absent_section"
    assert (result["claims"][0]["status"], result["claims"][0]["value"]) == ("unknown", None)
    assert result["limitations"] == ["required_evidence_section_not_collected",
                                     "required_evidence_section_not_collected:" + suffix]
    assert result["recommendations"] == ["collect_missing_evidence_section"]


def test_ungated_missing_sections_are_named_and_null_retains_default():
    detail = precheck_policy("MS.AAD.1.1v1", {}, ["conditional_access_policies", "scuba_config"])
    assert detail["class"] == "absent_section"
    assert detail["section"] == ["conditional_access_policies", "scuba_config"]
    record = precheck_case(build_case("MS.AAD.1.1v1", {}, "unused"))
    assert (record["claims"][0]["status"], record["claims"][0]["value"]) == ("unknown", None)
    # Explicit null is a collected default, not an absent section for ordinary policies.
    assert precheck_policy("MS.AAD.7.3v1", {"privileged_users": None}, ["privileged_users"]) is None


PBI = "MS.POWERBI.7.1v1"
PBI_SECTIONS = {"powerbi_access_denied_reason": None, "powerbi_license_found": True}


def test_field_rules_are_well_formed_and_leave_gate_fields_to_the_gate():
    rules = rule_catalogue()["field_rules"]
    assert len({rule["rule_id"] for rule in rules}) == len(rules) == 18
    gates = {(rule["policy_id"], rule["section"], field_name(rule)) for rule in rule_catalogue()["rules"]}
    for rule in rules:
        assert rule["path"] and rule["source"] and rule["complete"] is True
        assert (rule["policy_id"], rule["section"], field_name(rule)) not in gates
        assert all(type(value) in (bool, type(None)) for value in rule["requires"].values())


@pytest.mark.parametrize("pid,field", [(SP, "RequireAnonymousLinksExpireInDays"),
    ("MS.SHAREPOINT.3.2v1", "FolderAnonymousLinkType"), ("MS.SHAREPOINT.3.3v2", "EmailAttestationRequired"),
    ("MS.SHAREPOINT.1.1v1", "SharingCapability")])
@pytest.mark.parametrize("wrapped", [False, True])
def test_safe_sharepoint_field_absent_is_unknown_only_when_enabled(pid, field, wrapped):
    observed = {"SharingCapability": 2, "RequireAnonymousLinksExpireInDays": 30, "FileAnonymousLinkType": 1,
                "FolderAnonymousLinkType": 1, "EmailAttestationRequired": True, "EmailAttestationReAuthDays": 30}
    del observed[field]
    case = build_case(pid, {"SPO_tenant": [observed] if wrapped else observed}, "unused")
    assert precheck_case(case) is None
    record = precheck_case(case, absent_fields=True)
    assert record["rule_precheck"] == {"class": "absent_field", "rule_id": f"{pid}.{field}_absent",
                                       "section": ["SPO_tenant"], "field": field, "value": None}
    assert record["claims"][0] == {"id": "requirement_met", "status": "unknown", "value": None,
                                   "evidence_ids": ["e0", "e1"]}
    assert record["limitations"] == ["required_evidence_section_not_collected",
                                     f"required_evidence_section_not_collected:SPO_tenant.{field}"]
    assert record["recommendations"] == ["collect_missing_evidence_section"]


@pytest.mark.parametrize("settings", [[], [{"settingName": "PublishToWeb", "enabled": False}],
    [{"title": "Allow users to apply sensitivity labels for content", "enabled": True}],
    [{"settingName": "", "enabled": True}]])
def test_powerbi_missing_policy_setting_is_unknown(settings):
    case = build_case(PBI, {**PBI_SECTIONS, "powerbi_tenant_settings": settings}, "unused")
    record = precheck_case(case, absent_fields=True, named_limitations=False)
    assert record["rule_precheck"]["class"] == "absent_field"
    assert record["rule_precheck"]["field"] == "[settingName=EimInformationProtectionEdit]"
    assert record["claims"][0]["evidence_ids"] == ["e0", "e3"]


@pytest.mark.parametrize("pid,projection", [
    # Unregistered tuples: no v10 evidence that absence is always unknown.
    ("MS.EXO.7.1v1", {"transport_rule": [{"Mode": "Enforce"}]}),
    # The present-but-null field is a collected default.
    (SP, {"SPO_tenant": [{"SharingCapability": 2, "RequireAnonymousLinksExpireInDays": None}]}),
    # Several tenant objects or duplicate setting entries are ambiguous.
    ("MS.SHAREPOINT.1.2v1", {"SPO_tenant": [{"SharingCapability": 2}, {"SharingCapability": 2}]}),
    (PBI, {**PBI_SECTIONS, "powerbi_tenant_settings": [{"settingName": "EimInformationProtectionEdit", "enabled": True}] * 2}),
    # Licence and access blockers are cited with other evidence by the oracle.
    (PBI, {**PBI_SECTIONS, "powerbi_license_found": False, "powerbi_tenant_settings": []}),
    (PBI, {**PBI_SECTIONS, "powerbi_access_denied_reason": "HTTP 403", "powerbi_tenant_settings": []}),
    (PBI, {**PBI_SECTIONS, "powerbi_tenant_settings": None}),
])
def test_unregistered_null_ambiguous_or_blocked_fields_are_left_to_the_model(pid, projection):
    assert check_fields(pid, projection) is None
    assert precheck_case(build_case(pid, projection, "unused"), absent_fields=True) is None


@pytest.mark.parametrize("projection,expected", [
    ({"SPO_tenant": NOT_COLLECTED}, ("absent_section", "required_sections_present")),
    ({"SPO_tenant": [{"SharingCapability": 0}]}, ("closed_gate", "MS.SHAREPOINT.3.1v1.sharing_closed")),
    ({"SPO_tenant": [{}]}, ("absent_section", "MS.SHAREPOINT.3.1v1.sharing_closed")),
    ({"SPO_tenant": []}, ("absent_section", "MS.SHAREPOINT.3.1v1.sharing_closed")),
])
def test_gate_and_section_absence_take_precedence_over_absent_field(projection, expected):
    detail = precheck_case(build_case(SP, projection, "unused"), absent_fields=True)["rule_precheck"]
    assert (detail["class"], detail["rule_id"]) == expected
    pbi = {"powerbi_access_denied_reason": None, "powerbi_license_found": NOT_COLLECTED, "powerbi_tenant_settings": []}
    assert precheck_case(build_case(PBI, pbi, "unused"), absent_fields=True)["rule_precheck"]["class"] == "absent_section"


def _frozen_v10_file(name):
    pack = os.environ.get("AUDITEX_TEST_PRECHECK_PACK")
    if not pack:
        pytest.skip("AUDITEX_TEST_PRECHECK_PACK unset; opt in to frozen v10 pack tests")
    path = Path(pack) / name
    if not path.is_file():
        pytest.skip(f"frozen v10 pack file not present: {path}")
    return path


@pytest.mark.parametrize("name", ["test.jsonl", "approved-cases.jsonl"])
def test_absent_field_rows_are_unknown_in_every_frozen_v10_row(name):
    path = _frozen_v10_file(name)
    fired = 0
    for line in path.read_text().splitlines():
        row = json.loads(line)
        case = json.loads(next(m["content"] for m in row["messages"] if m["role"] == "user"))
        if "policy_id" not in case:
            continue
        record = precheck_case(case, absent_fields=True, named_limitations=False)
        if record is None or record["rule_precheck"]["class"] != "absent_field":
            continue
        fired += 1
        assert row["expected"]["claims"][0]["status"] == "unknown", row["id"]
        assert {key: record[key] for key in ("claims", "limitations", "recommendations")} == {
            key: row["expected"][key] for key in ("claims", "limitations", "recommendations")}, row["id"]
    # P6 closes SP 1.3 at SharingCapability=3 before checking fields. Approved
    # rows ending 49ff76adfe and 9bf1a53d64 lack SharingDomainRestrictionMode:
    # both move absent_field -> closed_gate (69 -> 67); test.jsonl stays at 5.
    assert fired == (5 if name == "test.jsonl" else 67)


def run_assessment(tmp_path, monkeypatch, projection, **kwargs):
    # Exercise the legacy precheck contract explicitly; no environment flag changes production routing.
    from auditex.rule_assessment import precheck_case
    monkeypatch.setattr("auditex.rule_assessment.precheck_case", lambda case, **kw: precheck_case(
        case, **{**kw, "value_rules": False}))
    (tmp_path / "run-manifest.json").write_text('{"run_id":"precheck-test"}')
    from test_model_serving import fake_projection
    monkeypatch.setattr("auditex.rule_assessment.project_run", lambda root, **kw: fake_projection(root, projection))
    return assess_run(tmp_path, policies=[SP], **kwargs)


@pytest.mark.parametrize("projection", [{"SPO_tenant": [{"SharingCapability": 0}]},
                                       {"SPO_tenant": NOT_COLLECTED}, {"SPO_tenant": [{}]}, {"unrelated": 1}])
def test_rule_rows_are_valid_and_never_call_model(tmp_path, monkeypatch, projection):
    result = run_assessment(tmp_path, monkeypatch, projection)
    row = result["policies"][0]
    assert row["reason"] == "rule_precheck" and row["attempts"] == 0
    assert row["prompt_sha256"] is row["response_sha256"] is None
    assert "model_shadow" not in row
    assert result["totals"]["rule_answered"] == 1
    assert result["totals"]["answered"] + result["totals"]["unknown"] == 1
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / "schemas/model_assessment.schema.json").read_text()))


@pytest.mark.parametrize("mutation", ["attempts", "prompt", "response", "reason", "class", "value", "section", "field",
                                      "rule_id", "limitations", "recommendations", "claims", "totals", "shadow"])
def test_rule_contract_rejects_tampering(tmp_path, monkeypatch, mutation):
    result = run_assessment(tmp_path, monkeypatch, {"SPO_tenant": [{"SharingCapability": 0}]})
    row = result["policies"][0]
    if mutation in {"attempts", "reason", "limitations", "recommendations", "claims"}:
        row[mutation] = {"attempts": 1, "reason": None, "limitations": [],
                         "recommendations": ["review_policy_against_baseline_text"], "claims": []}[mutation]
    elif mutation in {"prompt", "response"}:
        row[mutation + "_sha256"] = "a" * 64
    elif mutation == "totals":
        result["totals"]["rule_answered"] = 0
    elif mutation == "shadow":
        row["model_shadow"] = deepcopy(row)
    else:
        row["rule_precheck"][mutation] = {"class": "absent_section", "value": 2, "section": ["invented"],
                                          "field": "invented", "rule_id": "invented"}[mutation]
    with pytest.raises(ValueError):
        validate_assessment(result)


# --- empty required list (`empty_required_list`) ------------------------------------------------------------------------

CA_RULES = ["MS.AAD.1.1v1", "MS.AAD.2.1v1", "MS.AAD.2.3v1", "MS.AAD.3.1v1", "MS.AAD.3.2v2", "MS.AAD.3.6v1",
            "MS.AAD.3.7v1", "MS.AAD.3.8v1", "MS.AAD.3.9v1", "MS.AAD.9.1v1"]


def empty_ca(pid, **sections):
    """Every input of the policy collected, the Conditional Access list empty."""
    from auditex.rule_assessment import policy_catalogue
    projection = {section: [] for section in policy_catalogue()["policies"][pid]["sections"]}
    projection["scuba_config"] = {"CapExclusions": {}, "M365Environment": "commercial"}
    return {**projection, **sections}


def test_list_rules_are_well_formed():
    rules = rule_catalogue()["list_rules"]
    assert [rule["policy_id"] for rule in rules] == CA_RULES
    assert len({rule["rule_id"] for rule in rules}) == len(rules)
    for rule in rules:
        assert rule["section"] == "conditional_access_policies" and rule["source"] and rule["complete"] is True
        assert rule["rule_id"] == rule["policy_id"] + ".conditional_access_policies_empty"
        assert all(c["section"] and c["path"] and c["values"] for c in rule["unless"])
    # MS.AAD.3.3v2 can be met by the Authenticator configuration alone; it is not registered.
    assert "MS.AAD.3.3v2" not in {rule["policy_id"] for rule in rules}


@pytest.mark.parametrize("pid", CA_RULES)
def test_empty_conditional_access_list_is_not_met_only_when_enabled(pid):
    case = build_case(pid, empty_ca(pid), "unused")
    assert precheck_case(case, absent_fields=True) is None
    record = precheck_case(case, absent_fields=True, empty_lists=True)
    assert record["rule_precheck"] == {"class": "empty_required_list", "rule_id": f"{pid}.conditional_access_policies_empty",
                                       "section": ["conditional_access_policies"], "field": None, "value": None}
    sections = len(case["evidence"]) - 1
    assert record["claims"][0] == {"id": "requirement_met", "status": "confirmed", "value": False,
                                   "evidence_ids": ["e0", *(f"e{i + 1}" for i in range(sections))]}
    assert record["limitations"] == []
    assert record["recommendations"] == ["review_policy_against_baseline_text"]
    assert precheck_case(case, empty_lists=True, named_limitations=False)["limitations"] == []


@pytest.mark.parametrize("pid,projection", [
    # Unregistered: an empty list can be met through the Authenticator configuration.
    ("MS.AAD.3.3v2", {"authentication_method": [{"authentication_method_feature_settings": [
        {"Id": "MicrosoftAuthenticator", "State": "enabled"}]}], "conditional_access_policies": [], "scuba_config": {}}),
    # Unregistered section of a registered policy.
    ("MS.AAD.2.1v1", {"conditional_access_policies": [{"State": "enabled"}], "scuba_config": {}, "service_plans": []}),
    # Not exactly an empty list: entries, null, an object.
    ("MS.AAD.1.1v1", {"conditional_access_policies": [{}], "scuba_config": {}}),
    ("MS.AAD.1.1v1", {"conditional_access_policies": None, "scuba_config": {}}),
    ("MS.AAD.1.1v1", {"conditional_access_policies": {}, "scuba_config": {}}),
])
def test_unregistered_non_empty_or_possibly_not_applicable_lists_are_left_to_the_model(pid, projection):
    assert precheck_case(build_case(pid, projection, "unused"), absent_fields=True, empty_lists=True) is None


@pytest.mark.parametrize("environment", ["commercial", "gcc"])
def test_ai_agents_rule_applies_outside_the_excluded_environments(environment):
    projection = empty_ca("MS.AAD.9.1v1", scuba_config={"M365Environment": environment})
    record = precheck_case(build_case("MS.AAD.9.1v1", projection, "unused"), empty_lists=True)
    assert record["rule_precheck"]["class"] == "empty_required_list"
    del projection["scuba_config"]["M365Environment"]
    assert precheck_case(build_case("MS.AAD.9.1v1", projection, "unused"), empty_lists=True)["rule_precheck"]["class"] == "absent_section"


# stage 6: P6 closes the two government environments and fails closed on an unreadable gate.
@pytest.mark.parametrize("config,expected", [
    ({"M365Environment": "gcchigh"}, "closed_gate"), ({"M365Environment": "dod"}, "closed_gate"),
    (None, "absent_section"), ([], "absent_section"), ({}, "absent_section"),
    ({"M365Environment": None}, "absent_section"), ({"M365Environment": "GCCHIGH"}, "absent_section"),
    ({"M365Environment": 0}, "absent_section"),
])
def test_ai_agents_applicability_gate_precedes_empty_lists(config, expected):
    projection = empty_ca("MS.AAD.9.1v1", scuba_config=config)
    record = precheck_case(build_case("MS.AAD.9.1v1", projection, "unused"), empty_lists=True)
    assert record["rule_precheck"]["class"] == expected


@pytest.mark.parametrize("restriction_mode", [None, 0])
def test_p6_sp13_slider3_reclassifies_field_and_model_rows(monkeypatch, restriction_mode):
    """Synthetic witnesses for both SP transitions in the frozen-pack reconciliation."""
    pid = "MS.SHAREPOINT.1.3v1"
    spo = {"SharingCapability": 3}
    if restriction_mode is not None:
        spo["SharingDomainRestrictionMode"] = restriction_mode
    case = build_case(pid, {"SPO_tenant": [spo]}, "unused")
    legacy = deepcopy(rule_catalogue())
    next(r for r in legacy["rules"] if r["policy_id"] == pid)["closed_values"] = [0]
    with monkeypatch.context() as before_p6:
        before_p6.setattr("azure_tenant_audit.scuba_precheck.rule_catalogue", lambda: legacy)
        before = precheck_case(case, absent_fields=True, empty_lists=True)
    if restriction_mode is None:
        assert before["rule_precheck"]["class"] == "absent_field"
        assert before["rule_precheck"]["field"] == "SharingDomainRestrictionMode"
    else:
        assert before is None  # A collected field used to leave the row to the model.
    after = precheck_case(case, absent_fields=True, empty_lists=True)
    assert after["rule_precheck"]["class"] == "closed_gate"
    assert after["limitations"] == ["policy_not_applicable"]


@pytest.mark.parametrize("environment,ca,missing_plans,before_class,after_class", [
    (None, [], False, "empty_required_list", "absent_section"),
    (None, [{"State": "enabled"}], False, None, "absent_section"),
    ("gcchigh", [{"State": "enabled"}], False, None, "closed_gate"),
    ("dod", [{"State": "enabled"}], False, None, "closed_gate"),
    ("gcchigh", [], True, "absent_section", "closed_gate"),
    ("dod", [], True, "absent_section", "closed_gate"),
])
def test_p6_aad91_reclassifies_unreadable_and_closed_environments(
        monkeypatch, environment, ca, missing_plans, before_class, after_class):
    """Synthetic witnesses for every AAD transition, including the empty-list loss."""
    pid = "MS.AAD.9.1v1"
    projection = empty_ca(pid, scuba_config={"M365Environment": environment},
                          conditional_access_policies=ca)
    if missing_plans:
        del projection["service_plans"]
    case = build_case(pid, projection, "unused")
    legacy = deepcopy(rule_catalogue())
    legacy["rules"] = [r for r in legacy["rules"] if r["policy_id"] != pid]
    with monkeypatch.context() as before_p6:
        before_p6.setattr("azure_tenant_audit.scuba_precheck.rule_catalogue", lambda: legacy)
        before = precheck_case(case, absent_fields=True, empty_lists=True)
    assert (before["rule_precheck"]["class"] if before else None) == before_class
    after = precheck_case(case, absent_fields=True, empty_lists=True)
    assert after["rule_precheck"]["class"] == after_class
    assert after["rule_precheck"]["field"] == "M365Environment"
    assert after["claims"][0]["status"] == ("unknown" if after_class == "absent_section" else "inferred")


@pytest.mark.parametrize("projection,expected", [
    ({"conditional_access_policies": NOT_COLLECTED, "scuba_config": {}}, ("absent_section", "required_sections_present")),
    ({"conditional_access_policies": []}, ("absent_section", "required_sections_present")),
    ({"conditional_access_policies": [], "scuba_config": NOT_COLLECTED}, ("absent_section", "required_sections_present")),
])
def test_section_absence_takes_precedence_over_empty_list(projection, expected):
    detail = precheck_case(build_case("MS.AAD.1.1v1", projection, "unused"), absent_fields=True,
                           empty_lists=True)["rule_precheck"]
    assert (detail["class"], detail["rule_id"]) == expected


def test_gate_and_absent_field_take_precedence_over_empty_list(monkeypatch):
    """Registered list rules never share a policy with a gate or a field rule today; pin the order regardless."""
    import azure_tenant_audit.scuba_precheck as engine
    catalogue = rule_catalogue()
    extra = [{"rule_id": f"{pid}.test_empty", "policy_id": pid, "section": section, "unless": [], "source": "test",
              "complete": True} for pid, section in ((SP, "SPO_tenant"), (PBI, "powerbi_tenant_settings"),
                                                     ("MS.AAD.3.3v2", "conditional_access_policies"))]
    monkeypatch.setattr(engine, "rule_catalogue", lambda: {**catalogue, "list_rules": catalogue["list_rules"] + extra})
    assert precheck_policy(SP, {"SPO_tenant": []}, ["SPO_tenant"], absent_fields=True, empty_lists=True)["class"] == \
        "absent_section"  # gate input missing
    assert precheck_policy(PBI, {**PBI_SECTIONS, "powerbi_tenant_settings": []}, list(PBI_SECTIONS) + [
        "powerbi_tenant_settings"], absent_fields=True, empty_lists=True)["class"] == "absent_field"
    disabled = [{"authentication_method_feature_settings": [{"Id": "MicrosoftAuthenticator", "State": "disabled"}]}]
    projection = {"authentication_method": disabled, "conditional_access_policies": [], "scuba_config": {}}
    assert precheck_policy("MS.AAD.3.3v2", projection, list(projection), empty_lists=True)["class"] == "closed_gate"
    projection["authentication_method"] = [{"authentication_method_feature_settings": [
        {"Id": "MicrosoftAuthenticator", "State": "enabled"}]}]
    assert precheck_policy("MS.AAD.3.3v2", projection, list(projection), empty_lists=True)["class"] == \
        "empty_required_list"
    assert precheck_policy("MS.AAD.3.3v2", projection, list(projection)) is None


@pytest.mark.parametrize("name", ["test.jsonl", "approved-cases.jsonl"])
def test_empty_list_rows_are_not_met_in_every_frozen_v10_row(name):
    path = _frozen_v10_file(name)
    fired = 0
    for line in path.read_text().splitlines():
        row = json.loads(line)
        case = json.loads(next(m["content"] for m in row["messages"] if m["role"] == "user"))
        if "policy_id" not in case:
            continue
        record = precheck_case(case, absent_fields=True, empty_lists=True, named_limitations=False)
        if record is None or record["rule_precheck"]["class"] != "empty_required_list":
            continue
        fired += 1
        assert (row["expected"]["claims"][0]["status"], row["expected"]["claims"][0]["value"]) == ("confirmed", False), row["id"]
        assert {key: record[key] for key in ("claims", "limitations", "recommendations")} == {
            key: row["expected"][key] for key in ("claims", "limitations", "recommendations")}, row["id"]
    # P6 requires a usable AAD 9.1 M365Environment before evaluating the CA list.
    # One AAD 9.1 row occurs in both files with a null
    # environment and CA=[]: empty_required_list -> absent_section, so 1 -> 0
    # in test.jsonl and 7 -> 6 in approved-cases.jsonl. Other list rows stay put.
    assert fired == (0 if name == "test.jsonl" else 6)


def test_empty_list_rule_is_served_and_validated(tmp_path, monkeypatch):
    from test_model_serving import fake_projection
    pid = "MS.AAD.1.1v1"
    # AAD 1.1 has a value rule (stage 7), which answers first; this is the legacy empty-list class kept for rollback.
    monkeypatch.setenv("AUDITEX_DISABLE_VALUE_RULES", "1")
    (tmp_path / "run-manifest.json").write_text('{"run_id":"precheck-test"}')
    def projected(root, **kw):
        projection = fake_projection(root, {"conditional_access_policies": [],
                                            "scuba_config": {"CapExclusions": {}}})
        projection.views[pid] = {"scuba_config": {"CapExclusions": {}}}
        return projection
    monkeypatch.setattr("auditex.rule_assessment.project_run", projected)
    from auditex.rule_assessment import precheck_case
    monkeypatch.setattr("auditex.rule_assessment.precheck_case", lambda case, **kw: precheck_case(
        case, **{**kw, "value_rules": False}))
    result = assess_run(tmp_path, policies=[pid])
    row = result["policies"][0]
    assert row["reason"] == "rule_precheck" and row["rule_precheck"]["class"] == "empty_required_list"
    assert (row["claims"][0]["status"], row["claims"][0]["value"]) == ("confirmed", False)
    assert row["comparison"]["model_status"] == "fail"
    assert result["totals"]["rule_answered"] == result["totals"]["answered"] == 1
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / "schemas/model_assessment.schema.json").read_text()))
    for key, value in (("class", "closed_gate"), ("class", "absent_field"), ("field", "conditional_access_policies"),
                       ("value", 0), ("section", ["scuba_config"]),
                       ("rule_id", "MS.AAD.3.1v1.conditional_access_policies_empty")):
        tampered = deepcopy(result)
        tampered["policies"][0]["rule_precheck"][key] = value
        with pytest.raises(ValueError):
            validate_assessment(tampered)
    tampered = deepcopy(result)
    tampered["policies"][0]["claims"][0]["value"] = True
    tampered["policies"][0]["comparison"]["model_status"] = "pass"
    with pytest.raises(ValueError):
        validate_assessment(tampered)


@pytest.mark.parametrize("rule_projection", [None, {}])
def test_rule_failure_on_case_evidence_and_rule_view(monkeypatch, caplog, rule_projection):
    """Both value-rule inputs (the serving rule view and the case evidence) answer a raising rule with the catalogued
    product-fault reason; nothing of the exception reaches the record or the log."""
    from azure_tenant_audit import value_rules
    secret = "Failure Canary DisplayName"
    def broken(policy_id, sections):
        raise KeyError(secret)
    monkeypatch.setattr(value_rules, "assess", broken)
    case = build_case("MS.TEAMS.2.2v2", {}, "unused")
    with caplog.at_level("DEBUG"):
        record = precheck_case(case, value_rules=True, rule_projection=rule_projection)
    assert record["rule_precheck"]["cell"] is None and record["rule_precheck"]["reason_code"] == "rule_evaluation_failed"
    assert record["rule_precheck"]["section"] == ["federation_configuration", "scuba_config"]
    assert record["recommendations"] == ["report_product_fault"] and record["limitations"] == []
    assert secret not in json.dumps(record) and secret not in caplog.text
    assert "MS.TEAMS.2.2v2.two_flag" in caplog.text and "KeyError" in caplog.text
