from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import runpy

import jsonschema
import pytest

from auditex.cli import main
from auditex.model_precheck import evaluate_precheck, precheck_case
from auditex.model_serving import ModelClient, ModelConfig, assess_run, build_case, canonical, messages_for
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import check_gate, policy_rule, precheck_policy, rule_catalogue

ROOT = Path(__file__).resolve().parents[1]
SP = "MS.SHAREPOINT.3.1v1"


@pytest.mark.parametrize("pid,closed", [(SP, {0, 1, 3}), ("MS.SHAREPOINT.3.2v1", {0, 1, 3}),
                                      ("MS.SHAREPOINT.3.3v2", {0}), ("MS.SHAREPOINT.1.3v1", {0})])
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


def run_assessment(tmp_path, monkeypatch, projection, **kwargs):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"precheck-test"}')
    from test_model_serving import fake_projection
    monkeypatch.setattr("auditex.model_serving.project_run", lambda root, **kw: fake_projection(root, projection))
    return assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=[SP], **kwargs)


@pytest.mark.parametrize("projection", [{"SPO_tenant": [{"SharingCapability": 0}]},
                                       {"SPO_tenant": NOT_COLLECTED}, {"SPO_tenant": [{}]}, {"unrelated": 1}])
def test_rule_rows_are_valid_and_never_call_model(tmp_path, monkeypatch, projection):
    monkeypatch.setattr(ModelClient, "assess", lambda *a: pytest.fail("Rule-answered row called the model"))
    result = run_assessment(tmp_path, monkeypatch, projection)
    row = result["policies"][0]
    assert row["reason"] == "rule_precheck" and row["attempts"] == 0
    assert row["prompt_sha256"] is row["response_sha256"] is None
    assert "model_shadow" not in row
    assert result["totals"]["rule_answered"] == 1
    assert result["totals"]["answered"] + result["totals"]["unknown"] == 1
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / "schemas/model_assessment.schema.json").read_text()))


@pytest.mark.parametrize("shadow_failure", [False, True])
def test_shadow_records_real_client_answer_without_changing_verdict(tmp_path, monkeypatch, shadow_failure):
    calls = []
    def request(self, method, path, payload):
        calls.append(payload)
        if shadow_failure:
            return b"broken"
        case = json.loads(payload["messages"][1]["content"])
        answer = {"claims": [
            {"id": "requirement_met", "status": "confirmed", "value": False, "evidence_ids": ["e0", "e1"]},
            {"id": "policy_criticality", "status": "confirmed", "value": case["evidence"][0]["observed"]["criticality"],
             "evidence_ids": ["e0"]}], "limitations": [], "recommendations": ["review_policy_against_baseline_text"]}
        return canonical({"choices": [{"message": {"content": canonical(answer)}}]}).encode()
    monkeypatch.setattr(ModelClient, "_request", request)
    result = run_assessment(tmp_path, monkeypatch, {"SPO_tenant": [{"SharingCapability": 0}]}, shadow_model_on_precheck=True)
    row = result["policies"][0]
    assert len(calls) == (2 if shadow_failure else 1)
    assert row["claims"][0]["status"] == "inferred" and row["claims"][0]["value"] is True
    assert row["attempts"] == 0 and result["totals"]["answered"] == 1
    assert row["comparison"]["model_status"] is None
    assert row["model_shadow"]["validation_status"] == ("invalid" if shadow_failure else "valid")
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / "schemas/model_assessment.schema.json").read_text()))


def test_shadow_flag_reaches_serving(tmp_path, monkeypatch, capsys):
    seen = {}
    def assess(*args, **kwargs):
        seen.update(kwargs)
        return {}
    monkeypatch.setattr("auditex.model_serving.assess_run", assess)
    assert main(["model", "assess", str(tmp_path), "--model", "test", "--shadow-model-on-precheck"]) == 0
    assert seen["shadow_model_on_precheck"] is True


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


def test_generator_uses_shared_gate_instead_of_conflicting_learned_gate():
    miner = runpy.run_path(str(ROOT / "scripts/build-oracle-cases.py"))
    assert miner["APPLICABILITY_NOTES"] == rule_catalogue()["applicability_notes"]
    rows = [({"SharingCapability": value}, value) for value in (0, 2)]
    evaluations = [({"input": {"SPO_tenant": [observed]}, "name": str(value), "sha256": "a" * 64}, [{"PolicyId": SP, "Criticality": "Shall",
        "RequirementMet": False, "ReportDetails": "SPO_tenant or SharingCapability are missing from input JSON"}])
        for observed, value in rows]
    cases, _ = miner["build_cases"]("sharepoint", evaluations, {SP: ["SPO_tenant"]}, {}, {"SPO_tenant": []},
        commit="abcdef123456", opa_version="test", config_name="test.rego", not_collected_every=1000,
        gates={SP: {("SPO_tenant", 0, "SharingCapability"): {"2"}}})
    assert [row["provenance"]["oracle_outcome"] for row in cases] == ["not_applicable", "fail_closed_missing_input"]
    assert "doc-sourced" in policy_rule("MS.SHAREPOINT.1.3v1")["source"]


def test_generator_rejects_oracle_gate_drift_and_abstains_on_unusable_gate():
    miner = runpy.run_path(str(ROOT / "scripts/build-oracle-cases.py"))
    def generate(value):
        return miner["build_cases"]("sharepoint", [({"name": "test", "sha256": "a" * 64,
            "input": {"SPO_tenant": [{"SharingCapability": value}]}}, [
                {"PolicyId": SP, "Criticality": "Shall", "RequirementMet": True,
                 "ReportDetails": "This policy is only applicable if sharing is Anyone."}])],
            {SP: ["SPO_tenant"]}, {}, {}, commit="abcdef123456", opa_version="test",
            config_name="test.rego", not_collected_every=1000)
    with pytest.raises(ValueError, match="disagrees with shipped pre-check"):
        generate(2)
    cases, _ = generate(4)
    assert cases[0]["expected"]["claims"][0]["status"] == "unknown"


@pytest.mark.parametrize("report", ["federation_configuration is missing from input JSON", "Requirement met"])
def test_generator_and_serving_agree_when_closed_gate_has_removed_dependency(report):
    miner = runpy.run_path(str(ROOT / "scripts/build-oracle-cases.py"))
    pid = "MS.TEAMS.2.3v2"
    projection = {"scuba_config": {"M365Environment": "gcc"}}
    cases, _ = miner["build_cases"]("teams", [({"name": "test", "sha256": "a" * 64, "input": projection}, [
        {"PolicyId": pid, "Criticality": "Should", "RequirementMet": False,
         "ReportDetails": report}])],
        {pid: ["federation_configuration", "scuba_config"]}, {}, {**projection, "federation_configuration": {}},
        commit="abcdef123456", opa_version="test", config_name="test.rego", not_collected_every=1000)
    case = json.loads(cases[0]["messages"][1]["content"])
    record = precheck_case(case, named_limitations=False)
    assert record["claims"] == cases[0]["expected"]["claims"]
    assert (record["claims"][0]["status"], record["claims"][0]["value"]) == ("inferred", True)
    assert record["limitations"] == cases[0]["expected"]["limitations"] == ["policy_not_applicable"]
    assert record["recommendations"] == cases[0]["expected"]["recommendations"] == []


@pytest.mark.parametrize("licensed,denied,refs", [
    (False, None, ["e0", "e2", "e3"]),
    (True, "HTTP 403", ["e0", "e1", "e3"]),
])
def test_generator_and_serving_cite_all_powerbi_unavailable_input_blockers(licensed, denied, refs):
    miner = runpy.run_path(str(ROOT / "scripts/build-oracle-cases.py"))
    pid = "MS.POWERBI.7.1v1"
    sections = ["powerbi_access_denied_reason", "powerbi_license_found", "powerbi_tenant_settings"]
    projection = {"powerbi_access_denied_reason": denied, "powerbi_license_found": licensed}
    base = {**projection, "powerbi_tenant_settings": [{"settingName": "EnableSensitivityLabels", "enabled": True}]}
    details = ("Power BI license was not found. Unable to evaluate tenant setting." if not licensed else
               "Unable to evaluate tenant setting. HTTP 403")
    cases, _ = miner["build_cases"]("powerbi", [({"name": "test", "sha256": "a" * 64, "input": projection}, [
        {"PolicyId": pid, "Criticality": "Should", "RequirementMet": False, "ReportDetails": details}])],
        {pid: sections}, {}, base, commit="abcdef123456", opa_version="test",
        config_name="test.rego", not_collected_every=1000)
    case = json.loads(cases[0]["messages"][1]["content"])
    expected = cases[0]["expected"]
    assert expected["claims"][0] == {"id": "requirement_met", "status": "unknown", "value": None,
                                      "evidence_ids": refs}
    record = precheck_case(case, named_limitations=False)
    assert {key: record[key] for key in ("claims", "limitations", "recommendations")} == {
        key: expected[key] for key in ("claims", "limitations", "recommendations")}
    assert precheck_case(case)["limitations"] == ["required_evidence_section_not_collected", *(
        "required_evidence_section_not_collected:" + sections[int(ref[1:]) - 1] for ref in refs[1:])]


def benchmark_row(projection):
    case = build_case(SP, projection, "unused")
    record = precheck_case(case, named_limitations=False)
    response = ({key: record[key] for key in ("claims", "limitations", "recommendations")} if record else {
        "claims": [{"id": "requirement_met", "status": "confirmed", "value": True, "evidence_ids": ["e0", "e1"]},
                   {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]}],
        "limitations": [], "recommendations": []})
    return {"id": case["case_id"], "family": "precheck-test", "split": "test",
            "provenance": {"source": "synthetic:precheck-test", "synthetic": True, "review_status": "approved",
                           "reviewer": "unit-test"},
            "messages": [*messages_for(case), {"role": "assistant", "content": canonical(response)}],
            "expected": {**response, "allowed_evidence_ids": ["e0", "e1"]}}


def test_evaluator_combines_rules_with_recorded_model_and_counts_missing(tmp_path):
    cases = [benchmark_row({"SPO_tenant": [{"SharingCapability": 0}]}), benchmark_row({}),
             benchmark_row({"SPO_tenant": [{"SharingCapability": 2}]})]
    path = tmp_path / "test.jsonl"
    path.write_text("".join(canonical(row) + "\n" for row in cases))
    report = evaluate_precheck(str(path))
    assert report["rule_answered"] == report["rule_correct"] == 2
    assert report["left_to_model"] == 1
    responses = tmp_path / "responses.jsonl"
    responses.write_text("".join(canonical({"case_id": row["id"], "model_id": "test-model",
        "response": {key: row["expected"][key] for key in ("claims", "limitations", "recommendations")}
                    if i == 2 else "invalid unused model answer"}) + "\n" for i, row in enumerate(cases)))
    report = evaluate_precheck(str(path), str(responses))
    assert report["product_scores"][0] == {"model_id": "test-model", "correct": 3, "out_of": 3,
        "model_correct_on_remaining": 1, "missing_model_on_remaining": 0}
    responses.write_text(canonical({"case_id": cases[0]["id"], "model_id": "test-model", "response": "broken"}) + "\n")
    report = evaluate_precheck(str(path), str(responses))
    assert report["product_scores"][0]["correct"] == 2
    assert report["product_scores"][0]["missing_model_on_remaining"] == 1
