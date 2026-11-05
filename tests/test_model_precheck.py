from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import runpy

import jsonschema
import pytest

from auditex.cli import main
from auditex.model_precheck import evaluate_precheck, precheck_case
from auditex.model_serving import ModelClient, ModelConfig, assess_run, build_case, canonical, messages_for
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import check_fields, check_gate, field_name, policy_rule, precheck_policy, rule_catalogue

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


def test_value_rules_are_off_in_offline_scoring_by_default():
    from hashlib import sha256

    path = ROOT / "tests/fixtures/model-serving-cases.jsonl"
    report = evaluate_precheck(str(path))
    digest = sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    # Pinned from HEAD before value-rule support was added.
    assert digest == "0cfe7d1d50db6532fb51a7a199ec38eb996c7fb9a7358dcf85142360a2cd24eb"
    rows = []
    for line in path.read_text().splitlines():
        item = json.loads(line)
        case = json.loads(next(message["content"] for message in item["messages"] if message["role"] == "user"))
        rows.append(precheck_case(case))
    digest = sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert digest == "95cb9b4f84ceff132cc7a875d8c192bf4997016a939ee64141c1fd628c0e8738"

    case = build_case("MS.POWERBI.1.1v1", {"powerbi_license_found": False,
        "powerbi_access_denied_reason": "", "powerbi_tenant_settings": []}, "unused")
    default = precheck_case(case)
    enabled = precheck_case(case, value_rules=True)
    assert default is None or default["rule_precheck"]["class"] != "value_rule"
    assert enabled["rule_precheck"]["class"] == "value_rule"


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
    ("MS.AAD.9.1v1", {"conditional_access_policies": [{"State": "enabled"}], "scuba_config": {}, "service_plans": []}),
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


FROZEN_V10 = Path(os.environ.get("AUDITEX_TEST_PRECHECK_PACK", "/Volumes/4TB/dev/auditex-data/development-kit/"
                                 "20261030-oracle-pack-v10/training-pack-oracle-v10-ministral3-8b"))


@pytest.mark.parametrize("name", ["test.jsonl", "approved-cases.jsonl"])
def test_absent_field_rows_are_unknown_in_every_frozen_v10_row(name):
    path = FROZEN_V10 / name
    if not path.is_file():
        pytest.skip(f"frozen v10 pack not present ({path}); set AUDITEX_TEST_PRECHECK_PACK")
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
    assert fired == (5 if name == "test.jsonl" else 69)


def test_evaluator_scores_absent_field_only_on_request(tmp_path):
    case = benchmark_row({"SPO_tenant": [{"SharingCapability": 2}]})
    case["messages"][1]["content"] = canonical({**json.loads(case["messages"][1]["content"]), "policy_id": PBI})
    path = tmp_path / "test.jsonl"
    rows = []
    for observed in ([], [{"settingName": "EimInformationProtectionEdit", "enabled": True}]):
        built = build_case(PBI, {**PBI_SECTIONS, "powerbi_tenant_settings": observed}, "unused")
        record = precheck_case(built, absent_fields=True, named_limitations=False) or {
            "claims": [{"id": "requirement_met", "status": "confirmed", "value": True, "evidence_ids": ["e0", "e1", "e2", "e3"]},
                       {"id": "policy_criticality", "status": "confirmed", "value": "Should", "evidence_ids": ["e0"]}],
            "limitations": [], "recommendations": []}
        response = {key: record[key] for key in ("claims", "limitations", "recommendations")}
        rows.append({"id": built["case_id"], "family": "precheck-test", "split": "test",
                     "provenance": {"source": "synthetic:precheck-test", "synthetic": True, "review_status": "approved",
                                    "reviewer": "unit-test"},
                     "messages": [*messages_for(built), {"role": "assistant", "content": canonical(response)}],
                     "expected": {**response, "allowed_evidence_ids": ["e0", "e1", "e2", "e3"]}})
    path.write_text("".join(canonical(row) + "\n" for row in rows))
    assert evaluate_precheck(str(path))["rule_answered"] == 0
    report = evaluate_precheck(str(path), absent_fields=True)
    assert report["classes"]["absent_field"] == {"rule_answered": 1, "correct": 1}
    assert report["left_to_model"] == 1


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
    monkeypatch.setattr("auditex.model_serving.sleep", lambda seconds: None)
    result = run_assessment(tmp_path, monkeypatch, {"SPO_tenant": [{"SharingCapability": 0}]}, shadow_model_on_precheck=True)
    row = result["policies"][0]
    assert len(calls) == (2 if shadow_failure else 1)
    assert row["claims"][0]["status"] == "inferred" and row["claims"][0]["value"] is True
    assert row["attempts"] == 0 and result["totals"]["answered"] == 1
    assert row["comparison"]["model_status"] is None
    # A non-JSON body is a reply lost in transit, not a model answer.
    assert row["model_shadow"]["validation_status"] == ("unknown" if shadow_failure else "valid")
    assert row["model_shadow"]["reason"] == ("model_transport_failed" if shadow_failure else None)
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


# --- empty required list (`empty_required_list`) ------------------------------------------------------------------------

CA_RULES = ["MS.AAD.1.1v1", "MS.AAD.2.1v1", "MS.AAD.2.3v1", "MS.AAD.3.1v1", "MS.AAD.3.2v2", "MS.AAD.3.6v1",
            "MS.AAD.3.7v1", "MS.AAD.3.8v1", "MS.AAD.3.9v1", "MS.AAD.9.1v1"]


def empty_ca(pid, **sections):
    """Every input of the policy collected, the Conditional Access list empty."""
    from auditex.model_serving import policy_catalogue
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
    # MS.AAD.9.1v1 is a Not-Implemented skip in GCC High and DoD, and an unusable scuba_config cannot rule that out.
    ("MS.AAD.9.1v1", {"conditional_access_policies": [], "scuba_config": {"M365Environment": "gcchigh"}, "service_plans": []}),
    ("MS.AAD.9.1v1", {"conditional_access_policies": [], "scuba_config": {"M365Environment": "dod"}, "service_plans": []}),
    ("MS.AAD.9.1v1", {"conditional_access_policies": [], "scuba_config": None, "service_plans": []}),
    ("MS.AAD.9.1v1", {"conditional_access_policies": [], "scuba_config": [], "service_plans": []}),
])
def test_unregistered_non_empty_or_possibly_not_applicable_lists_are_left_to_the_model(pid, projection):
    assert precheck_case(build_case(pid, projection, "unused"), absent_fields=True, empty_lists=True) is None


@pytest.mark.parametrize("environment", ["commercial", "gcc", None, "GCCHIGH", 0])
def test_ai_agents_rule_applies_outside_the_excluded_environments(environment):
    projection = empty_ca("MS.AAD.9.1v1", scuba_config={"M365Environment": environment})
    record = precheck_case(build_case("MS.AAD.9.1v1", projection, "unused"), empty_lists=True)
    assert record["rule_precheck"]["class"] == "empty_required_list"
    del projection["scuba_config"]["M365Environment"]  # undefined in Rego: the not-applicable branch cannot fire
    assert precheck_case(build_case("MS.AAD.9.1v1", projection, "unused"), empty_lists=True) is not None


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
    path = FROZEN_V10 / name
    if not path.is_file():
        pytest.skip(f"frozen v10 pack not present ({path}); set AUDITEX_TEST_PRECHECK_PACK")
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
    assert fired == (1 if name == "test.jsonl" else 7)


def test_evaluator_scores_empty_list_only_on_request(tmp_path):
    pid = "MS.AAD.1.1v1"
    built = build_case(pid, empty_ca(pid), "unused")
    response = {key: value for key, value in precheck_case(built, empty_lists=True, named_limitations=False).items()
                if key in ("claims", "limitations", "recommendations")}
    row = {"id": built["case_id"], "family": "precheck-test", "split": "test",
           "provenance": {"source": "synthetic:precheck-test", "synthetic": True, "review_status": "approved",
                          "reviewer": "unit-test"},
           "messages": [*messages_for(built), {"role": "assistant", "content": canonical(response)}],
           "expected": {**response, "allowed_evidence_ids": ["e0", "e1", "e2"]}}
    path = tmp_path / "test.jsonl"
    path.write_text(canonical(row) + "\n")
    assert evaluate_precheck(str(path))["rule_answered"] == 0
    report = evaluate_precheck(str(path), empty_lists=True)
    assert report["classes"]["empty_required_list"] == {"rule_answered": 1, "correct": 1}
    assert report["empty_lists"] is True


def test_empty_list_rule_is_served_and_validated(tmp_path, monkeypatch):
    from test_model_serving import fake_projection
    pid = "MS.AAD.1.1v1"
    (tmp_path / "run-manifest.json").write_text('{"run_id":"precheck-test"}')
    monkeypatch.setattr("auditex.model_serving.project_run",
                        lambda root, **kw: fake_projection(root, {"conditional_access_policies": [],
                                                                  "scuba_config": {"CapExclusions": {}}}))
    monkeypatch.setattr(ModelClient, "assess", lambda *a: pytest.fail("Rule-answered row called the model"))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=[pid])
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


SCUBAGEAR_PIN = "2446ad723b7f55031cc02c8aca244d731d468cba"   # the ScubaGear revision the oracle packs were mined from
OPA_PIN = "1.20.2"                                            # the OPA release the packs were evaluated with


@pytest.fixture(scope="module")
def pinned_rego():
    """The local oracle, only at the pinned revisions: another ScubaGear or OPA would test a different oracle."""
    import subprocess
    opa_value, scuba_value = os.environ.get("AUDITEX_TEST_OPA"), os.environ.get("AUDITEX_TEST_SCUBAGEAR")
    if not opa_value or not scuba_value:
        pytest.skip("export AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for local oracle evaluation")
    revision = subprocess.run(["git", "-C", scuba_value, "rev-parse", "HEAD"], capture_output=True, text=True, check=False).stdout.strip()
    assert revision == SCUBAGEAR_PIN, f"ScubaGear checkout at {revision or 'unknown'}, the oracle packs were mined from {SCUBAGEAR_PIN}"
    version = subprocess.run([opa_value, "version"], capture_output=True, text=True, check=False).stdout
    assert f"Version: {OPA_PIN}" in version, f"OPA is not {OPA_PIN}: {version.splitlines()[0] if version else 'no output'}"
    return Path(opa_value), Path(scuba_value)


def test_every_list_rule_is_not_met_in_the_pinned_rego(pinned_rego, tmp_path):
    """ScubaGear's Rego with an empty Conditional Access list, across environment, licence and Authenticator variants:
    every registered policy is not met unless its `unless` condition holds; MS.AAD.3.3v2 can be met."""
    import itertools
    opa, scuba = pinned_rego
    miner = runpy.run_path(str(ROOT / "scripts/build-oracle-cases.py"))
    meta = miner["product_meta"](scuba, "AAD")
    base = miner["load_base"](opa, meta)[0]
    rules = {rule["policy_id"]: rule for rule in rule_catalogue()["list_rules"]}
    met_33 = False
    for index, (env, licensed, auth) in enumerate(itertools.product(
            ["commercial", "gcc", "gcchigh", "dod", None], [True, False], ["enabled", "disabled"])):
        variant = deepcopy(base)
        variant["conditional_access_policies"] = []
        if env is None:
            variant.pop("scuba_config", None)
        else:
            variant["scuba_config"]["M365Environment"] = env
        if not licensed:
            variant["service_plans"] = []
        for method in variant["authentication_method"]:
            for setting in method.get("authentication_method_feature_settings", []):
                if setting.get("Id") == "MicrosoftAuthenticator":
                    setting["State"] = auth
        path = tmp_path / f"aad-{index}.json"
        path.write_text(json.dumps(variant))
        results = miner["opa_json"](opa, ["-d", str(meta["config"]), "-d", str(scuba / "Rego/Utils"), "-i", str(path),
                                          f"data.{meta['package']}.tests"])
        for pid, rule in rules.items():
            if any(env in c["values"] for c in rule["unless"]):
                continue
            target = [r for r in results if r.get("PolicyId") == pid and miner["is_verdict"](r)]
            assert len(target) == 1 and target[0]["RequirementMet"] is False, (pid, env, licensed, auth)
        met_33 |= any(r.get("PolicyId") == "MS.AAD.3.3v2" and r["RequirementMet"] is True for r in results)
    assert met_33
