"""GWS explanations are fixed by the catalogue, not evidence contents."""
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from azure_tenant_audit.explainer import ExplainerError, explain
from azure_tenant_audit.scuba_assessment import validate_explainer
from azure_tenant_audit.value_rules.gws.catalogue import catalogue

ROOT = Path(__file__).resolve().parents[1]


def records():
    rules = catalogue()
    for pid, row in rules["policies"].items():
        for name, cell in row["cells"].items():
            if name == "section_not_collected":
                cited = row["sections"][:1]
                reason = "Data unavailable: required evidence section(s) not collected: " + cited[0] + "."
            else:
                cited = cell.get("cited_variants", [cell.get("cited")])[0]
                reason = cell["reason_texts"][0]
            yield {"policy_id": pid, "cell": name, "verdict": cell["verdict"],
                   "reason_code": cell["reason_code"], "reason_text": reason, "cited_sections": cited}, row


@pytest.mark.parametrize("record,row", list(records()), ids=lambda x: None)
def test_all_cells_are_fixed_and_validate(record, row):
    sections = {s: {"untrusted": "example.com"} for s in row["sections"]}
    result = explain(record, sections, row["sections"])
    assert result == explain(record, {s: {} for s in sections}, row["sections"])
    verdict = record["verdict"]
    claim = {"id": "requirement_met", "evidence_ids": result["evidence_refs"],
             "status": "unknown" if verdict == "not_assessed" else "inferred" if verdict == "not_applicable" else "confirmed",
             "value": None if verdict == "not_assessed" else verdict in ("met", "not_applicable")}
    assessment = {"reason": "rule_precheck", "rule_precheck": {"class": "value_rule"}, "claims": [claim],
                  "limitations": ["policy_not_applicable"] if verdict == "not_applicable" else []}
    validate_explainer(assessment, result)
    changed = copy.deepcopy(record)
    changed["reason_text"] += " altered"
    with pytest.raises(ExplainerError):
        explain(changed, sections, row["sections"])


def test_literal_example_and_generator_drift():
    record = {"policy_id": "GWS.ASSUREDCONTROLS.1.1v1", "cell": "section_not_collected",
              "verdict": "not_assessed", "reason_code": "required_evidence_section_not_collected",
              "reason_text": "Data unavailable: required evidence section(s) not collected: gws_tenant.",
              "cited_sections": ["gws_tenant"]}
    assert explain(record, {}, ["gws_tenant", "gws_policies"]) == {
        "explanation": "Access Approvals SHOULD be enabled. Data unavailable: required evidence section(s) not collected: gws_tenant.",
        "remediation_steps": ["Check the setting and collect complete evidence in the Admin console."],
        "evidence_refs": ["e0"],
    }
    subprocess.run([sys.executable, "scripts/generate-gws-explainer.py", "--check"], cwd=ROOT, check=True)
    assert json.loads((ROOT / "configs/explainer-gws-template.json").read_bytes())["schema_version"] == 1


def test_rederivation_rejects_tampered_explanation_after_l14_dispatch(monkeypatch):
    from azure_tenant_audit import scuba_assessment

    original = scuba_assessment.open_text_resource
    monkeypatch.setattr(scuba_assessment, "open_text_resource", lambda path: original(
        "configs/scuba-gws-policy-sections.json" if path == "configs/scuba-policy-sections.json" else path))
    row = {"policy_id": "GWS.ASSUREDCONTROLS.1.1v1", "reason": "rule_precheck",
           "rule_precheck": {"class": "value_rule", "cell": "section_not_collected",
                             "reason_code": "required_evidence_section_not_collected",
                             "reason_text": "Data unavailable: required evidence section(s) not collected: gws_tenant.",
                             "section": ["gws_tenant"]},
           "claims": [{"id": "requirement_met", "status": "unknown", "value": None,
                       "evidence_ids": ["e0"]}], "limitations": []}
    derived = scuba_assessment.derive_explainer(row)
    assert derived is not None
    row["explainer"] = copy.deepcopy(derived)
    row["explainer"]["explanation"] += " altered"
    assert row["explainer"] != scuba_assessment.derive_explainer(row)


def test_shared_failure_and_invalid_inputs():
    row = catalogue()["policies"]["GWS.ASSUREDCONTROLS.1.1v1"]
    record = {"policy_id": "GWS.ASSUREDCONTROLS.1.1v1", "cell": None, "verdict": "not_assessed",
              "reason_code": "rule_evaluation_failed",
              "reason_text": "Not assessed: Auditex could not evaluate this policy on the collected evidence. This is a product fault, not a tenant setting.",
              "cited_sections": ["gws_tenant", "gws_policies"]}
    result = explain(record, {}, row["sections"])
    assert result["remediation_steps"] == ["Check the policy and report the assessment problem."]
    for sections, order in [(None, row["sections"]), ({}, []), ({}, list(reversed(row["sections"])) )]:
        with pytest.raises(ExplainerError):
            explain(record, sections, order)
