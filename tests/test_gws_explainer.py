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
        "remediation_steps": ["Grant the scope the missing evidence section needs, then run the collection again."],
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


def _rec(pid, cell, verdict, code, text, cited):
    return {"policy_id": pid, "cell": cell, "verdict": verdict, "reason_code": code, "reason_text": text,
            "cited_sections": cited}


DNS_ID = "GWS.GMAIL.4.2v1"
CAL_ID = "GWS.CALENDAR.3.1v1"
CAL_SECTIONS = ["gws_tenant", "gws_policies"]


def test_literal_output_for_met_not_met_not_applicable_and_dns():
    met = explain(_rec(CAL_ID, "no_unit_violates", "met", "no_unit_violates",
                       "Requirement met: no organisational unit or group holds a value that violates the setting.",
                       CAL_SECTIONS), {"gws_tenant": {}, "gws_policies": {}}, CAL_SECTIONS)
    assert met == {
        "explanation": "Calendar Interop SHOULD be disabled. Requirement met: no organisational unit or group holds a value "
                       "that violates the setting. Check the setting again after any change in the Admin console.",
        "remediation_steps": [], "evidence_refs": ["e0", "e1", "e2"]}
    not_met = explain(_rec(CAL_ID, "unit_violates", "not_met", "unit_violates",
                           "Requirement not met: at least one organisational unit or group holds a value that violates the setting.",
                           CAL_SECTIONS), {"gws_tenant": {}}, CAL_SECTIONS)
    assert not_met == {
        "explanation": "Calendar Interop SHOULD be disabled. Requirement not met: at least one organisational unit or group "
                       "holds a value that violates the setting.",
        "remediation_steps": ["In the Admin console, change the setting on each organisational unit or group that holds a "
                              "value the baseline forbids."],
        "evidence_refs": ["e0", "e1"]}
    not_applicable = explain(_rec(CAL_ID, "service_off_everywhere", "not_applicable", "service_off_everywhere",
                                  "Not applicable: the Google Workspace service this policy covers is turned off in every "
                                  "organisational unit.", CAL_SECTIONS), {}, CAL_SECTIONS)
    assert not_applicable == {
        "explanation": "Calendar Interop SHOULD be disabled. Not applicable: the Google Workspace service this policy covers "
                       "is turned off in every organisational unit. Check the service is meant to stay off in every "
                       "organisational unit.",
        "remediation_steps": [], "evidence_refs": ["e0"]}
    unassessed = explain(_rec(CAL_ID, "policy_read_incomplete", "not_assessed", "data_unavailable_policy_read_incomplete",
                              "Data unavailable: the Google Workspace policy read is incomplete; the policy was not assessed.",
                              CAL_SECTIONS), {}, CAL_SECTIONS)
    assert unassessed["remediation_steps"] == [
        "Run the collection again so the policy and organisational unit read completes."]


def test_dns_policies_point_at_the_dns_host_not_the_admin_console():
    dns_met = explain(_rec(DNS_ID, "no_domain_violates", "met", "no_domain_violates",
                           "Requirement met: every domain the policy covers meets it.", ["gws_dns"]),
                      {"gws_dns": {}}, ["gws_dns"])
    assert dns_met["explanation"] == (
        "The DMARC message rejection option SHALL be p=reject. Requirement met: every domain the policy covers meets it. "
        "Check the domain DNS records again after any change at the DNS host.")
    dns_not_met = explain(_rec(DNS_ID, "domain_violates", "not_met", "domain_violates",
                               "Requirement not met: at least one domain the policy covers does not meet it.", ["gws_dns"]),
                          {"gws_dns": {}}, ["gws_dns"])
    assert dns_not_met["remediation_steps"] == [
        "Correct the failing domain's SPF TXT, DKIM selector or DMARC TXT (at _dmarc) record at its DNS host; generate "
        "DKIM keys in the Admin console, then publish them in DNS."]
    template = json.loads((ROOT / "configs/explainer-gws-template.json").read_text(encoding="utf-8"))
    dns_cells = template["kinds"]["gws_dns"]
    # DNS evidence is never fixed in the Admin console; only DKIM key generation is, and two lines say it is not there.
    assert all("DNS" in cell["remediation_steps"] for cell in dns_cells.values())
    assert {n for n, c in dns_cells.items() if "Admin console" in c["remediation_steps"]} == {
        "dns_read_incomplete", "domain_violates", "section_not_collected"}
    assert dns_cells["section_not_collected"]["remediation_steps"] == (
        "Run the collection again so the DNS lookups run; the records are read from each domain's DNS host, not the "
        "Admin console.")
    assert dns_cells["resolver_error"]["remediation_steps"] == (
        "Run the collection again; if a lookup keeps failing, check the SPF TXT, DKIM selector or DMARC TXT (at _dmarc) "
        "record answers at the domain's DNS host.")


def test_check_line_depends_on_the_cell_not_only_the_verdict():
    cells = json.loads((ROOT / "configs/explainer-gws-template.json").read_text(encoding="utf-8"))["kinds"]["setting"]
    assert cells["section_not_collected"]["remediation_steps"] == (
        "Grant the scope the missing evidence section needs, then run the collection again.")
    assert cells["setting_absent"]["remediation_steps"] == (
        "Check in the Admin console that the setting is configured at the top-level organisational unit, then collect again.")
    assert cells["service_status_absent"]["remediation_steps"] == (
        "Run the collection again so the service on or off status is read for every unit this policy covers.")
    assert cells["setting_value_unusable"]["remediation_steps"] == (
        "Check the setting in the Admin console for an unknown or malformed value, then collect again.")
    template = json.loads((ROOT / "configs/explainer-gws-template.json").read_text(encoding="utf-8"))["kinds"]
    lines = [cell["remediation_steps"] for kind in template.values() for cell in kind.values()]
    assert len(lines) == 67
    assert len(set(lines)) > 40
    assert not [line for line in lines if "—" in line or len(line.split()) > 30]


def _generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("_gws_explainer_generator", ROOT / "scripts/generate-gws-explainer.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generator_refuses_section_or_cell_drift(monkeypatch):
    generator = _generator()
    original = generator.open_text_resource

    def skewed(path):
        data = json.loads(original(path))
        data["policies"][CAL_ID]["sections"] = list(reversed(data["policies"][CAL_ID]["sections"]))
        return json.dumps(data)

    monkeypatch.setattr(generator, "open_text_resource", skewed)
    with pytest.raises(ValueError, match="sections disagree"):
        generator.generate()
    monkeypatch.setattr(generator, "open_text_resource", original)
    monkeypatch.setattr(generator, "CHECKS", {k: v for k, v in generator.CHECKS.items() if k != ("twosv", "unit_violates")})
    with pytest.raises(ValueError, match="do not match"):
        generator.generate()
