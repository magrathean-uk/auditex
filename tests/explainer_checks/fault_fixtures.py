"""Product-authored synthetic controls for the brief's shared-fault literal."""
from .shared_reason import FAULT_ENTRY, FAULT_REASON


def fault_pair():
    record = {"policy_id": "MS.AAD.5.6v1", "verdict": "not_assessed", "cell": None,
              "reason_code": "rule_evaluation_failed", "reason_text": FAULT_REASON,
              "cited_sections": ["app_management_policies", "default_app_management_policy"]}
    evidence = [{"id": "e0", "section": "policy", "observed": {
        "policy_id": record["policy_id"], "requirement": "A password lifetime SHALL be configured.", "criticality": "Shall"}},
        {"id": "e1", "section": "app_management_policies", "observed": []},
        {"id": "e2", "section": "default_app_management_policy", "observed": {}}]
    data = {key: record[key] for key in ("policy_id", "verdict", "cell", "reason_code", "reason_text")}
    data.update(evidence=evidence, approved_remediation=list(FAULT_ENTRY["remediation_steps"]))
    return {"id": "SHARED-rule_evaluation_failed", "prompt": {"record": record, "data": data, "full_record_terms": []},
            "output": {"explanation": FAULT_ENTRY["explanation"], "remediation_steps": list(FAULT_ENTRY["remediation_steps"]),
                       "evidence_refs": ["e0", "e1", "e2"]}}
