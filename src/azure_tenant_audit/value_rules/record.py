"""Value-rule records and the existing assessment response vocabulary."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.scuba_precheck import unavailable_input_sections


def _rec(policy_id: str, verdict: str, code: str, text: str, cell: str,
         cited: list[str] | None = None, **detail: Any) -> dict[str, Any]:
    from .catalogue import row_for
    row = row_for(policy_id)
    entry = row["cells"].get(cell) if row else None
    if (entry is None or entry["verdict"] != verdict or entry["reason_code"] != code
            or text not in entry["reason_texts"]):
        raise ValueError("Value-rule answer is not in the shipped catalogue")
    if cell != "section_not_collected" and (cited or row["sections"]) != entry["cited"]:
        raise ValueError("Value-rule answer cites the wrong section")
    return {"policy_id": policy_id, "verdict": verdict, "reason_code": code,
            "reason_text": text, "cell": cell, "cited_sections": cited, "detail": detail}


def _A(policy_id: str, code: str, text: str, cell: str, cited: list[str],
       **detail: Any) -> dict[str, Any]:
    return _rec(policy_id, "not_assessed", code, text, cell, cited, **detail)


def _not_collected(policy_id: str, projection: dict[str, Any], names: list[str] | tuple[str, ...]) -> dict | None:
    cited = unavailable_input_sections(projection, list(names))
    if not cited:
        return None
    return _A(policy_id, "required_evidence_section_not_collected",
              "Data unavailable: required evidence section(s) not collected: " + ", ".join(cited) + ".",
              "section_not_collected", cited)


def as_pack_response(record: dict[str, Any], criticality: str, section_order: list[str]) -> dict[str, Any]:
    refs = {name: f"e{index + 1}" for index, name in enumerate(section_order)}
    verdict = record["verdict"]
    if verdict == "not_assessed":
        cited = record["cited_sections"] or []
        claim = {"id": "requirement_met", "status": "unknown", "value": None,
                 "evidence_ids": ["e0", *(refs[name] for name in cited if name in refs)]}
        limits, recommendations = ["required_evidence_section_not_collected"], ["collect_missing_evidence_section"]
    elif verdict == "not_applicable":
        claim = {"id": "requirement_met", "status": "inferred", "value": True,
                 "evidence_ids": ["e0", *refs.values()]}
        limits, recommendations = ["policy_not_applicable"], []
    else:
        met = verdict == "met"
        claim = {"id": "requirement_met", "status": "confirmed", "value": met,
                 "evidence_ids": ["e0", *refs.values()]}
        limits, recommendations = [], [] if met else ["review_policy_against_baseline_text"]
    return {"claims": [claim, {"id": "policy_criticality", "status": "confirmed",
                               "value": criticality, "evidence_ids": ["e0"]}],
            "limitations": limits, "recommendations": recommendations}
