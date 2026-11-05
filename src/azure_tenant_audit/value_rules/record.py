"""Value-rule records and the existing assessment response vocabulary."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import unavailable_input_sections

# Shared reason codes (spec v3.9 section 3: every list policy).
SECTION_NOT_COLLECTED = "required_evidence_section_not_collected"
BAD_SECTION_LIST = "data_unusable_section_not_a_list"
EMPTY_SECTION = "data_unavailable_section_empty"
ITEM_VALUE = "data_unusable_item_value"
ITEM_LABEL = "data_unusable_item_label_absent"


def _marker(value: Any) -> bool:
    return isinstance(value, dict) and value.get("collection_status") == NOT_COLLECTED["collection_status"]


def _rec(policy_id: str, verdict: str, code: str, text: str, cell: str,
         cited: list[str] | None = None, **detail: Any) -> dict[str, Any]:
    """Build a record. The shipped inventory is enforced once, by ``checked`` at the dispatch boundary."""
    return {"policy_id": policy_id, "verdict": verdict, "reason_code": code,
            "reason_text": text, "cell": cell, "cited_sections": None if cited is None else list(cited),
            "detail": detail}


def _A(policy_id: str, code: str, text: str, cell: str, cited: list[str],
       **detail: Any) -> dict[str, Any]:
    return _rec(policy_id, "not_assessed", code, text, cell, cited, **detail)


def checked(record: dict[str, Any]) -> dict[str, Any]:
    """Refuse any answer that is not a (cell, verdict, code, text, cited) of the shipped inventory."""
    from .catalogue import row_for
    row = row_for(record["policy_id"])
    entry = row["cells"].get(record["cell"]) if row else None
    if (entry is None or entry["verdict"] != record["verdict"] or entry["reason_code"] != record["reason_code"]
            or record["reason_text"] not in entry["reason_texts"]):
        raise ValueError("Value-rule answer is not in the shipped catalogue")
    cited = record["cited_sections"]
    if record["cell"] == "section_not_collected":
        if not cited or cited != [name for name in row["sections"] if name in cited]:
            raise ValueError("Value-rule answer cites the wrong section")
    # stage 4: parser and Defender cells have explicit, closed citation variants.
    # stage 8: PP 2.2 shape/empty cells can cite either of its two sections.
    elif (cited or row["sections"]) not in entry.get("cited_variants", [entry["cited"]]):
        raise ValueError("Value-rule answer cites the wrong section")
    return record


def _not_collected(policy_id: str, projection: dict[str, Any], names: list[str] | tuple[str, ...]) -> dict | None:
    cited = unavailable_input_sections(projection, list(names))
    if not cited:
        return None
    return _A(policy_id, SECTION_NOT_COLLECTED,
              "Data unavailable: required evidence section(s) not collected: " + ", ".join(cited) + ".",
              "section_not_collected", cited)


def _evidence_ids(cited: list[str] | None, refs: dict[str, str]) -> list[str]:
    return ["e0", *(refs[name] for name in cited or [] if name in refs)]


def as_pack_response(record: dict[str, Any], criticality: str, section_order: list[str]) -> dict[str, Any]:
    refs = {name: f"e{index + 1}" for index, name in enumerate(section_order)}
    verdict = record["verdict"]
    if record.get("cell") == RULE_FAILURE_CELL:
        # Our fault, not the evidence's: no missing-evidence limitation, one product-fault recommendation.
        claim = {"id": "requirement_met", "status": "unknown", "value": None,
                 "evidence_ids": _evidence_ids(record["cited_sections"], refs)}
        limits, recommendations = [], [RULE_FAILURE_RECOMMENDATION]
    elif verdict == "not_assessed":
        claim = {"id": "requirement_met", "status": "unknown", "value": None,
                 "evidence_ids": _evidence_ids(record["cited_sections"], refs)}
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


# A rule that raises on collected evidence (main, 5 Nov 07:12 GMT): additive, catalogued once in
# configs/scuba-value-rules.json ("rule_failure"); the loader checks these constants against it.
RULE_FAILURE_CELL = "rule_evaluation_failed"
RULE_FAILURE_RECOMMENDATION = "report_product_fault"


def rule_failure(policy_id: str) -> dict[str, Any]:
    """The constant answer for a rule that raised: every section the rule reads, no evidence text."""
    from .catalogue import catalogue, row_for
    entry, row = catalogue()["rule_failure"], row_for(policy_id)
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_text"], entry["cell"],
                list(row["sections"]))
