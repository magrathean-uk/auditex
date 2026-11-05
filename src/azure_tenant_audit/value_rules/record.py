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

LIMIT_UNUSABLE = "evidence_unusable"
REC_BY_KIND = {"blocked": "check_licence_or_permissions", "absent": "recollect_unusable_evidence",
               "unusable": "recollect_unusable_evidence", "undecidable": "review_policy_against_baseline_text"}
BLOCKED_CODES = frozenset({"data_unavailable_no_licence", "data_unavailable_licence_flag_unusable",
                           "data_unavailable_access_denied"})
UNDECIDABLE_CODES = frozenset({"data_unusable_policy_set", "data_unusable_qualifier_shadowed",
                               "data_unusable_hidden_covering_rule", "data_unusable_partial_tier",
                               "data_unusable_partial_tier_may_cover", "data_unusable_rule_priority_tie",
                               "data_unavailable_custom_policy_priority", "data_unavailable_no_baseline_text"})


def evidence_kind(code: str) -> str | None:
    """A1's reason-code families; no evidence values contribute to the response."""
    if code == SECTION_NOT_COLLECTED:
        return None
    if code in BLOCKED_CODES:
        return "blocked"
    if code in UNDECIDABLE_CODES:
        return "undecidable"
    if code.startswith("data_unavailable_"):
        return "absent"
    if code.startswith("data_unusable_"):
        return "unusable"
    raise ValueError("Unsupported evidence reason code")


def _marker(value: Any) -> bool:
    return isinstance(value, dict) and value.get("collection_status") == NOT_COLLECTED["collection_status"]


def _rec(policy_id: str, verdict: str, code: str, text: str, cell: str | None,
         cited: list[str] | None = None, **detail: Any) -> dict[str, Any]:
    """Build a record. The shipped inventory is enforced once, by ``checked`` at the dispatch boundary."""
    return {"policy_id": policy_id, "verdict": verdict, "reason_code": code,
            "reason_text": text, "cell": cell, "cited_sections": None if cited is None else list(cited),
            "detail": detail}


def _A(policy_id: str, code: str, text: str, cell: str, cited: list[str],
       **detail: Any) -> dict[str, Any]:
    return _rec(policy_id, "not_assessed", code, text, cell, cited, **detail)


def is_shared_reason(code: Any) -> bool:
    """A reason a rule record carries with a null cell. ``rule_not_implemented`` is not one: product answers it as a
    row-level reason (``model_serving._uncovered_record``) before any rule record exists."""
    return code == RULE_FAILURE_CODE


def checked(record: dict[str, Any]) -> dict[str, Any]:
    """Refuse any answer that is not a (cell, verdict, code, text, cited) of the shipped inventory.

    A1.2: ``rule_evaluation_failed`` is dispatched first, before any cell lookup; it is not a cell, so its record
    has ``cell`` None and the catalogued constant text.
    """
    from .catalogue import cell_entry, citation_variants, reason_matches, row_for, shared_reason
    row = row_for(record["policy_id"])
    if record["cell"] in {RULE_FAILURE_CODE, RULE_NOT_IMPLEMENTED_CODE}:
        raise ValueError("Legacy rule-failure sentinel: a shared reason is not a cell, the record's cell must be null")
    if is_shared_reason(record["reason_code"]) or record["cell"] is None:
        shared = shared_reason(record["reason_code"]) if is_shared_reason(record["reason_code"]) else None
        if (shared is None or record["cell"] is not None or record["verdict"] != shared["verdict"]
                or record["reason_text"] != shared["reason_text"]):
            raise ValueError("Value-rule shared reason is not in the shipped catalogue")
        if record["reason_code"] == RULE_FAILURE_CODE and (row is None or record["cited_sections"] != list(row["sections"])):
            raise ValueError("Value-rule failure must cite every section the rule reads")
        return record
    entry = cell_entry(record["policy_id"], record["cell"], row) if row else None
    if (entry is None or entry["verdict"] != record["verdict"]
            or not reason_matches(entry, record["reason_code"], record["reason_text"])):
        raise ValueError("Value-rule answer is not in the shipped catalogue")
    cited = record["cited_sections"]
    if record["cell"] == "section_not_collected":
        if not cited or cited != [name for name in row["sections"] if name in cited]:
            raise ValueError("Value-rule answer cites the wrong section")
        if record["reason_text"] != ("Data unavailable: required evidence section(s) not collected: "
                                      + ", ".join(cited) + "."):
            raise ValueError("Value-rule missing-section reason differs from citation")
    elif (row["sections"] if cited is None else cited) not in citation_variants(entry):
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


def as_pack_response(record: dict[str, Any], criticality: str, section_order: list[str], *,
                     legacy: bool = False) -> dict[str, Any]:
    refs = {name: f"e{index + 1}" for index, name in enumerate(section_order)}
    verdict = record["verdict"]
    if is_shared_reason(record["reason_code"]):
        # Our fault, not the evidence's: no missing-evidence limitation; the catalogued recommendation
        # (report_product_fault).
        from .catalogue import shared_reason
        claim = {"id": "requirement_met", "status": "unknown", "value": None,
                 "evidence_ids": _evidence_ids(record["cited_sections"], refs)}
        recommendation = shared_reason(record["reason_code"])["recommendation"]
        limits, recommendations = [], [recommendation] if recommendation else []
    elif verdict == "not_assessed":
        claim = {"id": "requirement_met", "status": "unknown", "value": None,
                 "evidence_ids": _evidence_ids(record["cited_sections"], refs)}
        kind = None if legacy else evidence_kind(record["reason_code"])
        if kind is None:
            limits, recommendations = [SECTION_NOT_COLLECTED], ["collect_missing_evidence_section"]
        else:
            limits, recommendations = [LIMIT_UNUSABLE], [REC_BY_KIND[kind]]
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


# A1.2: the shared reasons are catalogued once, under "shared_reasons" in configs/scuba-value-rules.json.
RULE_FAILURE_CODE = "rule_evaluation_failed"
RULE_NOT_IMPLEMENTED_CODE = "rule_not_implemented"


def rule_failure(policy_id: str) -> dict[str, Any]:
    """The constant answer for a rule that raised: every section the rule reads, no evidence text, no cell."""
    from .catalogue import row_for, shared_reason
    entry, row = shared_reason(RULE_FAILURE_CODE), row_for(policy_id)
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_text"], None, list(row["sections"]))

