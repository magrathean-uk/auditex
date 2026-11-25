"""``checked`` for Google Workspace records: ``record.checked`` with cells resolved through the row's kind.

The record builders, ``evidence_kind`` and ``as_pack_response`` are the M365 ones, unchanged.
"""
from __future__ import annotations

from typing import Any

from ..catalogue import cell_entry, citation_variants, reason_matches
from ..record import (
    RULE_FAILURE_CODE,
    RULE_NOT_IMPLEMENTED_CODE,
    _rec,
    is_shared_reason,
)
from .catalogue import row_for, shared_reason


def checked_gws(record: dict[str, Any]) -> dict[str, Any]:
    """Refuse any answer that is not a (cell, verdict, code, text, cited) of the shipped GWS inventory."""
    row = row_for(record["policy_id"])
    if record["cell"] in {RULE_FAILURE_CODE, RULE_NOT_IMPLEMENTED_CODE}:
        raise ValueError("Legacy rule-failure sentinel: a shared reason is not a cell, the record's cell must be null")
    if is_shared_reason(record["reason_code"]) or record["cell"] is None:
        shared = shared_reason(record["reason_code"]) if is_shared_reason(record["reason_code"]) else None
        if (shared is None or record["cell"] is not None or record["verdict"] != shared["verdict"]
                or record["reason_text"] != shared["reason_text"]):
            raise ValueError("Value-rule shared reason is not in the shipped catalogue")
        if row is None or record["cited_sections"] != list(row["sections"]):
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


def rule_failure_gws(policy_id: str) -> dict[str, Any]:
    """The constant answer for a GWS rule that raised: every section the rule reads, no evidence text, no cell."""
    entry, row = shared_reason(RULE_FAILURE_CODE), row_for(policy_id)
    if row is None:
        raise ValueError("GWS value-rule failure for a policy without a row")
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_text"], None, list(row["sections"]))
