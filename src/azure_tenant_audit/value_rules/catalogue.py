"""Shipped value-rule policy and cell inventory."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from hashlib import sha256
from typing import Any

from azure_tenant_audit.resources import open_text_resource

_ID = r"[a-z][a-z0-9_.]{0,63}"

# A1.3 and A2: the exact variable-citation contract, 64 cells with two or more variants plus the three SS 7.x reference
# orders (67 cells, 193 lists). The digest covers every cited_variants list of the catalogue, keyed "policy:cell", so a
# dropped, added or reordered variant is refused, not just an unsound one.
_VARIANT_CONTRACT_SHA256 = "00fd8197ded5350556d989e70be23d6c53c30ff536833ae426f0a15d85f192b7"

# A1 preserves these three reference citation lists in their specified order.
_ORDER_EXCEPTIONS = {(f"MS.SECURITYSUITE.7.{n}v1", "preset_rule_unusable") for n in (1, 2, 3)}


def cell_entry(policy_id: str, cell: str, row: dict[str, Any], data: dict[str, Any] | None = None) -> dict | None:
    """The effective contract of one cell of ``row``; the catalogue carries every variant on the cell itself.

    ``policy_id`` and ``data`` are kept so existing callers need no change.
    """
    return row["cells"].get(cell)


def reason_matches(entry: dict, code: str, text: str) -> bool:
    """A1's two-code cell pairs each code with its own constant text."""
    pairs = entry.get("reason_texts_by_code")
    if pairs is not None:
        return code in pairs and pairs[code] == text
    return code == entry["reason_code"] and text in entry["reason_texts"]


def citation_variants(entry: dict) -> list[list[str]]:
    return entry.get("cited_variants", [entry["cited"]])


def _check_reason_variants(policy_id: str, cell: str, pairs: Any) -> None:
    if ((policy_id, cell) != ("MS.AAD.6.1v1", "orphan_sub_domain")
            or not isinstance(pairs, dict) or set(pairs) != {
                "data_unusable_sub_domain_root_case", "data_unusable_sub_domain_without_root"}
            or any(not isinstance(text, str) or not 0 < len(text) <= 400 for text in pairs.values())):
        raise ValueError("Invalid value-rule reason variants")


# A1.2: two reasons that are not cells, catalogued once under ``shared_reasons``. A rule that raised answers the first
# with a rule record whose cell is null, dispatched before any cell lookup. A policy without a rule answers the second
# as a row-level reason in ``auditex.rule_assessment`` (never a rule record); the constant text is kept here so one
# test can pin the serving constant to the catalogue.
FAILURE_REASON = "rule_evaluation_failed"
NOT_IMPLEMENTED_REASON = "rule_not_implemented"
_SHARED_REASONS = {
    FAILURE_REASON: {
        "reason_code": FAILURE_REASON, "verdict": "not_assessed", "recommendation": "report_product_fault",
        "reason_text": ("Not assessed: Auditex could not evaluate this policy on the collected evidence. "
                        "This is a product fault, not a tenant setting.")},
    NOT_IMPLEMENTED_REASON: {
        "reason_code": NOT_IMPLEMENTED_REASON, "verdict": "not_assessed", "recommendation": None,
        "reason_text": "Not assessed: Auditex has no rule for this policy yet."},
}


def _check_shared_reasons(entries: Any) -> None:
    if entries != _SHARED_REASONS:
        raise ValueError("Invalid value-rule shared reasons")


def _check_evidence(policy_id: str, cell: str, entry: dict) -> None:
    """A1: collected-but-unusable evidence has a kind, two limitations and one recommendation; nothing else does."""
    from .record import (
        LIMIT_UNUSABLE,
        REC_BY_KIND,
        SECTION_NOT_COLLECTED,
        evidence_kind,
    )
    keys = {"evidence_kind", "limitations", "recommendations"}
    if entry["verdict"] != "not_assessed":
        if keys & entry.keys():
            raise ValueError("Invalid value-rule evidence fields")
        return
    codes = list(entry.get("reason_texts_by_code", {entry["reason_code"]: None}))
    kinds = {evidence_kind(code) for code in codes}
    if not keys <= entry.keys() or len(kinds) != 1 or entry["evidence_kind"] not in kinds:
        raise ValueError("Invalid value-rule evidence kind")
    kind = entry["evidence_kind"]
    if kind is None:
        expected = ([SECTION_NOT_COLLECTED, SECTION_NOT_COLLECTED + ":<section>"], ["collect_missing_evidence_section"])
    else:
        expected = ([LIMIT_UNUSABLE, f"{LIMIT_UNUSABLE}:<section>:{kind}"], [REC_BY_KIND[kind]])
    if (entry["limitations"], entry["recommendations"]) != expected or (kind is None) != (cell == "section_not_collected"):
        raise ValueError("Invalid value-rule evidence limitations")


_CELL_KEYS = {"cited", "cited_variants", "reason_code", "reason_codes", "reason_texts", "reason_texts_by_code",
              "verdict", "evidence_kind", "limitations", "recommendations"}


@lru_cache(maxsize=1)
def catalogue() -> dict[str, Any]:
    data = json.loads(open_text_resource("configs/scuba-value-rules.json"))
    if (data.get("schema_version") != 1 or data.get("scubagear_revision") != "2446ad72"
            or data.get("spec_version") != "v3.9.1" or not isinstance(data.get("policies"), dict)
            or {"rule_failure", "cell_contracts"} & data.keys()):
        raise ValueError("Invalid value-rule catalogue")
    _check_shared_reasons(data.get("shared_reasons"))
    for policy_id, row in data["policies"].items():
        if (not re.fullmatch(r"MS\.[A-Z]+\.\d+\.\d+v\d+", policy_id)
                or row.get("rule_id") != f"{policy_id}.{row.get('kind')}"
                or not row.get("sections") or not row.get("cells") or not isinstance(row.get("params"), dict)):
            raise ValueError("Invalid value-rule policy")
        if len(set(row["sections"])) != len(row["sections"]):
            raise ValueError("Duplicate value-rule section")
        # stage 4: optional reads never enter required-section checks or citation inventories.
        optional = row.get("optional_sections", [])
        if (not isinstance(optional, list)
                or any(not isinstance(name, str) or not name for name in optional)
                or len(set(optional)) != len(optional) or set(optional) & set(row["sections"])):
            raise ValueError("Invalid optional value-rule sections")
        for cell, entry in row["cells"].items():
            if (not re.fullmatch(_ID, cell) or not isinstance(entry, dict) or set(entry) - _CELL_KEYS
                    or entry.get("verdict") not in {"met", "not_met", "not_assessed", "not_applicable"}
                    or cell in _SHARED_REASONS):
                raise ValueError("Invalid value-rule cell")
            texts = entry.get("reason_texts")
            if (not isinstance(entry.get("reason_code"), str) or not re.fullmatch(_ID, entry["reason_code"])
                    or not isinstance(texts, list) or not texts or
                    any(not isinstance(text, str) or len(text) > 400 for text in texts)
                    or texts != sorted(set(texts))):
                raise ValueError("Incomplete value-rule cell")
            pairs = entry.get("reason_texts_by_code")
            if "reason_texts_by_code" in entry or "reason_codes" in entry:
                _check_reason_variants(policy_id, cell, pairs)
                if (entry["reason_code"] not in pairs or sorted(pairs.values()) != texts
                        or entry.get("reason_codes") != sorted(pairs)):
                    raise ValueError("Incomplete value-rule reason variants")
            _check_evidence(policy_id, cell, entry)
            variants = citation_variants(entry)
            if ((policy_id, cell) in _ORDER_EXCEPTIONS
                    and variants != [["protection_policy_rules", "atp_policy_rules"]]):
                raise ValueError("Invalid value-rule cell citation")
            if ("cited_variants" in entry and (cell == "section_not_collected" or entry["verdict"] != "not_assessed")):
                raise ValueError("Invalid value-rule cell citation")
            if (not isinstance(variants, list) or not variants or entry.get("cited") not in variants
                    or any(not isinstance(cited, list) or not cited or len(set(cited)) != len(cited)
                           or any(not isinstance(name, str) or name not in row["sections"] for name in cited)
                           for cited in variants)
                    or len({tuple(v) for v in variants}) != len(variants)
                    or any(cited != [name for name in row["sections"] if name in cited]
                           and not ((policy_id, cell) in _ORDER_EXCEPTIONS
                                    and cited == ["protection_policy_rules", "atp_policy_rules"])
                           for cited in variants)):
                raise ValueError("Invalid value-rule cell citation")
    contract = {f"{policy_id}:{cell}": entry["cited_variants"]
                for policy_id, row in data["policies"].items() for cell, entry in row["cells"].items()
                if "cited_variants" in entry}
    if sha256(json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode()).hexdigest() != _VARIANT_CONTRACT_SHA256:
        raise ValueError("Invalid value-rule cell citation")
    return data


def row_for(policy_id: str) -> dict[str, Any] | None:
    return catalogue()["policies"].get(policy_id)


def rule_policies() -> tuple[str, ...]:
    return tuple(catalogue()["policies"])


def cells_for(policy_id: str) -> tuple[str, ...]:
    row = row_for(policy_id)
    return tuple(row["cells"]) if row else ()


def shared_reason(code: str) -> dict[str, Any]:
    """The catalogued constant of ``rule_evaluation_failed`` or ``rule_not_implemented``."""
    return catalogue()["shared_reasons"][code]
