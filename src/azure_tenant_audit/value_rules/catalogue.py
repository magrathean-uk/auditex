"""Shipped value-rule policy and cell inventory."""
from __future__ import annotations

from functools import lru_cache
import json
import re
from typing import Any

from azure_tenant_audit.resources import open_text_resource

_ID = r"[a-z][a-z0-9_.]{0,63}"
SUPPORT_ADDRESS = "contact+auditex@magrathean.uk"

# A1 preserves these three reference citation lists in their specified order.
_ORDER_EXCEPTIONS = {(f"MS.SECURITYSUITE.7.{n}v1", "preset_rule_unusable") for n in (1, 2, 3)}


def cell_entry(policy_id: str, cell: str, row: dict[str, Any], data: dict[str, Any] | None = None) -> dict | None:
    """One effective cell contract, including A1 entries for stages that have not shipped yet.

    Catalogue-level entries do not register a policy or add a decision cell. Existing
    policy-level citation variants remain the single source for those cells.
    """
    data = catalogue() if data is None else data
    entry = row["cells"].get(cell)
    if entry is None:
        return None
    extension = data.get("cell_contracts", {}).get(policy_id, {}).get(cell, {})
    for key in extension.keys() & entry.keys():
        if extension[key] != entry[key]:
            raise ValueError("Conflicting value-rule cell contract")
    return {**entry, **extension}


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


def _check_failure_entry(entry: Any) -> None:
    from .record import RULE_FAILURE_CELL, RULE_FAILURE_RECOMMENDATION
    if (not isinstance(entry, dict) or set(entry) != {"cell", "verdict", "reason_code", "reason_text",
                                                      "recommendation", "support"}
            or entry["cell"] != RULE_FAILURE_CELL or entry["reason_code"] != RULE_FAILURE_CELL
            or entry["verdict"] != "not_assessed" or entry["recommendation"] != RULE_FAILURE_RECOMMENDATION
            or entry["support"] != SUPPORT_ADDRESS
            or not isinstance(entry["reason_text"], str) or not 0 < len(entry["reason_text"]) <= 400):
        raise ValueError("Invalid value-rule failure entry")


@lru_cache(maxsize=1)
def catalogue() -> dict[str, Any]:
    data = json.loads(open_text_resource("configs/scuba-value-rules.json"))
    if (data.get("schema_version") != 1 or data.get("scubagear_revision") != "2446ad72"
            or data.get("spec_version") != "v3.9" or not isinstance(data.get("policies"), dict)):
        raise ValueError("Invalid value-rule catalogue")
    _check_failure_entry(data.get("rule_failure"))
    contracts = data.get("cell_contracts", {})
    if not isinstance(contracts, dict):
        raise ValueError("Invalid value-rule cell contracts")
    for policy_id, cells in contracts.items():
        if not re.fullmatch(r"MS\.[A-Z]+\.\d+\.\d+v\d+", policy_id) or not isinstance(cells, dict):
            raise ValueError("Invalid value-rule cell contracts")
        for cell, extension in cells.items():
            if (not re.fullmatch(_ID, cell) or not isinstance(extension, dict) or not extension
                    or set(extension) - {"cited_variants", "reason_texts_by_code"}):
                raise ValueError("Invalid value-rule cell contract")
            if "cited_variants" in extension:
                variants = extension["cited_variants"]
                if (not isinstance(variants, list) or not variants
                        or any(not isinstance(v, list) or not v or any(not isinstance(s, str)
                               or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s) for s in v)
                               or len(set(v)) != len(v) for v in variants)
                        or len({tuple(v) for v in variants}) != len(variants)):
                    raise ValueError("Invalid value-rule cell citation")
            if "reason_texts_by_code" in extension:
                _check_reason_variants(policy_id, cell, extension["reason_texts_by_code"])
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
        if data["rule_failure"]["cell"] in row["cells"]:
            raise ValueError("Value-rule failure is not a policy cell")
        for cell, entry in row["cells"].items():
            entry = cell_entry(policy_id, cell, row, data)
            if (not re.fullmatch(_ID, cell)
                    or entry["verdict"] not in {"met", "not_met", "not_assessed", "not_applicable"}):
                raise ValueError("Invalid value-rule cell")
            texts = entry["reason_texts"]
            if (not re.fullmatch(_ID, entry["reason_code"])
                    or not isinstance(texts, list) or not texts or
                    any(not isinstance(text, str) or len(text) > 400 for text in texts)
                    or texts != sorted(set(texts))):
                raise ValueError("Incomplete value-rule cell")
            pairs = entry.get("reason_texts_by_code")
            if "reason_texts_by_code" in entry:
                _check_reason_variants(policy_id, cell, pairs)
                if entry["reason_code"] not in pairs or sorted(pairs.values()) != texts:
                    raise ValueError("Incomplete value-rule reason variants")
            variants = citation_variants(entry)
            if ((policy_id, cell) in _ORDER_EXCEPTIONS
                    and variants != [["protection_policy_rules", "atp_policy_rules"]]):
                raise ValueError("Invalid value-rule cell citation")
            if (not isinstance(variants, list) or not variants or entry.get("cited") not in variants
                    or any(not isinstance(cited, list) or not cited or len(set(cited)) != len(cited)
                           or any(name not in row["sections"] for name in cited) for cited in variants)
                    or len({tuple(v) for v in variants}) != len(variants)
                    or any(cited != [name for name in row["sections"] if name in cited]
                           and not ((policy_id, cell) in _ORDER_EXCEPTIONS
                                    and cited == ["protection_policy_rules", "atp_policy_rules"])
                           for cited in variants)):
                raise ValueError("Invalid value-rule cell citation")
    return data


def row_for(policy_id: str) -> dict[str, Any] | None:
    return catalogue()["policies"].get(policy_id)


def rule_policies() -> tuple[str, ...]:
    return tuple(catalogue()["policies"])


def cells_for(policy_id: str) -> tuple[str, ...]:
    row = row_for(policy_id)
    return tuple(row["cells"]) if row else ()


def failure_entry() -> dict[str, Any]:
    return catalogue()["rule_failure"]
