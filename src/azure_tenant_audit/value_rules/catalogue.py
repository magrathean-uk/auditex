"""Shipped value-rule policy and cell inventory."""
from __future__ import annotations

from functools import lru_cache
import json
import re
from typing import Any

from azure_tenant_audit.resources import open_text_resource

_ID = r"[a-z][a-z0-9_.]{0,63}"
SUPPORT_ADDRESS = "contact+auditex@magrathean.uk"


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
            if (not re.fullmatch(_ID, cell)
                    or entry["verdict"] not in {"met", "not_met", "not_assessed", "not_applicable"}):
                raise ValueError("Invalid value-rule cell")
            texts = entry["reason_texts"]
            if (not re.fullmatch(_ID, entry["reason_code"])
                    or not isinstance(texts, list) or not texts or
                    any(not isinstance(text, str) or len(text) > 400 for text in texts)
                    or texts != sorted(set(texts))):
                raise ValueError("Incomplete value-rule cell")
            # stage 4: explicit citation variants include SS 7.x's reference cell order.
            variants = entry.get("cited_variants", [entry.get("cited")])
            if (not isinstance(variants, list) or not variants or entry.get("cited") not in variants
                    or any(not isinstance(cited, list) or not cited or len(set(cited)) != len(cited)
                           or any(name not in row["sections"] for name in cited) for cited in variants)
                    or ("cited_variants" not in entry
                        and entry["cited"] != [name for name in row["sections"] if name in entry["cited"]])):
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
