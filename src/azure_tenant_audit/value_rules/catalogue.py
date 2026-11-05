"""Shipped value-rule policy and cell inventory."""
from __future__ import annotations

from functools import lru_cache
import json
import re
from typing import Any

from azure_tenant_audit.resources import open_text_resource


@lru_cache(maxsize=1)
def catalogue() -> dict[str, Any]:
    data = json.loads(open_text_resource("configs/scuba-value-rules.json"))
    if (data.get("schema_version") != 1 or data.get("scubagear_revision") != "2446ad72"
            or data.get("spec_version") != "v3.6" or not isinstance(data.get("policies"), dict)):
        raise ValueError("Invalid value-rule catalogue")
    for policy_id, row in data["policies"].items():
        if (not re.fullmatch(r"MS\.[A-Z]+\.\d+\.\d+v\d+", policy_id)
                or row.get("rule_id") != f"{policy_id}.{row.get('kind')}"
                or not row.get("sections") or not row.get("cells")):
            raise ValueError("Invalid value-rule policy")
        if len(set(row["sections"])) != len(row["sections"]):
            raise ValueError("Duplicate value-rule section")
        for cell, entry in row["cells"].items():
            if (not re.fullmatch(r"[a-z][a-z0-9_.]{0,63}", cell)
                    or entry["verdict"] not in {"met", "not_met", "not_assessed", "not_applicable"}):
                raise ValueError("Invalid value-rule cell")
            texts = entry["reason_texts"]
            if (not re.fullmatch(r"[a-z][a-z0-9_.]{0,63}", entry["reason_code"])
                    or not isinstance(texts, list) or not texts or
                    any(not isinstance(text, str) or len(text) > 400 for text in texts)
                    or texts != sorted(set(texts))):
                raise ValueError("Incomplete value-rule cell")
            if (not isinstance(entry.get("cited"), list) or not entry["cited"]
                    or entry["cited"] != [name for name in row["sections"] if name in entry["cited"]]):
                raise ValueError("Invalid value-rule cell citation")
    return data


def row_for(policy_id: str) -> dict[str, Any] | None:
    return catalogue()["policies"].get(policy_id)


def rule_policies() -> tuple[str, ...]:
    return tuple(catalogue()["policies"])


def cells_for(policy_id: str) -> tuple[str, ...]:
    row = row_for(policy_id)
    return tuple(row["cells"]) if row else ()
