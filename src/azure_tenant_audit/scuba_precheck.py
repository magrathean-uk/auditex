"""Data-driven SCuBA applicability checks shared by serving and oracle generation.

Only explicit, typed values close gates. Lists representing singleton tenant
objects are accepted; empty, ambiguous or malformed objects fail closed.
"""
from __future__ import annotations

import json
import math
from typing import Any

from .model_evidence import NOT_COLLECTED
from .resources import open_text_resource


def rule_catalogue() -> dict[str, Any]:
    return json.loads(open_text_resource("configs/scuba-rule-precheck.json"))


def policy_rule(policy_id: str) -> dict[str, Any] | None:
    return next((rule for rule in rule_catalogue()["rules"] if rule["policy_id"] == policy_id), None)


def field_name(rule: dict[str, Any]) -> str:
    return ".".join(part if isinstance(part, str) else
                    "[" + ",".join(f"{key}={value}" for key, value in part.items()) + "]"
                    for part in rule["path"])


def gate_value(rule: dict[str, Any], projection: dict[str, Any]) -> Any:
    value = projection.get(rule["section"])
    if isinstance(value, dict) and value.get("collection_status") == NOT_COLLECTED["collection_status"]:
        return None
    for part in rule["path"]:
        if isinstance(part, dict):
            if not isinstance(value, list):
                return None
            matches = [item for item in value if isinstance(item, dict)
                       and all(item.get(key) == target for key, target in part.items())]
            if len(matches) != 1:
                return None
            value = matches[0]
        else:
            if isinstance(value, list):
                if len(value) != 1:
                    return None
                value = value[0]
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
    if rule["value_type"] == "integer":
        if type(value) not in (int, float) or (type(value) is float and
                (not math.isfinite(value) or not value.is_integer())):
            return None
        value = int(value)
    elif type(value) is not str:
        return None
    return value if value in rule["allowed_values"] else None


def check_gate(policy_id: str, projection: dict[str, Any]) -> dict[str, Any] | None:
    """Return a closed gate or a fail-closed missing/unusable gate field."""
    rule = policy_rule(policy_id)
    if rule is None:
        return None
    value = gate_value(rule, projection)
    if value is not None and value not in rule["closed_values"]:
        return None
    return {"class": "absent_section" if value is None else "closed_gate",
            "rule_id": rule["rule_id"], "section": [rule["section"]],
            "field": field_name(rule), "value": value}


def unavailable_input_sections(projection: dict[str, Any], sections: list[str], *,
                               additional: list[str] | None = None, unreadable: bool = False) -> list[str]:
    """Cite unavailable inputs and every Power BI blocker that explains them.

    Oracle wording can additionally identify missing fields or an unreadable
    tenant. Serving uses only the projected evidence. A licence/access blocker
    supplements missing tenant settings; it never displaces their marker.
    """
    cited = set(additional or ())
    cited.update(section for section in sections if section not in projection or
                 isinstance(projection[section], dict) and
                 projection[section].get("collection_status") == NOT_COLLECTED["collection_status"])
    if unreadable or "powerbi_tenant_settings" in cited:
        reason = ("powerbi_license_found" if projection.get("powerbi_license_found") is not True
                  else "powerbi_access_denied_reason")
        if unreadable or projection.get(reason) is False or bool(projection.get(reason)):
            cited.update([reason] if reason in sections else sections)
    return [section for section in sections if section in cited]


def field_absent(rule: dict[str, Any], projection: dict[str, Any]) -> bool:
    """True only when a collected section definitely lacks the rule's field.

    Path parts follow ``gate_value``. A singleton list that is empty, a missing
    key and a selector without a match are absent, as in the policy's Rego. A
    field shown as null is a collected default; markers, null or non-object
    sections, several tenant objects and duplicate selector matches are left
    to the earlier classes or the model.
    """
    value = projection.get(rule["section"])
    if isinstance(value, dict) and value.get("collection_status") == NOT_COLLECTED["collection_status"]:
        return False
    for part in rule["path"]:
        if isinstance(part, dict):
            if not isinstance(value, list):
                return False
            matches = [item for item in value if isinstance(item, dict)
                       and all(item.get(key) == target for key, target in part.items())]
            if not matches:
                return True
            if len(matches) != 1:
                return False
            value = matches[0]
            continue
        if isinstance(value, list):
            if not value:
                return True
            if len(value) != 1:
                return False
            value = value[0]
        if not isinstance(value, dict):
            return False
        if part not in value:
            return True
        value = value[part]
    return False


def check_fields(policy_id: str, projection: dict[str, Any]) -> dict[str, Any] | None:
    """Return the first registered field that a collected section lacks.

    ``requires`` pins other sections to exact typed values (Power BI: licence
    found, access not denied), because the oracle answers those blockers with
    different evidence.
    """
    for rule in rule_catalogue()["field_rules"]:
        if rule["policy_id"] != policy_id:
            continue
        if any(section not in projection or type(projection[section]) is not type(target)
               or projection[section] != target for section, target in rule["requires"].items()):
            continue
        if field_absent(rule, projection):
            return {"class": "absent_field", "rule_id": rule["rule_id"], "section": [rule["section"]],
                    "field": field_name(rule), "value": None}
    return None


def precheck_policy(policy_id: str, projection: dict[str, Any], sections: list[str], *,
                    skip_absent_sections: bool = False, absent_fields: bool = False) -> dict[str, Any] | None:
    """A usable closed gate wins over absent dependent evidence.

    The serving caller alone opts out for the entirely empty P1 projection.
    Pack evaluation never opts out. A missing gate is included in the absence
    class, with ``field`` naming the unavailable input. ``absent_fields`` adds
    the field-level class after both; it is off until the assessment contract
    accepts ``absent_field`` rows.
    """
    if skip_absent_sections:
        return None
    gate = check_gate(policy_id, projection)
    if gate and gate["class"] == "closed_gate":
        return gate
    missing = unavailable_input_sections(projection, sections)
    if missing:
        return {"class": "absent_section", "rule_id": "required_sections_present",
                "section": missing, "field": None, "value": None}
    if gate is None and absent_fields:
        return check_fields(policy_id, projection)
    return gate


def precheck_response(detail: dict[str, Any], policy_item: dict[str, Any], sections: list[str], *,
                      named_limitations: bool = True) -> dict[str, Any]:
    """Render the pack verdict; serving also names each unavailable input.

    The named limitations are assessment-contract extensions, not new pack
    vocabulary. Offline scoring compares the original pack response vocabulary.
    """
    closed = detail["class"] == "closed_gate"
    refs = [f"e{index + 1}" for index, section in enumerate(sections)
            if closed or section in detail["section"]]
    limitations = ["policy_not_applicable"] if closed else ["required_evidence_section_not_collected"]
    if not closed and named_limitations:
        limitations += ["required_evidence_section_not_collected:" + section +
                        ("." + detail["field"] if detail["field"] else "") for section in detail["section"]]
    return {"claims": [
        {"id": "requirement_met", "status": "inferred" if closed else "unknown",
         "value": True if closed else None, "evidence_ids": ["e0", *refs]},
        {"id": "policy_criticality", "status": "confirmed", "value": policy_item["criticality"],
         "evidence_ids": ["e0"]},
    ], "limitations": limitations,
        "recommendations": [] if closed else ["collect_missing_evidence_section"]}
