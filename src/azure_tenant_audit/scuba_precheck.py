"""Data-driven SCuBA applicability checks shared by serving and oracle generation.

Only explicit, typed values close gates. Lists representing singleton tenant
objects are accepted; empty, ambiguous or malformed objects fail closed.
"""
from __future__ import annotations

import json
import math
from typing import Any

from .collection_markers import NOT_COLLECTED
from .resources import open_text_resource


def optional_collection_entry() -> dict[str, Any]:
    """Constant, policy-scoped optional-collection contract; no evidence text."""
    from .value_rules.catalogue import catalogue
    return catalogue()["optional_collection"]


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


def check_lists(policy_id: str, projection: dict[str, Any]) -> dict[str, Any] | None:
    """Return a registered list section that was collected and is exactly empty.

    Every registered policy passes only when some entry of that list satisfies
    it, so an empty list is not met. ``unless`` leaves the row to the model when
    a not-applicable branch could apply (a listed value at the path) or the path
    does not run through objects; a missing final key is Rego's undefined, which
    does not open that branch.
    """
    for rule in rule_catalogue()["list_rules"]:
        if rule["policy_id"] != policy_id:
            continue
        value = projection.get(rule["section"])
        if type(value) is not list or value:
            continue
        blocked = False
        for condition in rule["unless"]:
            found = projection.get(condition["section"])
            for part in condition["path"]:
                if not isinstance(found, dict):
                    blocked = True
                    break
                found = found.get(part)
            if blocked or any(type(found) is type(target) and found == target for target in condition["values"]):
                blocked = True
                break
        if not blocked:
            return {"class": "empty_required_list", "rule_id": rule["rule_id"], "section": [rule["section"]],
                    "field": None, "value": None}
    return None


def precheck_policy(policy_id: str, projection: dict[str, Any], sections: list[str], *,
                    skip_absent_sections: bool = False, absent_fields: bool = False,
                    empty_lists: bool = False, value_rules: bool = False) -> dict[str, Any] | None:
    """A usable closed gate wins over absent dependent evidence.

    The serving caller alone opts out for the entirely empty P1 projection.
    Pack evaluation never opts out. A missing gate is included in the absence
    class, with ``field`` naming the unavailable input. ``absent_fields`` adds
    the field-level class after both, and ``empty_lists`` the empty required
    list after that; serving enables both, the oracle generator neither.
    """
    if skip_absent_sections:
        return None
    if value_rules:
        from .value_rules import assess
        from .value_rules.catalogue import row_for
        row = row_for(policy_id)
        if row is not None:
            # assess runs the whole value-rule order: the shared closed gate (rendered as the rule's
            # closed_gate cell), then missing or marked rule sections, then the kind, which always answers.
            result = assess(policy_id, projection)
            if result is not None:
                cited = result["cited_sections"] or list(row["sections"])
                return {"class": "value_rule", "rule_id": row["rule_id"],
                        "section": cited, "field": None, "value": None,
                        "cell": result["cell"], "reason_code": result["reason_code"],
                        "reason_text": result["reason_text"]}
    gate = check_gate(policy_id, projection)
    if gate and gate["class"] == "closed_gate":
        return gate
    missing = unavailable_input_sections(projection, sections)
    if missing:
        return {"class": "absent_section", "rule_id": "required_sections_present",
                "section": missing, "field": None, "value": None}
    if gate is None and absent_fields:
        gate = check_fields(policy_id, projection)
    if gate is None and empty_lists:
        gate = check_lists(policy_id, projection)
    return gate


def precheck_response(detail: dict[str, Any], policy_item: dict[str, Any], sections: list[str], *,
                      named_limitations: bool = True, legacy: bool | None = None) -> dict[str, Any]:
    """Render the pack verdict; serving also names each unavailable input.

    An empty required list is the oracle's not-met shape: confirmed false citing
    every section, no limitation, the baseline-review recommendation.

    The named limitations are assessment-contract extensions, not new pack
    vocabulary. Offline scoring compares the original pack response vocabulary.
    """
    optional = optional_collection_entry()
    if detail.get("reason_code") == optional["reason_code"]:
        return {"claims": [
            {"id": "requirement_met", "status": "unknown", "value": None,
             "evidence_ids": ["e0", *(f"e{i + 1}" for i, s in enumerate(sections) if s in detail["section"])]},
            {"id": "policy_criticality", "status": "confirmed", "value": policy_item["criticality"],
             "evidence_ids": ["e0"]},
        ], "limitations": [optional["reason_code"]], "recommendations": []}
    if detail["class"] == "value_rule":
        from .value_rules.catalogue import row_for
        from .value_rules.record import (
            RULE_FAILURE_CODE,
            RULE_NOT_IMPLEMENTED_CODE,
            as_pack_response,
            evidence_kind,
            is_shared_reason,
        )
        # A1.2: a shared reason (failed rule, no rule) has no cell and is dispatched before any cell lookup.
        shared = detail["cell"] is None
        if detail["cell"] in {RULE_FAILURE_CODE, RULE_NOT_IMPLEMENTED_CODE}:
            raise ValueError("Legacy rule-failure sentinel: a shared reason is not a cell, its cell must be null")
        if shared and not is_shared_reason(detail["reason_code"]):
            raise ValueError("A value-rule answer without a cell must carry a shared reason")
        row = row_for(policy_item["policy_id"])
        verdict = "not_assessed" if shared else row["cells"][detail["cell"]]["verdict"]
        record = {"verdict": verdict, "cell": detail["cell"], "reason_code": detail["reason_code"],
                  "cited_sections": detail["section"] if verdict == "not_assessed" else None}
        # The unnamed form is offline pack scoring; retain its original vocabulary.
        legacy = not named_limitations if legacy is None else legacy
        response = as_pack_response(record, policy_item["criticality"], sections, legacy=legacy)
        if verdict == "not_assessed" and named_limitations and not shared:
            kind = None if legacy else evidence_kind(detail["reason_code"])
            response["limitations"] += [(f"evidence_unusable:{name}:{kind}" if kind else
                                         "required_evidence_section_not_collected:" + name)
                                        for name in detail["section"]]
        return response
    if detail["class"] == "empty_required_list":
        return {"claims": [
            {"id": "requirement_met", "status": "confirmed", "value": False,
             "evidence_ids": ["e0", *(f"e{index + 1}" for index in range(len(sections)))]},
            {"id": "policy_criticality", "status": "confirmed", "value": policy_item["criticality"],
             "evidence_ids": ["e0"]},
        ], "limitations": [], "recommendations": ["review_policy_against_baseline_text"]}
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
