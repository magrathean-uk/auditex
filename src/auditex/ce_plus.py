"""CE+ practice run: evidence observed and proof still needed per Cyber Essentials requirement (DEC-146).

A pure function of one finished run bundle's ``baseline_alignment.frameworks.cyber_essentials`` section, its run
manifest, the shipped action catalogue (``configs/ce-plus-practice.json``) and an as-of date. It adds no verdict:
every state is re-worded from the section the value rules and the Google findings already wrote. Unknown is never
folded into observed: an unevaluated rule, an empty rule list or a malformed row reads ``evidence_unknown``.

The output carries ids, counts, catalogue text and dates only; tenant free text (policy or user names, finding titles)
is never copied. Finding ids are the only tenant-derived strings.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import UTC, date, datetime
from typing import Any

from azure_tenant_audit.baselines import rule_evidence_collectors
from azure_tenant_audit.collection_gaps import list_truncations, section_gap_records

SCHEMA_VERSION = "ce-plus-practice-v1"
PAYLOAD_KIND = "ce_plus_practice_run"
CATALOGUE_PATH = "configs/ce-plus-practice.json"
FRAMEWORK_CATALOGUE_PATH = "configs/framework-catalog.json"

EVIDENCE_STATES = (
    "gap_observed",
    "evidence_unknown",
    "gap_accepted",
    "supporting_only",
    "evidence_observed_partial",
    "outside_tenant_evidence",
)
RULE_STATES = ("gap_found", "no_gap_found", "not_evaluated", "accepted_risk")
EVIDENCE_FLAGS = ("missing", "truncated", "stale", "conflicting")
RUN_FLAGS = (*EVIDENCE_FLAGS, "requirements_version_mismatch")
PLATFORMS = ("m365", "google_workspace", "unknown")
REQUIREMENT_STATUSES = ("automated", "partial", "manual", "ce_plus_assessor_test", "provider_responsibility")
OUTSIDE_TENANT_STATUSES = frozenset({"manual", "ce_plus_assessor_test", "provider_responsibility"})
TENANT_EVIDENCE_STATUSES = frozenset({"automated", "partial"})
WITNESS_STATUS = "assessor_witness_required"

REASON_SECTION_MISSING = "cyber_essentials_section_missing"
REASON_ROW_MALFORMED = "row_missing_or_malformed"
REASON_STATE_UNREADABLE = "state_unreadable"
REASON_STATUS_UNREADABLE = "status_unreadable"
_ROW_REASONS = frozenset({REASON_SECTION_MISSING, REASON_ROW_MALFORMED, REASON_STATE_UNREADABLE})

_RULE_STATUS_WORDS = {
    "fail": "gap_found",
    "pass": "no_gap_found",
    "not_assessed": "not_evaluated",
    "accepted_risk": "accepted_risk",
}
_CONFIDENCE_VALUES = ("full", "partial", "supporting")
_PARTIAL_NO_GAP_REASON = "partial_requirement_no_gap_found"
_SUPPORTING_REASONS = frozenset({"supporting_evidence_only", "no_mapped_rules"})
_FINDING_ID_LIMIT = 20

DISCLAIMER = (
    "This practice run lists the evidence observed in one read-only audit and the proof still needed. It is not a "
    "Cyber Essentials or Cyber Essentials Plus assessment and gives no assessment result: only an authorised "
    "assessor decides the outcome. It covers one cloud tenant and no device, network or other service."
)


def load_catalogue() -> dict[str, Any]:
    """The shipped action catalogue, with the requirement titles and themes of the shipped framework catalogue."""
    from azure_tenant_audit.resources import open_text_resource

    catalogue = json.loads(open_text_resource(CATALOGUE_PATH))
    framework = json.loads(open_text_resource(FRAMEWORK_CATALOGUE_PATH))["frameworks"]["cyber_essentials"]
    controls = framework["controls"]
    catalogue["requirements"] = [
        {
            "requirement_id": note["requirement_id"],
            "title": controls[note["requirement_id"]]["title"],
            "theme": controls[note["requirement_id"]]["theme"],
            "requirement_status": controls[note["requirement_id"]]["status"],
            "evidence_limits": note["evidence_limits"],
        }
        for note in catalogue["requirement_notes"]
    ]
    return catalogue


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _platform(manifest: Mapping[str, Any]) -> str:
    value = manifest.get("platform", "m365")
    if value is None:
        return "m365"
    return value if value in ("m365", "google_workspace") else "unknown"


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _as_of_date(as_of: date | datetime | None) -> date | None:
    if isinstance(as_of, datetime):
        return as_of.astimezone(UTC).date() if as_of.tzinfo else as_of.date()
    return as_of if isinstance(as_of, date) else None


def evidence_age_days(created_utc: Any, as_of: date | datetime | None) -> int | None:
    """Whole days from the run's evidence date to ``as_of``; ``None`` when either is not established."""
    created = _parse_utc(created_utc)
    day = _as_of_date(as_of)
    if created is None or day is None:
        return None
    age = (day - created.astimezone(UTC).date()).days
    return age if age >= 0 else None


def _rule_state(item: Mapping[str, Any]) -> dict[str, Any]:
    status = item.get("status")
    state = _RULE_STATUS_WORDS.get(status) if isinstance(status, str) else None
    reason = _text(item.get("reason"))
    if state is None:
        state, reason = "not_evaluated", REASON_STATUS_UNREADABLE
    elif item.get("evaluated") is not True and state != "not_evaluated":
        # A verdict on a rule that was not evaluated is not evidence either way.
        state, reason = "not_evaluated", reason or REASON_STATUS_UNREADABLE
    elif state == "not_evaluated" and reason is None:
        reason = REASON_STATUS_UNREADABLE
    confidence = item.get("confidence")
    row: dict[str, Any] = {
        "rule_id": item["rule_id"],
        "state": state,
        "confidence": confidence if confidence in _CONFIDENCE_VALUES else "partial",
    }
    if state == "not_evaluated" and reason:
        row["reason"] = reason
    return row


def _read_rules(row: Mapping[str, Any]) -> tuple[list[dict[str, Any]], bool, bool]:
    """(rule states, list readable, every entry readable) from a section row's ``rule_statuses``."""
    raw = row.get("rule_statuses")
    if not isinstance(raw, list):
        return [], False, False
    states = []
    clean = True
    for item in raw:
        if not isinstance(item, Mapping) or not _text(item.get("rule_id")):
            clean = False
            continue
        states.append(_rule_state(item))
    return states, True, clean


def _evidence_state(
    row: Any, requirement_status: str | None, rules: list[dict[str, Any]], readable: bool, clean: bool
) -> tuple[str, list[str]]:
    if not isinstance(row, Mapping) or requirement_status is None:
        return "evidence_unknown", [REASON_ROW_MALFORMED]
    if requirement_status in OUTSIDE_TENANT_STATUSES:
        return "outside_tenant_evidence", []
    status = row.get("status")
    if status == "fail":
        return "gap_observed", []
    if status == "accepted_risk":
        return "gap_accepted", []
    if row.get("reason") in _SUPPORTING_REASONS:
        return "supporting_only", []
    deciding = [rule for rule in rules if rule["confidence"] != "supporting"]
    unevaluated = [rule for rule in deciding if rule["state"] == "not_evaluated"]
    if unevaluated or not clean:
        reasons = {rule.get("reason") or REASON_STATUS_UNREADABLE for rule in unevaluated}
        if not clean:
            reasons.add(REASON_STATUS_UNREADABLE)
        return "evidence_unknown", sorted(reasons)
    clean_result = status == "pass" or (status == "not_assessed" and row.get("reason") == _PARTIAL_NO_GAP_REASON)
    if readable and deciding and clean_result and all(rule["state"] == "no_gap_found" for rule in deciding):
        return "evidence_observed_partial", []
    return "evidence_unknown", [REASON_STATE_UNREADABLE]


def _conflict_holds(conflict: Mapping[str, Any], states: Mapping[str, str]) -> bool:
    policy = conflict.get("policy_rule_ids") or []
    state_rules = conflict.get("state_rule_ids") or []
    return bool(policy) and all(states.get(rule) == "no_gap_found" for rule in policy) and any(
        states.get(rule) == "gap_found" for rule in state_rules
    )


def _platform_matches(platforms: Iterable[str], platform: str) -> bool:
    platforms = list(platforms)
    return "any" in platforms or (platform != "unknown" and platform in platforms)


def _truncated_collectors(manifest: Mapping[str, Any], coverage_rows: list[Any] | None) -> tuple[list[dict[str, str]], set[str]]:
    records: dict[tuple[str, str], dict[str, str]] = {}
    rows = coverage_rows or []
    for item in list_truncations(rows):
        records[(item["collector"], item["list"])] = {"collector": item["collector"], "list": item["list"], "reason": item["reason"]}
    for item in section_gap_records(rows):
        collector, section = str(item.get("collector") or ""), str(item.get("section") or "")
        records.setdefault((collector, section), {"collector": collector, "list": section, "reason": "section_gap"})
    gaps = manifest.get("coverage_gaps")
    for gap in gaps if isinstance(gaps, list) else []:
        if not isinstance(gap, Mapping):
            continue
        for key, field, default in (("truncated_lists", "list", "truncated"), ("section_gaps", "section", "section_gap")):
            entries = gap.get(key)
            for entry in entries if isinstance(entries, list) else []:
                if isinstance(entry, Mapping) and _text(entry.get("collector")) and _text(entry.get(field)):
                    reason = _text(entry.get("reason")) if key == "truncated_lists" else None
                    records.setdefault(
                        (entry["collector"], entry[field]),
                        {"collector": entry["collector"], "list": entry[field], "reason": reason or default},
                    )
    rows_out = [records[key] for key in sorted(records) if key[0] and key[1]]
    return rows_out, {row["collector"] for row in rows_out}


def _ranking_formula(catalogue: Mapping[str, Any]) -> str:
    states = ", ".join(f"{row['state']} {row['weight']}" for row in catalogue["state_weights"])
    bands = ", ".join(f"{row['id']} {row['weight']}" for row in catalogue["effort_bands"])
    return (
        "rank_score = coverage_gained * 4 // effort_weight. coverage_gained is the sum, over the requirements an "
        f"action applies to, of the state weight ({states}) plus {catalogue['conflict_weight']} where a conflict "
        f"holds. effort_weight: {bands}. Ties go to the lower effort weight, then the action id. The weights are "
        "Auditex product defaults, not scheme rules."
    )


def _section_rows(section: Any) -> tuple[dict[str, Any] | None, str | None, list[str]]:
    """(rows by requirement id, section version, ids in order) or (None, None, []) for a missing section."""
    if not isinstance(section, Mapping) or not isinstance(section.get("controls"), list):
        return None, None, []
    rows: dict[str, Any] = {}
    order: list[str] = []
    for row in section["controls"]:
        requirement_id = _text(row.get("control_id")) if isinstance(row, Mapping) else None
        if requirement_id is None or requirement_id in rows:
            continue
        rows[requirement_id] = row
        order.append(requirement_id)
    return rows, _text(section.get("version")), order


def build_practice_run(
    section: Any,
    manifest: Mapping[str, Any],
    catalogue: Mapping[str, Any],
    *,
    as_of: date | datetime | None,
    coverage_rows: list[Any] | None = None,
    collector_coverage: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The practice-run payload (``schemas/ce_plus_practice.schema.json``)."""
    manifest = manifest if isinstance(manifest, Mapping) else {}
    platform = _platform(manifest)
    created = _parse_utc(manifest.get("created_utc"))
    age = evidence_age_days(manifest.get("created_utc"), as_of)
    stale = age is not None and age > int(catalogue["stale_after_days"])
    state_weights = {row["state"]: int(row["weight"]) for row in catalogue["state_weights"]}
    effort_weights = {row["id"]: int(row["weight"]) for row in catalogue["effort_bands"]}
    conflict_weight = int(catalogue["conflict_weight"])

    rows_by_id, section_version, section_order = _section_rows(section)
    truncated_lists, truncated_collectors = _truncated_collectors(manifest, coverage_rows)
    coverage = collector_coverage or {}
    incomplete = sorted(str(name) for name, row in coverage.items() if not (isinstance(row, Mapping) and row.get("complete") is True))
    coverage_data = "available" if coverage_rows or coverage else "unavailable"
    catalogue_ids = [row["requirement_id"] for row in catalogue["requirements"]]

    requirements: list[dict[str, Any]] = []
    held_conflicts: dict[str, list[dict[str, str]]] = {}
    rule_states_by_requirement: dict[str, dict[str, str]] = {}
    for spec in catalogue["requirements"]:
        requirement_id = spec["requirement_id"]
        row = rows_by_id.get(requirement_id) if rows_by_id is not None else None
        requirement_status = row.get("requirement_status") if isinstance(row, Mapping) else None
        requirement_status = requirement_status if requirement_status in REQUIREMENT_STATUSES else None
        rules, readable, clean = _read_rules(row) if isinstance(row, Mapping) else ([], False, False)
        if rows_by_id is None:
            state, reasons = "evidence_unknown", [REASON_SECTION_MISSING]
        else:
            state, reasons = _evidence_state(row, requirement_status, rules, readable, clean)
        tenant_evidence = requirement_status in TENANT_EVIDENCE_STATUSES
        deciding = [rule for rule in rules if rule["confidence"] != "supporting"] if tenant_evidence else []
        unevaluated = [rule for rule in deciding if rule["state"] == "not_evaluated"]
        flags: list[str] = []
        if unevaluated or state == "evidence_unknown":
            flags.append("missing")
        unknown_reasons = sorted({*(rule.get("reason") or REASON_STATUS_UNREADABLE for rule in unevaluated), *reasons})
        feeding = {collector for rule in deciding for collector in rule_evidence_collectors(rule["rule_id"])}
        if feeding & truncated_collectors:
            flags.append("truncated")
        if stale and (tenant_evidence or requirement_status is None):
            flags.append("stale")
        states = {rule["rule_id"]: rule["state"] for rule in deciding}
        rule_states_by_requirement[requirement_id] = states
        conflicts = [
            {"conflict_id": conflict["id"], "note": conflict["note"]}
            for conflict in catalogue["conflicts"]
            if conflict["requirement_id"] == requirement_id
            and _platform_matches(conflict["platforms"], platform)
            and "any" not in conflict["platforms"]
            and _conflict_holds(conflict, states)
        ]
        if conflicts:
            flags.append("conflicting")
            held_conflicts[requirement_id] = conflicts
        finding_ids = row.get("finding_ids") if isinstance(row, Mapping) else None
        finding_ids = [item for item in finding_ids if isinstance(item, str) and item] if isinstance(finding_ids, list) else []
        open_count = row.get("open_finding_count") if isinstance(row, Mapping) else None
        requirements.append(
            {
                "requirement_id": requirement_id,
                "title": spec["title"],
                "theme": spec["theme"],
                "requirement_status": requirement_status or spec["requirement_status"],
                "evidence_state": state,
                "evidence_flags": flags,
                "unknown_reasons": unknown_reasons,
                "evidence_observed": {
                    "rules_mapped": len(rules),
                    "rules_evaluated": sum(1 for rule in rules if rule["state"] != "not_evaluated"),
                    "rules_with_gap": sum(1 for rule in rules if rule["state"] == "gap_found"),
                    "open_finding_count": open_count if isinstance(open_count, int) and not isinstance(open_count, bool) and open_count >= 0 else None,
                    "finding_ids": finding_ids[:_FINDING_ID_LIMIT],
                    "rule_states": rules,
                },
                "conflicts": conflicts,
                "evidence_limits": spec["evidence_limits"],
                "proof_still_needed": [],
                "assessor_test_ids": [
                    test["id"] for test in catalogue["assessor_tests"] if requirement_id in test["requirement_ids"]
                ],
            }
        )
    by_id = {row["requirement_id"]: row for row in requirements}

    def triggers(action: Mapping[str, Any], requirement: Mapping[str, Any]) -> list[str]:
        trigger = action["trigger"]
        requirement_id = requirement["requirement_id"]
        states = rule_states_by_requirement.get(requirement_id, {})
        if trigger == "rule_gap":
            return [rule for rule in action["rule_ids"] if states.get(rule) == "gap_found"]
        if trigger == "rule_not_evaluated":
            listed = action["rule_ids"] or list(states)
            hits = [rule for rule in listed if states.get(rule) == "not_evaluated"]
            if not action["rule_ids"] and requirement["evidence_state"] == "evidence_unknown":
                hits += [reason for reason in requirement["unknown_reasons"] if reason in _ROW_REASONS]
            return hits
        if trigger == "conflict":
            held = {item["conflict_id"] for item in held_conflicts.get(requirement_id, [])}
            return [conflict for conflict in action["conflict_ids"] if conflict in held]
        if trigger == "requirement_state":
            return [requirement["evidence_state"]] if requirement["evidence_state"] in action["states"] else []
        if trigger == "assessor_test":
            return ["assessor_test"]
        if trigger == "stale_evidence":
            return ["stale"] if "stale" in requirement["evidence_flags"] else []
        return []

    ranked: list[dict[str, Any]] = []
    for action in catalogue["actions"]:
        if not _platform_matches(action["platforms"], platform):
            continue
        coverage_rows_out: list[dict[str, Any]] = []
        triggered: set[str] = set()
        for requirement_id in action["requirement_ids"]:
            requirement = by_id.get(requirement_id)
            if requirement is None:
                continue
            hits = triggers(action, requirement)
            if not hits:
                continue
            triggered.update(hits)
            weight = state_weights[requirement["evidence_state"]]
            if requirement_id in held_conflicts:
                weight += conflict_weight
            coverage_rows_out.append(
                {"requirement_id": requirement_id, "evidence_state": requirement["evidence_state"], "weight": weight}
            )
        if not coverage_rows_out:
            continue
        gained = sum(row["weight"] for row in coverage_rows_out)
        effort_weight = effort_weights[action["effort"]]
        ranked.append(
            {
                "action_id": action["id"],
                "title": action["title"],
                "kind": action["kind"],
                "effort": action["effort"],
                "effort_weight": effort_weight,
                "coverage": coverage_rows_out,
                "coverage_gained": gained,
                "rank_score": gained * 4 // effort_weight,
                "proof_to_gather": action["proof_to_gather"],
                "triggered_by": sorted(triggered),
            }
        )
    ranked.sort(key=lambda row: (-row["rank_score"], row["effort_weight"], row["action_id"]))
    next_actions = [{"rank": index, **row} for index, row in enumerate(ranked, start=1)]
    for action in next_actions:
        for row in action["coverage"]:
            by_id[row["requirement_id"]]["proof_still_needed"].append(action["action_id"])

    run_flags = [flag for flag in EVIDENCE_FLAGS if any(flag in row["evidence_flags"] for row in requirements)]
    version_mismatch = rows_by_id is not None and section_version != catalogue["requirements_version"]
    if version_mismatch:
        run_flags.append("requirements_version_mismatch")
    by_state = {state: sum(1 for row in requirements if row["evidence_state"] == state) for state in EVIDENCE_STATES}
    source = catalogue["source"]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": PAYLOAD_KIND,
        "catalogue_version": catalogue["catalogue_version"],
        "requirements_version": catalogue["requirements_version"],
        "test_specification_version": catalogue["test_specification_version"],
        "disclaimer": DISCLAIMER,
        "ranking_formula": _ranking_formula(catalogue),
        "run": {
            "run_id": _text(manifest.get("run_id")),
            "tenant_name": _text(manifest.get("tenant_name")),
            "platform": platform,
            "evidence_collected_utc": created.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if created else None,
            "as_of": _as_of_date(as_of).isoformat() if _as_of_date(as_of) else None,
            "evidence_age_days": age,
        },
        "evidence_quality": {
            "flags": run_flags,
            "coverage_data": coverage_data,
            "incomplete_collectors": incomplete,
            "truncated_lists": truncated_lists,
            "unmapped_requirement_ids": [rid for rid in section_order if rid not in catalogue_ids],
        },
        "summary": {
            "requirements_total": len(requirements),
            "by_evidence_state": by_state,
            "next_action_count": len(next_actions),
            "conflict_count": sum(len(items) for items in held_conflicts.values()),
        },
        "requirements": requirements,
        "next_actions": next_actions,
        "assessor_tests": [
            {
                "test_id": test["id"],
                "number": test["number"],
                "title": test["title"],
                "auditex_prepares": test["auditex_prepares"],
                "assessor_witnesses": test["assessor_witnesses"],
                "requirement_ids": list(test["requirement_ids"]),
                "linked_evidence": [
                    {
                        "requirement_id": requirement_id,
                        "evidence_state": by_id[requirement_id]["evidence_state"],
                        "evidence_flags": list(by_id[requirement_id]["evidence_flags"]),
                    }
                    for requirement_id in test["requirement_ids"]
                ],
                "prepare_action_ids": list(test["prepare_action_ids"]),
                "witness_status": WITNESS_STATUS,
            }
            for test in catalogue["assessor_tests"]
        ],
        "source": {
            "document_title": source["document_title"],
            "document_url": source["document_url"],
            "licence": source["licence"],
        },
    }
