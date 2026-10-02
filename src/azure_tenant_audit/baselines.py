"""Baseline alignment and Microsoft Secure Score reconciliation.

The report pack carries a ``baseline_alignment`` section built from the
shipped control mappings (``configs/control-mappings.json``), the framework
catalog (``configs/framework-catalog.json``), the run's findings, and the
collector coverage ledger. It answers two reviewer questions:

* Which benchmark controls did this run touch, and did they pass, fail, or go
  unassessed?
* Where does Microsoft Secure Score agree or disagree with Auditex?

Everything here is derived from local bundle data. Nothing calls a tenant.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from .resources import resolve_resource_path

BASELINE_ALIGNMENT_SCHEMA_VERSION = "2026-10-02"
BASELINE_FRAMEWORK_KEYS = ("cis_m365_v7", "cisa_scuba", "ms_secure_score", "ms_zero_trust", "mcsb")
SECURE_SCORE_LOW_THRESHOLD_PERCENT = 50.0

_FRAMEWORK_CATALOG_PATH = Path("configs/framework-catalog.json")
_CONTROL_MAPPINGS_PATH = Path("configs/control-mappings.json")

# The collector whose successful run means a rule was evaluated. Rules are
# looked up by exact id first, then by namespace (the text before the first
# dot). Add new namespaces here when a new rule family ships; unknown
# namespaces report ``not_assessed`` unless a finding fails.
_RULE_COLLECTORS = {
    "identity.global_admin_mfa_not_registered": "auth_methods",
    "identity.user_mfa_not_registered": "auth_methods",
}
_NAMESPACE_COLLECTORS = {
    "app_consent": "app_consent",
    "attack_path": "identity",
    "app_credentials": "app_credentials",
    "consent_policy": "consent_policy",
    "cross_tenant_access": "cross_tenant_access",
    "detection": "exchange_policy",
    "dns_posture": "dns_posture",
    "exchange": "exchange_policy",
    "exposure": "dns_posture",
    "external_identity": "external_identity",
    "identity": "identity",
    "intune": "intune",
    "mailbox_forwarding": "mailbox_forwarding",
    "reports_usage": "reports_usage",
    "secure_score": "defender",
    "security": "security",
    "service_health": "service_health",
    "sharepoint": "sharepoint_access",
}
_STATUS_ORDER = ("fail", "accepted_risk", "pass", "not_assessed")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(resolve_resource_path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return {}


@lru_cache(maxsize=1)
def load_framework_catalog() -> dict[str, Any]:
    payload = _read_json(_FRAMEWORK_CATALOG_PATH)
    return payload if isinstance(payload, dict) else {}


@lru_cache(maxsize=1)
def _shipped_control_mappings() -> dict[str, dict[str, list[str]]]:
    payload = _read_json(_CONTROL_MAPPINGS_PATH)
    if not isinstance(payload, Mapping):
        return {}
    return {
        str(rule_id): {str(key): [str(item) for item in value] for key, value in mapping.items() if isinstance(value, list)}
        for rule_id, mapping in payload.items()
        if isinstance(rule_id, str) and not rule_id.startswith("_") and isinstance(mapping, Mapping)
    }


def framework_entry(framework: str) -> dict[str, Any]:
    frameworks = load_framework_catalog().get("frameworks")
    entry = frameworks.get(framework) if isinstance(frameworks, Mapping) else None
    return dict(entry) if isinstance(entry, Mapping) else {}


def framework_control_title(framework: str, control_id: str) -> str | None:
    controls = framework_entry(framework).get("controls")
    if not isinstance(controls, Mapping):
        return None
    value = controls.get(control_id)
    if isinstance(value, Mapping):
        title = value.get("title")
        return str(title) if title else None
    return str(value) if value else None


def rule_evidence_collector(rule_id: str) -> str | None:
    if rule_id in _RULE_COLLECTORS:
        return _RULE_COLLECTORS[rule_id]
    return _NAMESPACE_COLLECTORS.get(rule_id.split(".", 1)[0])


def _records(snapshot: Mapping[str, Any] | None, section: str) -> list[dict[str, Any]]:
    if not isinstance(snapshot, Mapping):
        return []
    payload = snapshot.get(section)
    rows = payload.get("records") if isinstance(payload, Mapping) else None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def latest_secure_score(normalized_snapshot: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return the newest usable ``security_scores`` record with its percentage."""
    candidates = []
    for record in _records(normalized_snapshot, "security_scores"):
        current = _number(record.get("current_score"))
        maximum = _number(record.get("max_score"))
        if current is None or maximum is None or maximum <= 0:
            continue
        candidates.append((str(record.get("created") or ""), str(record.get("id") or ""), record, current, maximum))
    if not candidates:
        return None
    _, _, record, current, maximum = max(candidates, key=lambda item: (item[0], item[1]))
    return {
        "record": record,
        "id": record.get("id"),
        "created": record.get("created"),
        "current_score": current,
        "max_score": maximum,
        "percentage": round(current / maximum * 100, 1),
    }


def _open_findings_by_rule(findings: list[dict[str, Any]]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    open_by_rule: dict[str, list[str]] = defaultdict(list)
    accepted_by_rule: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if not rule_id:
            continue
        status = str(finding.get("status") or "open")
        target = open_by_rule if status == "open" else accepted_by_rule
        target[rule_id].append(str(finding.get("id") or rule_id))
    return open_by_rule, accepted_by_rule


def _microsoft_state(score: float | None, maximum: float | None, percent: float | None) -> str:
    if score is None and percent is None:
        return "no_data"
    if maximum is not None and maximum > 0 and score is not None:
        percent = score / maximum * 100
    if percent is None:
        return "no_data" if score is None else ("not_implemented" if score <= 0 else "partial")
    if percent >= 100:
        return "implemented"
    if percent <= 0:
        return "not_implemented"
    return "partial"


def _agreement(auditex_state: str, microsoft_state: str) -> str:
    if microsoft_state == "no_data":
        return "no_microsoft_data"
    microsoft_gap = microsoft_state != "implemented"
    if auditex_state == "fail":
        return "agrees" if microsoft_gap else "auditex_only"
    return "microsoft_only" if microsoft_gap else "agrees"


def build_secure_score_reconciliation(
    findings: list[dict[str, Any]],
    normalized_snapshot: Mapping[str, Any] | None,
    *,
    mappings: Mapping[str, Mapping[str, list[str]]] | None = None,
) -> dict[str, Any]:
    """Compare Microsoft Secure Score control results with Auditex findings.

    ``agreement`` values: ``agrees`` (both flag a gap, or neither does),
    ``auditex_only`` (Auditex has an open finding but Microsoft scores the
    control as fully implemented), ``microsoft_only`` (Microsoft reports a gap
    and Auditex has no open finding, which can also mean the rule was not
    assessed), ``no_microsoft_data`` (no control score in the snapshot).
    """
    mapping_rows = mappings if mappings is not None else _shipped_control_mappings()
    rules_by_control: dict[str, set[str]] = defaultdict(set)
    for rule_id, mapping in mapping_rows.items():
        for control_id in mapping.get("ms_secure_score") or []:
            rules_by_control[str(control_id)].add(rule_id)
    for finding in findings:
        framework_mappings = finding.get("framework_mappings")
        if isinstance(framework_mappings, Mapping):
            for control_id in framework_mappings.get("ms_secure_score") or []:
                rules_by_control[str(control_id)].add(str(finding.get("rule_id") or finding.get("id") or ""))

    latest = latest_secure_score(normalized_snapshot)
    control_scores: dict[str, dict[str, Any]] = {}
    if latest:
        for row in latest["record"].get("control_scores") or []:
            if isinstance(row, Mapping) and row.get("control_name"):
                control_scores[str(row["control_name"])] = dict(row)
    profiles = {
        str(record.get("id")): record
        for record in _records(normalized_snapshot, "security_score_control_profiles")
        if record.get("id")
    }
    open_by_rule, _ = _open_findings_by_rule(findings)

    rows: list[dict[str, Any]] = []
    for control_id in sorted(rules_by_control):
        rule_ids = sorted(item for item in rules_by_control[control_id] if item)
        open_ids = sorted({finding_id for rule_id in rule_ids for finding_id in open_by_rule.get(rule_id, [])})
        control_score = control_scores.get(control_id, {})
        profile = profiles.get(control_id, {})
        score = _number(control_score.get("score"))
        maximum = _number(profile.get("max_score"))
        percent = _number(control_score.get("score_in_percentage"))
        microsoft_state = _microsoft_state(score, maximum, percent)
        auditex_state = "fail" if open_ids else "no_finding"
        rows.append(
            {
                "control_profile_id": control_id,
                "title": profile.get("title") or framework_control_title("ms_secure_score", control_id),
                "microsoft_score": score,
                "microsoft_max_score": maximum,
                "microsoft_state": microsoft_state,
                "auditex_rule_ids": rule_ids,
                "auditex_state": auditex_state,
                "auditex_open_finding_count": len(open_ids),
                "auditex_finding_ids": open_ids[:20],
                "agreement": _agreement(auditex_state, microsoft_state),
            }
        )
    overall = None
    if latest:
        overall = {key: latest[key] for key in ("id", "created", "current_score", "max_score", "percentage")}
    return {
        "available": latest is not None,
        "threshold_percent": SECURE_SCORE_LOW_THRESHOLD_PERCENT,
        "overall": overall,
        "control_profile_count": len(profiles),
        "controls": rows,
        "agreement_counts": dict(sorted(_count(row["agreement"] for row in rows).items())),
    }


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for value in values:
        counts[str(value)] += 1
    return dict(counts)


def _complete_collectors(coverage_ledger: list[dict[str, Any]] | None) -> set[str]:
    complete: set[str] = set()
    for row in coverage_ledger or []:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("coverage_status") or "").startswith("complete"):
            complete.add(str(row.get("collector") or ""))
    return complete


def _rule_status(
    rule_id: str,
    open_by_rule: Mapping[str, list[str]],
    accepted_by_rule: Mapping[str, list[str]],
    complete_collectors: set[str],
) -> str:
    if open_by_rule.get(rule_id):
        return "fail"
    if accepted_by_rule.get(rule_id):
        return "accepted_risk"
    collector = rule_evidence_collector(rule_id)
    if collector and collector in complete_collectors:
        return "pass"
    return "not_assessed"


def _control_status(rule_statuses: list[str]) -> str:
    if "fail" in rule_statuses:
        return "fail"
    if "accepted_risk" in rule_statuses:
        return "accepted_risk"
    if rule_statuses and all(status == "pass" for status in rule_statuses):
        return "pass"
    return "not_assessed"


def build_baseline_alignment(
    findings: list[dict[str, Any]],
    *,
    normalized_snapshot: Mapping[str, Any] | None = None,
    coverage_ledger: list[dict[str, Any]] | None = None,
    mappings: Mapping[str, Mapping[str, list[str]]] | None = None,
) -> dict[str, Any]:
    """Per-framework control status plus Secure Score reconciliation.

    A control is ``fail`` when any mapped rule has an open finding,
    ``accepted_risk`` when the only findings are waived, ``pass`` when every
    mapped rule's evidence collector completed without a finding, and
    ``not_assessed`` otherwise.
    """
    mapping_rows = mappings if mappings is not None else _shipped_control_mappings()
    open_by_rule, accepted_by_rule = _open_findings_by_rule(findings)
    complete = _complete_collectors(coverage_ledger)

    frameworks: dict[str, Any] = {}
    for framework in BASELINE_FRAMEWORK_KEYS:
        rules_by_control: dict[str, set[str]] = defaultdict(set)
        for rule_id, mapping in mapping_rows.items():
            for control_id in mapping.get(framework) or []:
                rules_by_control[str(control_id)].add(rule_id)
        for finding in findings:
            framework_mappings = finding.get("framework_mappings")
            rule_id = str(finding.get("rule_id") or "")
            if rule_id and isinstance(framework_mappings, Mapping):
                for control_id in framework_mappings.get(framework) or []:
                    rules_by_control[str(control_id)].add(rule_id)
        controls = []
        for control_id in sorted(rules_by_control):
            rule_ids = sorted(rules_by_control[control_id])
            statuses = [_rule_status(rule_id, open_by_rule, accepted_by_rule, complete) for rule_id in rule_ids]
            finding_ids = sorted({fid for rule_id in rule_ids for fid in open_by_rule.get(rule_id, [])})
            controls.append(
                {
                    "control_id": control_id,
                    "title": framework_control_title(framework, control_id),
                    "status": _control_status(statuses),
                    "rule_ids": rule_ids,
                    # A list, not a mapping: rule ids such as
                    # ``app_credentials.*`` would trip the bundle's
                    # sensitive-key scan if used as object keys.
                    "rule_statuses": [
                        {"rule_id": rule_id, "status": status} for rule_id, status in zip(rule_ids, statuses)
                    ],
                    "open_finding_count": len(finding_ids),
                    "finding_ids": finding_ids[:20],
                }
            )
        entry = framework_entry(framework)
        status_counts = _count(control["status"] for control in controls)
        frameworks[framework] = {
            "title": entry.get("title"),
            "version": entry.get("version"),
            "published": entry.get("published"),
            "status_counts": {status: status_counts.get(status, 0) for status in _STATUS_ORDER},
            "controls": controls,
        }
    return {
        "schema_version": BASELINE_ALIGNMENT_SCHEMA_VERSION,
        "catalog_verified_on": load_framework_catalog().get("verified_on"),
        "assessed_collectors": sorted(item for item in complete if item),
        "frameworks": frameworks,
        "secure_score": build_secure_score_reconciliation(findings, normalized_snapshot, mappings=mapping_rows),
    }
