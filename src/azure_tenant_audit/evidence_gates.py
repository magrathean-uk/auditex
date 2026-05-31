from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .capability_gate import capability_blocker_summary, classify_capability_blocker


_TRUSTED_CAPABILITY_STATUSES = {
    "ok",
    "supported",
    "supported_exact_scope",
    "supported_equivalent_scope",
    "supported_effective_role",
    "complete",
    "complete_exact_scope",
    "complete_equivalent_scope",
    "complete_effective_role",
    "complete_offline_sample",
    "offline_sample",
}

_PARTIAL_CAPABILITY_STATUSES = {"partial", "setup_only", "unknown"}


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def capability_status(row: Mapping[str, Any] | None) -> str:
    if row is None:
        return "unverified"
    raw_status = str(row.get("status") or "unknown")
    if raw_status in _TRUSTED_CAPABILITY_STATUSES:
        return "complete"
    if raw_status in _PARTIAL_CAPABILITY_STATUSES:
        return "partial"
    if raw_status.startswith("blocked") or raw_status in {"failed", "unauthenticated", "unsupported"}:
        return "blocked"
    return "unverified"


def build_evidence_gate_summary(
    *,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    dependency_available: bool = True,
) -> dict[str, Any]:
    selected = [str(item) for item in selected_collectors if str(item)]
    rows_by_collector = {
        str(row.get("collector") or row.get("name") or ""): row
        for row in _rows(capability_rows)
        if row.get("collector") or row.get("name")
    }

    trusted: list[str] = []
    partial: list[str] = []
    blocked: list[str] = []
    unverified: list[str] = []
    missing_permissions: dict[str, list[str]] = {}
    evidence_gates: list[dict[str, Any]] = []

    if not dependency_available:
        for collector in selected:
            gate = {
                "collector": collector,
                "status": "blocked",
                "required_permissions": [],
                "missing_permissions": [],
                "reason": "dependency_unavailable",
                "blocker_kind": "local_tool",
                "blocker_reason": "required local dependency is unavailable",
                "next_step": "Install the missing dependency, then rerun probe.",
            }
            blocked.append(collector)
            evidence_gates.append(gate)
    else:
        for collector in selected:
            row = rows_by_collector.get(collector)
            status = capability_status(row)
            missing = _strings(row.get("missing_permissions")) if row else []
            if status == "complete":
                trusted.append(collector)
            elif status == "partial":
                partial.append(collector)
            elif status == "blocked":
                blocked.append(collector)
            else:
                unverified.append(collector)
            if missing:
                missing_permissions[collector] = missing
            blocker = classify_capability_blocker(row)
            evidence_gates.append(
                {
                    "collector": collector,
                    "status": status,
                    "required_permissions": _strings(row.get("required_permissions")) if row else [],
                    "missing_permissions": missing,
                    "reason": str(row.get("reason") or "") if row else "not live-verified",
                    "blocker_kind": blocker["blocker_kind"],
                    "blocker_reason": blocker["blocker_reason"],
                    "next_step": blocker["next_step"],
                }
            )

    cannot_trust = [*blocked, *partial, *unverified]
    if not selected:
        trust_level = "unknown"
    elif not dependency_available:
        trust_level = "blocked"
    elif not capability_rows and unverified:
        trust_level = "setup_only"
    elif trusted and not cannot_trust:
        trust_level = "live_verified"
    elif trusted:
        trust_level = "partial"
    elif blocked:
        trust_level = "blocked"
    else:
        trust_level = "setup_only"

    return {
        "trust_level": trust_level,
        "selected_collectors": selected,
        "evidence_gates": evidence_gates,
        "trusted_collectors": trusted,
        "partial_collectors": partial,
        "blocked_collectors": blocked,
        "unverified_collectors": unverified,
        "can_trust": trusted,
        "cannot_trust": cannot_trust,
        "missing_permissions": missing_permissions,
        "blocker_summary": capability_blocker_summary(evidence_gates),
        "statement": (
            "Live evidence is verified for all selected collectors."
            if trust_level == "live_verified"
            else "Some selected audit data is blocked, partial, or not live-verified."
        ),
    }
