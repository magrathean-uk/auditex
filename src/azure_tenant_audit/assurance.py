from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from .capability_gate import capability_blocker_summary, classify_capability_blocker
from .evidence_gates import build_evidence_gate_summary


_GOOGLE_SURFACES = {
    "google_directory": ("identity",),
    "google_reports": ("audit_logs",),
    "google_alert_center": ("security",),
    "google_gmail_settings": ("mail",),
    "google_devices": ("devices",),
    "google_dns_posture": ("dns",),
    "google_drive_posture": ("collaboration", "data_exposure"),
    "google_groups_settings": ("collaboration",),
    "google_calendar_posture": ("calendar", "collaboration", "data_exposure"),
}

_M365_SURFACES = {
    "identity": ("identity",),
    "auth_methods": ("identity",),
    "conditional_access": ("identity", "security"),
    "security": ("security",),
    "defender": ("security",),
    "defender_cloud_apps": ("security",),
    "sentinel_xdr": ("security",),
    "reports_usage": ("audit_logs",),
    "service_health": ("operations",),
    "domains_hybrid": ("dns", "identity"),
    "dns_posture": ("dns",),
    "mail": ("mail",),
    "exchange": ("mail",),
    "exchange_policy": ("mail",),
    "mailbox_forwarding": ("mail",),
    "sharepoint": ("collaboration",),
    "sharepoint_access": ("collaboration", "data_exposure"),
    "onedrive_posture": ("collaboration", "data_exposure"),
    "teams": ("collaboration",),
    "teams_policy": ("collaboration",),
    "app_consent": ("apps",),
    "app_credentials": ("apps",),
    "consent_policy": ("apps",),
    "external_identity": ("identity",),
    "cross_tenant_access": ("identity", "external_access"),
    "identity_governance": ("governance",),
    "intune": ("devices",),
    "intune_depth": ("devices",),
    "purview": ("data_protection",),
    "ediscovery": ("data_protection",),
    "licensing": ("operations",),
    "power_platform": ("apps", "governance"),
    "copilot_governance": ("governance",),
}

_SURFACE_ORDER = (
    "identity",
    "security",
    "audit_logs",
    "mail",
    "collaboration",
    "data_exposure",
    "devices",
    "dns",
    "apps",
    "external_access",
    "governance",
    "data_protection",
    "calendar",
    "operations",
    "other",
)

_SURFACE_SCORES = {
    "complete": 100,
    "partial": 60,
    "blocked": 0,
    "unknown": 0,
}

def _status_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(row.get("status") or "unknown") for row in rows if isinstance(row, Mapping))
    return {key: counts[key] for key in sorted(counts)}


def _grade(score: int) -> str:
    if score == 100:
        return "complete"
    if score >= 85:
        return "strong"
    if score >= 65:
        return "usable"
    if score > 0:
        return "weak"
    return "blocked"


def build_assurance_summary(
    *,
    collector_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    sample_truncated: bool = False,
) -> dict[str, Any]:
    collector_counts = _status_counts(collector_rows)
    coverage_counts = _status_counts(coverage_rows)
    penalty = 0
    penalty += collector_counts.get("failed", 0) * 25
    penalty += collector_counts.get("partial", 0) * 15
    penalty += coverage_counts.get("failed", 0) * 5
    penalty += coverage_counts.get("partial", 0) * 3
    if sample_truncated:
        penalty += 10
    score = max(0, min(100, 100 - penalty))
    return {
        "score": score,
        "grade": _grade(score),
        "collector_count": len(collector_rows),
        "coverage_row_count": len(coverage_rows),
        "sample_truncated": bool(sample_truncated),
        "collector_status_counts": collector_counts,
        "coverage_status_counts": coverage_counts,
    }


def _collector_surfaces(name: str, platform: str) -> tuple[str, ...]:
    mapping = _GOOGLE_SURFACES if platform == "google_workspace" else _M365_SURFACES
    return mapping.get(name, ("other",))


def _surface_status(status_counts: dict[str, int]) -> str:
    if status_counts.get("ok") and not (status_counts.get("partial") or status_counts.get("failed")):
        return "complete"
    if status_counts.get("ok") or status_counts.get("partial"):
        return "partial"
    if status_counts.get("failed"):
        return "blocked"
    return "unknown"


def _row_name(row: dict[str, Any]) -> str:
    return str(row.get("name") or row.get("collector") or "")


def _gap_severity(status: str) -> str:
    if status == "blocked":
        return "high"
    if status == "partial":
        return "medium"
    return "low"


def _scorecard_grade(score: int) -> str:
    if score >= 95:
        return "complete"
    if score >= 85:
        return "strong"
    if score >= 65:
        return "usable"
    if score > 0:
        return "weak"
    return "blocked"


def _surface_sort_key(row: dict[str, Any]) -> tuple[int, str]:
    surface = str(row.get("surface") or "other")
    try:
        index = _SURFACE_ORDER.index(surface)
    except ValueError:
        index = len(_SURFACE_ORDER)
    return (index, surface)


def build_live_readiness_summary(
    *,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    dependency_available: bool = True,
) -> dict[str, Any]:
    return build_evidence_gate_summary(
        selected_collectors=selected_collectors,
        capability_rows=capability_rows,
        dependency_available=dependency_available,
    )


def build_surface_coverage_map(
    *,
    collector_rows: list[dict[str, Any]],
    platform: str = "m365",
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in collector_rows:
        name = str(row.get("name") or row.get("collector") or "")
        if not name:
            continue
        for surface in _collector_surfaces(name, platform):
            grouped.setdefault(surface, []).append(row)

    records: list[dict[str, Any]] = []
    for surface in sorted(grouped):
        rows = grouped[surface]
        counts = _status_counts(rows)
        records.append(
            {
                "surface": surface,
                "status": _surface_status(counts),
                "collector_count": len(rows),
                "collectors": [str(row.get("name") or row.get("collector")) for row in rows],
                "status_counts": counts,
            }
        )
    return records


def build_coverage_gap_summary(
    *,
    surface_coverage: list[dict[str, Any]],
    collector_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows_by_collector: dict[str, list[dict[str, Any]]] = {}
    for row in [*collector_rows, *coverage_rows]:
        if not isinstance(row, Mapping):
            continue
        name = _row_name(dict(row))
        if name:
            rows_by_collector.setdefault(name, []).append(dict(row))

    gaps: list[dict[str, Any]] = []
    for surface in surface_coverage:
        status = str(surface.get("status") or "unknown")
        if status == "complete":
            continue
        collectors = [str(item) for item in surface.get("collectors") or [] if str(item)]
        error_classes = sorted(
            {
                str(row.get("error_class"))
                for collector in collectors
                for row in rows_by_collector.get(collector, [])
                if row.get("error_class")
            }
        )
        surface_name = str(surface.get("surface") or "unknown")
        gaps.append(
            {
                "surface": surface_name,
                "status": status,
                "severity": _gap_severity(status),
                "collectors": collectors,
                "error_classes": error_classes,
                "message": f"{surface_name} coverage is {status}; affected collectors: {', '.join(collectors) if collectors else 'unknown'}",
            }
        )
    return gaps


def build_provider_scorecard(
    *,
    platform: str,
    surface_coverage: list[dict[str, Any]],
    coverage_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    gaps_by_surface = {
        str(gap.get("surface") or ""): gap
        for gap in coverage_gaps
        if isinstance(gap, Mapping) and gap.get("surface")
    }
    rows: list[dict[str, Any]] = []
    for surface in sorted([dict(row) for row in surface_coverage if isinstance(row, Mapping)], key=_surface_sort_key):
        name = str(surface.get("surface") or "other")
        status = str(surface.get("status") or "unknown")
        score = _SURFACE_SCORES.get(status, 0)
        gap = gaps_by_surface.get(name, {})
        row = {
            "surface": name,
            "status": status,
            "score": score,
            "collector_count": int(surface.get("collector_count") or len(surface.get("collectors") or [])),
            "collectors": [str(item) for item in surface.get("collectors") or []],
        }
        if gap:
            row["gap_severity"] = gap.get("severity")
            row["error_classes"] = [str(item) for item in gap.get("error_classes") or []]
        rows.append(row)

    score = int(round(sum(row["score"] for row in rows) / len(rows))) if rows else 0
    return {
        "platform": platform,
        "score": score,
        "grade": _scorecard_grade(score),
        "surface_count": len(rows),
        "coverage_gap_count": len(coverage_gaps),
        "surfaces": rows,
    }
