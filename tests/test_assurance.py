from __future__ import annotations

import azure_tenant_audit.assurance as assurance
from azure_tenant_audit.assurance import build_assurance_summary, build_surface_coverage_map


def test_assurance_summary_scores_partial_failed_and_truncated_evidence() -> None:
    summary = build_assurance_summary(
        collector_rows=[
            {"name": "identity", "status": "ok"},
            {"name": "mail", "status": "partial"},
            {"name": "alerts", "status": "failed"},
        ],
        coverage_rows=[
            {"collector": "identity", "status": "ok"},
            {"collector": "alerts", "status": "failed"},
        ],
        sample_truncated=True,
    )

    assert summary == {
        "score": 45,
        "grade": "weak",
        "collector_count": 3,
        "coverage_row_count": 2,
        "sample_truncated": True,
        "collector_status_counts": {"ok": 1, "partial": 1, "failed": 1},
        "coverage_status_counts": {"ok": 1, "failed": 1},
    }


def test_assurance_summary_marks_complete_clean_run() -> None:
    summary = build_assurance_summary(
        collector_rows=[{"name": "identity", "status": "ok"}],
        coverage_rows=[{"collector": "identity", "status": "ok"}],
    )

    assert summary["score"] == 100
    assert summary["grade"] == "complete"


def test_surface_coverage_map_groups_google_collectors() -> None:
    rows = build_surface_coverage_map(
        collector_rows=[
            {"name": "google_directory", "status": "ok"},
            {"name": "google_gmail_settings", "status": "partial"},
            {"name": "google_drive_posture", "status": "failed"},
            {"name": "google_calendar_posture", "status": "ok"},
        ],
        platform="google_workspace",
    )

    by_surface = {row["surface"]: row for row in rows}
    assert by_surface["identity"]["status"] == "complete"
    assert by_surface["mail"]["status"] == "partial"
    assert by_surface["collaboration"]["status"] == "partial"
    assert by_surface["collaboration"]["collectors"] == ["google_drive_posture", "google_calendar_posture"]
    assert by_surface["calendar"]["status"] == "complete"


def test_surface_coverage_map_groups_m365_collectors() -> None:
    rows = build_surface_coverage_map(
        collector_rows=[
            {"name": "identity", "status": "ok"},
            {"name": "mailbox_forwarding", "status": "ok"},
            {"name": "sharepoint_access", "status": "partial"},
        ],
        platform="m365",
    )

    by_surface = {row["surface"]: row for row in rows}
    assert by_surface["identity"]["status"] == "complete"
    assert by_surface["mail"]["status"] == "complete"
    assert by_surface["collaboration"]["status"] == "partial"


def test_coverage_gap_summary_promotes_blocked_surfaces_and_error_classes() -> None:
    surface_coverage = build_surface_coverage_map(
        collector_rows=[
            {"name": "google_directory", "status": "ok"},
            {"name": "google_reports", "status": "failed", "error_class": "unauthorized_client"},
            {"name": "google_gmail_settings", "status": "partial", "error_class": "invalid_scope"},
        ],
        platform="google_workspace",
    )

    build_coverage_gap_summary = getattr(assurance, "build_coverage_gap_summary", None)
    assert build_coverage_gap_summary is not None

    gaps = build_coverage_gap_summary(
        surface_coverage=surface_coverage,
        collector_rows=[
            {"name": "google_directory", "status": "ok"},
            {"name": "google_reports", "status": "failed", "error_class": "unauthorized_client"},
            {"name": "google_gmail_settings", "status": "partial", "error_class": "invalid_scope"},
        ],
        coverage_rows=[
            {"collector": "google_reports", "status": "failed", "error_class": "unauthorized_client"},
            {"collector": "google_gmail_settings", "status": "failed", "error_class": "invalid_scope"},
        ],
    )

    by_surface = {gap["surface"]: gap for gap in gaps}
    assert by_surface["audit_logs"]["severity"] == "high"
    assert by_surface["audit_logs"]["error_classes"] == ["unauthorized_client"]
    assert by_surface["mail"]["severity"] == "medium"
    assert by_surface["mail"]["error_classes"] == ["invalid_scope"]
    assert by_surface["mail"]["message"] == "mail coverage is partial; affected collectors: google_gmail_settings"


def test_provider_scorecard_scores_shared_surfaces_consistently() -> None:
    build_provider_scorecard = getattr(assurance, "build_provider_scorecard", None)
    assert build_provider_scorecard is not None

    surface_coverage = [
        {"surface": "identity", "status": "complete", "collectors": ["google_directory"]},
        {"surface": "mail", "status": "partial", "collectors": ["google_gmail_settings"]},
        {"surface": "audit_logs", "status": "blocked", "collectors": ["google_reports"]},
    ]
    gaps = [
        {"surface": "mail", "severity": "medium", "error_classes": ["invalid_scope"]},
        {"surface": "audit_logs", "severity": "high", "error_classes": ["unauthorized_client"]},
    ]

    scorecard = build_provider_scorecard(
        platform="google_workspace",
        surface_coverage=surface_coverage,
        coverage_gaps=gaps,
    )

    assert scorecard["platform"] == "google_workspace"
    assert scorecard["score"] == 53
    assert scorecard["grade"] == "weak"
    assert scorecard["surface_count"] == 3
    assert scorecard["coverage_gap_count"] == 2
    rows = {row["surface"]: row for row in scorecard["surfaces"]}
    assert rows["identity"]["score"] == 100
    assert rows["mail"]["score"] == 60
    assert rows["mail"]["gap_severity"] == "medium"
    assert rows["audit_logs"]["score"] == 0


def test_live_readiness_summary_distinguishes_trusted_blocked_and_unverified() -> None:
    build_live_readiness_summary = getattr(assurance, "build_live_readiness_summary", None)
    assert build_live_readiness_summary is not None

    summary = build_live_readiness_summary(
        selected_collectors=["google_directory", "google_reports", "google_gmail_settings"],
        capability_rows=[
            {"collector": "google_directory", "status": "supported_exact_scope"},
            {"collector": "google_reports", "status": "blocked_by_scope", "missing_permissions": ["reports.scope"]},
        ],
    )

    assert summary["trust_level"] == "partial"
    assert summary["trusted_collectors"] == ["google_directory"]
    assert summary["blocked_collectors"] == ["google_reports"]
    assert summary["unverified_collectors"] == ["google_gmail_settings"]
    assert summary["can_trust"] == ["google_directory"]
    assert summary["cannot_trust"] == ["google_reports", "google_gmail_settings"]
    assert summary["blocker_summary"]["counts"] == {"auth_scope": 1, "unverified": 1}
    blockers = {row["collector"]: row for row in summary["blocker_summary"]["blockers"]}
    assert blockers["google_reports"]["blocker_kind"] == "auth_scope"
    assert blockers["google_reports"]["next_step"]
