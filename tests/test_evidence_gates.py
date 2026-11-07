from __future__ import annotations

import pytest

from azure_tenant_audit.evidence_gates import build_evidence_gate_summary


def test_evidence_gate_summary_classifies_shared_gate_rows() -> None:
    summary = build_evidence_gate_summary(
        selected_collectors=["google_directory", "google_reports", "google_gmail_settings"],
        capability_rows=[
            {"collector": "google_directory", "status": "supported_exact_scope"},
            {
                "collector": "google_reports",
                "status": "blocked_by_scope",
                "reason": "runtime_permission_block",
                "missing_permissions": ["admin.reports.audit.readonly"],
            },
        ],
        coverage_rows=[{"collector": "google_directory", "status": "ok", "item_count": 1}],
    )

    assert summary["trust_level"] == "partial"
    assert summary["trusted_collectors"] == ["google_directory"]
    assert summary["blocked_collectors"] == ["google_reports"]
    assert summary["unverified_collectors"] == ["google_gmail_settings"]
    gates = {row["collector"]: row for row in summary["evidence_gates"]}
    assert gates["google_directory"]["status"] == "complete"
    assert gates["google_reports"]["status"] == "blocked"
    assert gates["google_reports"]["blocker_kind"] == "auth_scope"
    assert gates["google_reports"]["missing_permissions"] == ["admin.reports.audit.readonly"]
    assert gates["google_gmail_settings"]["status"] == "unverified"


def test_evidence_gate_summary_marks_dependency_unavailable_as_local_tool() -> None:
    summary = build_evidence_gate_summary(
        selected_collectors=["google_directory", "google_reports"],
        capability_rows=[],
        dependency_available=False,
    )

    assert summary["trust_level"] == "blocked"
    assert summary["blocked_collectors"] == ["google_directory", "google_reports"]
    assert summary["blocker_summary"]["counts"] == {"local_tool": 2}
    for row in summary["evidence_gates"]:
        assert row["status"] == "blocked"
        assert row["blocker_kind"] == "local_tool"


@pytest.mark.parametrize("reason", ["not_applicable", "teams_token_unavailable", "license_required", "preflight_blocked"])
def test_skips_and_derived_rows_do_not_verify_a_collector(reason: str) -> None:
    summary = build_evidence_gate_summary(
        selected_collectors=["identity", "other"],
        capability_rows=[
            {"collector": "identity", "status": "supported_exact_scope"},
            {"collector": "other", "status": "supported_exact_scope"},
        ],
        coverage_rows=[
            {"collector": "identity", "type": "graph", "status": "ok", "item_count": 1},
            *[{"collector": "other", "type": "command", "status": "skipped", "error_class": reason} for _ in range(7)],
            {"collector": "other", "type": "derived", "status": "ok", "item_count": 0},
        ],
    )

    assert summary["trust_level"] == "partial"
    assert summary["trusted_collectors"] == ["identity"]
    assert summary["unverified_collectors"] == ["other"]
    assert summary["can_trust"] == ["identity"]
    assert summary["cannot_trust"] == ["other"]


@pytest.mark.parametrize("rows", [[], [{"collector": "other", "status": "failed"}]])
def test_missing_or_failed_reads_are_not_trusted(rows: list[dict]) -> None:
    summary = build_evidence_gate_summary(
        selected_collectors=["other"],
        capability_rows=[{"collector": "other", "status": "supported_exact_scope"}],
        coverage_rows=rows,
    )
    assert summary["trust_level"] == "setup_only"
    assert summary["trusted_collectors"] == []
    assert summary["unverified_collectors"] == ["other"]


@pytest.mark.parametrize("status", ["offline_sample", "complete_offline_sample"])
def test_offline_success_is_not_live_verified(status: str) -> None:
    summary = build_evidence_gate_summary(
        selected_collectors=["other"],
        capability_rows=[{"collector": "other", "status": status}],
        coverage_rows=[{"collector": "other", "status": "ok", "item_count": 1}],
    )
    assert summary["trust_level"] == "setup_only"
    assert summary["trusted_collectors"] == []


def test_healthy_multiple_collectors_remain_live_verified() -> None:
    summary = build_evidence_gate_summary(
        selected_collectors=["identity", "licensing"],
        capability_rows=[{"collector": name, "status": "supported_exact_scope"} for name in ("identity", "licensing")],
        coverage_rows=[{"collector": name, "status": "ok", "item_count": 1} for name in ("identity", "licensing")],
    )
    assert summary["trust_level"] == "live_verified"
    assert summary["trusted_collectors"] == ["identity", "licensing"]
    assert summary["statement"] == "Live evidence is verified for all selected collectors."


@pytest.mark.parametrize("item_count,skipped", [(0, False), (0, True), (3, True), (3, False)])
def test_successful_reads_including_empty_and_mixed_stay_trusted(item_count: int, skipped: bool) -> None:
    rows = [{"collector": "other", "type": "graph", "status": "ok", "item_count": item_count}]
    if skipped:
        rows.append({"collector": "other", "type": "command", "status": "skipped", "error_class": "not_applicable"})
    summary = build_evidence_gate_summary(
        selected_collectors=["other"],
        capability_rows=[{"collector": "other", "status": "supported_exact_scope"}],
        coverage_rows=rows,
    )
    assert summary["trust_level"] == "live_verified"
    assert summary["trusted_collectors"] == ["other"]
    assert summary["statement"] == "Live evidence is verified for all selected collectors."
