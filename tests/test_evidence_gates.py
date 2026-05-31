from __future__ import annotations

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
