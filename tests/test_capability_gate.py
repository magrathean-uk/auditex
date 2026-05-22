from __future__ import annotations

from azure_tenant_audit.capability_gate import capability_blocker_summary, classify_capability_blocker


def test_capability_gate_classifies_scope_role_license_service_tool_and_policy() -> None:
    rows = [
        {"status": "blocked_by_scope", "reason": "missing_required_permissions", "missing_permissions": ["Reports.Read.All"]},
        {"status": "blocked_by_role", "reason": "global_reader_limit"},
        {"status": "partial", "reason": "copilot license unavailable"},
        {"status": "partial", "reason": "service_not_available"},
        {"status": "blocked", "reason": "module_not_found"},
        {
            "status": "blocked_by_scope",
            "reason": "runtime_permission_block",
            "missing_permissions": ["admin.reports.audit.readonly"],
            "endpoint_statuses": [{"error": "unauthorized_client: client not authorized for scopes"}],
        },
    ]

    assert [classify_capability_blocker(row)["blocker_kind"] for row in rows] == [
        "auth_scope",
        "admin_role",
        "license",
        "service_absent",
        "local_tool",
        "tenant_policy",
    ]


def test_capability_blocker_summary_counts_actionable_blockers() -> None:
    summary = capability_blocker_summary(
        [
            {"collector": "identity", "status": "supported_exact_scope"},
            {"collector": "reports", "status": "blocked_by_scope", "missing_permissions": ["Reports.Read.All"]},
            {"collector": "intune", "status": "partial", "reason": "service_not_available"},
        ]
    )

    assert summary["counts"] == {"auth_scope": 1, "service_absent": 1}
    assert summary["blockers"][0]["collector"] == "reports"
    assert summary["blockers"][0]["next_step"]
