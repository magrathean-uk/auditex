from __future__ import annotations

import json
from pathlib import Path

from auditex.mcp_server import diff_runs
from azure_tenant_audit.diffing import diff_run_directories


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_diff_run_directories_reports_added_removed_and_changed(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "partial"})

    _write_json(
        run_a / "normalized" / "users.json",
        {
            "kind": "users",
            "records": [
                {"key": "user:user-1", "display_name": "Alice", "department": "Sales"},
                {"key": "user:user-2", "display_name": "Bob", "department": "IT"},
            ],
        },
    )
    _write_json(
        run_b / "normalized" / "users.json",
        {
            "kind": "users",
            "records": [
                {"key": "user:user-1", "display_name": "Alice", "department": "Finance"},
                {"key": "user:user-3", "display_name": "Charlie", "department": "IT"},
            ],
        },
    )
    _write_json(
        run_a / "normalized" / "policies.json",
        {"kind": "policies", "records": [{"key": "policy:conditionalAccessPolicies:ca-1", "display_name": "Require MFA"}]},
    )
    _write_json(
        run_b / "normalized" / "policies.json",
        {"kind": "policies", "records": [{"key": "policy:conditionalAccessPolicies:ca-1", "display_name": "Require MFA"}]},
    )

    diff = diff_run_directories(run_a, run_b)

    assert diff["summary"]["added"] == 1
    assert diff["summary"]["removed"] == 1
    assert diff["summary"]["changed"] == 1
    assert diff["run_a_info"]["run_id"] == "run-1"
    assert diff["run_b_info"]["run_id"] == "run-2"
    assert diff["compare_context"]["same_tenant"] is True
    assert diff["changes"]["users"]["added"][0]["key"] == "user:user-3"
    assert diff["changes"]["users"]["removed"][0]["key"] == "user:user-2"
    assert diff["changes"]["users"]["changed"][0]["before"]["department"] == "Sales"
    assert diff["changes"]["users"]["changed"][0]["after"]["department"] == "Finance"


def test_diff_run_directories_suppresses_volatile_timestamp_only_changes_by_default(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "ok"})
    _write_json(
        run_a / "normalized" / "devices.json",
        {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows", "last_sync": "2026-05-01T00:00:00Z"}]},
    )
    _write_json(
        run_b / "normalized" / "devices.json",
        {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows", "last_sync": "2026-05-02T00:00:00Z"}]},
    )

    diff = diff_run_directories(run_a, run_b)

    assert diff["classic"] is False
    assert diff["summary"]["changed"] == 0
    assert diff["noise_suppression"]["enabled"] is True
    assert diff["noise_suppression"]["raw_changed"] == 1
    assert diff["noise_suppression"]["suppressed_changed"] == 1
    assert diff["noise_suppression"]["suppressed_reason_counts"] == {"volatile_fields_only": 1}
    assert diff["noise_suppression"]["suppressed_path_counts"] == {"last_sync": 1}
    assert diff["changes"]["devices"]["suppressed"][0]["reason"] == "volatile_fields_only"
    assert diff["changes"]["devices"]["suppressed"][0]["changed_paths"] == ["last_sync"]


def test_diff_run_directories_suppresses_usage_report_refresh_churn_by_kind(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "ok"})
    _write_json(
        run_a / "normalized" / "usage_report_objects.json",
        {
            "kind": "usage_report_objects",
            "records": [{"key": "usage:users", "source_name": "office365ActiveUserCounts", "report_refresh_date": "2026-05-01"}],
        },
    )
    _write_json(
        run_b / "normalized" / "usage_report_objects.json",
        {
            "kind": "usage_report_objects",
            "records": [{"key": "usage:users", "source_name": "office365ActiveUserCounts", "report_refresh_date": "2026-05-02"}],
        },
    )
    _write_json(
        run_a / "normalized" / "copilot_usage_objects.json",
        {
            "kind": "copilot_usage_objects",
            "records": [{"key": "copilot:summary", "report_period": "D7", "assigned_users": 10, "active_users": 5, "created": "2026-05-01"}],
        },
    )
    _write_json(
        run_b / "normalized" / "copilot_usage_objects.json",
        {
            "kind": "copilot_usage_objects",
            "records": [{"key": "copilot:summary", "report_period": "D7", "assigned_users": 10, "active_users": 5, "created": "2026-05-02"}],
        },
    )

    diff = diff_run_directories(run_a, run_b)

    assert diff["summary"]["changed"] == 0
    assert diff["noise_suppression"]["raw_changed"] == 2
    assert diff["noise_suppression"]["suppressed_changed"] == 2
    assert diff["noise_suppression"]["suppressed_object_kinds"] == 2
    assert diff["noise_suppression"]["suppressed_path_counts"] == {"created": 1, "report_refresh_date": 1}
    assert diff["changes"]["usage_report_objects"]["suppressed"][0]["changed_paths"] == ["report_refresh_date"]
    assert diff["changes"]["copilot_usage_objects"]["suppressed"][0]["changed_paths"] == ["created"]


def test_diff_run_directories_keeps_usage_metric_changes_when_refresh_date_also_moves(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "ok"})
    _write_json(
        run_a / "normalized" / "copilot_usage_objects.json",
        {
            "kind": "copilot_usage_objects",
            "records": [{"key": "copilot:summary", "report_period": "D7", "assigned_users": 10, "active_users": 5, "created": "2026-05-01"}],
        },
    )
    _write_json(
        run_b / "normalized" / "copilot_usage_objects.json",
        {
            "kind": "copilot_usage_objects",
            "records": [{"key": "copilot:summary", "report_period": "D7", "assigned_users": 10, "active_users": 8, "created": "2026-05-02"}],
        },
    )

    diff = diff_run_directories(run_a, run_b)

    assert diff["summary"]["changed"] == 1
    assert diff["noise_suppression"]["suppressed_changed"] == 0
    assert "suppressed" not in diff["changes"]["copilot_usage_objects"]
    assert diff["changes"]["copilot_usage_objects"]["changed"][0]["after"]["active_users"] == 8


def test_diff_run_directories_classic_mode_keeps_volatile_timestamp_changes(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "ok"})
    _write_json(
        run_a / "normalized" / "devices.json",
        {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows", "last_sync": "2026-05-01T00:00:00Z"}]},
    )
    _write_json(
        run_b / "normalized" / "devices.json",
        {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows", "last_sync": "2026-05-02T00:00:00Z"}]},
    )

    diff = diff_run_directories(run_a, run_b, classic=True)

    assert diff["classic"] is True
    assert diff["summary"]["changed"] == 1
    assert diff["noise_suppression"]["enabled"] is False
    assert diff["noise_suppression"]["suppressed_changed"] == 0
    assert "suppressed" not in diff["changes"]["devices"]


def test_mcp_diff_runs_returns_summary_and_compared_files(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2"})
    _write_json(run_a / "normalized" / "devices.json", {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows"}]})
    _write_json(run_b / "normalized" / "devices.json", {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows 11"}]})

    result = diff_runs(str(run_a), str(run_b))

    assert result["summary"]["changed"] == 1
    assert "devices.json" in result["compared_files"]
    assert result["changes"]["devices"]["changed"][0]["key"] == "device:d1"
    assert "run-manifest.json" in [row["artifact_path"] for row in result["citations"]]
    assert "normalized/devices.json" in [row["artifact_path"] for row in result["citations"]]
    assert result["evidence_missing"] == []


def test_diff_run_directories_treats_matching_tenant_id_as_same_tenant(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme-a", "tenant_id": "tenant-1", "run_id": "run-1"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme-b", "tenant_id": "tenant-1", "run_id": "run-2"})
    _write_json(run_a / "normalized" / "devices.json", {"kind": "devices", "records": [{"key": "device:d1"}]})
    _write_json(run_b / "normalized" / "devices.json", {"kind": "devices", "records": [{"key": "device:d1"}]})

    result = diff_run_directories(run_a, run_b)

    assert result["compare_context"]["same_tenant"] is True


def test_diff_run_directories_blocks_cross_provider_compare(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "platform": "m365", "run_id": "run-1"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "platform": "google_workspace", "run_id": "run-2"})
    _write_json(run_a / "normalized" / "users.json", {"kind": "users", "records": [{"key": "user:alice"}]})
    _write_json(run_b / "normalized" / "users.json", {"kind": "users", "records": [{"key": "user:alice"}]})

    result = diff_run_directories(run_a, run_b)

    assert result["status"] == "blocked"
    assert result["reason"] == "same_platform_required"
    assert result["compare_context"]["same_platform"] is False
    assert result["summary"] == {"added": 0, "removed": 0, "changed": 0, "object_kinds": 0}
    assert result["citations"] == [
        {
            "artifact_path": "run-manifest.json",
            "reason": "Run identity and compare gate for both compared runs.",
        }
    ]


def test_diff_run_directories_reports_accepted_risk_state_transitions(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "partial"})
    _write_json(run_a / "normalized" / "users.json", {"kind": "users", "records": [{"key": "user:alice"}]})
    _write_json(run_b / "normalized" / "users.json", {"kind": "users", "records": [{"key": "user:alice"}]})
    _write_json(
        run_a / "reports" / "report-pack.json",
        {
            "summary": {"tenant_name": "acme"},
            "findings": [
                {
                    "id": "f1",
                    "rule_id": "x",
                    "severity": "high",
                    "title": "Known issue",
                    "status": "accepted_risk",
                    "waiver": {"expires_on": "2099-01-01", "comment": "Temporary exception"},
                }
            ],
        },
    )
    _write_json(
        run_b / "reports" / "report-pack.json",
        {
            "summary": {"tenant_name": "acme"},
            "findings": [
                {
                    "id": "f1",
                    "rule_id": "x",
                    "severity": "high",
                    "title": "Known issue",
                    "status": "open",
                }
            ],
        },
    )

    result = diff_run_directories(run_a, run_b)

    assert result["drift_summary"]["state_transition_count"] == 1
    assert result["drift_summary"]["state_transitions"][0]["from_status"] == "accepted_risk"
    assert result["drift_summary"]["state_transitions"][0]["to_status"] == "open"
    assert result["drift_summary"]["reactivated_accepted_risk_count"] == 1
    assert result["drift_summary"]["reactivated_accepted_risks"][0]["id"] == "f1"
    assert result["drift_summary"]["notification_recommended"] is True


def test_diff_run_directories_reports_stale_accepted_risk_summary(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-1", "overall_status": "ok"})
    _write_json(run_b / "run-manifest.json", {"tenant_name": "acme", "run_id": "run-2", "overall_status": "partial"})
    _write_json(run_a / "normalized" / "users.json", {"kind": "users", "records": [{"key": "user:alice"}]})
    _write_json(run_b / "normalized" / "users.json", {"kind": "users", "records": [{"key": "user:alice"}]})
    _write_json(run_a / "reports" / "report-pack.json", {"summary": {"tenant_name": "acme"}, "findings": []})
    _write_json(
        run_b / "reports" / "report-pack.json",
        {
            "summary": {"tenant_name": "acme"},
            "findings": [
                {
                    "id": "f-stale",
                    "rule_id": "stale",
                    "severity": "critical",
                    "title": "Expired waiver",
                    "status": "accepted_risk",
                    "waiver": {"expires_on": "2020-01-01", "comment": "Old exception"},
                }
            ],
        },
    )

    result = diff_run_directories(run_a, run_b)

    assert result["drift_summary"]["accepted_risk_summary"]["stale_count"] == 1
    assert result["drift_summary"]["stale_accepted_risk_count"] == 1
    assert result["drift_summary"]["stale_accepted_risks"][0]["id"] == "f-stale"
    assert result["drift_summary"]["notification_recommended"] is True
