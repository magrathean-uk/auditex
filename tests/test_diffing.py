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


def test_mcp_diff_runs_returns_summary_and_compared_files(tmp_path: Path) -> None:
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    _write_json(run_a / "normalized" / "devices.json", {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows"}]})
    _write_json(run_b / "normalized" / "devices.json", {"kind": "devices", "records": [{"key": "device:d1", "platform": "Windows 11"}]})

    result = diff_runs(str(run_a), str(run_b))

    assert result["summary"]["changed"] == 1
    assert "devices.json" in result["compared_files"]
    assert result["changes"]["devices"]["changed"][0]["key"] == "device:d1"


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
