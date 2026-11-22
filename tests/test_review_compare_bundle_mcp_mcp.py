"""Review lane compare-bundle-mcp: the MCP server: shipped resources, summary size and command timeouts (R024, R025, R063)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# R024: shipped resources from another working directory


def test_mcp_collector_list_and_schema_inventory_work_outside_the_source_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from auditex.mcp_server import contract_schema_inventory, list_collectors

    monkeypatch.chdir(tmp_path)

    collectors = list_collectors()
    schemas = contract_schema_inventory()

    assert "error" not in collectors
    assert collectors["collectors"]
    assert any(row["required_permissions"] for row in collectors["collectors"])
    assert schemas["schemas"]
    assert schemas["evidence_missing"] == []


# R025: MCP summary size


def test_mcp_summary_of_a_large_run_fits_a_client_output_cap_and_points_at_the_omitted_sections(tmp_path: Path) -> None:
    from support import RunBundleBuilder

    from auditex.mcp_server import summarize_run

    findings = [
        {"id": f"identity:finding:{index}", "rule_id": "identity.example_check", "severity": "low",
         "title": "Example finding " + "x" * 400, "collector": "identity"}
        for index in range(600)
    ]
    run_dir = (
        RunBundleBuilder(tmp_path)
        .report_pack(summary={"overall_status": "partial"}, findings=findings, evidence_paths=[])
        .build()
    )

    summary = summarize_run(str(run_dir))

    assert len(json.dumps(summary, default=str)) <= 48_000
    assert "report_pack" not in summary
    omitted = summary["omitted_sections"]["report_pack"]
    assert omitted["path"].endswith("reports/report-pack.json")
    assert omitted["read_with"] == "auditex_report_analyze"
    assert summary["manifest"]["tenant_name"]
    assert summary["summary_truncated"] is True


def test_mcp_summary_of_a_run_with_many_artifacts_still_fits_the_cap(tmp_path: Path) -> None:
    # A 250,000-user run lists hundreds of raw pages and chunks (each with a .meta.json) in its manifest.
    from support import RunBundleBuilder

    from auditex.mcp_server import summarize_run

    artifacts = [f"chunks/identity/users-page-{index:05d}.json" for index in range(1500)]
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(artifacts=artifacts)
        .report_pack(summary={"overall_status": "partial"}, findings=[], evidence_paths=[])
        .build()
    )

    summary = summarize_run(str(run_dir))

    assert len(json.dumps(summary, default=str)) <= 48_000
    assert summary["manifest"]["tenant_name"]
    omitted = summary["omitted_sections"]["manifest.artifacts"]
    assert omitted["items"] == 1500
    assert omitted["path"] == "run-manifest.json"


def test_mcp_summary_of_a_small_run_keeps_every_section(tmp_path: Path) -> None:
    from support import RunBundleBuilder

    from auditex.mcp_server import summarize_run

    run_dir = RunBundleBuilder(tmp_path).report_pack(summary={"overall_status": "partial"}, findings=[], evidence_paths=[]).build()

    summary = summarize_run(str(run_dir))

    assert summary["report_pack"]["summary"]["overall_status"] == "partial"
    assert "omitted_sections" not in summary


# R063 / R026: MCP command timeouts


def test_the_command_timeout_is_configurable_and_names_the_resumable_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from auditex.command_runner import run_cli_command

    monkeypatch.setenv("AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS", "1")
    started = time.monotonic()

    result = run_cli_command(["sh", "-c", "sleep 5"])

    assert time.monotonic() - started < 4
    assert result["error_class"] == "timeout"
    assert "--resume-from" in result["error"]


def test_live_audits_have_no_fifteen_minute_limit_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex import command_runner

    monkeypatch.delenv("AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS", raising=False)

    assert command_runner.command_timeout_seconds() >= 4 * 3600
