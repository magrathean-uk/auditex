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


def test_mcp_summary_fits_the_cap_when_kept_sections_alone_are_too_large(tmp_path: Path) -> None:
    # Repair round 1 (R025): 300 coverage gaps repeated in the manifest, the summary and the run metadata.
    from support import RunBundleBuilder

    from auditex.mcp_server import summarize_run, tool_handlers

    gaps = [
        {"collector": f"collector_{index}", "surface": f"surface {index}", "status": "blocked_permission",
         "reason": "The reader app lacks the permission this read needs. " * 2}
        for index in range(300)
    ]
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(coverage_gaps=gaps)
        .summary(coverage_gaps=gaps)
        .report_pack(summary={"overall_status": "partial"}, findings=[], evidence_paths=[])
        .build()
    )

    handlers = tool_handlers()
    for result in (summarize_run(str(run_dir)), handlers["auditex_probe_summarize"](run_dir=str(run_dir))):
        assert len(json.dumps(result, default=str)) <= 48_000
        assert result["summary_truncated"] is True
        assert result["manifest"]["tenant_name"]
        assert result["manifest"]["run_id"]
        assert result["omitted_sections"]


def test_mcp_summary_fits_the_cap_when_a_kept_section_has_many_small_fields(tmp_path: Path) -> None:
    # Impact (R025): the list of what was left out must not itself grow past the budget.
    from support import RunBundleBuilder

    from auditex.mcp_server import summarize_run

    many = {f"surface_{index}": {"status": "blocked_permission", "note": "x" * 60} for index in range(1500)}
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(**many)
        .report_pack(summary={"overall_status": "partial"}, findings=[], evidence_paths=[])
        .build()
    )

    result = summarize_run(str(run_dir))

    assert len(json.dumps(result, default=str)) <= 48_000
    assert result["manifest"]["tenant_name"]


def test_mcp_summary_fits_the_cap_when_left_out_field_names_are_long(tmp_path: Path) -> None:
    # Repair round 2 (R025): 21 long manifest extension field names. The record of what was left out is bounded too,
    # and the manifest's identity stays.
    from support import RunBundleBuilder

    from auditex.mcp_server import summarize_run, tool_handlers

    long_fields = {f"extension_{index:02d}_" + "n" * 2800: {"status": "blocked_permission"} for index in range(21)}
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(**long_fields)
        .report_pack(summary={"overall_status": "partial"}, findings=[], evidence_paths=[])
        .build()
    )

    handlers = tool_handlers()
    for result in (summarize_run(str(run_dir)), handlers["auditex_probe_summarize"](run_dir=str(run_dir))):
        assert len(json.dumps(result, default=str)) <= 48_000
        assert result["summary_truncated"] is True
        assert result["manifest"]["tenant_name"]
        assert result["manifest"]["run_id"]


def test_a_capped_summary_never_exceeds_the_budget_even_when_its_core_keys_do() -> None:
    # Repair round 2 (R025): the keys a capped summary always keeps can be over the budget on their own.
    from auditex.mcp_server import _cap_summary

    citations = [{"artifact_path": f"normalized/section_{index}.json", "reason": "r" * 200} for index in range(400)]
    result = _cap_summary({"manifest": {"tenant_name": "acme", "run_id": "r1"}, "citations": citations}, budget=4_000)

    assert len(json.dumps(result, default=str)) <= 4_000
    assert result["summary_truncated"] is True
    assert result["manifest"] == {"tenant_name": "acme", "run_id": "r1"}
    assert result["citations_omitted"] == 400


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

    result = run_cli_command(["sh", "-c", "sleep 5"], resumable=True)

    assert time.monotonic() - started < 4
    assert result["error_class"] == "timeout"
    assert "--resume-from" in result["error"]
    assert "AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS" in result["error"]


def test_a_command_without_resume_does_not_advise_resume_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.command_runner import run_cli_command

    monkeypatch.setenv("AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS", "1")

    result = run_cli_command(["sh", "-c", "sleep 5"])

    assert result["error_class"] == "timeout"
    assert "--resume-from" not in result["error"]


def test_the_certificate_audit_tool_timeout_names_resume(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import subprocess

    from auditex import mcp_server

    def time_out(command: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout") or 1)

    monkeypatch.setattr("auditex.command_runner._run_process", time_out)
    certificate = tmp_path / "reader.pem"
    certificate.write_text("not a key", encoding="utf-8")

    result = mcp_server.tool_handlers()["auditex_run_certificate_audit"](
        tenant_name="lab", tenant_id="11111111-1111-1111-1111-111111111111",
        client_id="22222222-2222-2222-2222-222222222222", certificate_path=str(certificate),
        certificate_thumbprint="A" * 40, out_dir=str(tmp_path / "out"),
    )

    assert result.get("error_class") == "timeout", result
    assert "--resume-from" in result["error"]


def test_a_command_timeout_stops_the_child_and_every_process_it_started(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Repair round 1 (R063/R026): the engine's own children (pwsh) are in its process group and stop with it.
    import time

    from auditex.command_runner import run_cli_command

    monkeypatch.setenv("AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS", "1")
    marker = tmp_path / "grandchild-finished"

    result = run_cli_command(["sh", "-c", f"(sleep 2; touch '{marker}') & wait"])

    assert result["error_class"] == "timeout"
    time.sleep(2.5)
    assert not marker.exists()


def test_a_resumable_command_timeout_names_the_partial_run_folder(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Repair round 1 (R063/R026): the error names the folder --resume-from needs, not just the option.
    from auditex.command_runner import run_cli_command

    monkeypatch.setenv("AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS", "1")
    out = tmp_path / "live"
    (out / "acme-run_earlier").mkdir(parents=True)
    script = 'mkdir -p "$2/$4-run_20261122T040000Z" && sleep 5'

    result = run_cli_command(["sh", "-c", script, "sh", "--out", str(out), "--tenant-name", "acme"], resumable=True)

    partial = out / "acme-run_20261122T040000Z"
    assert result["error_class"] == "timeout"
    assert result["partial_run_dir"] == str(partial)
    assert f"--resume-from {partial}" in result["error"]


_SERVER_STAND_IN = """
import os, signal, sys, threading, time
from auditex import command_runner, mcp_server
install = getattr(mcp_server, "_install_shutdown_handlers", None)
if install is not None:
    install()
marker = sys.argv[1]
threading.Thread(target=command_runner.run_cli_command, args=(["sh", "-c", f"(sleep 2; touch '{marker}') & wait"],),
                 daemon=True).start()
time.sleep(0.5)
os.kill(os.getpid(), signal.SIGTERM)
time.sleep(5)
"""


def test_a_terminated_mcp_server_stops_the_commands_it_started(tmp_path: Path) -> None:
    # Review of repair round 1 (R063): the child runs in its own session, so the server must stop it on SIGTERM.
    import os
    import subprocess
    import sys
    import time

    marker = tmp_path / "grandchild-finished"
    script = tmp_path / "server_stand_in.py"
    script.write_text(_SERVER_STAND_IN, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}

    server = subprocess.run([sys.executable, str(script), str(marker)], env=env, timeout=30, check=False)

    assert server.returncode != 0
    time.sleep(2.5)
    assert not marker.exists()


def test_the_certificate_audit_tool_timeout_names_the_partial_run_folder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Repair round 2 (R063/R026): through the public handler, whose command carries the certificate flags.
    import subprocess

    from auditex import mcp_server

    out = tmp_path / "out"
    partial = out / "lab-run_20261122T060000Z"

    def start_then_time_out(command: list[str], **kwargs: object) -> None:
        partial.mkdir(parents=True)
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout") or 1)

    monkeypatch.setattr("auditex.command_runner._run_process", start_then_time_out)
    certificate = tmp_path / "reader.pem"
    certificate.write_text("not a key", encoding="utf-8")

    result = mcp_server.tool_handlers()["auditex_run_certificate_audit"](
        tenant_name="lab", tenant_id="11111111-1111-1111-1111-111111111111",
        client_id="22222222-2222-2222-2222-222222222222", certificate_path=str(certificate),
        certificate_thumbprint="A" * 40, out_dir=str(out),
    )

    assert result.get("error_class") == "timeout", result
    assert result.get("partial_run_dir") == str(partial), result
    assert f"--resume-from {partial}" in result["error"]


def test_a_terminated_mcp_server_stops_a_command_whose_first_process_already_exited(tmp_path: Path) -> None:
    # Repair round 2 (R063): the engine's own process has exited but a process it started still holds the pipes.
    import os
    import subprocess
    import sys
    import time

    marker = tmp_path / "grandchild-finished"
    script = tmp_path / "server_stand_in.py"
    script.write_text(
        _SERVER_STAND_IN.replace("& wait", "& exit 0").replace("time.sleep(0.5)", "time.sleep(1.0)"), encoding="utf-8"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}

    server = subprocess.run([sys.executable, str(script), str(marker)], env=env, timeout=30, check=False)

    assert server.returncode != 0
    time.sleep(2.5)
    assert not marker.exists()
