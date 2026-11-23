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


def test_capping_a_wide_section_measures_the_summary_a_bounded_number_of_times(monkeypatch: pytest.MonkeyPatch) -> None:
    # Review of repair round 2 (R025): re-measuring the whole summary after every dropped field is quadratic.
    from auditex import mcp_server

    calls = {"count": 0}
    real = mcp_server._json_size

    def counted(value: object) -> int:
        calls["count"] += 1
        return real(value)

    monkeypatch.setattr(mcp_server, "_json_size", counted)
    manifest = {"tenant_name": "acme", "run_id": "r1"}
    manifest |= {f"surface_{index}": {"status": "blocked_permission"} for index in range(3000)}
    manifest |= {f"note_{index}": "x" * 20 for index in range(3000)}
    result = mcp_server._cap_summary({"manifest": manifest}, budget=4_000)
    whole_summary_measures = calls["count"] - 6000  # one measure per field when they are sorted

    assert real(result) <= 4_000
    assert result["manifest"]["run_id"] == "r1"
    assert whole_summary_measures < 300, whole_summary_measures


def test_a_section_dropped_whole_keeps_its_pointer_and_the_citations(tmp_path: Path) -> None:
    # Review of repair round 2 (R025): the last-resort trimming of the omitted record and the citations runs only
    # when dropping sections cannot make the summary fit.
    from auditex.mcp_server import _cap_summary

    citations = [{"artifact_path": "run-manifest.json", "reason": "Run identity."}]
    result = _cap_summary(
        {"manifest": {"tenant_name": "acme", "run_id": "r1"}, "run_dir": "x" * 6000, "citations": citations},
        budget=4_000,
    )

    assert result["citations"] == citations
    assert result["omitted_sections"]["run_dir"]["bytes"] > 6000
    assert result["manifest"]["run_id"] == "r1"


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


# Bot review wave 2, group L: summary capping and command shutdown


def _sections_copied_per_field_drop(field_count: int, monkeypatch: pytest.MonkeyPatch) -> tuple[int, dict, dict]:
    from auditex import mcp_server

    seen: list[object] = []  # held, so each copy keeps its own id
    real = mcp_server._record_omitted_field

    def record(capped, omitted, key, name, size):
        seen.append(capped[key])
        return real(capped, omitted, key, name, size)

    monkeypatch.setattr(mcp_server, "_record_omitted_field", record)
    manifest = {"tenant_name": "acme", "run_id": "r1"} | {f"note_{index}": "x" * 20 for index in range(field_count)}
    original = dict(manifest)
    result = mcp_server._cap_summary({"manifest": manifest}, budget=4_000)
    return len({id(section) for section in seen}), manifest == original and len(manifest) == len(original), result


@pytest.mark.parametrize("field_count", [2_000, 4_000])
def test_capping_a_wide_section_copies_it_once_however_many_fields_it_loses(
    field_count: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Bot review (greptile/coderabbit, PR 172): every dropped field copied the whole shrinking section.
    copies, input_unchanged, result = _sections_copied_per_field_drop(field_count, monkeypatch)

    assert copies == 1
    assert input_unchanged
    assert len(json.dumps(result, default=str)) <= 4_000
    assert result["manifest"]["run_id"] == "r1"
    assert result["omitted_sections"]["manifest.fields"]["more_fields"] > 0


def test_omitted_diagnostics_point_at_a_place_that_holds_them(tmp_path: Path) -> None:
    # Bot review (coderabbit, PR 172): the hint named auditex_list_blockers, which returns no diagnostics.
    from support import RunBundleBuilder

    from auditex.mcp_server import _cap_summary, list_blockers, summarize_run_raw

    run_dir = RunBundleBuilder(tmp_path).blockers([{"collector": "identity", "status": "blocked"}]).build()
    (run_dir / "diagnostics.json").write_text(
        json.dumps([{"collector": f"c{index}", "note": "n" * 200} for index in range(400)]), encoding="utf-8"
    )

    summary = _cap_summary(summarize_run_raw(str(run_dir)), budget=20_000)
    entry = summary["omitted_sections"]["diagnostics"]
    read_with = entry.get("read_with")

    if read_with == "auditex_list_blockers":
        assert "diagnostics" in list_blockers(str(run_dir)), "the named tool does not return the diagnostics"
    assert read_with is None
    assert entry["artifact"] == "diagnostics.json"
    assert entry["path"].endswith("diagnostics.json")


def test_emptied_citations_leave_a_citation_summary_that_agrees() -> None:
    # Bot review (coderabbit, PR 172): the summary still counted the citation the cap had removed.
    from auditex.mcp_server import _cap_summary
    from azure_tenant_audit.citations import build_citation_summary

    citations = [{"artifact_path": "run-manifest.json", "reason": "r" * 200}]
    payload = {
        "manifest": {"tenant_name": "acme", "run_id": "r1"},
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
    }

    result = _cap_summary(payload, budget=400)

    assert len(json.dumps(result, default=str)) <= 400
    assert result["citations"] == []
    assert result["citations_omitted"] == 1
    summary = result["citation_summary"]
    assert summary == {} or summary.get("citation_count") == 0, summary
    assert payload["citations"] == citations


def _alive(pid: int) -> bool:
    import os

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for(predicate, seconds: float) -> bool:
    import time

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def _descendant_command(pid_file: Path) -> list[str]:
    # The shell starts a long sleep, writes the sleep's own PID (the readiness marker) and waits for it.
    return ["sh", "-c", f"sleep 60 & echo $! > '{pid_file}.tmp' && mv '{pid_file}.tmp' '{pid_file}'; wait"]


def test_a_command_timeout_stops_the_descendant_it_started(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Bot review (coderabbit, PR 172): the timeout test passed even when the launched sleep survived the timeout.
    from auditex.command_runner import run_cli_command

    monkeypatch.setenv("AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS", "1")
    pid_file = tmp_path / "descendant.pid"

    result = run_cli_command(_descendant_command(pid_file))

    assert result["error_class"] == "timeout"
    assert pid_file.exists(), "the command never started its descendant"
    descendant = int(pid_file.read_text(encoding="utf-8"))
    assert _wait_for(lambda: not _alive(descendant), 5), f"descendant {descendant} survived the timeout"


_SIGNALLED_SERVER = """
import os, signal, sys, threading, time
from pathlib import Path
from auditex import command_runner, mcp_server
mcp_server._install_shutdown_handlers()
pid_file = Path(sys.argv[1])
command = ["sh", "-c", f"sleep 60 & echo $! > '{pid_file}.tmp' && mv '{pid_file}.tmp' '{pid_file}'; wait"]
mode = sys.argv[2]
if mode in ("registered", "leader_exited"):
    if mode == "leader_exited":
        # The engine's own process exits; the process it started still runs and holds the output pipes.
        command[-1] = command[-1].replace("; wait", "; exit 0")
    threading.Thread(target=command_runner.run_cli_command, args=(command,), daemon=True).start()
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.3)
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "lock_held":
    with command_runner._RUNNING_LOCK:
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(0.5)
elif mode == "launch_gap":
    real_popen = command_runner.subprocess.Popen

    def popen_then_signal(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        deadline = time.monotonic() + 10
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        os.kill(os.getpid(), signal.SIGTERM)  # the signal lands before the process is registered
        return process

    command_runner.subprocess.Popen = popen_then_signal
    command_runner.run_cli_command(command)
elif mode == "slow_worker_launch":
    # A worker thread's command has started but is not yet registered when the server is terminated, and stays so
    # for longer than the ten seconds the stop once waited for launches to settle.
    real_popen = command_runner.subprocess.Popen

    def popen_then_stall(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        time.sleep(11)
        return process

    command_runner.subprocess.Popen = popen_then_stall
    threading.Thread(target=command_runner.run_cli_command, args=(command,), daemon=True).start()
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "nested_signal":
    # A SIGHUP lands while the SIGTERM stop is killing the registered process groups.
    real_kill_group = command_runner._kill_process_group

    def kill_group_after_a_second_signal(process):
        os.kill(os.getpid(), signal.SIGHUP)
        time.sleep(0.3)
        real_kill_group(process)

    command_runner._kill_process_group = kill_group_after_a_second_signal
    threading.Thread(target=command_runner.run_cli_command, args=(command,), daemon=True).start()
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "late_signal":
    # A SIGHUP lands after the commands are stopped but before the stop re-sends the SIGTERM that ends the server.
    real_kill = os.kill

    def kill_after_a_late_signal(pid, signum):
        if threading.current_thread().name == "auditex-signal-stop" and signum == signal.SIGTERM:
            real_kill(pid, signal.SIGHUP)
            time.sleep(0.3)
        real_kill(pid, signum)

    os.kill = kill_after_a_late_signal
    threading.Thread(target=command_runner.run_cli_command, args=(command,), daemon=True).start()
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    os.kill(os.getpid(), signal.SIGTERM)
elif mode == "finished_during_stop":
    # Command A is running when SIGTERM lands; its own process exits during the stop (while a second launch is still
    # in flight) and leaves a descendant with its output redirected, so A's run returns before the stop is done.
    go_file = pid_file.with_name("go")
    command = [
        "sh", "-c",
        f"sleep 60 </dev/null >/dev/null 2>&1 & echo $! > '{pid_file}.tmp' && mv '{pid_file}.tmp' '{pid_file}'; "
        f"while [ ! -e '{go_file}' ]; do sleep 0.05; done; exit 0",
    ]
    threading.Thread(target=command_runner.run_cli_command, args=(command,), daemon=True).start()
    deadline = time.monotonic() + 10
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    real_popen = command_runner.subprocess.Popen
    in_launch = threading.Event()

    def popen_until_a_finished(*args, **kwargs):
        in_launch.set()
        deadline = time.monotonic() + 10
        while not go_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(1)  # A's own process exits and its run returns meanwhile
        return real_popen(*args, **kwargs)

    command_runner.subprocess.Popen = popen_until_a_finished
    threading.Thread(target=command_runner.run_cli_command, args=(["sleep", "30"],), daemon=True).start()
    in_launch.wait(10)
    os.kill(os.getpid(), signal.SIGTERM)
    go_file.touch()
# Idle until the signal ends the process; exiting by itself would race the stop that ends it by the signal.
time.sleep(20)
sys.exit(0)
"""


@pytest.mark.parametrize(
    "mode",
    [
        "registered", "leader_exited", "lock_held", "launch_gap", "slow_worker_launch", "nested_signal", "late_signal",
        "finished_during_stop",
    ],
)
def test_a_terminated_mcp_server_stops_its_command_at_every_point_of_launch(mode: str, tmp_path: Path) -> None:
    # R063: the command runs in its own session, so the server must stop it on SIGTERM; the check waits for the
    # command's readiness marker and follows the PID of the process it started. Bot review (coderabbit, PR 172): a
    # signal while the main thread held the registry lock hung the server, and a signal between the launch and its
    # registration left the command running. Review of PR 187: a worker launch that outlasted the stop's wait left its
    # command running, and a second signal during the stop deadlocked the server. Second review of PR 187: a command
    # whose own process exited during the stop left its descendant running, and a later SIGHUP changed the exit signal.
    import os
    import signal
    import subprocess
    import sys

    pid_file = tmp_path / "descendant.pid"
    script = tmp_path / "server_stand_in.py"
    script.write_text(_SIGNALLED_SERVER, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}

    try:
        server = subprocess.run([sys.executable, str(script), str(pid_file), mode], env=env, timeout=30, check=False)
    finally:
        descendant = int(pid_file.read_text(encoding="utf-8")) if pid_file.exists() else None
        survived = descendant is not None and not _wait_for(lambda: not _alive(descendant), 5)
        if survived:
            os.kill(descendant, signal.SIGKILL)

    assert server.returncode == -signal.SIGTERM
    if mode != "lock_held":
        assert descendant is not None, "the command never started its descendant"
    assert not survived, f"descendant {descendant} survived the server"


def test_a_command_launched_while_a_stop_is_waiting_is_stopped_and_later_launches_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Bot review (coderabbit, PR 172): a stop that snapshots the registry between another thread's launch and its
    # registration must still stop that command, and no command may start once the stop has begun.
    import threading

    from auditex import command_runner

    monkeypatch.setattr(command_runner, "_RUNNING", set())
    monkeypatch.setattr(command_runner, "_STOP_REQUESTED", False)
    pid_file = tmp_path / "descendant.pid"
    launched, release = threading.Event(), threading.Event()
    real_popen = command_runner.subprocess.Popen

    def paused_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        launched.set()
        release.wait(10)
        return process

    monkeypatch.setattr(command_runner.subprocess, "Popen", paused_popen)
    results: list[dict] = []
    worker = threading.Thread(target=lambda: results.append(command_runner.run_cli_command(_descendant_command(pid_file))))
    worker.start()
    try:
        assert launched.wait(10)
        assert _wait_for(pid_file.exists, 10)
        threading.Timer(0.3, release.set).start()
        command_runner.stop_running_commands()
        descendant = int(pid_file.read_text(encoding="utf-8"))
        stopped = _wait_for(lambda: not _alive(descendant), 5)
    finally:
        release.set()
        worker.join(15)
        if pid_file.exists() and _alive(int(pid_file.read_text(encoding="utf-8"))):
            import os
            import signal

            os.kill(int(pid_file.read_text(encoding="utf-8")), signal.SIGKILL)

    assert stopped, "the command launched during the stop survived it"
    assert results and results[0]["returncode"] != 0
    monkeypatch.setattr(command_runner.subprocess, "Popen", real_popen)
    refused = command_runner.run_cli_command(["sh", "-c", "exit 0"])
    assert refused.get("error_class") == "shutting_down", refused
