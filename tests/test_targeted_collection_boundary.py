"""SS 2.1 adapter privacy boundary for ``Get-AntiPhishPolicy`` with a real synthetic child process.

``pwsh`` is replaced by a small executable script that ignores its arguments and writes planted bytes, so the tests
drive the adapter's own process handling (no live PowerShell, credentials or network). Tests that call
``PowerShellGraphAdapter.run`` without the new keyword use only the base API and are the fail-first proofs: on the
base adapter the planted target canaries reach the returned evidence or the audit events.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import time

import pytest

from azure_tenant_audit.adapters import powershell_graph as pg
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors.exchange_policy import ExchangePolicyCollector

COMMANDS = dict(ExchangePolicyCollector.command_collectors)
ANTI_PHISH = COMMANDS["antiPhishPolicies"]
OTHER = COMMANDS["transportConfig"]
ADDRESSES = ("alice@example.invalid", "bob@example.invalid")
DIGEST = "440e979a9184114e5d0376ee777b8c0ff444ca0db3a2242e01937331f494538a"
TARGETS = ["Zebulon Quarkwright;zq-canary@unlisted-canary.invalid", "canary-domain-x.invalid",
           "Name;;bad@@canary-malformed", *ADDRESSES]
FRAGMENTS = ("Zebulon", "Quarkwright", "zq-canary", "unlisted-canary", "canary-domain-x", "canary-malformed")
SETTINGS = {"Identity": "Default", "Name": "Default", "IsDefault": True, "Enabled": True,
            "EnableTargetedUserProtection": True, "TargetedUserProtectionAction": "Quarantine",
            "TargetedDomainsToProtect": ["partner.example.invalid"], "EnableViaTag": True}
ROWS = json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS, "UnselectedExtra": "Zebulon"}])
SAFE_DETAIL_KEYS = {"adapter", "command", "command_words", "executable", "return_code", "status", "error_class",
                    "duration_ms", "stdout_bytes", "stderr_bytes", "state"}
FLOOD = 80 * 1024 * 1024

CHILD = """\
import os, sys, time
def emit(stream, name):
    path = os.environ.get(name)
    if path:
        with open(path, "rb") as handle:
            stream.buffer.write(handle.read())
        stream.buffer.flush()
emit(sys.stderr, "SS21_STDERR_FILE")
emit(sys.stdout, "SS21_STDOUT_FILE")
flood = int(os.environ.get("SS21_FLOOD") or 0)
block = b"x" * (1024 * 1024)
sent = 0
while sent < flood:
    sys.stdout.buffer.write(block)
    sent += len(block)
sys.stdout.buffer.flush()
time.sleep(float(os.environ.get("SS21_SLEEP") or 0))
sys.exit(int(os.environ.get("SS21_EXIT") or 0))
"""


@pytest.fixture
def child(tmp_path, monkeypatch):
    """Point ``pwsh`` at the synthetic child; returns a function that plants its output."""
    script = tmp_path / "pwsh"
    script.write_text(f"#!{sys.executable} -I\n{CHILD}")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(pg.shutil, "which", lambda name: str(script) if name == "pwsh" else None)

    def plant(stdout: bytes | str = b"", stderr: bytes | str = b"", *, exit_code=0, flood=0, sleep=0):
        for name, data in (("SS21_STDOUT_FILE", stdout), ("SS21_STDERR_FILE", stderr)):
            path = tmp_path / name
            path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
            monkeypatch.setenv(name, str(path))
        monkeypatch.setenv("SS21_EXIT", str(exit_code))
        monkeypatch.setenv("SS21_FLOOD", str(flood))
        monkeypatch.setenv("SS21_SLEEP", str(sleep))
    return plant


def _run(command=ANTI_PHISH, session=None, **kwargs):
    events = []
    response = PowerShellGraphAdapter().run(
        command, log_event=lambda kind, message, details: events.append((kind, message, details)),
        session=session, **kwargs)
    return response, events


def _assert_private(response, events):
    text = json.dumps(response, default=str) + json.dumps(events, default=str)
    assert not [fragment for fragment in FRAGMENTS if fragment in text]
    assert '"TargetedUsersToProtect":' not in text.replace(" ", "")
    for kind, _message, details in events:
        assert set(details) <= SAFE_DETAIL_KEYS, (kind, sorted(set(details) - SAFE_DETAIL_KEYS))
    assert not {"stdout", "stderr", "stdout_sample", "stderr_sample"} & set(response)


def test_success_without_a_callback_strips_targets_and_records_no_output(child):
    child(ROWS, "WARNING: Zebulon Quarkwright zq-canary@unlisted-canary.invalid\n")
    response, events = _run()
    _assert_private(response, events)
    (row,) = response["value"]
    assert {key: row[key] for key in SETTINGS} == SETTINGS, "the warning is discarded, the read still succeeds"
    assert row["TargetedUsersCoverage"] == {"version": 1, "state": "not_collected"}
    assert set(row) == {*SETTINGS, "TargetedUsersCoverage"}
    completed = [details for kind, _m, details in events if kind == "command.completed"]
    assert completed and completed[-1]["status"] == "ok" and completed[-1]["stderr_bytes"] > 0


def test_success_with_the_collector_transform_returns_a_bound_summary(child):
    from functools import partial

    from azure_tenant_audit.collectors import targeted_users_coverage as tuc
    from azure_tenant_audit.sensitive_users import SensitiveUsers
    from azure_tenant_audit.value_rules.defender_targeted_users import (
        SensitiveUsersBinding,
    )
    child(ROWS)
    transform = partial(tuc.sanitise_response, sensitive_users=SensitiveUsers(ADDRESSES),
                        binding=SensitiveUsersBinding(2, DIGEST), observed=True)
    response, events = _run(response_transform=transform)
    _assert_private(response, events)
    assert response["value"][0]["TargetedUsersCoverage"] == {
        "version": 1, "state": "known", "input_hmac_sha256": DIGEST, "input_count": 2,
        "protected_nonempty": True, "missing_count": 0}
    assert DIGEST not in json.dumps(events)


@pytest.mark.parametrize("stdout,stderr,exit_code,session,error,error_class", [
    ("{not json Zebulon Quarkwright", "", 0, None, "command_output_parse_error", "command_parse_error"),
    ("NaN", "", 0, None, "command_output_parse_error", "command_parse_error"),
    (json.dumps("Zebulon Quarkwright zq-canary@unlisted-canary.invalid"), "", 0, None,
     "command_output_parse_error", "command_parse_error"),
    (json.dumps([{**SETTINGS, "TargetedUsersToProtect": TARGETS}, "Zebulon Quarkwright"]), "", 0, None,
     "command_output_parse_error", "command_parse_error"),
    (b"\xff\xfe Zebulon", "", 0, None, "command_output_parse_error", "command_parse_error"),
    ("", "", 0, None, "command_output_empty", "command_output_empty"),
    ("  \n", "Zebulon Quarkwright canary-domain-x.invalid", 0, None, "command_error", "command_error"),
    (ROWS, "Zebulon Quarkwright failed", 3, None, "command_failed:3", "command_error"),
    ("", "Access denied for zq-canary@unlisted-canary.invalid", 1, None, "command_failed:1", "command_not_authenticated"),
    ("", "The term 'Get-AntiPhishPolicy' is not recognized Zebulon", 1, {"kind": "none"},
     "command_failed:1", "session_not_connected"),
    ("", "The term 'Get-AntiPhishPolicy' is not recognized Zebulon", 1, None, "command_failed:1", "command_not_found"),
])
def test_failures_keep_their_class_and_no_text(child, stdout, stderr, exit_code, session, error, error_class):
    child(stdout, stderr, exit_code=exit_code)
    response, events = _run(session=session)
    _assert_private(response, events)
    assert (response["error"], response["error_class"]) == (error, error_class)
    assert "value" not in response, "no policy is invented for a failed or unrepresentable read"


def test_aggregate_stdout_cap_kills_reaps_and_keeps_nothing(child):
    child(ROWS[:-1] + ",", flood=FLOOD)
    started = time.monotonic()
    response, events = _run()
    _assert_private(response, events)
    assert response["error_class"] == "command_error" and response.get("state") == "over_limit"
    assert "value" not in response and "x" * 64 not in json.dumps(response)
    assert response["stdout_bytes"] <= 64 * 1024 * 1024 + pg.READ_CHUNK
    assert time.monotonic() - started < 60


def test_bounded_reader_is_inclusive_in_small_chunks():
    code = "import sys; sys.stdout.buffer.write(b'a' * int(sys.argv[1]))"
    exact = pg._run_bounded([sys.executable, "-I", "-c", code, "1000"], env=None, timeout=30,
                            stdout_limit=1000, chunk_size=7)
    assert not exact.overflow and bytes(exact.stdout) == b"a" * 1000 and exact.returncode == 0
    over = pg._run_bounded([sys.executable, "-I", "-c", code, "1001"], env=None, timeout=30,
                           stdout_limit=1000, chunk_size=7)
    assert over.overflow and len(over.stdout) <= 1000 and over.stdout_total <= 1000 + 7
    assert "a" not in repr(over)


def _reaped(pid: int) -> bool:
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return False


def test_bounded_reader_stops_at_the_limit_and_reaps_a_flooding_child():
    code = "import sys\nblock = b'x' * 65536\nwhile True: sys.stdout.buffer.write(block)"
    run = pg._run_bounded([sys.executable, "-I", "-c", code], env=None, timeout=60,
                          stdout_limit=64 * 1024 * 1024, chunk_size=4096)
    assert run.overflow and not run.timed_out
    assert len(run.stdout) <= 64 * 1024 * 1024 and run.stdout_total <= 64 * 1024 * 1024 + 4096
    assert run.returncode != 0, "the child was killed, not left writing"
    assert _reaped(run.pid)


def test_bounded_reader_timeout_kills_and_reaps():
    started = time.monotonic()
    run = pg._run_bounded([sys.executable, "-I", "-c", "import time; time.sleep(60)"], env=None, timeout=1,
                          stdout_limit=1024)
    assert run.timed_out and not run.overflow and run.returncode != 0
    assert time.monotonic() - started < 20 and _reaped(run.pid)


def test_bounded_reader_drains_a_large_stderr_without_deadlock():
    code = ("import sys; sys.stderr.buffer.write(b'e' * (8 * 1024 * 1024)); sys.stderr.flush(); "
            "sys.stdout.write('[]')")
    run = pg._run_bounded([sys.executable, "-I", "-c", code], env=None, timeout=30, stdout_limit=1024)
    assert not run.timed_out and not run.overflow and bytes(run.stdout) == b"[]"
    assert run.stderr_total == 8 * 1024 * 1024 and len(run.stderr) <= pg.STDERR_KEEP


def test_adapter_timeout_is_a_fixed_class(child, monkeypatch):
    real = pg._run_bounded
    monkeypatch.setattr(pg, "_run_bounded", lambda argv, **kw: real(argv, **{**kw, "timeout": 1}))
    child(ROWS, sleep=30)
    response, events = _run()
    _assert_private(response, events)
    assert (response["error"], response["error_class"]) == ("command_timeout", "command_timeout")


def test_adapter_exception_is_a_fixed_class_with_no_message(child, monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("Zebulon Quarkwright zq-canary@unlisted-canary.invalid")
    monkeypatch.setattr(pg, "_run_bounded", boom)
    child(ROWS)
    response, events = _run()
    _assert_private(response, events)
    assert response["error_class"] == "command_exception"


@pytest.mark.parametrize("variant", ["raises", "returns_targets", "returns_text"])
def test_a_failing_or_wrong_transform_never_carries_values_out(child, variant):
    child(ROWS)

    def transform(response):
        if variant == "raises":
            raise ValueError("Zebulon Quarkwright " + json.dumps(response))
        if variant == "returns_targets":
            return response
        return {"value": [], "error": "Zebulon Quarkwright"}
    response, events = _run(response_transform=transform)
    _assert_private(response, events)
    assert response["error_class"] == "command_exception" and "value" not in response


def test_other_commands_keep_their_existing_diagnostics(child):
    child(json.dumps([{"Name": "Admin", "SmtpClientAuthenticationDisabled": True}]))
    response, events = _run(OTHER)
    assert response["value"] == [{"Name": "Admin", "SmtpClientAuthenticationDisabled": True}]
    completed = [details for kind, _m, details in events if kind == "command.completed"]
    assert "stdout_sample" in completed[-1]


def test_sensitive_recognition_matches_the_boundary_module():
    from azure_tenant_audit.collectors.targeted_users_coverage import (
        is_sensitive_command,
    )
    for script in (ANTI_PHISH, ANTI_PHISH.lower(), "Get-AntiPhishPolicy", ",@(get-antiphishpolicy | Select-Object Name)",
                   "Get-Foo | Select-Object TargetedUsersToProtect"):
        assert pg._sensitive(script) and is_sensitive_command(script)
    for script in (OTHER, COMMANDS["antiPhishRules"]):
        assert not pg._sensitive(script) and not is_sensitive_command(script)
