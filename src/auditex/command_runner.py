from __future__ import annotations

import atexit
import os
import re
import signal
import subprocess
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from azure_tenant_audit.secret_hygiene import (
    collect_sensitive_argv_values,
    redact_argv,
    redact_output,
    redact_text,
)

SENSITIVE_ARGS = {
    "--sensitive-users",
    "--partner-domains",
    "--access-token",
    "--client-secret",
    "--token",
    "--command-override",
    "--adapter-override",
    "--service-account-key",
    "--oauth-client",
    "--token-cache",
    "--token-file",
    "--env",
    "--break-glass-accounts",
    # A DoH resolver URL path can carry an account token.
    "--doh-endpoint",
}
OPERATOR_ARGS = {
    "--tenant-name", "--tenant-id", "--out", "--run-name",
    "--target", "--subject", "--domain", "--run-dir",
}
# Extend this registry when adding an operator input, including inputs whose
# environment name does not end in _FILE. Values are their CLI flag forms.
OPERATOR_INPUTS = {
    "AUDITEX_SENSITIVE_USERS_FILE": "--sensitive-users",
    "AUDITEX_PARTNER_DOMAINS_FILE": "--partner-domains",
    "AUDITEX_BREAK_GLASS_ACCOUNTS": "--break-glass-accounts",
}
# Offline validation needs no AUDITEX_* environment settings. Any future
# exception must be deliberately added here after reviewing its effect.
OFFLINE_AUDITEX_ENV_ALLOWLIST: frozenset[str] = frozenset()


def _without_operator_input_args(command: list[str]) -> list[str]:
    flags = set(OPERATOR_INPUTS.values())
    result: list[str] = []
    index = 0
    while index < len(command):
        name, separator, _ = command[index].partition("=")
        if name in flags:
            index += 1
            if not separator and index < len(command) and not command[index].startswith("-"):
                index += 1
        else:
            result.append(command[index])
            index += 1
    return result


def _sensitive_values(command: list[str]) -> set[str]:
    return collect_sensitive_argv_values(command, sensitive_flags=SENSITIVE_ARGS)


def redact_command(command: list[str]) -> list[str]:
    sensitive_values = _sensitive_values(command)
    return [redact_text(item, sensitive_values) for item in redact_argv(command, sensitive_flags=SENSITIVE_ARGS)]


def _redact_text(value: str | bytes, sensitive_values: set[str], operator_values: set[str]) -> str:
    # Credentials take precedence over identifier exemptions. The live MCP
    # response must preserve operator inputs and run paths for tool chaining.
    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    text = redact_text(text, sensitive_values)
    prefix = f"\x00auditex-operator-{uuid4().hex}-"
    while prefix in text:
        prefix = f"\x00auditex-operator-{uuid4().hex}-"
    replacements = {}
    for index, original in enumerate(sorted(operator_values, key=len, reverse=True)):
        marker = f"{prefix}{index}\x00"
        if original in text:
            # An operator address must not shield a suffix of another local part.
            text = re.sub(r"(?<![\w.!#$%&'*+=?^`{|}~\\-])" + re.escape(original), lambda _: marker, text)  # noqa: B023 - the closure runs within this loop iteration, so late binding cannot leak
            replacements[marker] = original
    text = redact_output(text, sensitive_values, limit=None)
    for marker, original in replacements.items():
        text = text.replace(marker, original)
    return text


# A full audit of a large tenant (paged users, SharePoint, Intune, Exchange PowerShell) can run for hours, so the
# MCP tools wait four hours by default. AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS sets another limit; 0 waits without one.
COMMAND_TIMEOUT_ENV = "AUDITEX_MCP_COMMAND_TIMEOUT_SECONDS"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 4 * 3600


def command_timeout_seconds() -> int | None:
    """The limit an MCP-launched command runs under: the environment setting, else four hours (``None``: no limit)."""
    raw = os.environ.get(COMMAND_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_COMMAND_TIMEOUT_SECONDS
    return None if value <= 0 else value


# How long a stopped command's process group gets to release its output pipes after SIGKILL.
_KILLED_GROUP_DRAIN_SECONDS = 5


def _kill_process_group(process: Any) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError):
        if process.poll() is None:
            process.kill()


# Commands started by this server whose process groups may still be live. Each starts in its own session, so a signal
# to the server's process group no longer reaches it: the server stops them itself when it exits (atexit) or is
# terminated (``install_signal_stop``). A command leaves the set only once its own process has been reaped, and never
# after a stop is requested, so every group live when the stop begins is in the snapshot the stop kills.
_RUNNING: set[Any] = set()
# Reentrant, so a thread that already holds it (a synchronous MCP tool launching a command) can take it again. A launch
# holds it from the stop check until its command is registered, so a stop's snapshot never falls inside a launch.
_RUNNING_LOCK = threading.RLock()
# True once a stop is requested; no command starts after it. A plain flag, so a signal handler can set it without a lock.
_STOP_REQUESTED = False


class ShuttingDown(RuntimeError):
    """The server is stopping its commands; no new command starts."""


def stop_running_commands() -> None:
    """Kill the process group of every command started and not yet finished; the server is going away and nothing
    will collect their results (R063).

    No command starts once this has begun, and none leaves the registry, so the snapshot taken under the lock holds
    every command running when the stop was requested, including one another thread was launching. Never call this
    from a signal handler (``install_signal_stop``).
    """
    global _STOP_REQUESTED
    _STOP_REQUESTED = True
    with _RUNNING_LOCK:
        running = list(_RUNNING)
    for process in running:
        # Kill the group even when its first process has exited: a process it started can still be running and
        # holding the output pipes, and the group outlives its leader while any member is left.
        _kill_process_group(process)


def _start_process(command: list[str], **kwargs: Any) -> Any:
    """Start ``command`` and register it, so a stop at any moment either refuses it or stops it."""
    with _RUNNING_LOCK:
        if _STOP_REQUESTED:
            raise ShuttingDown("the MCP server is shutting down; the command was not started")
        process = subprocess.Popen(command, **kwargs)
        _RUNNING.add(process)
    return process


def _forget_process(process: Any) -> None:
    """Drop a command whose own process has been reaped, unless a stop is requested: the stop must still kill its
    group, where a process it started may be running."""
    with _RUNNING_LOCK:
        if not _STOP_REQUESTED:
            _RUNNING.discard(process)


# How long the stop thread gives the main thread to end the process by the signal before it exits directly.
_SIGNAL_EXIT_GRACE_SECONDS = 5


def install_signal_stop(signal_names: tuple[str, ...] = ("SIGTERM", "SIGHUP")) -> None:
    """On any of ``signal_names``, stop every running command, then end the process by the first signal (R063).

    The handler takes no lock: it sets the stop flag and writes the signal number to a pipe. A stop thread reads the
    first number, kills the registered process groups outside the handler, and sends that signal again; the handler
    then restores the default action for it and re-raises it. Any other signal after the first changes nothing.
    """
    read_fd, write_fd = os.pipe()
    os.set_blocking(write_fd, False)
    first: list[int] = []  # the signal the process ends by, recorded before ``stopped`` is set
    stopped = threading.Event()

    def handle(signum: int, _frame: Any) -> None:
        global _STOP_REQUESTED
        _STOP_REQUESTED = True  # a plain assignment; takes no lock
        if stopped.is_set():  # reads a flag; takes no lock
            if signum == first[0]:
                signal.signal(signum, signal.SIG_DFL)
                signal.raise_signal(signum)
            return
        try:
            os.write(write_fd, bytes([signum]))
        except (BlockingIOError, OSError):
            pass  # the pipe already holds a signal the stop thread will act on

    def stop_on_signal() -> None:
        signum = os.read(read_fd, 1)[0]
        first.append(signum)
        stop_running_commands()
        stopped.set()
        os.kill(os.getpid(), signum)
        # The main thread ends the process from the handler; if it cannot run the handler, end it here.
        threading.Event().wait(_SIGNAL_EXIT_GRACE_SECONDS)
        os._exit(128 + signum)

    threading.Thread(target=stop_on_signal, name="auditex-signal-stop", daemon=True).start()
    for name in signal_names:
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), handle)


atexit.register(stop_running_commands)


def _run_process(
    command: list[str], *, cwd: str | None = None, text: bool = True, capture_output: bool = True,
    check: bool = False, timeout: int | None = None, env: dict[str, str] | None = None, stdin: Any = None,
) -> subprocess.CompletedProcess[str]:
    """``subprocess.run`` for an MCP command, except that a timeout stops the child's whole process group (R063).

    The child starts in its own session, so the PowerShell processes and other children the engine starts share
    its process group; on timeout the group is killed, not only the direct child, and ``TimeoutExpired`` is raised
    with whatever output was read.
    """
    del text, capture_output, check  # always text, captured and unchecked, as every caller asks
    process = _start_process(
        command, cwd=cwd, env=env, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        return _collect(command, process, timeout)
    finally:
        _forget_process(process)  # _collect has reaped it on every path


def _collect(command: list[str], process: Any, timeout: int | None) -> subprocess.CompletedProcess[str]:
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        try:
            stdout, stderr = process.communicate(timeout=_KILLED_GROUP_DRAIN_SECONDS)
        except subprocess.TimeoutExpired:
            # A descendant that left the group still holds the pipes; give up on its output.
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            process.wait()
            stdout, stderr = "", ""
        raise subprocess.TimeoutExpired(command, timeout or 0, output=stdout, stderr=stderr) from None
    except BaseException:
        _kill_process_group(process)
        process.wait()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _flag_values(command: list[str], flag: str) -> list[str]:
    """The values given for exactly ``flag`` (``--out X`` or ``--out=X``). Unlike ``collect_sensitive_argv_values``
    this reads no other flag: that helper also collects every certificate flag's value (R063)."""
    values: list[str] = []
    for index, item in enumerate(command):
        name, separator, value = item.partition("=")
        if name != flag:
            continue
        if separator:
            values.append(value)
        elif index + 1 < len(command):
            values.append(command[index + 1])
    return values


def _run_folders(command: list[str], cwd: str | None) -> tuple[Path, str] | None:
    """The ``--out`` folder and the ``<tenant-name>-`` prefix the engine names a new run folder with, if given."""
    outs = sorted(set(_flag_values(command, "--out")))
    tenants = sorted(set(_flag_values(command, "--tenant-name")))
    if len(outs) != 1 or len(tenants) != 1 or not outs[0] or not tenants[0]:
        return None
    return Path(cwd or Path.cwd()) / outs[0], f"{tenants[0]}-"


def _listed_run_folders(target: tuple[Path, str] | None) -> set[str]:
    if target is None:
        return set()
    out, prefix = target
    try:
        return {entry.name for entry in os.scandir(out) if entry.name.startswith(prefix) and entry.is_dir(follow_symlinks=False)}
    except OSError:
        return set()


def run_cli_command(
    command: list[str], cwd: str | None = None, *, timeout_seconds: int | None = None,
    scrub_operator_inputs: bool = False, resumable: bool = False,
) -> dict[str, Any]:
    """Run an Auditex command for an MCP tool and return its redacted output.

    ``timeout_seconds`` defaults to ``command_timeout_seconds()`` (R063): four hours, not the fifteen minutes a
    full audit of a large tenant outlasts. On timeout the command's whole process group is stopped. ``resumable``
    marks a command whose run folder ``--resume-from`` can complete (the Microsoft 365 certificate audit); only its
    timeout says so, naming the partial run folder (``partial_run_dir``) when exactly one new one appeared.
    """
    if timeout_seconds is None:
        timeout_seconds = command_timeout_seconds()
    run_target = _run_folders(command, cwd) if resumable else None
    folders_before = _listed_run_folders(run_target)
    child_env = None
    if scrub_operator_inputs:
        command = _without_operator_input_args(command)
        child_env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("AUDITEX_") or key in OFFLINE_AUDITEX_ENV_ALLOWLIST
        }
    sensitive_values = _sensitive_values(command)
    operator_values = collect_sensitive_argv_values(command, sensitive_flags=OPERATOR_ARGS)
    for path in collect_sensitive_argv_values(command, sensitive_flags={"--out", "--run-dir"}):
        operator_values.add(str((Path(cwd or Path.cwd()) / path).resolve()))
    # Ordinary labels need no exemption; shielding 'alice', for example, could
    # otherwise hide that local part inside an unrelated alice@example.com.
    operator_values = {value for value in operator_values if redact_output(value, limit=None) != value}
    try:
        completed = _run_process(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=child_env,
            stdin=subprocess.DEVNULL if scrub_operator_inputs else None,
        )
    except ShuttingDown as exc:
        return {
            "command": redact_command(command),
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error_class": "shutting_down",
            "error": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        new_folders = sorted(_listed_run_folders(run_target) - folders_before)
        partial = str(run_target[0] / new_folders[0]) if run_target is not None and len(new_folders) == 1 else None
        if partial is not None:
            operator_values.add(partial)
        resume_hint = ""
        if resumable:
            resume_hint = f"; complete it with --resume-from {partial}" if partial else "; complete it with --resume-from"
        result: dict[str, Any] = {
            "command": redact_command(command),
            "returncode": None,
            "stdout": _redact_text(stdout, sensitive_values, operator_values),
            "stderr": _redact_text(stderr, sensitive_values, operator_values),
            "error_class": "timeout",
            "error": _redact_text(
                f"command timed out after {timeout_seconds}s; the run folder is left unfinalised{resume_hint}"
                f". Set {COMMAND_TIMEOUT_ENV} for a longer limit (0 for none).",
                sensitive_values,
                operator_values,
            ),
        }
        if partial is not None:
            result["partial_run_dir"] = _redact_text(partial, sensitive_values, operator_values)
        return result
    return {
        "command": redact_command(command),
        "returncode": completed.returncode,
        "stdout": _redact_text(completed.stdout, sensitive_values, operator_values),
        "stderr": _redact_text(completed.stderr, sensitive_values, operator_values),
    }
