from __future__ import annotations

import subprocess
from typing import Any

from azure_tenant_audit.secret_hygiene import collect_sensitive_argv_values, redact_argv, redact_text


SENSITIVE_ARGS = {
    "--access-token",
    "--client-secret",
    "--token",
    "--command-override",
    "--adapter-override",
}


def _sensitive_values(command: list[str]) -> set[str]:
    return collect_sensitive_argv_values(command, sensitive_flags=SENSITIVE_ARGS)


def redact_command(command: list[str]) -> list[str]:
    return redact_argv(command, sensitive_flags=SENSITIVE_ARGS)


def _redact_text(value: str, sensitive_values: set[str]) -> str:
    return redact_text(value, sensitive_values)


def run_cli_command(command: list[str], cwd: str | None = None, *, timeout_seconds: int = 900) -> dict[str, Any]:
    sensitive_values = _sensitive_values(command)
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "command": redact_command(command),
            "returncode": None,
            "stdout": _redact_text(stdout, sensitive_values),
            "stderr": _redact_text(stderr, sensitive_values),
            "error_class": "timeout",
            "error": f"command timed out after {timeout_seconds}s",
        }
    return {
        "command": redact_command(command),
        "returncode": completed.returncode,
        "stdout": _redact_text(completed.stdout, sensitive_values),
        "stderr": _redact_text(completed.stderr, sensitive_values),
    }
