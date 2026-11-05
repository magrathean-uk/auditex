from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any
from uuid import uuid4

from azure_tenant_audit.secret_hygiene import collect_sensitive_argv_values, redact_argv, redact_output, redact_text


SENSITIVE_ARGS = {
    "--sensitive-users",
    "--partner-domains",
    "--access-token",
    "--client-secret",
    "--token",
    "--command-override",
    "--adapter-override",
}
OPERATOR_ARGS = {
    "--tenant-name", "--tenant-id", "--out", "--run-name",
    "--target", "--subject", "--domain", "--run-dir",
}


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
            text = re.sub(r"(?<![\w.!#$%&'*+=?^`{|}~\\-])" + re.escape(original), lambda _: marker, text)
            replacements[marker] = original
    text = redact_output(text, sensitive_values, limit=None)
    for marker, original in replacements.items():
        text = text.replace(marker, original)
    return text


def run_cli_command(command: list[str], cwd: str | None = None, *, timeout_seconds: int = 900) -> dict[str, Any]:
    sensitive_values = _sensitive_values(command)
    operator_values = collect_sensitive_argv_values(command, sensitive_flags=OPERATOR_ARGS)
    for path in collect_sensitive_argv_values(command, sensitive_flags={"--out", "--run-dir"}):
        operator_values.add(str((Path(cwd or Path.cwd()) / path).resolve()))
    # Ordinary labels need no exemption; shielding 'alice', for example, could
    # otherwise hide that local part inside an unrelated alice@example.com.
    operator_values = {value for value in operator_values if redact_output(value, limit=None) != value}
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
            "stdout": _redact_text(stdout, sensitive_values, operator_values),
            "stderr": _redact_text(stderr, sensitive_values, operator_values),
            "error_class": "timeout",
            "error": f"command timed out after {timeout_seconds}s",
        }
    return {
        "command": redact_command(command),
        "returncode": completed.returncode,
        "stdout": _redact_text(completed.stdout, sensitive_values, operator_values),
        "stderr": _redact_text(completed.stderr, sensitive_values, operator_values),
    }
