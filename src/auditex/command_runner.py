from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any
from uuid import uuid4

from azure_tenant_audit.secret_hygiene import collect_sensitive_argv_values, redact_argv, redact_output, redact_text


SENSITIVE_ARGS = {
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
            text = re.sub(r"(?<![\w.!#$%&'*+=?^`{|}~\\-])" + re.escape(original), lambda _: marker, text)
            replacements[marker] = original
    text = redact_output(text, sensitive_values, limit=None)
    for marker, original in replacements.items():
        text = text.replace(marker, original)
    return text


def run_cli_command(
    command: list[str], cwd: str | None = None, *, timeout_seconds: int = 900,
    scrub_operator_inputs: bool = False,
) -> dict[str, Any]:
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
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=child_env,
            stdin=subprocess.DEVNULL if scrub_operator_inputs else None,
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
