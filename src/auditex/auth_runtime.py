"""Local toolchain readiness for ``auditex doctor`` and the guided run.

Microsoft 365 audits sign in only as the reader app with a certificate (DEC-107), so nothing here checks a sign-in:
no Azure CLI, no CLI for Microsoft 365 and no saved auth context. It checks the Python the scripts select, the
virtual environment, PowerShell 7 and the ExchangeOnlineManagement module that exchange_policy needs.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from azure_tenant_audit.secret_hygiene import redact_output

JsonCommand = Callable[[list[str]], dict[str, Any]]

# The Python range Auditex is tested on: the one place that states it. Older than the minimum is blocked, newer than
# the newest tested minor is an "untested" warning, and a version that cannot be read is blocked, never supported.
# pyproject.toml (requires-python and the classifiers), the CI matrix and the docs follow these two values; a test
# checks that they do.
PYTHON_MINIMUM = (3, 11)
PYTHON_NEWEST_TESTED = (3, 15)
_PYTHON_VERSION = re.compile(r"(?:Python\s+)?(\d{1,4})\.(\d{1,4})(?![0-9])")


def tested_python_range_text() -> str:
    """For example ``3.11 to 3.14``."""
    return "{}.{} to {}.{}".format(*PYTHON_MINIMUM, *PYTHON_NEWEST_TESTED)


def classify_python_version(version: object) -> tuple[str, str | None]:
    """(status, error) for a Python version text such as ``Python 3.14.1``, ``3.15.0rc1`` or ``Python 3.12``.

    ``supported`` inside the tested range, ``untested`` above its newest minor (a warning, still usable),
    ``blocked`` below the minimum or when the text is not a readable major.minor version.
    """
    match = _PYTHON_VERSION.match(version.strip()) if isinstance(version, str) else None
    if match is None:
        return "blocked", "python_version_unreadable"
    found = (int(match.group(1)), int(match.group(2)))
    if found < PYTHON_MINIMUM:
        return "blocked", "python_too_old"
    if found > PYTHON_NEWEST_TESTED:
        return "untested", None
    return "supported", None

# A readiness command that runs longer than this is reported as blocked, so auditex doctor always returns.
COMMAND_TIMEOUT_SECONDS = 60


def _default_run_json_command(command: list[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return {
            "status": "blocked",
            "command": command,
            "error": "command_not_found",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "blocked",
            "command": command,
            "error": "command_timeout",
        }

    return {
        "status": "supported" if completed.returncode == 0 else "blocked",
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def exchange_module_status() -> dict[str, Any]:
    pwsh_exe = shutil.which("pwsh")
    if pwsh_exe is None:
        return {
            "status": "blocked",
            "error_class": "command_not_found",
            "error": "pwsh not installed",
        }
    try:
        completed = subprocess.run(
            [
                pwsh_exe,
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "Get-Module -ListAvailable ExchangeOnlineManagement | "
                "Select-Object -First 1 Name,Version | ConvertTo-Json -Compress",
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "blocked",
            "pwsh_path": pwsh_exe,
            "error_class": "command_timeout",
            "error": f"command_timeout:{COMMAND_TIMEOUT_SECONDS}s",
        }
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode == 0 and stdout and stdout != "null":
        payload: dict[str, Any] | None = None
        try:
            decoded = json.loads(stdout)
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = None
        return {
            "status": "supported",
            "pwsh_path": pwsh_exe,
            "module_name": (payload or {}).get("Name") or "ExchangeOnlineManagement",
            "module_version": (payload or {}).get("Version"),
        }
    return {
        "status": "blocked",
        "pwsh_path": pwsh_exe,
        "error_class": "module_not_found",
        "error": redact_output(stderr or stdout) or f"return_code:{completed.returncode}",
    }


@dataclass(frozen=True)
class ToolchainRuntimeAdapters:
    which: Callable[[str], str | None] = shutil.which
    run_json_command: JsonCommand = _default_run_json_command
    detect_package_manager: Callable[[], str | None] = lambda: "brew" if shutil.which("brew") else "apt" if shutil.which("apt-get") else "dnf" if shutil.which("dnf") else None


@dataclass(frozen=True)
class ToolchainRuntime:
    adapters: ToolchainRuntimeAdapters = field(default_factory=ToolchainRuntimeAdapters)
    repo_root: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    bootstrap_script: Path | None = None
    select_python_script: Path | None = None
    venv_dir: Path | None = None

    def __post_init__(self) -> None:
        if self.bootstrap_script is None:
            object.__setattr__(self, "bootstrap_script", self.repo_root / "scripts" / "bootstrap-local-tools.sh")
        if self.select_python_script is None:
            object.__setattr__(self, "select_python_script", self.repo_root / "scripts" / "select-python.sh")
        if self.venv_dir is None:
            object.__setattr__(self, "venv_dir", self.repo_root / ".venv")

    def command_version(
        self,
        command: list[str],
        *,
        parser: Callable[[str], str | None] | None = None,
    ) -> tuple[str | None, str | None]:
        result = self.adapters.run_json_command(command)
        if result["status"] != "supported":
            error = (result.get("stderr") or result.get("stdout") or result.get("error") or "").strip() or "version_check_failed"
            return None, redact_output(error)
        output = (result.get("stdout") or result.get("stderr") or "").strip()
        if not output:
            return None, "empty_version_output"
        if parser is not None:
            try:
                parsed = parser(output)
            except Exception as exc:  # noqa: BLE001
                return None, redact_output(str(exc))
            if not parsed:
                return None, "empty_version_output"
            return redact_output(parsed), None
        return redact_output(output), None

    def tool_status(
        self,
        command_name: str,
        *,
        version_args: list[str] | None = None,
        version_parser: Callable[[str], str | None] | None = None,
    ) -> dict[str, Any]:
        path = self.adapters.which(command_name)
        if not path:
            return {
                "name": command_name,
                "status": "blocked",
                "path": None,
                "version": None,
                "error": "command_not_found",
            }
        version = None
        error = None
        if version_args is not None:
            version, error = self.command_version([path, *version_args], parser=version_parser)
        status = "supported" if version or version_args is None else "blocked"
        return {
            "name": command_name,
            "status": status,
            "path": path,
            "version": version,
            "error": error,
        }

    def selected_python(self) -> dict[str, Any]:
        assert self.select_python_script is not None
        if not self.select_python_script.exists():
            return {
                "status": "blocked",
                "error": "missing_select_python_script",
                "path": str(self.select_python_script),
            }

        result = self.adapters.run_json_command(["bash", str(self.select_python_script)])
        stdout = (result.get("stdout") or "").strip()
        if result["status"] == "supported" and stdout:
            version, version_error = self.command_version([stdout, "--version"])
            status, error = classify_python_version(version) if version else ("blocked", version_error)
            return {
                "status": status,
                "path": stdout,
                "version": version,
                "selector": str(self.select_python_script),
                "error": error,
            }
        return {
            "status": "blocked",
            "path": None,
            "selector": str(self.select_python_script),
            "error": redact_output((result.get("stderr") or result.get("stdout") or result.get("error") or "").strip()) or "no_supported_python",
        }

    def venv_status(self) -> dict[str, Any]:
        assert self.venv_dir is not None
        python_path = self.venv_dir / "bin" / "python"
        return {
            "status": "supported" if python_path.exists() else "blocked",
            "path": str(self.venv_dir),
            "python_path": str(python_path),
        }
