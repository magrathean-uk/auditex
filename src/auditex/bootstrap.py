from __future__ import annotations

import importlib.util
import json
import platform
import shlex
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .auth_runtime import (
    ToolchainRuntime,
    ToolchainRuntimeAdapters,
    exchange_module_status,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP_SCRIPT = REPO_ROOT / "scripts" / "bootstrap-local-tools.sh"
SELECT_PYTHON_SCRIPT = REPO_ROOT / "scripts" / "select-python.sh"
DEFAULT_VENV_DIR = REPO_ROOT / ".venv"


def is_source_checkout() -> bool:
    """Whether this package runs from its own source checkout (with the bootstrap scripts) or an installed wheel/sdist."""
    try:
        own_tree = (REPO_ROOT / "src" / "auditex" / "bootstrap.py").resolve() == Path(__file__).resolve()
    except OSError:
        return False
    return own_tree and BOOTSTRAP_SCRIPT.is_file() and SELECT_PYTHON_SCRIPT.is_file()


# The module each optional extra provides, to tell which extras an installed Auditex already has.
_EXTRA_MODULES = {"google": "googleapiclient", "mcp": "mcp", "local-answer": "llama_cpp"}


def _extra_installed(extra: str) -> bool:
    module = _EXTRA_MODULES.get(extra)
    try:
        return bool(module) and importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _direct_url() -> dict[str, Any] | None:
    """This Auditex's PEP 610 direct_url.json, or None for an index install."""
    try:
        from importlib.metadata import PackageNotFoundError, distribution

        text = distribution("auditex").read_text("direct_url.json")
    except (PackageNotFoundError, OSError, ValueError):
        return None
    try:
        data = json.loads(text or "{}")
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("url") else None


def _installed_from_file() -> str | None:
    """The local wheel or sdist this Auditex was installed from (PEP 610 direct_url.json), or None for an index install."""
    data = _direct_url()
    url = str(data.get("url") or "") if data else ""
    if not url.startswith("file:") or "dir_info" in data:
        return None
    from urllib.parse import unquote, urlparse

    return unquote(urlparse(url).path) or None


def _installed_from_url() -> str | None:
    """The remote wheel, sdist or git commit this Auditex was installed from, as a PEP 508 direct-reference URL, or None
    for an index or local-file install. A git install names the commit it got, so a reinstall gets the same code."""
    data = _direct_url()
    url = str(data.get("url") or "") if data else ""
    if not url or url.startswith("file:") or "dir_info" in data:
        return None
    vcs = data.get("vcs_info")
    if isinstance(vcs, dict):
        kind, commit = str(vcs.get("vcs") or ""), str(vcs.get("commit_id") or "")
        if not kind:
            return None
        return f"{kind}+{url}@{commit}" if commit else f"{kind}+{url}"
    return url if "archive_info" in data else None


def _url_fit_for_record(url: str) -> bool:
    """A URL that may go into a run bundle: no user credentials and no query or fragment (a signed download link)."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return not (parts.username or parts.password or parts.query or parts.fragment)


def extra_install_command(extra: str, *, for_record: bool = False) -> str:
    """The command that adds an optional extra to this Auditex, for the route it was installed by.

    A source checkout takes an editable install in its folder. A pipx install is reinstalled with the extras it
    already has plus the new one (pipx keeps only the extras named on its last install). Any other environment
    installs through the interpreter that runs Auditex, never a bare `python` that may be another one. An Auditex
    installed from a downloaded wheel or sdist names that file again, and one installed from a URL or git commit
    names that URL or commit, not the package index.

    ``for_record`` gives a command that may be written into a run bundle: it never names a local path (the interpreter
    or the wheel file). In a plain environment it starts with a bare ``python``; ``extra_install_note`` says which one.
    """
    if is_source_checkout():
        return f"python -m pip install -e '.[{extra}]'"
    pipx = (Path(sys.prefix) / "pipx_metadata.json").is_file()
    extras = ",".join(sorted({name for name in _EXTRA_MODULES if _extra_installed(name)} | {extra})) if pipx else extra
    local_file = _installed_from_file()
    remote = None if local_file else _installed_from_url()
    if local_file and for_record:
        local_file = "<downloaded auditex wheel>"
    if remote and for_record and not _url_fit_for_record(remote):
        remote, local_file = None, "<downloaded auditex wheel>"
    if local_file:
        spec = shlex.quote(f"{local_file}[{extras}]")
    elif remote:
        spec = shlex.quote(f"auditex[{extras}] @ {remote}")
    else:
        spec = f'"auditex[{extras}]"' if pipx else f"'auditex[{extras}]'"
    if pipx:
        return f"pipx install --force {spec}"
    if for_record:
        return f"python -m pip install {spec}"
    return f"{shlex.quote(sys.executable)} -m pip install {spec}"


def extra_install_note() -> str:
    """What the operator must know beside a ``for_record`` command and outside it, so the command stays pasteable:
    in a plain environment, that ``python`` means the interpreter that runs Auditex. Empty for pipx and a checkout."""
    if is_source_checkout() or (Path(sys.prefix) / "pipx_metadata.json").is_file():
        return ""
    return "run it with the Python that runs Auditex"


def detect_package_manager() -> str | None:
    if shutil.which("brew"):
        return "brew"
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    return None


def _toolchain_runtime() -> ToolchainRuntime:
    return ToolchainRuntime(
        ToolchainRuntimeAdapters(
            which=shutil.which,
            run_json_command=_run_json_command,
            detect_package_manager=detect_package_manager,
        ),
        repo_root=REPO_ROOT,
        bootstrap_script=BOOTSTRAP_SCRIPT,
        select_python_script=SELECT_PYTHON_SCRIPT,
        venv_dir=DEFAULT_VENV_DIR,
    )


# A local readiness command (version check, select-python.sh) that runs longer than this is reported as blocked,
# so auditex doctor always returns.
COMMAND_TIMEOUT_SECONDS = 60


def _run_json_command(command: list[str]) -> dict[str, Any]:
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


def _command_version(command: list[str], *, parser: Callable[[str], str | None] | None = None) -> tuple[str | None, str | None]:
    return _toolchain_runtime().command_version(command, parser=parser)


def _tool_status(
    command_name: str,
    *,
    version_args: list[str] | None = None,
    version_parser: Callable[[str], str | None] | None = None,
) -> dict[str, Any]:
    return _toolchain_runtime().tool_status(command_name, version_args=version_args, version_parser=version_parser)


def _selected_python() -> dict[str, Any]:
    if not is_source_checkout():
        # An installed package runs in the interpreter it was installed into; that interpreter is the Python.
        supported = sys.version_info >= (3, 11)
        return {
            "status": "supported" if supported else "blocked",
            "path": sys.executable,
            "version": f"Python {platform.python_version()}",
            "selector": "installed",
            "error": None if supported else "python_too_old",
        }
    return _toolchain_runtime().selected_python()


def _venv_status() -> dict[str, Any]:
    if not is_source_checkout():
        return {"status": "supported", "path": sys.prefix, "python_path": sys.executable}
    return _toolchain_runtime().venv_status()


def build_doctor_report() -> dict[str, Any]:
    """Local readiness for the reader-app audit: Python, the venv, PowerShell 7 and ExchangeOnlineManagement.

    No sign-in is checked: Microsoft 365 audits use only the reader app with a certificate (DEC-107).
    """
    python_status = _selected_python()
    venv_status = _venv_status()
    tools = {"pwsh": _tool_status("pwsh", version_args=["--version"])}
    exchange = exchange_module_status()
    core_missing = [
        name for name, status in (("python", python_status), ("venv", venv_status)) if status["status"] != "supported"
    ]
    pwsh_missing = ["pwsh"] if tools["pwsh"]["status"] != "supported" else []
    exchange_missing = [*pwsh_missing, *([] if exchange.get("status") == "supported" else ["exchange_online_module"])]
    return {
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "package_manager": detect_package_manager(),
        },
        "bootstrap": {
            "script": str(BOOTSTRAP_SCRIPT),
            "exists": BOOTSTRAP_SCRIPT.exists(),
        },
        "python": python_status,
        "venv": venv_status,
        "tools": tools,
        "exchange_module": exchange,
        "readiness": {
            "core_ready": not core_missing,
            "core_missing": core_missing,
            "exchange_ready": not exchange_missing,
            "exchange_missing": exchange_missing,
            "pwsh_ready": not pwsh_missing,
            "pwsh_missing": pwsh_missing,
        },
    }


def _format_tool_line(name: str, tool: dict[str, Any]) -> str:
    version = tool.get("version")
    path = tool.get("path")
    if tool.get("status") == "supported":
        parts = [name, "supported"]
        if version:
            parts.append(version)
        if path:
            parts.append(f"[{path}]")
        return ": ".join([parts[0], " ".join(parts[1:])])
    return f"{name}: blocked" + (f" ({tool.get('error')})" if tool.get("error") else "")


def _format_missing(label: str, missing: list[str]) -> str:
    if not missing:
        return f"{label}: yes"
    return f"{label}: no (need {', '.join(missing)})"


def format_doctor_report(report: dict[str, Any]) -> str:
    tools = report.get("tools") or {}
    exchange = report.get("exchange_module") or {}
    readiness = report.get("readiness") or {}
    lines = [
        f"System: {report['system']['os']} {report['system']['machine']} ({report['system'].get('package_manager') or 'manual'})",
        _format_tool_line("Python", report["python"]),
        _format_tool_line("Venv", report["venv"]),
        _format_tool_line("pwsh", tools.get("pwsh", {})),
        "Exchange module: "
        + ("supported" if exchange.get("status") == "supported" else "blocked")
        + (f" [{exchange.get('module_version')}]" if exchange.get("module_version") else ""),
        _format_missing("Core ready", readiness.get("core_missing") or []),
        _format_missing("Exchange ready", readiness.get("exchange_missing") or []),
        _format_missing("Pwsh ready", readiness.get("pwsh_missing") or []),
    ]
    return "\n".join(lines)


def run_setup(*, with_exchange: bool = False, with_pwsh: bool = False, with_mcp: bool = False) -> int:
    if not is_source_checkout():
        # Nothing to bootstrap in an installed package; print the manual steps instead of failing, so guided-run
        # carries on and doctor still reports any missing optional pack.
        print(
            "auditex setup prepares a source checkout; this Auditex is an installed package, so its Python is ready.\n"
            "Optional packs are installed by hand:\n"
            f"  MCP server:      {extra_install_command('mcp')}\n"
            "  Exchange checks: install PowerShell 7, then the ExchangeOnlineManagement module\n"
            "                   for the current user (from PSGallery, without trusting the gallery)\n"
            "Run auditex doctor to check."
        )
        return 0
    command = ["bash", str(BOOTSTRAP_SCRIPT)]
    if with_exchange:
        command.append("--exchange")
    if with_pwsh:
        command.append("--pwsh")
    if with_mcp:
        command.append("--mcp")
    return subprocess.run(command, check=False).returncode


def print_doctor_report(*, json_output: bool = False) -> int:
    report = build_doctor_report()
    if json_output:
        print(json.dumps(report, indent=2))
    else:
        print(format_doctor_report(report))
    return 0
