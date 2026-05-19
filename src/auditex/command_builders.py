from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Iterable, Sequence

SUPPORTED_PLANES = ("inventory", "full", "export")
SUPPORTED_PROBE_MODES = ("delegated", "app", "response")


def _python_executable(value: str | None = None) -> str:
    return value or sys.executable


def _add_option(command: list[str], flag: str, value: object | None) -> None:
    if value is None:
        return
    text = str(value)
    if text:
        command.extend([flag, text])


def _add_bool(command: list[str], flag: str, enabled: bool) -> None:
    if enabled:
        command.append(flag)


def _csv(value: str | Sequence[str] | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    rendered = ",".join(str(item).strip() for item in value if str(item).strip())
    return rendered or None


@dataclass(frozen=True)
class AuditRunCommandSpec:
    tenant_name: str
    out_dir: str
    tenant_id: str | None = None
    auditor_profile: str = "global-reader"
    plane: str = "inventory"
    use_azure_cli_token: bool = True
    access_token: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    include_exchange: bool = False
    collectors: str | Sequence[str] | None = None
    since: str | None = None
    until: str | None = None
    offline: bool = False
    sample_path: str = "examples/sample_audit_bundle/sample_result.json"
    python_executable: str | None = None


def build_audit_run_command(spec: AuditRunCommandSpec) -> list[str]:
    if spec.plane not in SUPPORTED_PLANES:
        raise ValueError(f"Unsupported plane '{spec.plane}'. Supported planes: {', '.join(SUPPORTED_PLANES)}")
    command = [_python_executable(spec.python_executable), "-m", "azure_tenant_audit", "--tenant-name", spec.tenant_name, "--out", spec.out_dir]
    _add_option(command, "--tenant-id", spec.tenant_id)
    _add_option(command, "--auditor-profile", spec.auditor_profile)
    _add_option(command, "--plane", spec.plane)
    _add_bool(command, "--include-exchange", spec.include_exchange)
    _add_option(command, "--collectors", _csv(spec.collectors))
    _add_option(command, "--since", spec.since)
    _add_option(command, "--until", spec.until)
    if spec.offline:
        command.extend(["--offline", "--sample", spec.sample_path])
        return command
    if spec.access_token:
        command.extend(["--access-token", spec.access_token])
    elif spec.use_azure_cli_token:
        command.append("--use-azure-cli-token")
    else:
        _add_option(command, "--client-id", spec.client_id)
        _add_option(command, "--client-secret", spec.client_secret)
    return command


@dataclass(frozen=True)
class ProbeCommandSpec:
    tenant_name: str
    out_dir: str
    tenant_id: str | None = None
    auditor_profile: str = "global-reader"
    mode: str = "delegated"
    surface: str = "all"
    since: str | None = None
    until: str | None = None
    allow_lab_response: bool = False
    use_azure_cli_token: bool = True
    access_token: str | None = None
    auth_context: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    python_executable: str | None = None


def build_probe_command(spec: ProbeCommandSpec) -> list[str]:
    if spec.mode not in SUPPORTED_PROBE_MODES:
        raise ValueError(f"Unsupported probe mode '{spec.mode}'. Supported modes: {', '.join(SUPPORTED_PROBE_MODES)}")
    command = [_python_executable(spec.python_executable), "-m", "auditex", "probe", "live", "--tenant-name", spec.tenant_name, "--out", spec.out_dir]
    _add_option(command, "--tenant-id", spec.tenant_id)
    command.extend(["--auditor-profile", spec.auditor_profile, "--mode", spec.mode, "--surface", spec.surface])
    _add_option(command, "--since", spec.since)
    _add_option(command, "--until", spec.until)
    _add_bool(command, "--allow-lab-response", spec.allow_lab_response)
    if spec.access_token:
        command.extend(["--access-token", spec.access_token])
    elif spec.auth_context:
        command.extend(["--auth-context", spec.auth_context])
    elif spec.use_azure_cli_token and spec.mode == "delegated":
        command.append("--use-azure-cli-token")
    _add_option(command, "--client-id", spec.client_id)
    _add_option(command, "--client-secret", spec.client_secret)
    return command


@dataclass(frozen=True)
class ResponseCommandSpec:
    tenant_name: str
    out_dir: str
    action: str
    tenant_id: str | None = None
    auditor_profile: str = "exchange-reader"
    target: str | None = None
    intent: str = ""
    since: str | None = None
    until: str | None = None
    run_name: str | None = None
    execute: bool = False
    allow_write: bool = False
    allow_lab_response: bool = False
    auth_context: str | None = None
    adapter_override: str | None = None
    command_override: str | None = None
    allow_adapter_override: bool = False
    allow_command_override: bool = False
    python_executable: str | None = None


def build_response_command(spec: ResponseCommandSpec, *, supported_actions: Iterable[str] | None = None) -> list[str]:
    if supported_actions is None:
        from azure_tenant_audit.response import response_actions

        supported_actions = response_actions()
    supported = set(supported_actions)
    if spec.action not in supported:
        raise ValueError(f"Unsupported response action '{spec.action}'. Supported actions: {', '.join(sorted(supported))}")
    command = [
        _python_executable(spec.python_executable),
        "-m",
        "auditex",
        "response",
        "run",
        "--tenant-name",
        spec.tenant_name,
        "--out",
        spec.out_dir,
        "--action",
        spec.action,
        "--intent",
        spec.intent,
    ]
    _add_option(command, "--tenant-id", spec.tenant_id)
    _add_option(command, "--auditor-profile", spec.auditor_profile)
    _add_option(command, "--target", spec.target)
    _add_option(command, "--since", spec.since)
    _add_option(command, "--until", spec.until)
    _add_option(command, "--run-name", spec.run_name)
    _add_bool(command, "--execute", spec.execute)
    _add_bool(command, "--allow-write", spec.allow_write)
    _add_bool(command, "--allow-lab-response", spec.allow_lab_response)
    _add_bool(command, "--allow-adapter-override", spec.allow_adapter_override)
    _add_bool(command, "--allow-command-override", spec.allow_command_override)
    _add_option(command, "--auth-context", spec.auth_context)
    _add_option(command, "--adapter-override", spec.adapter_override)
    _add_option(command, "--command-override", spec.command_override)
    return command
