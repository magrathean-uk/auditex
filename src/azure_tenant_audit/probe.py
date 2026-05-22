from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from .adapters import get_adapter
from .auth_runtime import (
    acquire_azure_cli_access_token as _acquire_azure_cli_access_token,
    build_auth_context_payload as _build_auth_context_payload,
    capture_signed_in_context as _capture_signed_in_context,
    scrub_command_line as _scrub_command_line,
)
from . import run as run_core
from .collector_runner import AuditWriterCollectorAdapter, CollectorRunContext, CollectorRunOptions, CollectorRunner
from .collectors import REGISTRY
from .collectors.base import run_graph_endpoints
from .config import AuthConfig
from .diagnostics import build_diagnostics as _build_diagnostics, load_permission_hints as _load_permission_hints
from .findings import build_findings
from .graph import GraphClient
from .output import AuditWriter
from .profiles import get_profile
from .secret_hygiene import sanitize_token_claims

SUPPORTED_PROBE_MODES = ("delegated", "app", "response")
DEFAULT_COLLECTOR_SURFACES = ("identity", "security", "auth_methods", "intune", "sharepoint", "teams", "exchange")
LAB_TENANT_ENV = "AUDITEX_LAB_TENANT_IDS"
DEFAULT_LAB_TENANT_IDS: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbeConfig:
    tenant_name: str
    output_dir: Path
    tenant_id: str | None = None
    auditor_profile: str = "global-reader"
    mode: str = "delegated"
    surface: str = "all"
    run_name: str | None = None
    since: str | None = None
    until: str | None = None
    top: int = 5
    page_size: int = 5
    access_token: str | None = None
    use_azure_cli_token: bool = True
    auth_context: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    authority: str = "https://login.microsoftonline.com/"
    graph_scope: str = "https://graph.microsoft.com/.default"
    allow_lab_response: bool = False
    permission_hints_path: Path = Path("configs/collector-permissions.json")


def probe_mode_choices() -> tuple[str, ...]:
    return SUPPORTED_PROBE_MODES


def _lab_tenant_ids() -> set[str]:
    configured = os.environ.get(LAB_TENANT_ENV, "")
    values = [value.strip() for value in configured.split(",") if value.strip()]
    return set(values or DEFAULT_LAB_TENANT_IDS)


def _resolve_requested_surfaces(surface: str, mode: str) -> list[str]:
    requested = [item.strip() for item in (surface or "all").split(",") if item.strip()]
    if not requested or "all" in requested:
        if mode == "response":
            return ["response", "toolchain"]
        return [*DEFAULT_COLLECTOR_SURFACES, "windows365"]
    return requested


def _toolchain_for_row(row: dict[str, Any]) -> str:
    row_type = row.get("type")
    if row_type == "graph":
        return "graph"
    command = str(row.get("command") or "")
    if command.startswith("m365 "):
        return "m365_cli"
    if command.startswith("pwsh "):
        return "pwsh"
    return str(row_type or "unknown")


def _capability_row_from_coverage(surface: str, probe_mode: str, row: dict[str, Any]) -> dict[str, Any]:
    status = row.get("status")
    capability_status = "supported_exact_scope" if status == "ok" else "blocked" if status == "failed" else "partial"
    return {
        "surface": surface,
        "probe_mode": probe_mode,
        "collector": row.get("collector"),
        "type": row.get("type"),
        "name": row.get("name"),
        "endpoint": row.get("endpoint"),
        "command": row.get("command"),
        "toolchain": _toolchain_for_row(row),
        "status": capability_status,
        "item_count": row.get("item_count", 0),
        "duration_ms": row.get("duration_ms"),
        "error_class": row.get("error_class"),
        "error": row.get("error"),
        "message": row.get("error") or row.get("status") or "",
    }


def _subprocess_probe(command: list[str], *, timeout: int = 120) -> tuple[int, str, str]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
    return completed.returncode, completed.stdout, completed.stderr


def _toolchain_row(
    *,
    name: str,
    toolchain: str,
    status: str,
    message: str,
    command: str | None = None,
    error_class: str | None = None,
    error: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "surface": "toolchain",
        "probe_mode": "readiness",
        "collector": "toolchain",
        "type": "toolchain",
        "name": name,
        "toolchain": toolchain,
        "status": status,
        "item_count": 1 if status == "supported" else 0,
        "message": message,
    }
    if command:
        row["command"] = command
    if error_class:
        row["error_class"] = error_class
    if error:
        row["error"] = error
    if details:
        row["details"] = details
    return row


def _probe_toolchain_statuses(
    *,
    include_response: bool = False,
    log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    az_exe = shutil.which("az")
    if az_exe is None:
        results.append(
            _toolchain_row(
                name="az_cli_graph",
                toolchain="az",
                status="blocked",
                message="Azure CLI is not installed.",
                error_class="command_not_found",
            )
        )
    else:
        command = [
            az_exe,
            "account",
            "get-access-token",
            "--resource-type",
            "ms-graph",
            "--query",
            "{tenant:tenant,expiresOn:expiresOn}",
            "--output",
            "json",
        ]
        code, stdout, stderr = _subprocess_probe(command)
        if code == 0:
            try:
                payload = json.loads(stdout)
            except json.JSONDecodeError:
                payload = {"raw": stdout.strip()}
            results.append(
                _toolchain_row(
                    name="az_cli_graph",
                    toolchain="az",
                    status="supported",
                    message="Azure CLI Graph token is available.",
                    command=" ".join(command),
                    details=payload if isinstance(payload, dict) else {"raw": stdout.strip()},
                )
            )
        else:
            results.append(
                _toolchain_row(
                    name="az_cli_graph",
                    toolchain="az",
                    status="blocked",
                    message="Azure CLI Graph token could not be acquired.",
                    command=" ".join(command),
                    error_class="command_error",
                    error=(stderr or stdout).strip() or f"return_code:{code}",
                )
            )
        if log_event:
            log_event(
                "probe.toolchain.checked",
                "Azure CLI readiness checked",
                {"status": results[-1]["status"]},
            )

    pwsh_exe = shutil.which("pwsh")
    results.append(
        _toolchain_row(
            name="pwsh",
            toolchain="pwsh",
            status="supported" if pwsh_exe else "blocked",
            message="PowerShell is available." if pwsh_exe else "PowerShell is not installed.",
            error_class=None if pwsh_exe else "command_not_found",
        )
    )

    if pwsh_exe:
        module_command = [
            pwsh_exe,
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "Get-Module -ListAvailable ExchangeOnlineManagement | Select-Object -First 1 Name,Version | ConvertTo-Json -Compress",
        ]
        code, stdout, stderr = _subprocess_probe(module_command)
        if code == 0 and stdout.strip() and stdout.strip() != "null":
            results.append(
                _toolchain_row(
                    name="exchange_online_module",
                    toolchain="pwsh",
                    status="supported",
                    message="ExchangeOnlineManagement module is installed.",
                    command=" ".join(module_command),
                    details={"stdout": stdout.strip()},
                )
            )
        else:
            results.append(
                _toolchain_row(
                    name="exchange_online_module",
                    toolchain="pwsh",
                    status="blocked",
                    message="ExchangeOnlineManagement module is not available.",
                    command=" ".join(module_command),
                    error_class="module_not_found",
                    error=(stderr or stdout).strip() or f"return_code:{code}",
                )
            )
    else:
        results.append(
            _toolchain_row(
                name="exchange_online_module",
                toolchain="pwsh",
                status="blocked",
                message="ExchangeOnlineManagement module cannot be checked without PowerShell.",
                error_class="command_not_found",
            )
        )

    adapter = get_adapter("m365_cli")
    if not adapter.dependency_check():
        results.append(
            _toolchain_row(
                name="m365_cli_auth",
                toolchain="m365_cli",
                status="blocked",
                message="CLI for Microsoft 365 is not installed.",
                error_class="command_not_found",
            )
        )
    else:
        response = adapter.run("m365 status --output json", log_event=log_event)
        if response.get("error"):
            results.append(
                _toolchain_row(
                    name="m365_cli_auth",
                    toolchain="m365_cli",
                    status="blocked",
                    message="CLI for Microsoft 365 is not authenticated.",
                    command=str(response.get("command") or "m365 status --output json"),
                    error_class=str(response.get("error_class") or "command_error"),
                    error=str(response.get("error")),
                )
            )
        else:
            results.append(
                _toolchain_row(
                    name="m365_cli_auth",
                    toolchain="m365_cli",
                    status="supported",
                    message="CLI for Microsoft 365 is authenticated.",
                    command=str(response.get("command") or "m365 status --output json"),
                    details={"value": response.get("value")},
                )
            )

    if include_response:
        if pwsh_exe:
            response_command = [
                pwsh_exe,
                "-NoLogo",
                "-NoProfile",
                "-Command",
                "Import-Module ExchangeOnlineManagement; if (Get-Command Get-MessageTrace -ErrorAction SilentlyContinue) { '{\"available\":true}' } else { exit 3 }",
            ]
            code, stdout, stderr = _subprocess_probe(response_command)
            results.append(
                _toolchain_row(
                    name="response_message_trace_cmdlet",
                    toolchain="pwsh",
                    status="supported" if code == 0 else "blocked",
                    message="Message trace cmdlet is available."
                    if code == 0
                    else "Message trace cmdlet is not available through the local PowerShell module path.",
                    command=" ".join(response_command),
                    error_class=None if code == 0 else "command_not_available",
                    error=None if code == 0 else (stderr or stdout).strip() or f"return_code:{code}",
                )
            )
        else:
            results.append(
                _toolchain_row(
                    name="response_message_trace_cmdlet",
                    toolchain="pwsh",
                    status="blocked",
                    message="Message trace cmdlet cannot be checked without PowerShell.",
                    error_class="command_not_found",
                )
            )

    return results


def _toolchain_blockers(rows: list[dict[str, Any]], *, response: bool = False) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    collector_name = "response" if response else "toolchain"
    for row in rows:
        if row.get("status") == "supported":
            continue
        recommendations: dict[str, Any] = {"required_tools": [row.get("toolchain")]}
        if row.get("name") == "m365_cli_auth":
            recommendations["notes"] = "Run `m365 login` before retrying Microsoft 365 CLI-backed probes."
        elif row.get("name") == "az_cli_graph":
            recommendations["notes"] = "Run `az login` and ensure Microsoft Graph token acquisition succeeds."
        elif row.get("name") == "exchange_online_module":
            recommendations["notes"] = "Install ExchangeOnlineManagement for Exchange and response probes."
        blockers.append(
            {
                "collector": collector_name,
                "item": row.get("name"),
                "status": "failed",
                "error_class": row.get("error_class") or "toolchain_unavailable",
                "error": row.get("error") or row.get("message"),
                "recommendations": recommendations,
            }
        )
    return blockers


def _lab_guard_probe(cfg: ProbeConfig) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    allowed = cfg.allow_lab_response and (cfg.tenant_id in _lab_tenant_ids())
    row = {
        "surface": "response.lab_guard",
        "probe_mode": cfg.mode,
        "collector": "response",
        "type": "guard",
        "name": "response.lab_guard",
        "toolchain": "policy",
        "status": "supported" if allowed else "blocked",
        "item_count": 1 if allowed else 0,
        "message": "Response probes are allowed for this lab tenant."
        if allowed
        else "Response probes are blocked outside explicitly allowed lab tenants.",
    }
    if allowed:
        return row, []
    blocker = {
        "collector": "response",
        "item": "response.lab_guard",
        "status": "failed",
        "error_class": "lab_guard",
        "error": row["message"],
        "recommendations": {
            "notes": "Enable --allow-lab-response and target a configured lab tenant before running response probes."
        },
    }
    return row, [blocker]


def _run_windows365_probe(
    cfg: ProbeConfig,
    *,
    client: GraphClient,
    writer: AuditWriter,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    endpoints = {
        "cloudPCs": {
            "endpoint": "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs",
            "params": {},
        },
        "provisioningPolicies": {
            "endpoint": "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies",
            "params": {},
        },
        "userSettings": {
            "endpoint": "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings",
            "params": {},
        },
    }
    payload, coverage = run_graph_endpoints(
        "windows365",
        client,
        endpoints,
        top=cfg.top,
        page_size=cfg.page_size,
        chunk_writer=lambda collector_name, endpoint_name, page_number, records, metadata=None: str(
            writer.write_chunk_records(collector_name, endpoint_name, page_number, records, metadata).relative_to(writer.run_dir)
        ),
        log_event=writer.log_event,
    )
    result_row = {
        "name": "windows365",
        "status": "partial" if any(row.get("status") != "ok" for row in coverage) else "ok",
        "item_count": sum(int(row.get("item_count", 0)) for row in coverage),
        "message": "Windows 365 capability probe",
        "error": None,
        "coverage_rows": len(coverage),
    }
    writer.write_raw("windows365", payload)
    return result_row, coverage, payload


def _build_probe_snapshot(
    *,
    tenant_name: str,
    run_id: str,
    capability_matrix: list[dict[str, Any]],
    toolchain_rows: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    session_context: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    status_counts: dict[str, int] = {}
    for row in capability_matrix:
        status = str(row.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "snapshot": {
            "tenant_name": tenant_name,
            "run_id": run_id,
            "capability_count": len(capability_matrix),
            "toolchain_count": len(toolchain_rows),
            "blocker_count": len(blockers),
            "status_counts": status_counts,
            "session": {
                "principal": session_context.get("user_principal_name"),
                "roles": session_context.get("roles", []),
            },
        },
        "capabilities": {"kind": "probe_capability", "records": capability_matrix},
        "toolchains": {"kind": "toolchain_readiness", "records": toolchain_rows},
    }


def run_live_probe(cfg: ProbeConfig) -> int:
    writer = AuditWriter(cfg.output_dir.expanduser().resolve(), tenant_name=cfg.tenant_name, run_name=cfg.run_name)
    permission_hints = _load_permission_hints(cfg.permission_hints_path)
    profile = get_profile(cfg.auditor_profile)
    if cfg.mode not in SUPPORTED_PROBE_MODES:
        raise ValueError(f"Unsupported probe mode '{cfg.mode}'.")
    if cfg.mode != "response" and cfg.mode not in profile.supported_probe_modes:
        raise ValueError(f"Audit profile '{cfg.auditor_profile}' does not support probe mode '{cfg.mode}'.")

    requested_surfaces = _resolve_requested_surfaces(cfg.surface, cfg.mode)
    capability_matrix: list[dict[str, Any]] = []
    result_rows: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    collector_payloads: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, Any]] = []
    lab_guard_state = "not_applicable"
    auth_context_payload: dict[str, Any] | None = None
    auth_context_path: Path | None = None

    toolchain_rows = _probe_toolchain_statuses(include_response=(cfg.mode == "response"), log_event=writer.log_event)
    writer_adapter = AuditWriterCollectorAdapter(writer)
    collector_runner = CollectorRunner(writer_adapter)
    auth_mode = "none"
    session_context: dict[str, Any] = {}
    client: GraphClient | None = None
    auth_path = "none"

    command_line = _scrub_command_line(list(os.sys.argv))
    writer.log_event(
        "probe.started",
        "Live capability probe started",
        {
            "probe_mode": cfg.mode,
            "surface": cfg.surface,
            "tenant_id": cfg.tenant_id,
            "auditor_profile": cfg.auditor_profile,
            "command_line": command_line,
        },
    )

    if cfg.mode == "response":
        if not profile.response_allowed:
            lab_guard_state = "profile_blocked"
            profile_row = {
                "surface": "response.profile_guard",
                "probe_mode": cfg.mode,
                "collector": "response",
                "type": "guard",
                "name": "response.profile_guard",
                "toolchain": "policy",
                "status": "blocked",
                "item_count": 0,
                "message": f"Audit profile '{cfg.auditor_profile}' is not allowed to run response probes.",
            }
            capability_matrix.append(profile_row)
            writer.write_summary(
                {
                    "name": profile_row["name"],
                    "status": profile_row["status"],
                    "item_count": profile_row["item_count"],
                    "message": profile_row["message"],
                }
            )
            blockers.append(
                {
                    "collector": "response",
                    "item": "response.profile_guard",
                    "status": "failed",
                    "error_class": "profile_not_allowed",
                    "error": profile_row["message"],
                    "recommendations": {
                        "notes": "Use a response-capable profile such as exchange-reader for lab-only response readiness probes."
                    },
                }
            )
        else:
            guard_row, guard_blockers = _lab_guard_probe(cfg)
            lab_guard_state = "allowed" if not guard_blockers else "disabled" if not cfg.allow_lab_response else "blocked"
            capability_matrix.append(guard_row)
            writer.write_summary(
                {
                    "name": guard_row["name"],
                    "status": guard_row["status"],
                    "item_count": guard_row["item_count"],
                    "message": guard_row["message"],
                }
            )
            blockers.extend(guard_blockers)
            if not guard_blockers:
                include_response_toolchains = any(
                    surface in {"response", "toolchain", "exchange"} for surface in requested_surfaces
                )
                selected_toolchain_rows = toolchain_rows if include_response_toolchains else []
                capability_matrix.extend(selected_toolchain_rows)
                blockers.extend(_toolchain_blockers(selected_toolchain_rows, response=True))
    else:
        tenant_id = cfg.tenant_id
        access_token = cfg.access_token
        if cfg.auth_context:
            auth_module = importlib.import_module("auditex.auth")
            saved_context = auth_module.resolve_auth_context(cfg.auth_context)
            saved_claims = sanitize_token_claims(saved_context.get("token_claims") or {})
            tenant_id = tenant_id or saved_context.get("tenant_id")
            access_token = access_token or saved_context.get("token")
            auth_context_payload = {
                "name": saved_context.get("name") or cfg.auth_context,
                "auth_type": saved_context.get("auth_type"),
                "tenant_id": tenant_id,
                "token_claims": saved_claims,
            }
            session_context = {
                "user_principal_name": saved_claims.get("user_principal_name"),
                "roles": list(saved_claims.get("app_roles") or []),
            }

        tenant_id = tenant_id or "organizations"
        if cfg.mode == "delegated":
            auth_mode = "access_token" if access_token else "azure_cli"
            auth_path = "saved_context" if cfg.auth_context and access_token else auth_mode
            if not access_token and not cfg.use_azure_cli_token:
                blockers.append(
                    {
                        "collector": "probe_auth",
                        "item": "graph_auth",
                        "status": "failed",
                        "error_class": "unauthenticated",
                        "error": "Delegated probe requires either --access-token or --use-azure-cli-token.",
                        "recommendations": {
                            "notes": "Provide a delegated Graph token or enable Azure CLI token reuse before rerunning delegated probe mode."
                        },
                    }
                )
            elif not access_token and cfg.use_azure_cli_token:
                try:
                    access_token = _acquire_azure_cli_access_token(tenant_id, log_event=writer.log_event)
                except Exception as exc:  # noqa: BLE001
                    blockers.append(
                        {
                            "collector": "probe_auth",
                            "item": "graph_auth",
                            "status": "failed",
                            "error_class": "unauthenticated",
                            "error": str(exc),
                            "recommendations": {"notes": "Azure CLI delegated sign-in is required for delegated probes."},
                        }
                    )
            if access_token:
                auth = AuthConfig(
                    tenant_id=tenant_id,
                    client_id=cfg.client_id,
                    auth_mode=auth_mode,
                    access_token=access_token,
                    authority=cfg.authority,
                    graph_scope=cfg.graph_scope,
                )
                client = GraphClient(auth, audit_event=writer.log_event)
                if auth_path != "saved_context":
                    session_context = _capture_signed_in_context(client, log_event=writer.log_event)
                if auth_context_payload is None and hasattr(client, "token_claims"):
                    auth_context_payload = _build_auth_context_payload(
                        auth_mode=auth_mode,
                        tenant_id=tenant_id,
                        token_claims=client.token_claims(),
                        session_context=session_context,
                    )
        elif cfg.mode == "app":
            auth_mode = "app"
            auth_path = "app"
            if not cfg.client_id or not cfg.client_secret or not cfg.tenant_id:
                blockers.append(
                    {
                        "collector": "probe_auth",
                        "item": "graph_auth",
                        "status": "failed",
                        "error_class": "missing_app_credentials",
                        "error": "client-id, client-secret, and tenant-id are required for app probe mode.",
                        "recommendations": {
                            "notes": "Provide a customer-local read-only app registration before rerunning app probe mode."
                        },
                    }
                )
            else:
                auth = AuthConfig(
                    tenant_id=cfg.tenant_id,
                    client_id=cfg.client_id,
                    client_secret=cfg.client_secret,
                    auth_mode="app",
                    authority=cfg.authority,
                    graph_scope=cfg.graph_scope,
                )
                client = GraphClient(auth, audit_event=writer.log_event)
                if hasattr(client, "token_claims"):
                    auth_context_payload = _build_auth_context_payload(
                        auth_mode=auth_mode,
                        tenant_id=cfg.tenant_id,
                        token_claims=client.token_claims(),
                        session_context=session_context,
                    )

        if client is not None:
            for surface in requested_surfaces:
                if surface == "windows365":
                    result_row, windows_coverage, payload = _run_windows365_probe(cfg, client=client, writer=writer)
                    collector_payloads["windows365"] = payload
                    result_rows.append(result_row)
                    coverage_rows.extend(windows_coverage)
                    writer.write_summary(result_row)
                    capability_matrix.extend(
                        [_capability_row_from_coverage("windows365", cfg.mode, row) for row in windows_coverage]
                    )
                    continue

                collector = REGISTRY.get(surface)
                if collector is None:
                    capability_matrix.append(
                        {
                            "surface": surface,
                            "probe_mode": cfg.mode,
                            "collector": "probe",
                            "type": "surface",
                            "name": surface,
                            "toolchain": "unknown",
                            "status": "not_applicable",
                            "item_count": 0,
                            "message": "Requested surface is not implemented in the canonical probe registry.",
                        }
                    )
                    continue

                output = collector_runner.run(
                    collector,
                    CollectorRunContext(
                        client=client,
                        top=cfg.top,
                        page_size=cfg.page_size,
                        plane="inventory",
                        since=cfg.since,
                        until=cfg.until,
                        hooks=writer_adapter.hooks(),
                    ),
                    name=surface,
                    options=CollectorRunOptions(write_checkpoint=False),
                )
                collector_payloads[surface] = output.result.payload
                row = dict(output.result_row)
                result_rows.append(row)
                writer.write_summary(row)
                if output.coverage_rows:
                    coverage_rows.extend(output.coverage_rows)
                    capability_matrix.extend(
                        [_capability_row_from_coverage(surface, cfg.mode, coverage) for coverage in output.coverage_rows]
                    )

        diagnostics = _build_diagnostics(
            result_rows=result_rows,
            coverage_rows=coverage_rows,
            permission_hints=permission_hints,
            auditor_profile=cfg.auditor_profile,
        )
        blockers.extend(diagnostics)
        capability_matrix.extend(toolchain_rows)
        blockers.extend(_toolchain_blockers(toolchain_rows, response=False))

    for row in toolchain_rows:
        writer.write_summary(
            {
                "name": row["name"],
                "status": row["status"],
                "item_count": row["item_count"],
                "message": row["message"],
            }
        )

    capability_path = writer.write_json_artifact("capability-matrix.json", capability_matrix)
    toolchain_payload = {row["name"]: row for row in toolchain_rows}
    toolchain_path = writer.write_json_artifact("toolchain-readiness.json", toolchain_payload)
    writer.write_raw("toolchain", toolchain_payload)
    if auth_context_payload is not None:
        auth_context_path = writer.write_json_artifact("auth-context.json", auth_context_payload)
    if blockers:
        writer.write_diagnostics(blockers)
        writer.write_blockers(blockers)
    findings = build_findings(blockers)
    if findings:
        writer.write_findings(findings)

    normalized_snapshot = _build_probe_snapshot(
        tenant_name=cfg.tenant_name,
        run_id=writer.run_id,
        capability_matrix=capability_matrix,
        toolchain_rows=toolchain_rows,
        blockers=blockers,
        session_context=session_context,
    )
    return run_core.finalize_probe_run(
        writer=writer,
        cfg=cfg,
        requested_surfaces=requested_surfaces,
        capability_matrix=capability_matrix,
        toolchain_rows=toolchain_rows,
        blockers=blockers,
        findings=findings,
        normalized_snapshot=normalized_snapshot,
        capability_path=capability_path,
        toolchain_path=toolchain_path,
        auth_context_path=auth_context_path,
        command_line=command_line,
        auth_mode=auth_mode,
        auth_path=auth_path,
        session_context=session_context,
        lab_guard_state=lab_guard_state,
    )
