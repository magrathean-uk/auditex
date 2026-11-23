from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import run as run_core
from .auth_runtime import (
    build_auth_context_payload as _build_auth_context_payload,
)
from .auth_runtime import (
    scrub_command_line as _scrub_command_line,
)
from .certificate_auth import (
    CertificateAuthError,
    load_certificate_credential,
    refuse_sources_in_output,
)
from .collection_gaps import sample_only
from .collector_runner import (
    AuditWriterCollectorAdapter,
    CollectorRunContext,
    CollectorRunner,
    CollectorRunOptions,
)
from .collectors import REGISTRY
from .collectors.base import run_graph_endpoints
from .config import AUTH_MODE, CERTIFICATE_WAY, AuthConfig
from .data_handling import collector_activity_notices
from .diagnostics import PermissionHintsNotFoundError
from .diagnostics import build_diagnostics as _build_diagnostics
from .diagnostics import load_permission_hints as _load_permission_hints
from .findings import build_findings
from .graph import GraphClient
from .local_paths import path_names_in_text
from .output import AuditWriter
from .profiles import get_profile
from .secret_hygiene import redact_output

# "app" reads the tenant with the reader app's certificate (DEC-107); "response" checks lab response readiness.
SUPPORTED_PROBE_MODES = ("app", "response")
# ProbeConfig fields of the removed sign-in ways, refused when set, with what each was.
_REMOVED_PROBE_CREDENTIALS = (
    ("access_token", "an access token"),
    ("use_azure_cli_token", "an Azure CLI token"),
    ("auth_context", "a saved auth context"),
    ("client_secret", "a client secret"),
)
DEFAULT_COLLECTOR_SURFACES = ("identity", "security", "auth_methods", "intune", "sharepoint", "teams", "exchange")
LAB_TENANT_ENV = "AUDITEX_LAB_TENANT_IDS"
DEFAULT_LAB_TENANT_IDS: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbeConfig:
    tenant_name: str
    output_dir: Path
    tenant_id: str | None = None
    auditor_profile: str = "global-reader"
    mode: str = "app"
    surface: str = "all"
    run_name: str | None = None
    since: str | None = None
    until: str | None = None
    top: int = 5
    page_size: int = 5
    client_id: str | None = None
    # The audit CLI's certificate options: the key file, its SHA-1 thumbprint and one password source.
    certificate_path: str | None = None
    certificate_thumbprint: str | None = None
    certificate_password_env: str | None = None
    certificate_password_file: str | None = None
    authority: str = "https://login.microsoftonline.com/"
    graph_scope: str = "https://graph.microsoft.com/.default"
    allow_lab_response: bool = False
    permission_hints_path: Path = Path("configs/collector-permissions.json")
    # Deprecated and refused when set (DEC-107): the product layer still passes them until M09-T03.
    access_token: str | None = field(default=None, repr=False)
    use_azure_cli_token: bool = False
    auth_context: str | None = None
    client_secret: str | None = field(default=None, repr=False)


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
        return [*DEFAULT_COLLECTOR_SURFACES, *(["exchange_policy", "dns_posture"] if mode == "app" else []), "windows365"]
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


def _subprocess_probe(command: list[str], *, timeout: int = 120) -> tuple[int | None, str, str]:
    """Return code, stdout and stderr; the code is None when the command ran past ``timeout`` (a slow pwsh start or a
    stuck module path), so the caller records a blocked row instead of the probe dying mid-run."""
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", f"command_timeout:{timeout}s"
    return completed.returncode, completed.stdout, completed.stderr


def _mask_toolchain_details(value: Any) -> Any:
    """Mask readiness diagnostics after parsing; these are not collector evidence."""
    if isinstance(value, dict):
        return {redact_output(str(key)): _mask_toolchain_details(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_toolchain_details(item) for item in value]
    return redact_output(value) if isinstance(value, str) else value


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
        row["error"] = redact_output(error)
    if details:
        row["details"] = _mask_toolchain_details(details)
    return row


def _probe_toolchain_statuses(
    *,
    include_response: bool = False,
    log_event: Callable[[str, str, dict[str, Any] | None], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    # Sign-in tools (Azure CLI, CLI for Microsoft 365) are not checked: the reader app's certificate is the one
    # credential (DEC-107), so no probe or collection path signs a user in.
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
                    command=" ".join([Path(pwsh_exe).name, *module_command[1:]]),
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
                    command=" ".join([Path(pwsh_exe).name, *module_command[1:]]),
                    error_class="command_timeout" if code is None else "module_not_found",
                    error=path_names_in_text((stderr or stdout).strip()) or f"return_code:{code}",
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
                    command=" ".join([Path(pwsh_exe).name, *response_command[1:]]),
                    error_class=None if code == 0 else "command_timeout" if code is None else "command_not_available",
                    error=None if code == 0 else path_names_in_text((stderr or stdout).strip()) or f"return_code:{code}",
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
        if row.get("name") == "exchange_online_module":
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
    with sample_only():
        payload, coverage = run_graph_endpoints(
            "windows365",
            client,
            endpoints,
            top=cfg.top,
            page_size=cfg.page_size,
            chunk_writer=AuditWriterCollectorAdapter(writer).hooks().chunk_writer,
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
    records: list[dict[str, Any]] = []
    occurrences: dict[str, int] = {}
    for row in capability_matrix:
        status = str(row.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        # Labels repeat between collectors and per-object probes. Identify the
        # operation, not its result, so status/count changes retain their key.
        identity = {field: row.get(field) for field in (
            "surface", "probe_mode", "collector", "type", "name", "endpoint", "command", "toolchain",
        )}
        digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        key = f"probe_capability:{digest}"
        occurrences[key] = occurrences.get(key, 0) + 1
        if occurrences[key] > 1:
            key = f"{key}:{occurrences[key]}"
        records.append({**row, "key": key})
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
        "capabilities": {"kind": "probe_capability", "records": records},
        "toolchains": {"kind": "toolchain_readiness", "records": toolchain_rows},
    }


def _probe_certificate(cfg: ProbeConfig) -> tuple[Any, dict[str, Any] | None]:
    """Load the app probe's certificate before the probe folder exists: (credential, None) or (None, blocker).

    The blocker text is fixed: never the key path, the password or a library diagnostic.
    """
    if not (cfg.client_id and cfg.tenant_id and cfg.certificate_path and cfg.certificate_thumbprint):
        return None, {
            "collector": "probe_auth",
            "item": "graph_auth",
            "status": "failed",
            "error_class": "missing_app_credentials",
            "error": f"client-id, tenant-id and the certificate are required for app probe mode. {CERTIFICATE_WAY}.",
            "recommendations": {
                "notes": "Provide the customer-local reader app and its certificate before rerunning app probe mode."
            },
        }
    try:
        refuse_sources_in_output((cfg.certificate_path, cfg.certificate_password_file), (cfg.output_dir,))
        credential = load_certificate_credential(
            cfg.certificate_path,
            cfg.certificate_thumbprint,
            password_env=cfg.certificate_password_env,
            password_file=cfg.certificate_password_file,
        )
    except CertificateAuthError as exc:
        return None, {
            "collector": "probe_auth",
            "item": "graph_auth",
            "status": "failed",
            "error_class": exc.error_code,
            "error": str(exc),
            "recommendations": {"notes": "Fix the reader app's certificate before rerunning app probe mode."},
        }
    return credential, None


def run_live_probe(cfg: ProbeConfig) -> int:
    for name, label in _REMOVED_PROBE_CREDENTIALS:
        if getattr(cfg, name):
            raise ValueError(f"The probe no longer accepts {label}. {CERTIFICATE_WAY}.")
    if cfg.mode not in SUPPORTED_PROBE_MODES:
        raise ValueError(f"Unsupported probe mode '{cfg.mode}'. {CERTIFICATE_WAY}.")
    profile = get_profile(cfg.auditor_profile)
    if cfg.mode != "response" and cfg.mode not in profile.supported_probe_modes:
        raise ValueError(f"Audit profile '{cfg.auditor_profile}' does not support probe mode '{cfg.mode}'.")
    # A mistyped explicit --permission-hints stops the probe before its run folder exists (the shipped default
    # still falls back silently).
    try:
        permission_hints = _load_permission_hints(cfg.permission_hints_path)
    except PermissionHintsNotFoundError as exc:
        print(f"auditex probe: {exc}", file=sys.stderr)
        return 2
    certificate, certificate_blocker = _probe_certificate(cfg) if cfg.mode == "app" else (None, None)
    writer = AuditWriter(cfg.output_dir.expanduser().resolve(), tenant_name=cfg.tenant_name, run_name=cfg.run_name)

    requested_surfaces = _resolve_requested_surfaces(cfg.surface, cfg.mode)
    # The final shared notice describes run selection flags, not probe --surface.
    for notice in collector_activity_notices(requested_surfaces, "live")[:-1]:
        print(f"Collection notice: {notice}")
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
    # An app-only probe has no signed-in user, so its session context is empty.
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
        # App mode only (DEC-107): the reader app's certificate, loaded before the probe folder existed.
        auth_mode = AUTH_MODE
        auth_path = "app"
        if certificate_blocker is not None:
            blockers.append(certificate_blocker)
        else:
            auth = AuthConfig(
                tenant_id=cfg.tenant_id,
                client_id=cfg.client_id,
                authority=cfg.authority,
                graph_scope=cfg.graph_scope,
                certificate=certificate,
            )
            client = GraphClient(auth, audit_event=writer.log_event)
            if hasattr(client, "token_claims"):
                auth_context_payload = _build_auth_context_payload(
                    auth_mode=auth_mode,
                    tenant_id=cfg.tenant_id,
                    token_claims=client.token_claims(),
                )

        if client is not None:
            for surface in run_core.collector_execution_order(requested_surfaces):
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

                # A probe asks whether a surface can be read; its row limit is a sample, not a coverage gap.
                with sample_only():
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
                            extra={
                                "exchange_accepted_domains": collector_payloads.get("exchange_policy", {}).get("acceptedDomains"),
                            } if surface == "dns_posture" else {},
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

    claims = (auth_context_payload or {}).get("token_claims") or {}
    observed_permissions = sorted(set(claims.get("delegated_scopes", []) + claims.get("app_roles", [])))
    for row in capability_matrix:
        if row.get("type") == "graph":
            row["observed_permissions"] = observed_permissions
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
        coverage_rows=coverage_rows,
    )
