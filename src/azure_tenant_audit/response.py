from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from datetime import datetime

from .adapters import get_adapter
from .adapters import ADAPTERS
from .ai_context import build_privacy_block
from .finalize import finalize_bundle_contract
from .findings import build_report_pack
from .output import AuditWriter
from .profiles import get_profile
from .secret_hygiene import redact_argv, sanitize_token_claims


LAB_TENANT_ENV = "AUDITEX_LAB_TENANT_IDS"
DEFAULT_LAB_TENANT_IDS: tuple[str, ...] = ()
RESPONSE_SENSITIVE_ARGS = {"--command-override", "--adapter-override", "--access-token", "--client-secret", "--token"}
ALLOWED_RESPONSE_ADAPTERS = tuple(sorted(ADAPTERS.keys()))
SAFE_RESPONSE_FIELD_BLACKLIST = frozenset("\x00\r\n\t;&|`$<>\"'")
MAX_RESPONSE_FIELD_LENGTH = 512


def _is_safe_response_field(value: str | None) -> bool:
    if value is None:
        return True
    if not value.strip():
        return False
    if len(value) > MAX_RESPONSE_FIELD_LENGTH:
        return False
    if any(char in SAFE_RESPONSE_FIELD_BLACKLIST for char in value):
        return False
    if any(ord(char) < 0x20 for char in value):
        return False
    return True


def _is_iso_timestamp(value: str | None) -> bool:
    if value is None:
        return True
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class ResponseAction:
    name: str
    description: str
    adapter: str
    commands: tuple[str, ...]
    required_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResponseConfig:
    tenant_name: str
    out_dir: Path
    action: str
    tenant_id: str | None = None
    auth_context: str | None = None
    target: str | None = None
    intent: str = ""
    since: str | None = None
    until: str | None = None
    auditor_profile: str = "exchange-reader"
    run_name: str | None = None
    execute: bool = False
    allow_write: bool = False
    allow_lab_response: bool = False
    adapter_override: str | None = None
    command_override: str | None = None
    allow_adapter_override: bool = False
    allow_command_override: bool = False


RESPONSE_ACTIONS: dict[str, ResponseAction] = {
    "message_trace": ResponseAction(
        name="message_trace",
        description="Collect message trace evidence for one recipient over a time window.",
        adapter="powershell_graph",
        commands=(
            'Get-MessageTrace -RecipientAddress "{target}" -StartDate "{since}" -EndDate "{until}"',
            'Get-MessageTrace -RecipientAddress "{target}"',
        ),
        required_fields=("target",),
    ),
    "user_audit_history": ResponseAction(
        name="user_audit_history",
        description="Collect unified audit entries for a target user.",
        adapter="powershell_graph",
        commands=(
            'Search-UnifiedAuditLog -UserIds "{target}" -StartDate "{since}" -EndDate "{until}"',
            'Search-UnifiedAuditLog -UserIds "{target}"',
        ),
        required_fields=("target",),
    ),
    "purview_audit_export": ResponseAction(
        name="purview_audit_export",
        description="Export Purview audit records for a bounded time window.",
        adapter="m365_cli",
        commands=(
            "m365 purview auditlog list --output json",
            "m365 purview audit log list --output json",
        ),
        required_fields=("since", "until"),
    ),
}


def response_actions() -> list[str]:
    return sorted(RESPONSE_ACTIONS.keys())


def _lab_tenant_ids() -> set[str]:
    configured = os.environ.get(LAB_TENANT_ENV, "")
    values = [value.strip() for value in configured.split(",") if value.strip()]
    return set(values or DEFAULT_LAB_TENANT_IDS)


def _scrub_command_line(command_line: list[str]) -> list[str]:
    return redact_argv(command_line, sensitive_flags=RESPONSE_SENSITIVE_ARGS)


def _build_context(config: ResponseConfig) -> dict[str, str]:
    return {
        "target": config.target or "",
        "since": config.since or "",
        "until": config.until or "",
        "tenant_id": config.tenant_id or "organizations",
        "intent": config.intent,
        "action": config.action,
    }


def _resolve_action(name: str) -> ResponseAction | None:
    return RESPONSE_ACTIONS.get(name)


def _planned_commands(action: ResponseAction, config: ResponseConfig) -> list[str]:
    if config.command_override:
        return [config.command_override]
    context = _build_context(config)
    return [template.format(**context) for template in action.commands]


def _resolve_saved_auth_context(name: str) -> dict[str, Any]:
    auditex_auth = importlib.import_module("auditex.auth")
    return auditex_auth.resolve_auth_context(name)


def run_response(config: ResponseConfig, command_line: list[str] | None = None) -> int:
    writer = AuditWriter(config.out_dir.expanduser().resolve(), tenant_name=config.tenant_name, run_name=config.run_name)
    command_line = _scrub_command_line(list(command_line or []))

    profile = get_profile(config.auditor_profile)
    blockers: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    data_handling_events: list[dict[str, Any]] = []
    saved_auth_context: dict[str, Any] | None = None
    auth_context_payload: dict[str, Any] | None = None

    if config.auth_context:
        saved_auth_context = _resolve_saved_auth_context(config.auth_context)
        auth_context_payload = {
            "name": saved_auth_context.get("name") or config.auth_context,
            "auth_type": saved_auth_context.get("auth_type"),
            "tenant_id": saved_auth_context.get("tenant_id"),
            "token_claims": sanitize_token_claims(saved_auth_context.get("token_claims") or {}),
        }
    tenant_id = config.tenant_id or (saved_auth_context or {}).get("tenant_id") or "organizations"

    writer.log_event(
        "response.run.started",
        "Response run started",
        {
            "action": config.action,
            "tenant_id": tenant_id,
            "auditor_profile": config.auditor_profile,
            "execute": config.execute,
            "intent": config.intent,
            "command_line": command_line,
            "auth_context": config.auth_context,
        },
    )

    if not config.intent:
        blockers.append(
            {
                "collector": "response",
                "item": "response.intent",
                "status": "failed",
                "error_class": "missing_intent",
                "error": "Response action requires explicit --intent text.",
                "recommendations": {"notes": "Provide a short intent before rerunning the response action."},
            }
        )

    if not profile.response_allowed:
        blockers.append(
            {
                "collector": "response",
                "item": "response.profile_guard",
                "status": "failed",
                "error_class": "profile_not_allowed",
                "error": f"Profile '{config.auditor_profile}' is not response-capable.",
                "recommendations": {"notes": "Use a response-capable profile such as exchange-reader."},
            }
        )

    if not (config.allow_lab_response and tenant_id in _lab_tenant_ids()):
        blockers.append(
            {
                "collector": "response",
                "item": "response.lab_guard",
                "status": "failed",
                "error_class": "lab_guard",
                "error": "Response plane is restricted to explicitly configured lab tenant IDs.",
                "recommendations": {
                    "notes": "Pass --allow-lab-response and target a tenant in AUDITEX_LAB_TENANT_IDS."
                },
            }
        )

    action = _resolve_action(config.action)
    if action is None:
        blockers.append(
            {
                "collector": "response",
                "item": "response.action",
                "status": "failed",
                "error_class": "unknown_action",
                "error": f"Unsupported response action '{config.action}'.",
                "recommendations": {"notes": f"Use one of: {', '.join(response_actions())}"},
            }
        )

    if config.command_override and not config.allow_command_override:
        blockers.append(
            {
                "collector": "response",
                "item": "response.command_override",
                "status": "failed",
                "error_class": "response_command_override_disabled",
                "error": "Response command override is blocked unless allow_command_override is enabled.",
                "recommendations": {"notes": "Remove --command-override or pass --allow-command-override explicitly."},
            }
        )

    if config.adapter_override and not config.allow_adapter_override:
        blockers.append(
            {
                "collector": "response",
                "item": "response.adapter_override",
                "status": "failed",
                "error_class": "response_adapter_override_disabled",
                "error": "Response adapter override is blocked unless allow_adapter_override is enabled.",
                "recommendations": {"notes": "Remove --adapter-override or pass --allow-adapter-override explicitly."},
            }
        )

    for field_name in ("target", "since", "until"):
        field_value = getattr(config, field_name, None)
        if not _is_safe_response_field(field_value):
            blockers.append(
                {
                    "collector": "response",
                    "item": f"response.argument:{field_name}",
                    "status": "failed",
                    "error_class": "response_argument_unsafe",
                    "error": f"Response field '{field_name}' contains unsafe characters.",
                    "recommendations": {"notes": f"Provide a clean {field_name} value for response execution."},
                }
            )

    if config.since is not None and not _is_iso_timestamp(config.since):
        blockers.append(
            {
                "collector": "response",
                "item": "response.argument:since",
                "status": "failed",
                "error_class": "response_argument_malformed",
                "error": "Response field 'since' must be an ISO8601 timestamp.",
                "recommendations": {"notes": "Use a valid ISO8601 UTC timestamp for --since."},
            }
        )
    if config.until is not None and not _is_iso_timestamp(config.until):
        blockers.append(
            {
                "collector": "response",
                "item": "response.argument:until",
                "status": "failed",
                "error_class": "response_argument_malformed",
                "error": "Response field 'until' must be an ISO8601 timestamp.",
                "recommendations": {"notes": "Use a valid ISO8601 UTC timestamp for --until."},
            }
        )

    adapter = None
    adapter_name = config.adapter_override or (action.adapter if action else "")
    if config.adapter_override and config.adapter_override not in ALLOWED_RESPONSE_ADAPTERS:
        blockers.append(
            {
                "collector": "response",
                "item": f"response.adapter:{config.adapter_override}",
                "status": "failed",
                "error_class": "response_invalid_adapter_override",
                "error": f"Response adapter override '{config.adapter_override}' is not supported.",
                "recommendations": {"notes": f"Use one of: {', '.join(ALLOWED_RESPONSE_ADAPTERS)}"},
            }
        )
    if action is not None:
        try:
            adapter = get_adapter(adapter_name or action.adapter)
        except KeyError:
            blockers.append(
                {
                    "collector": "response",
                    "item": f"response.adapter:{adapter_name or action.adapter}",
                    "status": "failed",
                    "error_class": "toolchain_unavailable",
                    "error": f"Required adapter '{adapter_name or action.adapter}' is not available.",
                    "recommendations": {
                        "notes": "Install the required local tooling before rerunning the response action."
                    },
                }
            )
        else:
            if not adapter.dependency_check():
                blockers.append(
                    {
                        "collector": "response",
                        "item": f"response.adapter:{adapter.name}",
                        "status": "failed",
                        "error_class": "toolchain_unavailable",
                        "error": f"Required adapter '{adapter.name}' is not available.",
                        "recommendations": {
                            "notes": "Install and authenticate the required tooling before rerunning the response action."
                        },
                    }
                )
            if action.name != "message_trace" and not config.allow_write:
                blockers.append(
                    {
                        "collector": "response",
                        "item": f"response.write_guard:{action.name}",
                        "status": "failed",
                        "error_class": "response_write_guard",
                        "error": "Action is treated as write-capable; enable --allow-write to execute.",
                        "recommendations": {"notes": "Use a read-only response action or pass --allow-write explicitly."},
                    }
                )

        missing = [field for field in action.required_fields if not getattr(config, field, None)]
        if missing:
            blockers.append(
                {
                    "collector": "response",
                    "item": "response.arguments",
                    "status": "failed",
                    "error_class": "missing_argument",
                    "error": f"Missing required arguments for action '{config.action}': {', '.join(missing)}.",
                    "recommendations": {"notes": "Provide the required fields and rerun the response action."},
                }
            )

    if action and adapter and not blockers:
        planned_commands = _planned_commands(action, config)
        if not config.execute:
            for index, command in enumerate(planned_commands, start=1):
                row = {
                    "collector": "response",
                    "type": "action-plan",
                    "name": f"{action.name}:{index}",
                    "adapter": adapter.name,
                    "status": "skipped",
                    "item_count": 0,
                    "command": command,
                    "message": "Dry run command plan",
                    "rank": index,
                }
                coverage.append(row)
                writer.write_summary(
                    {
                        "name": action.name,
                        "status": "skipped",
                        "item_count": 0,
                        "message": "Dry run plan only.",
                        "command": command,
                        "rank": index,
                        "variant_count": len(planned_commands),
                    }
                )
            writer.write_index_records(coverage)
            writer.write_raw(
                f"response/{action.name}/plan",
                {
                    "action": action.name,
                    "adapter": adapter.name,
                    "intent": config.intent,
                    "planned_commands": planned_commands,
                    "execute": False,
                    "auth_context": config.auth_context,
                },
            )
            data_handling_events.append(
                {
                    "action": action.name,
                    "event": "planned",
                    "reason": config.intent,
                    "target": config.target,
                    "run_mode": "dry_run",
                    "auth_context": config.auth_context,
                }
            )
            writer.write_normalized(
                "response",
                {
                    "response": {
                        "action": action.name,
                        "intent": config.intent,
                        "adapter": adapter.name,
                        "planned_commands": planned_commands,
                        "dry_run": True,
                    }
                },
            )
        else:
            last_failure: dict[str, Any] | None = None
            for index, command in enumerate(planned_commands, start=1):
                command_payload = adapter.run(command, log_event=writer.log_event)
                command_payload.setdefault("command", command)
                command_payload.setdefault("plan_position", index)
                executed = command_payload.get("error") is None
                command_payload.setdefault("status", "ok" if executed else "failed")
                coverage_row = {
                    "collector": "response",
                    "type": "action",
                    "name": action.name,
                    "adapter": adapter.name,
                    "command": command,
                    "status": command_payload.get("status"),
                    "item_count": len(command_payload.get("value", [])) if isinstance(command_payload.get("value"), list) else 0,
                    "duration_ms": command_payload.get("duration_ms", 0),
                    "error_class": command_payload.get("error_class"),
                    "error": command_payload.get("error"),
                }
                coverage.append(coverage_row)
                writer.write_index_records([coverage_row])
                writer.write_raw(
                    f"response/{action.name}/attempt-{index}",
                    {
                        "action": action.name,
                        "command": command,
                        "intent": config.intent,
                        "response_payload": command_payload,
                        "executed": True,
                        "auth_context": config.auth_context,
                    },
                )
                data_handling_events.append(
                    {
                        "action": action.name,
                        "event": "executed",
                        "reason": config.intent,
                        "target": config.target,
                        "run_mode": "execute",
                        "command": command,
                        "error_class": command_payload.get("error_class"),
                        "auth_context": config.auth_context,
                    }
                )
                if executed:
                    writer.write_normalized(
                        "response",
                        {
                            "response": {
                                "action": action.name,
                                "intent": config.intent,
                                "adapter": adapter.name,
                                "command": command,
                                "ran": True,
                                "payload": command_payload,
                            }
                        },
                    )
                    break
                last_failure = {
                    "collector": "response",
                    "item": action.name,
                    "status": "failed",
                    "error_class": command_payload.get("error_class", "command_error"),
                    "error": command_payload.get("error", "command failed"),
                    "recommendations": {
                        "notes": "Check toolchain auth and command prerequisites. Retry with the dry-run plan first."
                    },
                }
            else:
                if last_failure is not None:
                    blockers.append(last_failure)

    if blockers:
        writer.write_diagnostics(blockers)
        writer.write_blockers(blockers)
        findings = [
            {
                "id": f"response:{config.action}:{item.get('error_class', 'blocked')}:{index}",
                "rule_id": "response_blocker",
                "severity": "medium",
                "category": "response",
                "title": "Response action blocked",
                "status": "open",
                "collector": "response",
                "description": item.get("error") or "Response action blocked",
                "returned_value": item.get("error"),
                "recommendations": item.get("recommendations", {}),
                "details": item,
                "evidence_refs": [
                    {
                        "artifact_path": "blockers/blockers.json",
                        "artifact_kind": "blockers_json",
                        "collector": "response",
                        "record_key": str(item.get("item") or config.action or "response"),
                        "source_name": "blockers",
                    }
                ],
            }
            for index, item in enumerate(blockers, start=1)
        ]
        writer.write_findings(findings)

    status = "partial" if blockers else "ok"
    response_collector = f"response:{config.action}"
    capability_rows = [
        {
            "collector": response_collector,
            "status": "response_execute" if config.execute else "response_dry_run",
            "reason": "guarded_response_plane",
            "required_permissions": [],
            "missing_permissions": [],
            "observed_permissions": [],
            "delegated_roles": [],
            "adapter": adapter.name if adapter else adapter_name,
            "write_risk": bool(action and action.name != "message_trace" and config.allow_write),
        }
    ]
    coverage_ledger = [
        {
            "collector": response_collector,
            "expected_status": capability_rows[0]["status"],
            "expected_reason": "guarded_response_plane",
            "actual_status": status,
            "coverage_status": "blocked_permission" if blockers else ("complete_exact_scope" if config.execute else "not_applicable"),
            "coverage_reason": "response_blocked" if blockers else ("response_executed" if config.execute else "dry_run_plan_only"),
            "item_count": len(coverage),
            "message": "Response bundle finalized",
            "diagnostic_count": len(blockers),
            "diagnostics": blockers,
        }
    ]
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    if not (writer.normalized_dir / "response.json").exists():
        writer.write_normalized(
            "response",
            {
                "response": {
                    "action": config.action,
                    "intent": config.intent,
                    "adapter": adapter.name if adapter else adapter_name,
                    "dry_run": not config.execute,
                    "blocked": bool(blockers),
                }
            },
        )
    normalized_snapshot = {
        "snapshot": {
            "tenant_name": config.tenant_name,
            "collector_count": 1,
            "coverage_row_count": len(coverage_ledger),
            "blocker_count": len(blockers),
            "normalized_counts": {"response": len(coverage)},
            "full_counts": {},
            "sample_counts": {},
            "chunk_counts": {},
            "sample_truncated": False,
            "truncated_sections": [],
        }
    }
    privacy = build_privacy_block(safe_for_external_llm=False)
    writer.write_ai_safe(
        "response_summary",
        {
            "tenant_name": config.tenant_name,
            "action": config.action,
            "status": status,
            "item_count": len(coverage),
            "target": config.target,
            "execute": config.execute,
            "blocked": len(blockers),
            "auth_context": config.auth_context,
        },
    )
    writer.write_json_artifact(
        "toolchain-readiness.json",
        {
            "adapter": adapter.name if adapter else adapter_name,
            "dependency_available": bool(adapter and adapter.dependency_check()),
        },
    )
    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "summary.md",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        "audit-log.jsonl",
        "audit-command-log.jsonl",
        "audit-debug.log",
        "toolchain-readiness.json",
        "normalized/response.json",
        "normalized/capability_matrix.json",
        "normalized/coverage_ledger.json",
        "ai_safe/response_summary.json",
        "raw/response/",
    ]
    if blockers:
        evidence_paths.append("blockers/blockers.json")
    if findings:
        evidence_paths.append("findings/findings.json")
    writer.write_report_pack(
        build_report_pack(
            tenant_name=config.tenant_name,
            overall_status=status,
            findings=findings,
            evidence_paths=evidence_paths,
            blocker_count=len(blockers),
            privacy=privacy,
            artifact_map={
                "action": config.action,
                "command_count": len(coverage),
                "intent": config.intent,
                "time_window": {"since": config.since, "until": config.until},
            },
        )
    )
    if auth_context_payload is not None:
        auth_context_path = writer.write_json_artifact("auth-context.json", auth_context_payload)
        auth_context_path_value = str(auth_context_path.relative_to(writer.run_dir))
    else:
        auth_context_path_value = None
    finalize_bundle_contract(
        writer=writer,
        bundle_metadata={
            "executed_by": "auditex_response",
            "collectors": [response_collector],
            "overall_status": status,
            "duration_seconds": 0,
            "mode": "response",
            "auditor_profile": config.auditor_profile,
            "tenant_id": tenant_id,
            "plane": "response",
            "since": config.since,
            "until": config.until,
            "session_context": {
                "tenant_id": tenant_id,
                "auditor_profile": config.auditor_profile,
                "action": config.action,
                "intent": config.intent,
                "target": config.target,
                "run_name": config.run_name,
                "allow_write": config.allow_write,
                "allow_lab_response": config.allow_lab_response,
                "auth_context": config.auth_context,
            },
            "command_line": command_line,
            "data_handling_events": data_handling_events,
            "response_action": config.action,
            "response_target": config.target,
            "response_execute": config.execute,
            "response_adapter": adapter.name if adapter else adapter_name,
            "response_allow_write": config.allow_write,
            "response_allow_lab_response": config.allow_lab_response,
            "auth_context_path": auth_context_path_value,
            "privacy": privacy,
        },
        run_metadata={
            "tenant_name": config.tenant_name,
            "tenant_id": tenant_id,
            "run_id": writer.run_id,
            "overall_status": status,
            "auditor_profile": config.auditor_profile,
            "mode": "response",
            "plane": "response",
            "selected_collectors": [response_collector],
            "duration_seconds": 0,
        },
        normalized_snapshot=normalized_snapshot,
        capability_rows=capability_rows,
        coverage_ledger=coverage_ledger,
        blockers=blockers,
        findings=findings,
    )
    writer.log_event(
        "response.run.completed",
        "Response run completed",
        {
            "action": config.action,
            "status": status,
            "blockers": len(blockers),
            "dry_run": not config.execute,
        },
    )
    return 1 if blockers else 0
