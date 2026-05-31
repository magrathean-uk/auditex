from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azure_tenant_audit.assurance import build_live_readiness_summary
from azure_tenant_audit.ai_context import build_privacy_block
from azure_tenant_audit.capability_gate import enrich_capability_row
from azure_tenant_audit.collector_runner import AuditWriterCollectorAdapter, CollectorRunContext, CollectorRunner
from azure_tenant_audit.output import AuditWriter
from azure_tenant_audit.provider_runtime import ProviderFinalizePlan, write_provider_bundle
from azure_tenant_audit.resources import resolve_resource_path
from azure_tenant_audit.run import build_coverage_ledger
from azure_tenant_audit.utils import parse_csv_list

from .auth import GoogleAuthConfig, build_google_credentials, google_dependency_status, read_service_account_summary, safe_auth_summary
from .client import GoogleWorkspaceClient
from .client import classify_google_error
from .collectors import DEFAULT_ORDER, PRESETS, REGISTRY
from .findings import build_google_findings
from .normalize import build_google_normalized_snapshot


LOG = logging.getLogger("auditex.google_workspace")
_OFFLINE_SAMPLE_METADATA_KEYS = frozenset({"_fixture_provenance"})


def _merged_fixture_provenance(
    sample_fixture_provenance: dict[str, Any] | None,
    fixture_provenance_override: dict[str, Any] | None,
) -> dict[str, Any] | None:
    merged: dict[str, Any] = {}
    if isinstance(sample_fixture_provenance, dict):
        merged.update(sample_fixture_provenance)
    if isinstance(fixture_provenance_override, dict):
        for key, value in fixture_provenance_override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
    return merged or None
_SENSITIVE_COMMAND_FLAGS = {"--service-account-key", "--oauth-client", "--token-cache"}


@dataclass(frozen=True)
class GoogleRunConfig:
    tenant_name: str
    out: Path
    domain: str | None = None
    customer_id: str | None = None
    run_name: str | None = None
    auth: str = "domain-delegation"
    subject: str | None = None
    service_account_key: Path | None = None
    oauth_client: Path | None = None
    token_cache: Path | None = None
    collector_preset: str | None = "core-security"
    collectors: str | None = None
    exclude: str | None = None
    top: int = 100
    page_size: int = 100
    since: str | None = None
    until: str | None = None
    offline: bool = False
    sample: Path | None = None
    fixture_provenance: dict[str, Any] | None = None


def scrub_google_command_line(command_line: list[str]) -> list[str]:
    scrubbed: list[str] = []
    skip_next = False
    for arg in command_line:
        if skip_next:
            scrubbed.append("***redacted***")
            skip_next = False
            continue
        if arg in _SENSITIVE_COMMAND_FLAGS:
            scrubbed.append(arg)
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _SENSITIVE_COMMAND_FLAGS):
            flag, _sep, _value = arg.partition("=")
            scrubbed.append(f"{flag}=***redacted***")
            continue
        scrubbed.append(arg)
    return scrubbed


def _selected_collectors(config: GoogleRunConfig) -> list[str]:
    selected = parse_csv_list(config.collectors) or []
    if not selected:
        selected = list(PRESETS.get(config.collector_preset or "core-security", DEFAULT_ORDER))
    excluded = set(parse_csv_list(config.exclude) or [])
    return [name for name in selected if name in REGISTRY and name not in excluded]


def scopes_for_collectors(selected: list[str]) -> tuple[str, ...]:
    scopes: list[str] = []
    for name in selected:
        collector = REGISTRY.get(name)
        for scope in getattr(collector, "required_scopes", ()):
            if scope not in scopes:
                scopes.append(scope)
    return tuple(scopes)


def build_google_auth_context_payload(config: GoogleRunConfig, auth_config: GoogleAuthConfig) -> dict[str, Any]:
    auth_summary = safe_auth_summary(auth_config)
    return {
        "platform": "google_workspace",
        "auth_mode": auth_config.auth_mode,
        "auth_type": auth_config.auth_mode,
        "subject": auth_config.subject,
        "workspace_domain": config.domain,
        "customer_id": config.customer_id,
        "scope_count": len(auth_config.scopes),
        "scopes": list(auth_config.scopes),
        "service_account_key_present": auth_summary["service_account_key_present"],
        "oauth_client_present": auth_summary["oauth_client_present"],
        "token_cache_present": auth_summary["token_cache_present"],
    }


def build_google_capability_rows(
    selected: list[str],
    *,
    auth_mode: str,
    dependency_status: dict[str, Any],
    coverage_rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    coverage_rows = coverage_rows or []
    failures_by_collector: dict[str, list[dict[str, Any]]] = {}
    seen_by_collector: dict[str, list[dict[str, Any]]] = {}
    for row in coverage_rows:
        seen_by_collector.setdefault(str(row.get("collector") or ""), []).append(row)
        if row.get("status") != "ok":
            failures_by_collector.setdefault(str(row.get("collector") or ""), []).append(row)
    status = "supported" if dependency_status.get("available") else "blocked"
    reason = "google_dependencies_available" if status == "supported" else "missing_google_dependencies"
    rows: list[dict[str, Any]] = []
    for name in selected:
        required = list(getattr(REGISTRY.get(name), "required_scopes", ()))
        failures = failures_by_collector.get(name, [])
        row_status = status
        row_reason = reason
        missing_permissions: list[str] = []
        if not failures and seen_by_collector.get(name) and status == "supported":
            row_status = "supported_exact_scope"
            row_reason = "runtime_preflight_ok"
        elif failures:
            classes = {str(item.get("error_class") or "") for item in failures}
            if classes & {"insufficient_permissions", "unauthenticated"}:
                row_status = "blocked_by_scope"
                row_reason = "runtime_permission_block"
                missing_permissions = required
            else:
                row_status = "partial"
                row_reason = "runtime_endpoint_block"
        rows.append(
            enrich_capability_row(
                {
                    "collector": name,
                    "status": row_status,
                    "reason": row_reason,
                    "required_permissions": required,
                    "missing_permissions": missing_permissions,
                    "observed_permissions": [],
                    "delegated_roles": [],
                    "minimum_role_hints": ["Google Workspace super admin or delegated admin"],
                    "notes": f"Google Workspace {auth_mode} auth.",
                    "endpoint_statuses": [
                        {
                            "name": item.get("name"),
                            "status": item.get("status"),
                            "error_class": item.get("error_class"),
                            "error": item.get("error"),
                        }
                        for item in failures
                    ],
                }
            )
        )
    return rows


def _capability_rows(
    selected: list[str],
    *,
    auth_mode: str,
    dependency_status: dict[str, Any],
    coverage_rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    return build_google_capability_rows(
        selected,
        auth_mode=auth_mode,
        dependency_status=dependency_status,
        coverage_rows=coverage_rows,
    )


def build_google_live_readiness(selected: list[str], capability_rows: list[dict[str, Any]], *, dependency_available: bool = True) -> dict[str, Any]:
    return build_live_readiness_summary(
        selected_collectors=selected,
        capability_rows=capability_rows,
        dependency_available=dependency_available,
    )


def build_google_toolchain_readiness(dependency_status: dict[str, Any]) -> dict[str, Any]:
    available = bool(dependency_status.get("available"))
    missing = [str(item) for item in dependency_status.get("missing") or []]
    return {
        "google_workspace_libraries": {
            "name": "google_workspace_libraries",
            "status": "supported" if available else "blocked",
            "item_count": 0 if available else len(missing),
            "message": "Google client libraries available" if available else dependency_status.get("install_hint", "Google client libraries missing"),
            "missing": missing,
            "install_hint": dependency_status.get("install_hint", ""),
        }
    }


def _preflight_call(collector: str, name: str, func: Any) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        rows = func()
        status = "ok"
        error_class = None
        error = None
    except Exception as exc:  # noqa: BLE001
        rows = []
        status = "failed"
        error_class, error = classify_google_error(exc)
    return {
        "collector": collector,
        "name": name,
        "status": status,
        "item_count": len(rows) if isinstance(rows, list) else 1,
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "error_class": error_class,
        "error": error,
    }


def build_google_preflight_rows(
    client: Any,
    selected: list[str],
    *,
    domain: str | None,
    top: int = 1,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for collector in selected:
        if collector == "google_directory":
            rows.append(_preflight_call(collector, "users", lambda: client.list_directory("users", top=top, domain=domain)))
        elif collector == "google_reports":
            rows.append(_preflight_call(collector, "loginActivities", lambda: client.list_report_activities("login", top=top)))
        elif collector == "google_alert_center":
            rows.append(_preflight_call(collector, "alerts", lambda: client.list_alerts(top=top)))
        elif collector == "google_gmail_settings":
            def gmail_check() -> list[dict[str, Any]]:
                users = client.list_directory("users", top=1, domain=domain)
                if not users:
                    return []
                email = str(users[0].get("primaryEmail") or users[0].get("email") or "")
                return [client.get_gmail_settings_for_user(email)] if email else []

            rows.append(_preflight_call(collector, "mailboxSettings", gmail_check))
        elif collector == "google_devices":
            rows.append(_preflight_call(collector, "mobileDevices", lambda: client.list_devices("mobile", top=top)))
        elif collector == "google_dns_posture":
            rows.append({"collector": collector, "name": "dns", "status": "ok", "item_count": 1 if domain else 0, "duration_ms": 0, "error_class": None, "error": None})
        elif collector == "google_drive_posture":
            rows.append(_preflight_call(collector, "driveFiles", lambda: client.list_drive_files(top=top)))
            rows.append(_preflight_call(collector, "sharedDrives", lambda: client.list_shared_drives(top=top)))
        elif collector == "google_groups_settings":
            def group_settings_check() -> list[dict[str, Any]]:
                groups = client.list_directory("groups", top=1, domain=domain)
                if not groups:
                    return []
                email = str(groups[0].get("email") or groups[0].get("id") or "")
                return [client.get_group_settings(email)] if email else []

            rows.append(_preflight_call(collector, "groupSettings", group_settings_check))
        elif collector == "google_calendar_posture":
            rows.append(_preflight_call(collector, "calendarResources", lambda: client.list_calendar_resources(top=top)))
    return rows


def _write_google_bundle(
    *,
    writer: AuditWriter,
    config: GoogleRunConfig,
    collector_payloads: dict[str, dict[str, Any]],
    result_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    capability_rows: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
    duration: float,
    mode: str,
    auth_context_path: Path | None = None,
    command_line: list[str] | None = None,
) -> int:
    normalized_snapshot = build_google_normalized_snapshot(
        tenant_name=config.tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        domain=config.domain,
        customer_id=config.customer_id,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        top_limit=config.top,
    )
    findings = build_google_findings(normalized_snapshot, diagnostics=diagnostics)
    if findings:
        writer.write_findings(findings)
    coverage_ledger = build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe(
        "run_summary",
        {
            "platform": "google_workspace",
            "tenant_name": config.tenant_name,
            "workspace_domain": config.domain,
            "customer_id": config.customer_id,
            "run_id": writer.run_id,
            "finding_count": len(findings),
            "collector_count": len(result_rows),
        },
    )
    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        "ai_safe/run_summary.json",
    ]
    if findings:
        evidence_paths.append("findings/findings.json")
    if diagnostics:
        evidence_paths.append("blockers/blockers.json")
    if auth_context_path is not None:
        evidence_paths.append(str(auth_context_path.relative_to(writer.run_dir)))
    evidence_paths.extend(f"normalized/{name}.json" for name in ["capability_matrix", "coverage_ledger", *normalized_snapshot.keys()])
    overall_status = "partial" if diagnostics or any(str(row.get("status")) not in {"ok", "skipped"} for row in result_rows) else "ok"
    privacy = build_privacy_block(safe_for_external_llm=False)
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=config.tenant_name,
            tenant_id=config.customer_id,
            executed_by="auditex_google_workspace",
            selected_collectors=[row["name"] for row in result_rows],
            overall_status=overall_status,
            duration_seconds=duration,
            mode=mode,
            auditor_profile="google-workspace",
            plane="inventory",
            findings=findings,
            blockers=diagnostics,
            evidence_paths=evidence_paths,
            normalized_snapshot=normalized_snapshot,
            capability_rows=capability_rows,
            coverage_ledger=coverage_ledger,
            privacy=privacy,
            bundle_metadata={
                "fixture_provenance": config.fixture_provenance,
                "since": config.since,
                "until": config.until,
                "platform": "google_workspace",
                "workspace_domain": config.domain,
                "customer_id": config.customer_id,
                "auth_context_path": str(auth_context_path.relative_to(writer.run_dir)) if auth_context_path is not None else None,
                "command_line": scrub_google_command_line(command_line or []),
                "coverage_count": len(coverage_rows),
                "top_limit": config.top,
                "sample_truncated": bool((normalized_snapshot.get("snapshot") or {}).get("sample_truncated")),
                "truncated_sections": (normalized_snapshot.get("snapshot") or {}).get("truncated_sections", []),
            },
        ),
    )
    return 1 if overall_status == "partial" else 0


def run_google_offline(
    *,
    sample_path: Path,
    out: Path,
    tenant_name: str,
    run_name: str | None,
    domain: str | None,
    customer_id: str | None,
    fixture_provenance_override: dict[str, Any] | None = None,
) -> int:
    target = resolve_resource_path(sample_path)
    try:
        sample = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOG.error("Unable to load Google sample bundle: %s", exc)
        return 2
    if not isinstance(sample, dict):
        LOG.error("Google sample bundle must be a JSON object.")
        return 2
    fixture_provenance = _merged_fixture_provenance(
        sample.get("_fixture_provenance") if isinstance(sample.get("_fixture_provenance"), dict) else None,
        fixture_provenance_override,
    )
    config = GoogleRunConfig(
        tenant_name=tenant_name,
        out=out,
        domain=domain,
        customer_id=customer_id,
        run_name=run_name,
        offline=True,
        sample=sample_path,
        fixture_provenance=fixture_provenance,
    )
    writer = AuditWriter(out, tenant_name=tenant_name, run_name=run_name)
    writer.log_event("run.started", "Google Workspace offline run started", {"platform": "google_workspace", "sample": str(target)})
    collector_payloads = {
        str(key): value
        for key, value in sample.items()
        if key not in _OFFLINE_SAMPLE_METADATA_KEYS and isinstance(value, dict)
    }
    result_rows: list[dict[str, Any]] = []
    for name, payload in collector_payloads.items():
        item_count = 0
        for section in payload.values():
            if isinstance(section, dict) and isinstance(section.get("value"), list):
                item_count += len(section["value"])
        row = {"name": name, "status": "ok", "item_count": item_count, "message": "offline simulation", "coverage_rows": 0}
        result_rows.append(row)
        writer.write_summary(row)
        writer.write_checkpoint(name, row)
        writer.write_raw(name, payload)
    capability_rows = _capability_rows(list(collector_payloads), auth_mode="offline", dependency_status={"available": True})
    return _write_google_bundle(
        writer=writer,
        config=config,
        collector_payloads=collector_payloads,
        result_rows=result_rows,
        coverage_rows=[],
        capability_rows=capability_rows,
        diagnostics=[],
        duration=0,
        mode="offline",
        command_line=[],
    )


def run_google_live(config: GoogleRunConfig, *, command_line: list[str] | None = None) -> int:
    dependency_status = google_dependency_status()
    if not dependency_status["available"]:
        print(json.dumps({"error": "missing_google_dependencies", **dependency_status}, indent=2), file=sys.stderr)
        return 2
    selected = _selected_collectors(config)
    auth_config = GoogleAuthConfig(
        auth_mode=config.auth,
        scopes=scopes_for_collectors(selected),
        subject=config.subject,
        service_account_key=config.service_account_key,
        oauth_client=config.oauth_client,
        token_cache=config.token_cache,
    )
    try:
        credentials = build_google_credentials(auth_config)
    except (RuntimeError, ValueError, OSError) as exc:
        print(json.dumps({"error": "google_auth_failed", "message": str(exc)}, indent=2), file=sys.stderr)
        return 2
    client = GoogleWorkspaceClient(credentials, customer_id=config.customer_id, domain=config.domain, page_size=config.page_size)
    writer = AuditWriter(config.out, tenant_name=config.tenant_name, run_name=config.run_name)
    auth_context_path = writer.write_json_artifact("auth-context.json", build_google_auth_context_payload(config, auth_config))
    writer.log_event(
        "run.started",
        "Google Workspace live run started",
        {"platform": "google_workspace", "domain": config.domain, "customer_id": config.customer_id, "auth": safe_auth_summary(auth_config)},
    )
    start = time.time()
    writer_adapter = AuditWriterCollectorAdapter(writer)
    runner = CollectorRunner(writer_adapter)
    result_rows: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    collector_payloads: dict[str, dict[str, Any]] = {}
    diagnostics: list[dict[str, Any]] = []
    for name in selected:
        output = runner.run(
            REGISTRY[name],
            CollectorRunContext(
                client=client,
                top=config.top,
                page_size=config.page_size,
                plane="inventory",
                since=config.since,
                until=config.until,
                hooks=writer_adapter.hooks(),
                extra={"domain": config.domain, "customer_id": config.customer_id},
            ),
            name=name,
        )
        result_rows.append(dict(output.result_row))
        writer.write_summary(dict(output.result_row))
        coverage_rows.extend(output.coverage_rows)
        collector_payloads[name] = output.result.payload
        for row in output.coverage_rows:
            if row.get("status") != "ok":
                diagnostics.append(dict(row))
    capability_rows = _capability_rows(
        selected,
        auth_mode=config.auth,
        dependency_status=dependency_status,
        coverage_rows=coverage_rows,
    )
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
    return _write_google_bundle(
        writer=writer,
        config=config,
        collector_payloads=collector_payloads,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        capability_rows=capability_rows,
        diagnostics=diagnostics,
        duration=round(time.time() - start, 2),
        mode=config.auth,
        auth_context_path=auth_context_path,
        command_line=command_line,
    )


def google_doctor(config: GoogleRunConfig | None = None) -> dict[str, Any]:
    dependency_status = google_dependency_status()
    payload: dict[str, Any] = {
        "platform": "google_workspace",
        "dependencies": dependency_status,
        "collectors": sorted(REGISTRY),
        "presets": sorted(PRESETS),
    }
    if config is not None:
        selected = _selected_collectors(config)
        scopes = list(scopes_for_collectors(selected))
        payload["auth"] = {
            "mode": config.auth,
            "subject": config.subject,
            "scope_count": len(scopes),
            "scopes": scopes,
            "scopes_csv": ",".join(scopes),
            "service_account": read_service_account_summary(config.service_account_key),
            "oauth_client_present": bool(config.oauth_client and config.oauth_client.expanduser().exists()),
            "token_cache_present": bool(config.token_cache and config.token_cache.expanduser().exists()),
        }
        payload["target"] = {"domain": config.domain, "customer_id": config.customer_id}
        payload["selected_collectors"] = selected
        payload["live_readiness"] = build_google_live_readiness(
            selected,
            [],
            dependency_available=bool(dependency_status.get("available")),
        )
    return payload


def _google_probe_summary_rows(selected: list[str], preflight_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows_by_collector: dict[str, list[dict[str, Any]]] = {}
    for row in preflight_rows:
        rows_by_collector.setdefault(str(row.get("collector") or ""), []).append(row)
    summary_rows: list[dict[str, Any]] = []
    for collector in selected:
        rows = rows_by_collector.get(collector, [])
        failures = [row for row in rows if row.get("status") != "ok"]
        item_count = sum(int(row.get("item_count") or 0) for row in rows)
        summary_rows.append(
            {
                "name": collector,
                "status": "failed" if failures else "ok",
                "item_count": item_count,
                "message": "preflight ok" if not failures else "preflight blocked",
                "coverage_rows": len(rows),
            }
        )
    return summary_rows


def _write_google_probe_bundle(
    *,
    writer: AuditWriter,
    config: GoogleRunConfig,
    selected: list[str],
    auth_config: GoogleAuthConfig,
    payload: dict[str, Any],
    dependency_status: dict[str, Any],
    command_line: list[str] | None,
) -> None:
    preflight_rows = [dict(row) for row in payload.get("preflight", []) if isinstance(row, dict)]
    capability_rows = [dict(row) for row in payload.get("capability_matrix", []) if isinstance(row, dict)]
    if not capability_rows:
        capability_rows = build_google_capability_rows(
            selected,
            auth_mode=config.auth,
            dependency_status=dependency_status,
            coverage_rows=preflight_rows,
        )
        payload["capability_matrix"] = capability_rows
    live_readiness = payload.get("live_readiness")
    if not isinstance(live_readiness, dict):
        live_readiness = build_google_live_readiness(
            selected,
            capability_rows,
            dependency_available=bool(dependency_status.get("available")),
        )
        payload["live_readiness"] = live_readiness

    writer.log_event(
        "probe.started",
        "Google Workspace probe started",
        {"platform": "google_workspace", "domain": config.domain, "customer_id": config.customer_id},
    )
    for row in _google_probe_summary_rows(selected, preflight_rows):
        writer.write_summary(row)
    auth_context_path = writer.write_json_artifact("auth-context.json", build_google_auth_context_payload(config, auth_config))
    preflight_path = writer.write_json_artifact("preflight.json", preflight_rows)
    writer.write_index_records(preflight_rows)
    capability_path = writer.write_json_artifact("capability-matrix.json", capability_rows)
    toolchain_path = writer.write_json_artifact("toolchain-readiness.json", build_google_toolchain_readiness(dependency_status))
    live_readiness_path = writer.write_json_artifact("live-readiness.json", live_readiness)
    probe_result_path = writer.write_json_artifact("probe-result.json", payload)
    coverage_ledger = build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=writer.summary.get("collectors", []),
        diagnostics=[row for row in preflight_rows if row.get("status") != "ok"],
    )
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    writer.write_normalized(
        "snapshot",
        {
            "kind": "google_workspace_probe_snapshot",
            "tenant_name": config.tenant_name,
            "run_id": writer.run_id,
            "workspace_domain": config.domain,
            "customer_id": config.customer_id,
            "collector_count": len(selected),
            "coverage_row_count": len(preflight_rows),
            "blocker_count": sum(1 for row in preflight_rows if row.get("status") != "ok"),
            "object_counts": {"preflight_rows": len(preflight_rows), "collectors": len(selected)},
            "normalized_counts": {"preflight_rows": len(preflight_rows), "collectors": len(selected)},
            "sample_truncated": False,
            "truncated_sections": [],
        },
    )
    blockers = [row for row in preflight_rows if row.get("status") != "ok"]
    if blockers:
        writer.write_diagnostics(blockers)
        writer.write_blockers(blockers)

    overall_status = "partial" if blockers or payload.get("preflight_error") or not dependency_status.get("available") else "ok"
    privacy = build_privacy_block(safe_for_external_llm=False)
    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        str(auth_context_path.relative_to(writer.run_dir)),
        str(preflight_path.relative_to(writer.run_dir)),
        str(capability_path.relative_to(writer.run_dir)),
        str(toolchain_path.relative_to(writer.run_dir)),
        str(live_readiness_path.relative_to(writer.run_dir)),
        str(probe_result_path.relative_to(writer.run_dir)),
        "normalized/capability_matrix.json",
        "normalized/coverage_ledger.json",
        "normalized/snapshot.json",
    ]
    if blockers:
        evidence_paths.append("blockers/blockers.json")
    evidence_index = {"artifacts": sorted(set(writer.artifact_paths() + ["run-manifest.json", "summary.json", "summary.md"]))}
    evidence_index_path = writer.write_json_artifact("evidence-index.json", evidence_index)
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=config.tenant_name,
            tenant_id=config.customer_id,
            executed_by="auditex_google_probe",
            selected_collectors=selected,
            overall_status=overall_status,
            duration_seconds=0,
            mode=config.auth,
            auditor_profile="google-workspace",
            plane="inventory",
            findings=[],
            blockers=blockers,
            evidence_paths=evidence_paths,
            normalized_snapshot={
                "snapshot": {
                    "normalized_counts": {"preflight_rows": len(preflight_rows), "collectors": len(selected)},
                    "collector_count": len(selected),
                    "coverage_row_count": len(preflight_rows),
                    "blocker_count": len(blockers),
                    "sample_truncated": False,
                    "truncated_sections": [],
                }
            },
            capability_rows=capability_rows,
            coverage_ledger=coverage_ledger,
            privacy=privacy,
            bundle_metadata={
                "since": config.since,
                "until": config.until,
                "command_line": scrub_google_command_line(command_line or []),
                "probe_mode": config.auth,
                "probe_surface": config.collectors or config.collector_preset or "",
                "capability_matrix_path": str(capability_path.relative_to(writer.run_dir)),
                "toolchain_readiness_path": str(toolchain_path.relative_to(writer.run_dir)),
                "live_readiness_path": str(live_readiness_path.relative_to(writer.run_dir)),
                "preflight_path": str(preflight_path.relative_to(writer.run_dir)),
                "evidence_index_path": str(evidence_index_path.relative_to(writer.run_dir)),
                "auth_context_path": str(auth_context_path.relative_to(writer.run_dir)),
                "platform": "google_workspace",
                "workspace_domain": config.domain,
                "customer_id": config.customer_id,
                "collector_preset": config.collector_preset,
                "top_limit": config.top,
            },
        ),
    )
    writer.log_event(
        "probe.completed",
        "Google Workspace probe completed",
        {"probe_mode": config.auth, "blockers": len(blockers)},
    )


def run_google_probe(config: GoogleRunConfig, *, command_line: list[str] | None = None) -> int:
    dependency_status = google_dependency_status()
    selected = _selected_collectors(config)
    payload = google_doctor(config)
    auth_config = GoogleAuthConfig(
        auth_mode=config.auth,
        scopes=scopes_for_collectors(selected),
        subject=config.subject,
        service_account_key=config.service_account_key,
        oauth_client=config.oauth_client,
        token_cache=config.token_cache,
    )
    writer = AuditWriter(config.out, tenant_name=config.tenant_name, run_name=config.run_name)
    if not dependency_status["available"]:
        payload["capability_matrix"] = build_google_capability_rows(
            selected,
            auth_mode=config.auth,
            dependency_status=dependency_status,
        )
        payload["live_readiness"] = build_google_live_readiness(
            selected,
            payload["capability_matrix"],
            dependency_available=False,
        )
        _write_google_probe_bundle(
            writer=writer,
            config=config,
            selected=selected,
            auth_config=auth_config,
            payload=payload,
            dependency_status=dependency_status,
            command_line=command_line,
        )
        print(json.dumps(payload, indent=2))
        return 2
    try:
        credentials = build_google_credentials(auth_config)
        client = GoogleWorkspaceClient(credentials, customer_id=config.customer_id, domain=config.domain, page_size=config.page_size)
        preflight_rows = build_google_preflight_rows(client, selected, domain=config.domain, top=max(1, min(config.top, 5)))
        payload["preflight"] = preflight_rows
        payload["capability_matrix"] = build_google_capability_rows(
            selected,
            auth_mode=config.auth,
            dependency_status=dependency_status,
            coverage_rows=preflight_rows,
        )
        payload["live_readiness"] = build_google_live_readiness(
            selected,
            payload["capability_matrix"],
            dependency_available=bool(dependency_status.get("available")),
        )
    except Exception as exc:  # noqa: BLE001
        error_class, message = classify_google_error(exc)
        payload["preflight"] = [
            {
                "collector": name,
                "name": "probe",
                "status": "failed",
                "item_count": 0,
                "duration_ms": 0,
                "error_class": error_class,
                "error": message,
            }
            for name in selected
        ]
        payload["preflight_error"] = {"error": "google_probe_failed", "message": str(exc)}
        payload["capability_matrix"] = build_google_capability_rows(
            selected,
            auth_mode=config.auth,
            dependency_status=dependency_status,
            coverage_rows=payload["preflight"],
        )
        payload["live_readiness"] = build_google_live_readiness(
            selected,
            payload["capability_matrix"],
            dependency_available=bool(dependency_status.get("available")),
        )
        _write_google_probe_bundle(
            writer=writer,
            config=config,
            selected=selected,
            auth_config=auth_config,
            payload=payload,
            dependency_status=dependency_status,
            command_line=command_line,
        )
        print(json.dumps(payload, indent=2))
        return 2
    _write_google_probe_bundle(
        writer=writer,
        config=config,
        selected=selected,
        auth_config=auth_config,
        payload=payload,
        dependency_status=dependency_status,
        command_line=command_line,
    )
    print(json.dumps(payload, indent=2))
    return 0 if all(row.get("status") == "ok" for row in payload["preflight"]) else 1
