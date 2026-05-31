from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .assurance import build_live_readiness_summary
from .capability_gate import enrich_capability_row
from .config import CollectorConfig, RunConfig
from .ai_context import build_privacy_block
from .provider_runtime import ProviderFinalizePlan, write_provider_bundle
from .profiles import AuditProfile, get_profile
from .scope_catalog import build_m365_scope_catalog
from .selection import select_collectors
from .utils import parse_csv_list


@dataclass(frozen=True)
class LiveRunPlan:
    run_config: RunConfig
    selected_collectors: list[str]
    execution_plane: str
    auth_scopes: list[str]
    permission_hints: dict[str, dict[str, Any]]
    collector_config: CollectorConfig
    profile: AuditProfile


def build_live_run_plan(
    args: Any,
    *,
    output_dir: Path,
    collector_config: CollectorConfig,
    permission_hints: dict[str, dict[str, Any]],
    profile: AuditProfile | None = None,
    collector_presets: dict[str, object] | None = None,
) -> LiveRunPlan:
    profile = profile or get_profile(args.auditor_profile)
    selected_collector_names = parse_csv_list(args.collectors)
    exclude_collector_names = parse_csv_list(args.exclude)
    run_cfg = RunConfig(
        tenant_name=args.tenant_name,
        output_dir=output_dir,
        collectors=selected_collector_names,
        excluded_collectors=exclude_collector_names,
        include_exchange=args.include_exchange,
        offline=args.offline,
        sample_path=Path(args.sample),
        run_name=args.run_name,
        top_items=args.top,
        page_size=args.page_size,
        auditor_profile=args.auditor_profile,
        default_collectors=profile.default_collectors,
        plane=args.plane,
        since=args.since,
        until=args.until,
    )
    available = [name for name in collector_config.default_order if name in collector_config.collectors]
    selected = select_collectors(
        available=available,
        profile_default_collectors=profile.default_collectors,
        preset_name=args.collector_preset,
        presets=collector_presets or {},
        explicit_collectors=selected_collector_names,
        excluded_collectors=exclude_collector_names,
        include_exchange=args.include_exchange,
    )
    if run_cfg.plane not in profile.supported_planes:
        raise ValueError(f"Audit profile '{run_cfg.auditor_profile}' does not support plane '{run_cfg.plane}'.")
    execution_plane = "export" if run_cfg.plane in {"full", "export"} else "inventory"

    auth_scopes = parse_csv_list(args.scopes)
    if args.interactive and not auth_scopes:
        auth_scopes = sorted({perm for name in selected for perm in collector_config.collectors[name].required_permissions})
    if args.interactive and not auth_scopes:
        auth_scopes = ["User.Read"]

    return LiveRunPlan(
        run_config=run_cfg,
        selected_collectors=selected,
        execution_plane=execution_plane,
        auth_scopes=auth_scopes,
        permission_hints=permission_hints,
        collector_config=collector_config,
        profile=profile,
    )


def build_capability_matrix_rows(
    *,
    auth_context: dict[str, Any],
    selected_collectors: list[str],
    auditor_profile: str,
    collector_config: CollectorConfig,
    permission_hints: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    token_claims = auth_context.get("token_claims") or {}
    available = {
        *[str(item) for item in token_claims.get("delegated_scopes") or [] if item],
        *[str(item) for item in token_claims.get("app_roles") or [] if item],
    }
    delegated_roles = {str(item) for item in auth_context.get("delegated_roles") or [] if item}
    has_global_reader = any(role.lower() == "global reader" for role in delegated_roles)
    profile = get_profile(auditor_profile)
    catalog = build_m365_scope_catalog(
        collector_config=collector_config,
        permission_hints=permission_hints,
    )
    rows: list[dict[str, Any]] = []
    for collector_name in selected_collectors:
        entry = catalog.get(collector_name, {})
        definition = collector_config.collectors.get(collector_name)
        required = list(entry.get("required_permissions") or [])
        missing = [perm for perm in required if perm not in available]
        status = "supported_exact_scope"
        reason = "required_permissions_present"
        if missing:
            status = "blocked_by_scope"
            reason = "missing_required_permissions"
        if definition and getattr(definition, "command_collectors", None) and not required:
            status = "supported_effective_role"
            reason = "command_toolchain_required"
        if collector_name in {"purview", "ediscovery"} and has_global_reader:
            status = "blocked_by_role"
            reason = "global_reader_limit"
        elif collector_name == "reports_usage" and has_global_reader and "Reports.Read.All" not in available:
            status = "partial"
            reason = "global_reader_tenant_level_reports_only"
        rows.append(
            enrich_capability_row(
                {
                    "collector": collector_name,
                    "status": status,
                    "reason": reason,
                    "required_permissions": required,
                    "missing_permissions": missing,
                    "observed_permissions": sorted(available),
                    "delegated_roles": sorted(delegated_roles),
                    "minimum_role_hints": list(entry.get("minimum_role_hints") or profile.delegated_role_hints),
                    "notes": entry.get("notes") or profile.notes,
                }
            )
        )
    return rows


def reconcile_capability_matrix_rows(
    capability_rows: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results_by_collector = {str(row.get("name")): row for row in result_rows if isinstance(row, dict)}
    reconciled: list[dict[str, Any]] = []
    for row in capability_rows:
        item = dict(row)
        collector = str(item.get("collector") or "")
        result = results_by_collector.get(collector, {})
        actual_status = str(result.get("status") or "")
        missing_permissions = list(item.get("missing_permissions") or [])
        delegated_roles = list(item.get("delegated_roles") or [])
        if actual_status == "ok":
            if missing_permissions:
                item["status"] = "supported_effective_role" if delegated_roles else "supported_equivalent_scope"
            elif item.get("status") not in {"supported_effective_role"}:
                item["status"] = "supported_exact_scope"
        elif actual_status == "partial":
            item["status"] = "partial"
        elif actual_status == "failed":
            item["status"] = "blocked"
        elif actual_status == "skipped":
            item["status"] = "not_applicable"
        item = enrich_capability_row(item)
        reconciled.append(item)
    return reconciled


def build_coverage_ledger(
    *,
    capability_rows: list[dict[str, Any]],
    result_rows: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results_by_collector = {str(row.get("name")): row for row in result_rows}
    diagnostics_by_collector: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in diagnostics:
        collector = str(item.get("collector") or "")
        if collector:
            diagnostics_by_collector[collector].append(item)

    def _has_permission_block(collector: str) -> bool:
        classes = {str(item.get("error_class") or "") for item in diagnostics_by_collector.get(collector, [])}
        return any(value in {"insufficient_permissions", "unauthenticated", "blocked_by_scope"} for value in classes)

    ledger: list[dict[str, Any]] = []
    for capability in capability_rows:
        collector = str(capability.get("collector") or "")
        result = results_by_collector.get(collector, {})
        actual_status = result.get("status")
        expected_status = capability.get("status")
        if not result:
            coverage_status = "not_run"
            coverage_reason = "collector_not_executed"
        elif _has_permission_block(collector):
            coverage_status = "blocked_permission"
            coverage_reason = "permission_or_auth_blocker"
        elif actual_status == "ok":
            if expected_status == "supported_effective_role":
                coverage_status = "complete_effective_role"
                coverage_reason = "runtime_success_with_effective_role"
            elif expected_status == "supported_equivalent_scope":
                coverage_status = "complete_equivalent_scope"
                coverage_reason = "runtime_success_with_equivalent_permission"
            elif expected_status == "offline_sample":
                coverage_status = "complete_offline_sample"
                coverage_reason = "offline_sample_materialized"
            else:
                coverage_status = "complete_exact_scope"
                coverage_reason = "runtime_success_with_expected_scope"
        elif actual_status == "partial":
            coverage_status = "partial_success"
            coverage_reason = "collector_returned_partial"
        elif actual_status == "skipped":
            coverage_status = "not_applicable" if expected_status not in {"blocked_by_scope", "blocked_by_role"} else "blocked_permission"
            coverage_reason = "collector_skipped"
        else:
            coverage_status = "failed_runtime"
            coverage_reason = "collector_failed_runtime"
        ledger.append(
            {
                "collector": collector,
                "expected_status": expected_status,
                "expected_reason": capability.get("reason"),
                "actual_status": actual_status,
                "coverage_status": coverage_status,
                "coverage_reason": coverage_reason,
                "item_count": result.get("item_count", 0),
                "message": result.get("message"),
                "diagnostic_count": len(diagnostics_by_collector.get(collector, [])),
                "diagnostics": diagnostics_by_collector.get(collector, []),
            }
        )
    return ledger


def collector_pause_seconds(throttle_mode: str) -> float:
    if throttle_mode == "ultra-safe":
        return 1.5
    if throttle_mode == "safe":
        return 0.5
    return 0.0


def run_preflight_probe(
    *,
    selected_collectors: list[str],
    completed_collectors: set[str],
    client: Any,
    run_cfg: RunConfig,
    writer: Any,
    include_blocked: bool,
    registry: dict[str, Any],
) -> tuple[list[str], list[dict[str, Any]], str]:
    rows: list[dict[str, Any]] = []
    runnable: list[str] = []
    preflight_top = max(1, min(5, run_cfg.top_items))
    preflight_page_size = max(1, min(5, run_cfg.page_size))
    writer.log_event(
        "preflight.started",
        "Collector preflight started",
        {
            "collector_count": len(selected_collectors),
            "top": preflight_top,
            "page_size": preflight_page_size,
            "include_blocked": include_blocked,
        },
    )
    for name in selected_collectors:
        if name in completed_collectors:
            runnable.append(name)
            rows.append({"collector": name, "decision": "run", "reason": "already_completed", "status": "ok", "item_count": 0})
            continue
        collector = registry.get(name)
        if collector is None:
            rows.append(
                {
                    "collector": name,
                    "decision": "skip",
                    "reason": "unknown_collector",
                    "status": "failed",
                    "item_count": 0,
                    "error": "unknown collector",
                }
            )
            continue

        writer.log_event("preflight.collector.started", "Preflight collector started", {"collector": name})
        try:
            result = collector.run(
                {
                    "client": client,
                    "top": preflight_top,
                    "page_size": preflight_page_size,
                    "plane": "inventory",
                    "since": run_cfg.since,
                    "until": run_cfg.until,
                    "collector_checkpoint_state": {},
                    "operation_checkpoint_state": {},
                    "chunk_writer": None,
                    "audit_logger": writer.log_event,
                }
            )
            coverage = result.coverage or []
            has_ok = any(item.get("status") == "ok" for item in coverage)
            decision = "run" if include_blocked or result.item_count > 0 or has_ok else "skip"
            reason = "supported" if decision == "run" else "known_blocked"
            rows.append(
                {
                    "collector": name,
                    "decision": decision,
                    "reason": reason,
                    "status": result.status,
                    "item_count": result.item_count,
                    "coverage_rows": len(coverage),
                    "message": result.message,
                }
            )
            if decision == "run":
                runnable.append(name)
            writer.log_event(
                "preflight.collector.finished",
                "Preflight collector finished",
                {"collector": name, "decision": decision, "status": result.status, "item_count": result.item_count},
            )
        except Exception as exc:  # noqa: BLE001
            decision = "run" if include_blocked else "skip"
            rows.append(
                {
                    "collector": name,
                    "decision": decision,
                    "reason": "preflight_exception",
                    "status": "failed",
                    "item_count": 0,
                    "error": str(exc),
                }
            )
            if include_blocked:
                runnable.append(name)
            writer.log_event(
                "preflight.collector.finished",
                "Preflight collector failed",
                {"collector": name, "decision": decision, "status": "failed", "error": str(exc)},
            )

    artifact = writer.write_json_artifact(
        "preflight-plan.json",
        {
            "collectors": rows,
            "runnable_collectors": runnable,
            "skipped_collectors": [row["collector"] for row in rows if row.get("decision") == "skip"],
        },
    )
    writer.log_event(
        "preflight.completed",
        "Collector preflight completed",
        {"run_count": len(runnable), "skip_count": len([row for row in rows if row.get("decision") == "skip"])},
    )
    return runnable, rows, str(artifact.relative_to(writer.run_dir))


def build_probe_ai_safe_summary(
    normalized_snapshot: dict[str, dict[str, Any]],
    *,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    snapshot = normalized_snapshot.get("snapshot", {})
    return {
        "tenant_name": snapshot.get("tenant_name"),
        "run_id": snapshot.get("run_id"),
        "capability_count": snapshot.get("capability_count", 0),
        "toolchain_count": snapshot.get("toolchain_count", 0),
        "blocker_count": snapshot.get("blocker_count", 0),
        "status_counts": snapshot.get("status_counts", {}),
        "findings_count": len(findings),
    }


def finalize_probe_run(
    *,
    writer: Any,
    cfg: Any,
    requested_surfaces: list[str],
    capability_matrix: list[dict[str, Any]],
    toolchain_rows: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    normalized_snapshot: dict[str, dict[str, Any]],
    capability_path: Path,
    toolchain_path: Path,
    auth_context_path: Path | None,
    command_line: list[str],
    auth_mode: str,
    auth_path: str,
    session_context: dict[str, Any],
    lab_guard_state: str,
) -> int:
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe("probe_summary", build_probe_ai_safe_summary(normalized_snapshot, findings=findings))
    live_readiness = build_live_readiness_summary(
        selected_collectors=requested_surfaces,
        capability_rows=capability_matrix,
    )
    live_readiness_path = writer.write_json_artifact("live-readiness.json", live_readiness)

    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "capability-matrix.json",
        "toolchain-readiness.json",
        "live-readiness.json",
    ]
    if auth_context_path is not None:
        evidence_paths.append("auth-context.json")
    if blockers:
        evidence_paths.append("blockers/blockers.json")
    if findings:
        evidence_paths.append("findings/findings.json")
    evidence_paths.extend(f"normalized/{name}.json" for name in normalized_snapshot)
    evidence_paths.extend(["ai_context.json", "validation.json"])
    overall_status = "partial" if blockers else "ok"
    privacy = build_privacy_block(safe_for_external_llm=False)
    evidence_index = {"artifacts": sorted(set(writer.artifact_paths() + ["run-manifest.json", "summary.json", "summary.md"]))}
    evidence_index_path = writer.write_json_artifact("evidence-index.json", evidence_index)
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=cfg.tenant_name,
            tenant_id=cfg.tenant_id,
            executed_by="auditex_probe",
            selected_collectors=requested_surfaces,
            overall_status=overall_status,
            duration_seconds=0,
            mode=auth_mode,
            auditor_profile=cfg.auditor_profile,
            plane="inventory",
            findings=findings,
            blockers=blockers,
            evidence_paths=evidence_paths,
            normalized_snapshot=normalized_snapshot,
            capability_rows=capability_matrix,
            coverage_ledger=[],
            privacy=privacy,
            bundle_metadata={
                "since": cfg.since,
                "until": cfg.until,
                "session_context": session_context,
                "command_line": command_line,
                "probe_mode": cfg.mode,
                "probe_surface": cfg.surface,
                "capability_matrix_path": str(capability_path.relative_to(writer.run_dir)),
                "toolchain_readiness_path": str(toolchain_path.relative_to(writer.run_dir)),
                "live_readiness_path": str(live_readiness_path.relative_to(writer.run_dir)),
                "evidence_index_path": str(evidence_index_path.relative_to(writer.run_dir)),
                "auth_path": auth_path,
                "auth_context_path": str(auth_context_path.relative_to(writer.run_dir)) if auth_context_path else None,
                "data_handling_events": [],
                "lab_guard_state": lab_guard_state,
                "platform": "m365",
            },
        ),
    )
    writer.log_event(
        "probe.completed",
        "Live capability probe completed",
        {"probe_mode": cfg.mode, "surface": cfg.surface, "blockers": len(blockers)},
    )
    return 1 if blockers else 0
