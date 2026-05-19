from __future__ import annotations

import argparse
import json
import importlib
import logging
import os
from typing import Any, Callable
import sys
import time
from pathlib import Path

from .auth_runtime import (
    acquire_azure_cli_access_token as _acquire_azure_cli_access_token,
    build_auth_context_payload as _build_auth_context_payload,
    capture_signed_in_context as _capture_signed_in_context,
    inspect_access_token as _inspect_access_token,
    scrub_command_line as _scrub_command_line,
)
from .collectors import REGISTRY
from .collector_runner import AuditWriterCollectorAdapter, CollectorRunContext, CollectorRunner
from .config import AuthConfig, CollectorConfig
from .diagnostics import build_diagnostics as _build_diagnostics, load_permission_hints as _load_permission_hints
from .findings import build_findings, build_report_pack
from .graph import GraphClient
from .normalize import build_ai_safe_summary, build_normalized_snapshot
from .output import AuditWriter
from .presets import load_collector_presets
from .profiles import get_profile, profile_choices
from .resources import resolve_resource_path
from .utils import load_env_file
from .ai_context import build_privacy_block
from .finalize import finalize_bundle_contract
from . import run as run_core

LOG = logging.getLogger("azure_tenant_audit")

PLANE_CHOICES = ("inventory", "full", "export")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Microsoft tenant audit collection.")
    parser.add_argument("--tenant-name", default="tenant", help="Label for the output folder.")
    parser.add_argument("--tenant-id", default=None, help="Entra tenant ID.")
    parser.add_argument("--client-id", default=None, help="App registration ID.")
    parser.add_argument("--client-secret", default=None, help="App secret.")
    parser.add_argument("--access-token", default=None, help="Optional preissued Graph access token.")
    parser.add_argument("--auth-context", default=None, help="Optional saved Auditex auth context name.")
    parser.add_argument(
        "--use-azure-cli-token",
        action="store_true",
        help="Use an existing Azure CLI Graph token if available (no app credentials required).",
    )
    parser.add_argument("--authority", default="https://login.microsoftonline.com/", help="Identity authority URL.")
    parser.add_argument("--graph-scope", default="https://graph.microsoft.com/.default", help="Graph scope.")
    parser.add_argument("--interactive", action="store_true", help="Use delegated browser login.")
    parser.add_argument("--scopes", default=None, help="Comma-separated delegated Graph scopes for interactive login.")
    parser.add_argument("--browser-command", default="firefox", help="Browser command used by interactive auth.")
    parser.add_argument("--out", default="audit-output", help="Base output directory.")
    parser.add_argument("--config", default="configs/collector-definitions.json", help="Collector configuration file.")
    parser.add_argument(
        "--collector-preset",
        default=None,
        help="Optional named collector preset from configs/collector-presets.json.",
    )
    parser.add_argument(
        "--waiver-file",
        default=None,
        help="Optional JSON waiver file for accepted findings.",
    )
    parser.add_argument("--collectors", default=None, help="Comma-separated collectors to run.")
    parser.add_argument("--exclude", default=None, help="Comma-separated collectors to skip.")
    parser.add_argument("--include-exchange", action="store_true", help="Enable optional exchange collectors.")
    parser.add_argument("--top", type=int, default=500, help="Per-endpoint result limit.")
    parser.add_argument("--page-size", type=int, default=100, help="Per-request page size for paged Graph endpoints.")
    parser.add_argument(
        "--throttle-mode",
        choices=("fast", "safe", "ultra-safe"),
        default="safe",
        help="Graph pacing mode used to reduce bursts and retry more carefully.",
    )
    parser.add_argument("--probe-first", dest="probe_first", action="store_true", default=False, help="Run a low-volume preflight before full collection.")
    parser.add_argument("--no-probe-first", dest="probe_first", action="store_false", help="Skip the low-volume preflight step.")
    parser.add_argument("--include-blocked", action="store_true", help="Run collectors even if preflight marks them as known blocked.")
    parser.add_argument("--run-name", default=None, help="Optional run subfolder identifier.")
    parser.add_argument(
        "--resume-from",
        default=None,
        help="Resume into an existing run directory and skip already completed collectors.",
    )
    parser.add_argument(
        "--plane",
        default="inventory",
        choices=PLANE_CHOICES,
        help="Run plane: inventory (default), full, or export. Full and export both run export collectors.",
    )
    parser.add_argument("--since", default=None, help="Optional ISO8601 lower bound for time-windowed collectors.")
    parser.add_argument("--until", default=None, help="Optional ISO8601 upper bound for time-windowed collectors.")
    parser.add_argument(
        "--auditor-profile",
        default="auto",
        choices=profile_choices(),
        help="Named audit profile for expected permission shape and escalation guidance.",
    )
    parser.add_argument("--offline", action="store_true", help="Use offline sample bundle.")
    parser.add_argument("--sample", default="examples/sample_audit_bundle/sample_result.json", help="Sample bundle path when offline.")
    parser.add_argument(
        "--permission-hints",
        default="configs/collector-permissions.json",
        help="Optional collector-permission matrix file for diagnostics.",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logs.")
    parser.add_argument("--env", default=None, help="Optional .env-like file to load.")
    return parser


def run_offline(
    sample_path: Path,
    out: Path,
    tenant_name: str,
    run_name: str | None,
    *,
    auditor_profile: str = "auto",
    plane: str = "inventory",
    since: str | None = None,
    until: str | None = None,
) -> int:
    sample_path = resolve_resource_path(sample_path)
    if not sample_path.exists():
        LOG.error("Sample file not found: %s", sample_path)
        return 2
    try:
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        LOG.error("Unable to load sample bundle: %s", exc)
        return 2

    writer = AuditWriter(out, tenant_name=tenant_name, run_name=run_name)
    writer.log_event(
        "run.started",
        "Offline run started",
        {
            "mode": "offline",
            "sample": str(sample_path),
            "auditor_profile": auditor_profile,
            "plane": plane,
            "since": since,
            "until": until,
        },
    )

    collector_payloads: dict[str, dict[str, Any]] = {}
    result_rows: list[dict[str, Any]] = []
    (writer.raw_dir / "sample_input.json").write_text(
        json.dumps(sample, indent=2),
        encoding="utf-8",
    )
    writer.record_artifact(writer.raw_dir / "sample_input.json")
    for key, value in sample.items():
        if isinstance(value, dict):
            collector_payloads[str(key)] = value
        row: dict[str, Any] = {
            "name": str(key),
            "status": "ok",
            "item_count": len(value.get("value", [])) if isinstance(value, dict) else 0,
            "message": "offline simulation",
            "coverage_rows": 0,
        }
        result_rows.append(row)
        writer.write_summary(row)
        writer.write_checkpoint(str(key), row)
        writer.log_event("collector.synthetic", "Offline collector simulated", {"name": key, "item_count": row["item_count"]})

    diagnostics: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    capability_rows = [
        {
            "collector": row["name"],
            "status": "offline_sample",
            "reason": "offline_bundle",
            "required_permissions": [],
            "missing_permissions": [],
            "observed_permissions": [],
            "delegated_roles": [],
            "minimum_role_hints": [],
            "notes": "Offline sample run; no tenant auth exercised.",
        }
        for row in result_rows
    ]
    coverage_ledger = run_core.build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    normalized_snapshot = build_normalized_snapshot(
        tenant_name=tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        run_dir=writer.run_dir,
    )
    findings = build_findings(diagnostics, normalized_snapshot=normalized_snapshot)
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe("run_summary", build_ai_safe_summary(normalized_snapshot, findings=findings))
    if findings:
        writer.write_findings(findings)

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
    evidence_paths.extend(f"normalized/{name}.json" for name in ["capability_matrix", "coverage_ledger", *normalized_snapshot.keys()])
    privacy = build_privacy_block(safe_for_external_llm=False)
    writer.write_report_pack(
        build_report_pack(
            tenant_name=tenant_name,
            overall_status="ok",
            findings=findings,
            evidence_paths=evidence_paths,
            blocker_count=0,
            privacy=privacy,
        )
    )
    finalize_bundle_contract(
        writer=writer,
        bundle_metadata={
            "executed_by": "azure_tenant_audit",
            "collectors": list(sample.keys()),
            "overall_status": "ok",
            "duration_seconds": 0,
            "mode": "offline",
            "auditor_profile": auditor_profile,
            "plane": plane,
            "since": since,
            "until": until,
            "command_line": [],
            "coverage_count": 0,
            "privacy": privacy,
        },
        run_metadata={
            "tenant_name": tenant_name,
            "tenant_id": None,
            "run_id": writer.run_id,
            "overall_status": "ok",
            "auditor_profile": auditor_profile,
            "mode": "offline",
            "plane": plane,
            "selected_collectors": list(sample.keys()),
            "duration_seconds": 0,
        },
        normalized_snapshot=normalized_snapshot,
        capability_rows=capability_rows,
        coverage_ledger=coverage_ledger,
        blockers=diagnostics,
        findings=findings,
    )
    LOG.info("Offline sample written to %s", writer.run_dir)
    return 0


def run_live(args: argparse.Namespace, event_listener: Callable[[dict[str, Any]], None] | None = None) -> int:
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    saved_auth_context: dict[str, Any] | None = None
    if args.auth_context:
        saved_auth_context = importlib.import_module("auditex.auth").resolve_auth_context(args.auth_context)
        args.access_token = args.access_token or saved_auth_context.get("token")
        args.tenant_id = args.tenant_id or saved_auth_context.get("tenant_id")

    try:
        config = CollectorConfig.from_path(Path(args.config))
        permission_hints = _load_permission_hints(Path(args.permission_hints))
        plan = run_core.build_live_run_plan(
            args,
            output_dir=out,
            collector_config=config,
            permission_hints=permission_hints,
            profile=get_profile(args.auditor_profile),
            collector_presets=load_collector_presets(),
        )
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    run_cfg = plan.run_config
    selected = plan.selected_collectors
    execution_plane = plan.execution_plane
    auth_scopes = plan.auth_scopes

    resume_from = Path(args.resume_from).expanduser().resolve() if args.resume_from else None
    writer = AuditWriter(
        run_cfg.output_dir,
        run_cfg.tenant_name,
        run_name=run_cfg.run_name,
        run_dir=resume_from,
        event_listener=event_listener,
    )
    completed_state = writer.load_checkpoint_state() if resume_from else {}
    completed_collectors = {
        name
        for name, state in completed_state.get("collectors", {}).items()
        if state.get("status") in {"ok", "partial", "skipped"}
    }
    collector_checkpoint_state = writer.load_collector_checkpoint_state() if resume_from else {}
    operation_checkpoint_state = writer.load_operation_checkpoint_state() if resume_from else {}
    if resume_from:
        writer.log_event(
            "run.resume",
            "Resuming from existing run state",
            {
                "resume_from": str(resume_from),
                "checkpoint_entries": len(completed_state.get("collectors", {})),
                "completed_collectors": sorted(completed_collectors),
            },
        )

    if args.use_azure_cli_token:
        if not args.access_token:
            try:
                args.access_token = _acquire_azure_cli_access_token(args.tenant_id, log_event=writer.log_event)
                writer.log_event(
                    "auth.cli.token.selected",
                    "Using Azure CLI cached token for Graph authentication.",
                    {"tenant_id": args.tenant_id or "organizations"},
                )
                LOG.info("Using Azure CLI cached Graph token.")
            except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                writer.log_event(
                    "auth.cli.token.rejected",
                    "Azure CLI token could not be used.",
                    {"tenant_id": args.tenant_id or "organizations", "error": str(exc)},
                )
                LOG.error("Unable to use Azure CLI token: %s", exc)
                return 2

    has_token_source = bool(args.access_token or args.use_azure_cli_token)
    if args.interactive and not args.client_id and not has_token_source:
        LOG.warning(
            "Interactive mode requested without --client-id. Falling back to Azure CLI token mode. "
            "Run `az login` first; this avoids creating an app registration."
        )
        args.interactive = False
        args.use_azure_cli_token = True
        has_token_source = True
    if not args.interactive and not has_token_source:
        if not args.client_id:
            LOG.error("client-id is required for app authentication.")
            return 2
        if not args.client_secret:
            LOG.error("client-id and client-secret are required for app auth. Use --interactive or --use-azure-cli-token.")
            return 2
        if not args.tenant_id:
            LOG.error("tenant-id is required for app authentication.")
            return 2
    if args.interactive and not args.tenant_id:
        args.tenant_id = "organizations"

    tenant_id = args.tenant_id or "organizations"

    auth_mode = "interactive" if args.interactive else "azure_cli" if args.use_azure_cli_token else "access_token" if args.access_token else "app"

    auth = AuthConfig(
        tenant_id=tenant_id,
        client_id=args.client_id,
        auth_mode=auth_mode,
        client_secret=args.client_secret,
        access_token=args.access_token,
        authority=args.authority,
        graph_scope=args.graph_scope,
        interactive_scopes=auth_scopes,
        throttle_mode=args.throttle_mode,
    )
    client = GraphClient(auth, audit_event=writer.log_event)
    session_context: dict[str, Any] = {}
    if auth_mode in {"azure_cli", "interactive"}:
        session_context = _capture_signed_in_context(client, log_event=writer.log_event)
    token_claims: dict[str, Any] = {}
    if args.access_token:
        try:
            token_claims = _inspect_access_token(args.access_token)
        except Exception as exc:  # noqa: BLE001
            writer.log_event(
                "auth.token.inspect_failed",
                "Access token could not be decoded locally.",
                {"error": str(exc)},
            )
            token_claims = {}
    elif hasattr(client, "token_claims"):
        token_claims = client.token_claims()
    auth_context_payload = _build_auth_context_payload(
        auth_mode=auth_mode,
        tenant_id=tenant_id,
        token_claims=token_claims,
        session_context=session_context,
        saved_context=saved_auth_context,
    )
    capability_rows = run_core.build_capability_matrix_rows(
        auth_context=auth_context_payload,
        selected_collectors=selected,
        auditor_profile=run_cfg.auditor_profile,
        collector_config=config,
        permission_hints=permission_hints,
    )
    selected_before_preflight = list(selected)
    preflight_rows: list[dict[str, Any]] = []
    preflight_path: str | None = None
    if args.probe_first:
        selected, preflight_rows, preflight_path = run_core.run_preflight_probe(
            selected_collectors=selected_before_preflight,
            completed_collectors=completed_collectors,
            client=client,
            run_cfg=run_cfg,
            writer=writer,
            include_blocked=args.include_blocked,
            registry=REGISTRY,
        )
        if not selected:
            writer.log_event(
                "run.aborted",
                "No runnable collectors remained after preflight.",
                {"preflight_path": preflight_path},
            )
            writer.write_bundle(
                {
                    "executed_by": "azure_tenant_audit",
                    "collectors": [],
                    "overall_status": "partial",
                    "duration_seconds": 0,
                    "mode": auth_mode,
                    "auditor_profile": run_cfg.auditor_profile,
                    "plane": run_cfg.plane,
                    "since": run_cfg.since,
                    "until": run_cfg.until,
                    "session_context": session_context,
                    "command_line": _scrub_command_line(list(getattr(args, "_command_line", sys.argv))),
                    "coverage_count": 0,
                    "throttle_mode": args.throttle_mode,
                    "preflight_path": preflight_path,
                }
            )
            return 1
    command_line = _scrub_command_line(list(getattr(args, "_command_line", sys.argv)))
    writer.log_event(
        "run.started",
        "Live run started",
        {
            "tenant_id": args.tenant_id,
            "collectors": selected,
            "top": run_cfg.top_items,
            "page_size": run_cfg.page_size,
            "include_exchange": args.include_exchange,
            "mode": auth_mode,
            "auditor_profile": run_cfg.auditor_profile,
            "plane": run_cfg.plane,
            "since": run_cfg.since,
            "until": run_cfg.until,
            "session_context": session_context,
            "auth_context": auth_context_payload,
            "command_line": command_line,
            "throttle_mode": args.throttle_mode,
            "preflight_path": preflight_path,
        },
    )
    start = time.time()
    result_rows: list[dict[str, object]] = []
    failures = 0
    summary_rows: list[dict[str, object]] = []
    coverage_rows: list[dict[str, Any]] = list(writer.coverage) if resume_from else []
    collector_payloads: dict[str, dict[str, Any]] = {}
    preflight_skipped = {
        row["collector"]: row
        for row in preflight_rows
        if row.get("decision") == "skip" and row.get("collector")
    }
    collector_pause_seconds = run_core.collector_pause_seconds(args.throttle_mode)
    writer_adapter = AuditWriterCollectorAdapter(writer)
    collector_runner = CollectorRunner(writer_adapter)

    for name, skip in preflight_skipped.items():
        skip_row: dict[str, object] = {
            "name": name,
            "status": "skipped",
            "item_count": 0,
            "message": "Collector skipped after preflight marked it as known blocked.",
            "error": skip.get("error"),
            "coverage_rows": 0,
        }
        result_rows.append(skip_row)
        summary_rows.append(skip_row)
        writer.write_checkpoint(name, skip_row)
        writer.log_event(
            "collector.skipped",
            "Collector skipped after preflight",
            {
                "collector": name,
                "reason": skip.get("reason"),
            },
        )

    for name in selected:
        collector = REGISTRY.get(name)
        if collector is None:
            LOG.warning("Unknown collector requested: %s", name)
            continue

        if resume_from and name in completed_collectors:
            previous_state = collector_checkpoint_state.get(name, {})
            skipped_row: dict[str, object] = {
                "name": name,
                "status": "skipped",
                "item_count": previous_state.get("item_count", 0),
                "message": "Collector skipped due to checkpoint resume.",
                "error": None,
                "coverage_rows": 0,
            }
            result_rows.append(skipped_row)
            existing_payload = writer._safe_load_json(writer.raw_dir / f"{name}.json")
            if isinstance(existing_payload, dict):
                collector_payloads[name] = existing_payload
            writer.log_event(
                "collector.skipped",
                "Collector skipped",
                {
                    "collector": name,
                    "resume_from": str(resume_from),
                    "previous_status": previous_state.get("status"),
                    "item_count": previous_state.get("item_count", 0),
                },
            )
            continue

        output = collector_runner.run(
            collector,
            CollectorRunContext(
                client=client,
                top=run_cfg.top_items,
                page_size=run_cfg.page_size,
                plane=execution_plane,
                since=run_cfg.since,
                until=run_cfg.until,
                collector_checkpoint_state=collector_checkpoint_state.get(name, {}),
                operation_checkpoint_state=operation_checkpoint_state.get(name, {}),
                hooks=writer_adapter.hooks(),
            ),
            name=name,
        )
        coverage_rows.extend(output.coverage_rows)
        if output.result.status != "ok":
            failures += 1
        if output.result.error:
            LOG.warning("%s collector error: %s", name, output.result.error)
        collector_payloads[name] = output.result.payload
        result_rows.append(dict(output.result_row))
        summary_rows.append(result_rows[-1])

        if collector_pause_seconds > 0:
            writer.log_event(
                "run.collector.pause",
                "Pausing before next collector",
                {"collector": name, "delay_seconds": collector_pause_seconds},
            )
            time.sleep(collector_pause_seconds)

    duration = round(time.time() - start, 2)
    for row in summary_rows:
        writer.write_summary(row)
    diagnostics = _build_diagnostics(
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        permission_hints=permission_hints,
        auditor_profile=run_cfg.auditor_profile,
    )
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
        writer.log_event(
            "run.diagnostics.generated",
            "Failure diagnostics generated",
            {"count": len(diagnostics)},
        )
    coverage_ledger = run_core.build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    capability_rows = run_core.reconcile_capability_matrix_rows(capability_rows, result_rows)
    normalized_snapshot = build_normalized_snapshot(
        tenant_name=run_cfg.tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        run_dir=writer.run_dir,
    )
    findings = build_findings(
        diagnostics,
        normalized_snapshot=normalized_snapshot,
        waiver_file=args.waiver_file,
    )
    writer.write_normalized("auth_context", auth_context_payload)
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    if findings:
        writer.write_findings(findings)
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe("run_summary", build_ai_safe_summary(normalized_snapshot, findings=findings))
    evidence_paths = ["run-manifest.json", "summary.json"]
    if coverage_rows:
        evidence_paths.append("coverage.json")
    if diagnostics:
        evidence_paths.append("blockers/blockers.json")
    if findings:
        evidence_paths.append("findings/findings.json")
    evidence_paths.extend(f"normalized/{name}.json" for name in normalized_snapshot)
    evidence_paths.extend(["ai_context.json", "validation.json"])
    overall_status = "partial" if failures or preflight_skipped else "ok"
    privacy = build_privacy_block(safe_for_external_llm=False)
    report_pack = build_report_pack(
        tenant_name=run_cfg.tenant_name,
        overall_status=overall_status,
        findings=findings,
        evidence_paths=evidence_paths,
        blocker_count=len(diagnostics),
        privacy=privacy,
    )
    writer.write_report_pack(report_pack)
    writer.log_event(
        "run.complete",
        "Live run completed",
        {"failures": failures, "collectors": len(result_rows), "coverage_rows": len(coverage_rows)},
    )
    finalize_bundle_contract(
        writer=writer,
        bundle_metadata={
            "executed_by": "azure_tenant_audit",
            "collectors": selected,
            "overall_status": overall_status,
            "duration_seconds": duration,
            "mode": auth_mode,
            "auditor_profile": run_cfg.auditor_profile,
            "plane": run_cfg.plane,
            "collector_preset": args.collector_preset,
            "waiver_path": args.waiver_file,
            "since": run_cfg.since,
            "until": run_cfg.until,
            "session_context": session_context,
            "auth_context_path": "normalized/auth_context.json",
            "capability_matrix_path": "normalized/capability_matrix.json",
            "coverage_ledger_path": "normalized/coverage_ledger.json",
            "command_line": command_line,
            "coverage_count": len(coverage_rows),
            "throttle_mode": args.throttle_mode,
            "preflight_path": preflight_path,
            "privacy": privacy,
        },
        run_metadata={
            "tenant_name": run_cfg.tenant_name,
            "tenant_id": args.tenant_id,
            "run_id": writer.run_id,
            "overall_status": overall_status,
            "auditor_profile": run_cfg.auditor_profile,
            "mode": auth_mode,
            "plane": run_cfg.plane,
            "selected_collectors": selected,
            "duration_seconds": duration,
        },
        normalized_snapshot=normalized_snapshot,
        capability_rows=capability_rows,
        coverage_ledger=coverage_ledger,
        blockers=diagnostics,
        findings=findings,
    )
    LOG.info("Completed in %.2fs. Output in %s", duration, writer.run_dir)
    return 1 if failures or preflight_skipped else 0


def main(argv: list[str] | None = None, event_listener: Callable[[dict[str, Any]], None] | None = None) -> int:
    parser = build_parser()
    parsed_argv = list(argv if argv is not None else sys.argv[1:])
    args = parser.parse_args(parsed_argv)
    args._command_line = ["azure-tenant-audit", *parsed_argv]
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    if args.env:
        load_env_file(Path(args.env))

    args.tenant_id = args.tenant_id or None
    args.client_id = args.client_id or None
    args.client_secret = args.client_secret or None
    args.access_token = args.access_token or None

    if args.tenant_id is None:
        args.tenant_id = __import__("os").environ.get("AZURE_TENANT_ID")
    if args.client_id is None:
        args.client_id = __import__("os").environ.get("AZURE_CLIENT_ID")
    if args.client_secret is None:
        args.client_secret = __import__("os").environ.get("AZURE_CLIENT_SECRET")
    if args.access_token is None and __import__("os").environ.get("AZURE_ACCESS_TOKEN") is not None:
        LOG.warning(
            "Ignoring AZURE_ACCESS_TOKEN environment variable. "
            "Pass --access-token explicitly or use a saved auth context."
        )
    if args.authority is None:
        args.authority = __import__("os").environ.get("AZURE_AUTHORITY", args.authority)
    if args.graph_scope is None:
        args.graph_scope = __import__("os").environ.get("AZURE_GRAPH_SCOPE", args.graph_scope)
    if args.interactive and args.browser_command:
        os.environ["BROWSER"] = args.browser_command
    if args.scopes:
        args.scopes = args.scopes.strip()
    if args.offline:
        return run_offline(
            Path(args.sample),
            Path(args.out),
            args.tenant_name,
            args.run_name,
            auditor_profile=args.auditor_profile,
            plane=args.plane,
            since=args.since,
            until=args.until,
        )
    return run_live(args, event_listener=event_listener)


if __name__ == "__main__":
    raise SystemExit(main())
