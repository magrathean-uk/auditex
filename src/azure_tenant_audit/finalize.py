from __future__ import annotations

from pathlib import Path
from typing import Any

from .ai_context import build_ai_context, build_privacy_block, build_validation_report
from .api_inventory import build_api_call_inventory
from .assurance import build_coverage_gap_summary, build_live_readiness_summary, build_surface_coverage_map
from .autopilot import build_audit_autopilot_plan
from .contracts import CONTRACT_VERSION
from .data_handling import build_data_handling_summary
from .evidence_db import build_run_evidence_index
from .output import AuditWriter


def _append_report_evidence_path(writer: AuditWriter, relative_path: str) -> None:
    report_path = writer.run_dir / "reports" / "report-pack.json"
    try:
        report_pack = writer._safe_load_json(report_path)
    except AttributeError:
        return
    if not isinstance(report_pack, dict):
        return
    evidence_paths = report_pack.get("evidence_paths")
    if not isinstance(evidence_paths, list):
        return
    if relative_path in evidence_paths:
        return
    report_pack["evidence_paths"] = [*evidence_paths, relative_path]
    writer.write_report_pack(report_pack)


def _auth_scopes_from_capabilities(capability_rows: list[dict[str, Any]]) -> list[str]:
    scopes: set[str] = set()
    for row in capability_rows:
        if not isinstance(row, dict):
            continue
        for key in ("required_permissions", "observed_permissions"):
            values = row.get(key)
            if isinstance(values, list):
                scopes.update(str(item) for item in values if str(item))
    return sorted(scopes)


def _collector_descriptions(platform: str) -> dict[str, str]:
    if platform == "google_workspace":
        try:
            from auditex.google_workspace.collectors import REGISTRY as google_registry
        except Exception:  # noqa: BLE001
            return {}
        return {
            str(name): str(getattr(collector, "description", ""))
            for name, collector in google_registry.items()
        }
    try:
        from .config import CollectorConfig
    except Exception:  # noqa: BLE001
        return {}
    try:
        config = CollectorConfig.from_path("configs/collector-definitions.json")
    except Exception:  # noqa: BLE001
        return {}
    return {name: definition.description for name, definition in config.collectors.items()}


def _apply_audit_plan_to_report_pack(writer: AuditWriter, audit_plan: dict[str, Any]) -> None:
    report_path = writer.run_dir / "reports" / "report-pack.json"
    try:
        report_pack = writer._safe_load_json(report_path)
    except AttributeError:
        return
    if not isinstance(report_pack, dict):
        return
    summary = report_pack.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    quality_gate = audit_plan.get("quality_gate") if isinstance(audit_plan.get("quality_gate"), dict) else {}
    summary["autopilot_quality"] = quality_gate
    report_pack["summary"] = summary
    report_pack["audit_plan"] = audit_plan
    writer.write_report_pack(report_pack)


def finalize_bundle_contract(
    *,
    writer: AuditWriter,
    bundle_metadata: dict[str, Any],
    run_metadata: dict[str, Any],
    normalized_snapshot: dict[str, Any],
    capability_rows: list[dict[str, Any]],
    coverage_ledger: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Write the stable post-run contract artifacts through one path.

    The manifest must exist before the evidence DB and validation can be checked against
    it, so this function writes a suppressed manifest snapshot first, builds the DB,
    writes ai_context/validation, then writes the final manifest.
    """

    privacy = bundle_metadata.get("privacy") or build_privacy_block(safe_for_external_llm=False)
    metadata = dict(bundle_metadata)
    selected_collectors = [str(item) for item in run_metadata.get("selected_collectors") or metadata.get("collectors") or [] if str(item)]
    if not metadata.get("data_handling_path"):
        data_handling_payload = build_data_handling_summary(
            platform=str(metadata.get("platform") or run_metadata.get("platform") or "m365"),
            mode=str(metadata.get("mode") or run_metadata.get("mode") or ""),
            plane=str(metadata.get("plane") or run_metadata.get("plane") or ""),
            collectors=selected_collectors,
            auth_scopes=_auth_scopes_from_capabilities(capability_rows),
            events=metadata.get("data_handling_events") if isinstance(metadata.get("data_handling_events"), list) else [],
            response_execute=bool(metadata.get("response_execute")),
            response_allow_write=bool(metadata.get("response_allow_write")),
        )
        data_handling_path = writer.write_json_artifact("data-handling.json", data_handling_payload)
        metadata["data_handling_path"] = str(data_handling_path.relative_to(writer.run_dir))
        _append_report_evidence_path(writer, metadata["data_handling_path"])
    else:
        data_handling_payload = writer._safe_load_json(writer.run_dir / str(metadata["data_handling_path"]))
        if not isinstance(data_handling_payload, dict):
            data_handling_payload = {}
    if not metadata.get("live_readiness_path") and capability_rows and metadata.get("mode") != "offline":
        live_readiness_path = writer.write_json_artifact(
            "live-readiness.json",
            build_live_readiness_summary(
                selected_collectors=selected_collectors,
                capability_rows=capability_rows,
                dependency_available=True,
            ),
        )
        metadata["live_readiness_path"] = str(live_readiness_path.relative_to(writer.run_dir))
        _append_report_evidence_path(writer, metadata["live_readiness_path"])
    platform = str(metadata.get("platform") or run_metadata.get("platform") or "m365")
    collector_rows = [dict(row) for row in writer.summary.get("collectors", []) if isinstance(row, dict)]
    coverage_rows = [dict(row) for row in writer.coverage if isinstance(row, dict)]
    surface_coverage = build_surface_coverage_map(collector_rows=collector_rows, platform=platform)
    computed_coverage_gaps = build_coverage_gap_summary(
        surface_coverage=surface_coverage,
        collector_rows=collector_rows,
        coverage_rows=coverage_rows,
    )
    audit_plan = build_audit_autopilot_plan(
        platform=platform,
        selected_collectors=selected_collectors,
        capability_rows=capability_rows,
        coverage_gaps=computed_coverage_gaps,
        blockers=blockers,
        findings=findings,
    )
    audit_plan_path = writer.write_json_artifact("audit-plan.json", audit_plan)
    metadata["audit_plan_path"] = str(audit_plan_path.relative_to(writer.run_dir))
    metadata["autopilot_quality"] = audit_plan.get("quality_gate", {})
    _append_report_evidence_path(writer, metadata["audit_plan_path"])
    if not metadata.get("api_inventory_path"):
        api_inventory_path = writer.write_json_artifact(
            "api-inventory.json",
            build_api_call_inventory(
                platform=platform,
                selected_collectors=selected_collectors,
                capability_rows=capability_rows,
                coverage_rows=[dict(row) for row in writer.coverage if isinstance(row, dict)] or coverage_ledger,
                data_handling=data_handling_payload,
                collector_descriptions=_collector_descriptions(platform),
            ),
        )
        metadata["api_inventory_path"] = str(api_inventory_path.relative_to(writer.run_dir))
        _append_report_evidence_path(writer, metadata["api_inventory_path"])
    metadata.update(
        {
            "privacy": privacy,
            "ai_context_path": "ai_context.json",
            "validation_path": "validation.json",
            "evidence_db_path": "index/evidence.sqlite",
            "schema_contract_version": CONTRACT_VERSION,
        }
    )

    # Pre-register the artifacts finalize is about to create so the suppressed
    # manifest write (and the evidence DB rebuild that reads it) sees the same
    # artifacts list on the first finalize call as it does on a re-finalize of
    # the same bundle. Without this the first call writes 22 artifacts and the
    # second writes 25, breaking idempotent re-finalize.
    for relative in ("index/evidence.sqlite", "ai_context.json", "validation.json"):
        writer.record_artifact(writer.run_dir / relative)

    writer.write_bundle({**metadata, "_suppress_completion_log": True})
    evidence_db_path = build_run_evidence_index(writer.run_dir)
    writer.record_artifact(evidence_db_path)

    ai_context = build_ai_context(
        run_dir=writer.run_dir,
        run_metadata=run_metadata,
        normalized_snapshot=normalized_snapshot,
        capability_rows=capability_rows,
        coverage_ledger=coverage_ledger,
        blockers=blockers,
        findings=findings,
    )
    writer.write_json_artifact("ai_context.json", ai_context)
    validation = build_validation_report(run_dir=writer.run_dir, ai_context=ai_context, findings=findings)
    writer.write_json_artifact("validation.json", validation)
    writer.log_event(
        "contract.validation.passed" if validation.get("valid") else "contract.validation.failed",
        "Bundle contract validation passed" if validation.get("valid") else "Bundle contract validation failed",
        {
            "contract_version": validation.get("contract_version"),
            "valid": validation.get("valid"),
            "issue_count": validation.get("issue_count", 0),
            "error_count": validation.get("error_count", 0),
        },
    )

    final_metadata = dict(metadata)
    final_metadata["contract_status"] = "valid" if validation.get("valid") else "invalid"
    final_metadata["contract_issue_count"] = validation.get("issue_count", 0)
    writer.write_bundle(final_metadata)
    _apply_audit_plan_to_report_pack(writer, audit_plan)

    # Rebuild the evidence DB once the final manifest (with contract_status /
    # contract_issue_count) is on disk so run_meta carries the final values.
    # build_run_evidence_index is idempotent (DROP TABLE / CREATE TABLE on each
    # call) so this second pass is safe and keeps re-finalise byte-stable.
    build_run_evidence_index(writer.run_dir)

    return {
        "evidence_db_path": str(Path(evidence_db_path).relative_to(writer.run_dir)),
        "ai_context_path": "ai_context.json",
        "validation_path": "validation.json",
        "validation": validation,
    }
