from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .finalize import finalize_bundle_contract
from .findings import build_report_pack


PROVIDER_ADAPTER_VERSION = "2026-05-31"
API_INVENTORY_RECORDER_VERSION = "2026-05-31"


def _optional_fixture_provenance(bundle_metadata: dict[str, Any]) -> dict[str, Any] | None:
    fixture_provenance = bundle_metadata.get("fixture_provenance")
    return dict(fixture_provenance) if isinstance(fixture_provenance, dict) else None


@dataclass(frozen=True)
class ProviderFinalizePlan:
    tenant_name: str
    tenant_id: str | None
    executed_by: str
    selected_collectors: list[str]
    overall_status: str
    duration_seconds: float | int
    mode: str
    auditor_profile: str
    plane: str
    findings: list[dict[str, Any]]
    blockers: list[dict[str, Any]]
    evidence_paths: list[str]
    normalized_snapshot: dict[str, dict[str, Any]]
    capability_rows: list[dict[str, Any]]
    coverage_ledger: list[dict[str, Any]]
    privacy: dict[str, Any]
    bundle_metadata: dict[str, Any] = field(default_factory=dict)
    run_metadata: dict[str, Any] = field(default_factory=dict)


def write_provider_bundle(*, writer: Any, plan: ProviderFinalizePlan) -> None:
    report_pack = build_report_pack(
        tenant_name=plan.tenant_name,
        overall_status=plan.overall_status,
        findings=plan.findings,
        evidence_paths=plan.evidence_paths,
        blocker_count=len(plan.blockers),
        privacy=plan.privacy,
    )
    fixture_provenance = _optional_fixture_provenance(plan.bundle_metadata)
    if fixture_provenance:
        report_pack["fixture_provenance"] = fixture_provenance
    writer.write_report_pack(report_pack)
    finalize_bundle_contract(
        writer=writer,
        bundle_metadata={
            **plan.bundle_metadata,
            "executed_by": plan.executed_by,
            "collectors": plan.selected_collectors,
            "overall_status": plan.overall_status,
            "duration_seconds": plan.duration_seconds,
            "mode": plan.mode,
            "auditor_profile": plan.auditor_profile,
            "plane": plan.plane,
            "privacy": plan.privacy,
            "provider_adapter_version": PROVIDER_ADAPTER_VERSION,
            "api_inventory_recorder_version": API_INVENTORY_RECORDER_VERSION,
        },
        run_metadata={
            **plan.run_metadata,
            "tenant_name": plan.tenant_name,
            "tenant_id": plan.tenant_id,
            "run_id": writer.run_id,
            "overall_status": plan.overall_status,
            "auditor_profile": plan.auditor_profile,
            "mode": plan.mode,
            "plane": plan.plane,
            "selected_collectors": plan.selected_collectors,
            "duration_seconds": plan.duration_seconds,
        },
        normalized_snapshot=plan.normalized_snapshot,
        capability_rows=plan.capability_rows,
        coverage_ledger=plan.coverage_ledger,
        blockers=plan.blockers,
        findings=plan.findings,
    )
