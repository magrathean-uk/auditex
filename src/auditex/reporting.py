from __future__ import annotations

import csv
import hashlib
import html
import json
import shutil
from collections.abc import Iterable, Mapping
from io import StringIO
from pathlib import Path
from typing import Any

from azure_tenant_audit.autopilot import build_basic_license_intelligence
from azure_tenant_audit.resources import resolve_resource_path

from .run_bundle import RunBundle

DEFAULT_SECTION_REGISTRY_PATH = Path("configs/report-sections.json")
FORMAT_EXTENSIONS = {
    "json": ".json",
    "md": ".md",
    "csv": ".csv",
    "html": ".html",
    "sarif": ".sarif.json",
    "oscal": ".oscal.json",
}

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
    "informational": "none",
}
AUDITEX_SARIF_TOOL_URI = "https://github.com/magrathean-uk/auditex"
AUDITEX_OSCAL_NS = "https://magrathean.uk/auditex/oscal"

_SECTION_ORDER = (
    "summary",
    "executive_summary",
    "technical_appendix",
    "limitations",
    "next_actions",
    "license_profile",
    "auditor_score",
    "attack_paths",
    "control_simulator",
    "report_qa",
    "findings",
    "proof_table",
    "action_plan",
    "api_inventory",
    "normalized",
    "blockers",
    "replay_context",
    "manifest",
)
_CSV_COLUMNS = (
    "id",
    "title",
    "severity",
    "status",
    "rule_id",
    "collector",
    "affected_objects",
    "impact",
    "remediation",
    "expected_value",
)
# Severity ordering used for deterministic CSV row sort (highest first).
# Anything outside this set sorts after ``info`` to keep the order stable.
_SEVERITY_RANK: Mapping[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return fallback


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _provider_platform(summary: Mapping[str, Any], manifest: Mapping[str, Any]) -> str:
    platform = _text(manifest.get("platform") or summary.get("platform") or "m365").strip()
    return platform or "m365"


def _provider_label(platform: str) -> str:
    labels = {
        "m365": "Microsoft 365",
        "microsoft_365": "Microsoft 365",
        "entra": "Microsoft 365",
        "google_workspace": "Google Workspace",
    }
    return labels.get(platform, platform.replace("_", " ").title())


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _relative_source(path: Path, run_path: Path) -> str:
    try:
        return str(path.relative_to(run_path))
    except ValueError:
        return str(path)


def load_section_registry(path: Path | None = None) -> list[dict[str, Any]]:
    payload = _mapping(_read_json(resolve_resource_path(path or DEFAULT_SECTION_REGISTRY_PATH), {}))
    rows = payload.get("sections")
    if not isinstance(rows, list):
        return []

    registry: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        section_id = _text(item.get("id")).strip()
        if not section_id or section_id in seen:
            continue
        seen.add(section_id)
        registry.append(
            {
                "id": section_id,
                "title": _text(item.get("title"), section_id).strip() or section_id,
                "description": _text(item.get("description")).strip(),
            }
        )
    return registry


def _load_normalized_sections(run_path: Path) -> dict[str, Any]:
    normalized_dir = run_path / "normalized"
    if not normalized_dir.is_dir():
        return {}

    sections: dict[str, Any] = {}
    for path in sorted(normalized_dir.glob("*.json"), key=lambda item: item.name):
        payload = _read_json(path, {})
        if payload not in ({}, [], None):
            sections[path.stem] = payload
    return sections


def load_report_bundle(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    manifest = bundle.manifest()
    fallback_summary = bundle.summary()
    summary = bundle.report_summary()
    live_readiness = _mapping(bundle.live_readiness()[1])
    if live_readiness:
        summary = {**summary, "live_readiness": live_readiness}

    _, report_pack = bundle.report_pack()
    report_pack = _mapping(report_pack)
    sections = {
        "summary": summary,
        "findings": bundle.finding_rows(),
        "proof_table": bundle.proof_table_rows(),
        "action_plan": bundle.action_plan_rows(),
        "api_inventory": _mapping(bundle.api_inventory()[1]),
        "normalized": _load_normalized_sections(run_path),
        "blockers": bundle.blocker_rows(),
        "manifest": manifest,
    }
    for key in (
        "executive_summary",
        "technical_appendix",
        "limitations",
        "next_actions",
        "license_profile",
        "auditor_score",
        "attack_paths",
        "control_simulator",
        "report_qa",
        "replay_context",
    ):
        if key in report_pack:
            sections[key] = report_pack[key]
    return {"run_dir": str(run_path), "manifest": manifest, "summary_json": fallback_summary, "sections": sections}


def analyze_report(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    manifest = bundle.manifest()
    report_summary = bundle.report_summary()
    _, report_pack_payload = bundle.report_pack()
    report_pack = _mapping(report_pack_payload)
    findings = bundle.finding_rows()
    evidence_paths = report_pack.get("evidence_paths")
    if not isinstance(evidence_paths, list):
        evidence_paths = [str(item) for item in manifest.get("artifacts") or [] if str(item)]
    coverage_gaps = report_pack.get("limitations") or report_summary.get("coverage_gaps") or manifest.get("coverage_gaps") or []
    intelligence = build_basic_license_intelligence(
        tenant_name=str(report_summary.get("tenant_name") or manifest.get("tenant_name") or ""),
        platform=str(manifest.get("platform") or report_summary.get("platform") or "m365"),
        overall_status=str(report_summary.get("overall_status") or manifest.get("overall_status") or "unknown"),
        findings=findings,
        evidence_paths=[str(item) for item in evidence_paths],
        coverage_gaps=[dict(item) for item in coverage_gaps if isinstance(item, Mapping)] if isinstance(coverage_gaps, list) else [],
    )
    return {
        "run_dir": str(run_path),
        **intelligence,
    }


def api_call_inventory(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    path, payload = bundle.api_inventory()
    inventory = _mapping(payload)
    return {
        "run_dir": str(run_path),
        "api_inventory_path": str(path) if path is not None else str(bundle.path("api-inventory.json")),
        "present": path is not None,
        **inventory,
    }


def permissions_ledger(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    api = api_call_inventory(run_path)
    _, audit_plan_payload = bundle.audit_plan()
    audit_plan = _mapping(audit_plan_payload)
    declared = {
        _text(row.get("collector")): row
        for row in _dict_rows(api.get("declared_collectors"))
        if _text(row.get("collector"))
    }
    gates = {
        _text(row.get("collector")): row
        for row in _dict_rows(audit_plan.get("evidence_gates"))
        if _text(row.get("collector"))
    }
    collectors = sorted(set(declared) | set(gates))
    rows: list[dict[str, Any]] = []
    required_permissions: set[str] = set()
    missing_permissions: set[str] = set()
    for collector in collectors:
        declaration = declared.get(collector, {})
        gate = gates.get(collector, {})
        required = [str(item) for item in (gate.get("required_permissions") or declaration.get("required_permissions") or []) if str(item)]
        observed = [str(item) for item in declaration.get("observed_permissions") or gate.get("observed_permissions") or [] if str(item)]
        missing = [str(item) for item in (gate.get("missing_permissions") or declaration.get("missing_permissions") or []) if str(item)]
        required_permissions.update(required)
        missing_permissions.update(missing)
        rows.append(
            {
                "collector": collector,
                "description": declaration.get("description"),
                "status": gate.get("status") or declaration.get("status"),
                "reason": gate.get("reason") or declaration.get("reason"),
                "required_permissions": required,
                "observed_permissions": observed,
                "missing_permissions": missing,
                "observed_call_count": declaration.get("observed_call_count", 0),
                "blocker_kind": gate.get("blocker_kind"),
                "blocker_reason": gate.get("blocker_reason"),
                "next_step": gate.get("next_step"),
            }
        )
    return {
        "run_dir": str(run_path),
        "platform": api.get("platform") or audit_plan.get("platform") or bundle.metadata().get("platform"),
        "api_inventory_path": api.get("api_inventory_path"),
        "audit_plan_path": str(bundle.audit_plan()[0]) if bundle.audit_plan()[0] is not None else str(bundle.path("audit-plan.json")),
        "counts": {
            "collectors": len(rows),
            "required_permissions": len(required_permissions),
            "missing_permissions": len(missing_permissions),
            "collectors_with_missing_permissions": sum(1 for row in rows if row["missing_permissions"]),
        },
        "required_permissions": sorted(required_permissions),
        "missing_permissions": sorted(missing_permissions),
        "collectors": rows,
    }


def proof_table(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    path, report_pack_payload = bundle.report_pack()
    report_pack = _mapping(report_pack_payload)
    rows = bundle.proof_table_rows()
    findings = bundle.finding_rows()
    counts: dict[str, int] = {
        "findings": len(findings),
        "proof_rows": len(rows),
        "supported": 0,
        "missing_evidence": 0,
        "unsupported": 0,
    }
    unsupported_claims: list[str] = []
    for row in rows:
        status = _text(row.get("proof_status"), "unsupported") or "unsupported"
        if status in counts:
            counts[status] += 1
        finding_id = _text(row.get("finding_id") or row.get("id"))
        if status != "supported" and finding_id:
            unsupported_claims.append(finding_id)
    return {
        "run_dir": str(run_path),
        "report_pack_path": str(path) if path is not None else str(bundle.path("reports/report-pack.json")),
        "present": path is not None,
        "summary": bundle.report_summary(),
        "counts": counts,
        "unsupported_claims": sorted(set(unsupported_claims)),
        "evidence_paths": [str(item) for item in report_pack.get("evidence_paths") or [] if str(item)],
        "proof_table": rows,
    }


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _artifact_row(run_path: Path, relative: str, purpose: str, *, customer_safe: bool = True) -> dict[str, Any]:
    path = run_path / relative
    return {
        "path": relative,
        "present": path.exists(),
        "purpose": purpose,
        "customer_safe": customer_safe,
        "sha256": _sha256_file(path) if path.exists() else None,
    }


def enterprise_handoff(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    manifest = bundle.manifest()
    summary = bundle.report_summary()
    metadata = bundle.metadata()
    validation_path, validation_payload = bundle.validation()
    validation = _mapping(validation_payload)
    data_handling_path, data_handling_payload = bundle.data_handling()
    data_handling = _mapping(data_handling_payload)
    api = api_call_inventory(run_path)
    proof = proof_table(run_path)
    live_readiness_path, live_readiness_payload = bundle.live_readiness()
    live_readiness = _mapping(live_readiness_payload)
    audit_plan_path, audit_plan_payload = bundle.audit_plan()
    audit_plan = _mapping(audit_plan_payload)
    report_pack_path, _ = bundle.report_pack()
    blockers = bundle.blocker_rows()
    coverage_gaps = _dict_rows(summary.get("coverage_gaps")) or _dict_rows(metadata.get("coverage_gaps"))
    api_safety = _mapping(api.get("safety"))
    proof_counts = _mapping(proof.get("counts"))

    validation_valid = validation.get("valid") if validation else None
    read_only = data_handling.get("read_only") is not False and api_safety.get("read_only") is not False
    no_content_reads = data_handling.get("content_reads") is not True and api_safety.get("no_content_reads") is not False
    write_actions = data_handling.get("write_actions") is True or api_safety.get("write_actions") is True
    unsupported_claims = [str(item) for item in proof.get("unsupported_claims") or [] if str(item)]

    if validation_valid is False or not read_only or not no_content_reads or write_actions:
        status = "unusable"
    elif validation_valid is None or not api.get("present") or not proof.get("present"):
        status = "incomplete"
    elif coverage_gaps or blockers or unsupported_claims:
        status = "ready_with_limitations"
    else:
        status = "ready"

    data_handling_relative = str(manifest.get("data_handling_path") or "data-handling.json")
    api_relative = str(manifest.get("api_inventory_path") or "api-inventory.json")
    audit_plan_relative = str(manifest.get("audit_plan_path") or "audit-plan.json")
    live_readiness_relative = str(manifest.get("live_readiness_path") or "live-readiness.json")
    report_pack_relative = str(manifest.get("report_pack_path") or "reports/report-pack.json")
    validation_relative = str(manifest.get("validation_path") or "validation.json")
    artifacts = [
        _artifact_row(run_path, "run-manifest.json", "Run identity, selected collectors, contract status, and artifact paths."),
        _artifact_row(run_path, "summary.json", "Top-level run summary and collector status."),
        _artifact_row(run_path, data_handling_relative, "Read-only, no-content-read, write-action, and scope-risk declaration."),
        _artifact_row(run_path, api_relative, "Endpoint-level API call ledger and safety classification."),
        _artifact_row(run_path, audit_plan_relative, "Expected collectors, scope gates, blockers, and quality gate."),
        _artifact_row(run_path, live_readiness_relative, "Trusted and untrusted collector surfaces with blocker summary."),
        _artifact_row(run_path, report_pack_relative, "Executive report pack, findings, proof table, limitations, and QA."),
        _artifact_row(run_path, "findings/findings.json", "Raw finding register with evidence refs."),
        _artifact_row(run_path, "ai_context.json", "AI-safe bundle context and artifact index."),
        _artifact_row(run_path, "index/evidence.sqlite", "Indexed normalized evidence for replay and lookup."),
        _artifact_row(run_path, validation_relative, "Bundle contract validation result."),
    ]

    return {
        "run_dir": str(run_path),
        "handoff_status": status,
        "tenant": {
            "name": summary.get("tenant_name") or manifest.get("tenant_name"),
            "id": manifest.get("tenant_id"),
            "platform": manifest.get("platform") or summary.get("platform") or "m365",
            "run_id": manifest.get("run_id") or summary.get("run_id"),
            "created_utc": manifest.get("created_utc") or summary.get("created_utc"),
        },
        "contract": {
            "valid": validation_valid,
            "issue_count": validation.get("issue_count"),
            "error_count": validation.get("error_count"),
            "warning_count": validation.get("warning_count"),
            "path": str(validation_path) if validation_path is not None else str(run_path / validation_relative),
        },
        "safety": {
            "read_only": read_only,
            "no_content_reads": no_content_reads,
            "write_actions": write_actions,
            "scope_risk": data_handling.get("scope_risk") or api_safety.get("scope_risk"),
            "write_capable_scopes": data_handling.get("write_capable_scopes") or api_safety.get("write_capable_scopes") or [],
        },
        "quality": {
            "audit_plan_status": _mapping(audit_plan.get("quality_gate")).get("status"),
            "live_readiness": live_readiness.get("trust_level"),
            "coverage_gap_count": len(coverage_gaps),
            "blocker_count": len(blockers),
            "unsupported_claim_count": len(unsupported_claims),
        },
        "counts": {
            "findings": int(proof_counts.get("findings") or len(bundle.finding_rows())),
            "proof_rows": int(proof_counts.get("proof_rows") or 0),
            "supported_proof_rows": int(proof_counts.get("supported") or 0),
            "api_calls": int(_mapping(api.get("counts")).get("observed_calls") or len(_dict_rows(api.get("observed_calls")))),
        },
        "artifacts": artifacts,
        "review_commands": {
            "render_report": f"auditex report render {run_path} --format md",
            "api_calls": f"auditex report api-calls {run_path} --format md",
            "proof_table": f"auditex report proof-table {run_path} --format md",
            "handoff": f"auditex report handoff {run_path} --format md",
        },
        "limitations": coverage_gaps,
        "blockers": blockers,
        "unsupported_claims": unsupported_claims,
    }


def render_api_call_inventory_markdown(inventory: Mapping[str, Any]) -> str:
    calls = _dict_rows(inventory.get("observed_calls"))
    counts = _mapping(inventory.get("counts"))
    safety = _mapping(inventory.get("safety"))
    lines = [
        "# Auditex API Call Inventory",
        "",
        f"- Run: {_markdown_cell(inventory.get('run_dir'))}",
        f"- Platform: {_markdown_cell(inventory.get('platform'))}",
        f"- Observed calls: {_markdown_cell(counts.get('observed_calls', len(calls)))}",
        f"- Read-only: {_markdown_cell(safety.get('read_only'))}",
        f"- No content reads: {_markdown_cell(safety.get('no_content_reads'))}",
        "",
        "| Collector | Method | Endpoint | Status | Items | Data class |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    if calls:
        for call in calls:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(call.get("collector")),
                        _markdown_cell(call.get("method")),
                        _markdown_cell(call.get("endpoint")),
                        _markdown_cell(call.get("status")),
                        _markdown_cell(call.get("item_count")),
                        _markdown_cell(call.get("data_class")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  |  | No observed calls in this bundle. |  |  |  |")
    return "\n".join(lines) + "\n"


def render_permissions_ledger_markdown(payload: Mapping[str, Any]) -> str:
    rows = _dict_rows(payload.get("collectors"))
    counts = _mapping(payload.get("counts"))
    lines = [
        "# Auditex Permission Ledger",
        "",
        f"- Run: {_markdown_cell(payload.get('run_dir'))}",
        f"- Platform: {_markdown_cell(payload.get('platform'))}",
        f"- Collectors: {_markdown_cell(counts.get('collectors', len(rows)))}",
        f"- Required permissions: {_markdown_cell(counts.get('required_permissions', 0))}",
        f"- Missing permissions: {_markdown_cell(counts.get('missing_permissions', 0))}",
        "",
        "| Collector | Status | Required | Observed | Missing | Calls | Next step |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if rows:
        for row in rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("collector")),
                        _markdown_cell(row.get("status")),
                        _markdown_cell(", ".join(str(item) for item in row.get("required_permissions") or [])),
                        _markdown_cell(", ".join(str(item) for item in row.get("observed_permissions") or [])),
                        _markdown_cell(", ".join(str(item) for item in row.get("missing_permissions") or [])),
                        _markdown_cell(row.get("observed_call_count")),
                        _markdown_cell(row.get("next_step")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  |  |  |  | No permission rows in this bundle. |  |  |")
    return "\n".join(lines) + "\n"


def render_enterprise_handoff_markdown(payload: Mapping[str, Any]) -> str:
    tenant = _mapping(payload.get("tenant"))
    contract = _mapping(payload.get("contract"))
    safety = _mapping(payload.get("safety"))
    quality = _mapping(payload.get("quality"))
    counts = _mapping(payload.get("counts"))
    commands = _mapping(payload.get("review_commands"))
    artifacts = _dict_rows(payload.get("artifacts"))
    lines = [
        "# Auditex Enterprise Handoff",
        "",
        f"- Run: {_markdown_cell(payload.get('run_dir'))}",
        f"- Status: {_markdown_cell(payload.get('handoff_status'))}",
        f"- Tenant: {_markdown_cell(tenant.get('name'))}",
        f"- Platform: {_markdown_cell(tenant.get('platform'))}",
        f"- Contract valid: {_markdown_cell(contract.get('valid'))}",
        f"- Read-only: {_markdown_cell(safety.get('read_only'))}",
        f"- No content reads: {_markdown_cell(safety.get('no_content_reads'))}",
        f"- Audit quality: {_markdown_cell(quality.get('audit_plan_status'))}",
        f"- Live readiness: {_markdown_cell(quality.get('live_readiness'))}",
        f"- Findings: {_markdown_cell(counts.get('findings'))}",
        f"- Proof rows: {_markdown_cell(counts.get('proof_rows'))}",
        f"- API calls: {_markdown_cell(counts.get('api_calls'))}",
        "",
        "## Review Commands",
        "",
    ]
    for key in ("render_report", "api_calls", "proof_table", "handoff"):
        if commands.get(key):
            lines.append(f"- `{_markdown_cell(commands.get(key))}`")
    lines.extend(
        [
            "",
            "## Review Artifacts",
            "",
            "| Path | Present | Purpose | SHA-256 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for artifact in artifacts:
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_cell(artifact.get("path")),
                    _markdown_cell(artifact.get("present")),
                    _markdown_cell(artifact.get("purpose")),
                    _markdown_cell(artifact.get("sha256")),
                ]
            )
            + " |"
        )
    limitations = _dict_rows(payload.get("limitations"))
    if limitations:
        lines.extend(["", "## Limitations", ""])
        for item in limitations:
            lines.append(f"- {_markdown_cell(item.get('surface'))}: {_markdown_cell(item.get('message') or item.get('status'))}")
    blockers = _dict_rows(payload.get("blockers"))
    if blockers:
        lines.extend(["", "## Blockers", ""])
        for item in blockers:
            lines.append(f"- {_markdown_cell(item.get('collector') or item.get('id') or 'blocker')}: {_markdown_cell(item.get('message') or item.get('error') or item.get('reason'))}")
    return "\n".join(lines) + "\n"


def render_proof_table_markdown(payload: Mapping[str, Any]) -> str:
    rows = _dict_rows(payload.get("proof_table"))
    counts = _mapping(payload.get("counts"))
    lines = [
        "# Auditex Proof Table",
        "",
        f"- Run: {_markdown_cell(payload.get('run_dir'))}",
        f"- Report pack: {_markdown_cell(payload.get('report_pack_path'))}",
        f"- Findings: {_markdown_cell(counts.get('findings', 0))}",
        f"- Proof rows: {_markdown_cell(counts.get('proof_rows', len(rows)))}",
        f"- Supported rows: {_markdown_cell(counts.get('supported', 0))}",
        f"- Missing evidence rows: {_markdown_cell(counts.get('missing_evidence', 0))}",
        "",
        "| Finding | Rule | Proof | Collector | Artifact | Record | Pointer |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if rows:
        for row in rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("finding_id") or row.get("id")),
                        _markdown_cell(row.get("rule_id")),
                        _markdown_cell(row.get("proof_status")),
                        _markdown_cell(row.get("collector")),
                        _markdown_cell(row.get("artifact_path")),
                        _markdown_cell(row.get("record_key")),
                        _markdown_cell(row.get("json_pointer")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  |  | No proof rows in this bundle. |  |  |  |  |")
    return "\n".join(lines) + "\n"


def _write_text_artifact(path: Path, content: str) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return {
        "path": str(path),
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
    }


_CUSTOMER_SAFE_SOURCE_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("run-manifest.json", "Run identity, selected collectors, contract status, and artifact paths."),
    ("summary.json", "Top-level run summary and collector status."),
    ("data-handling.json", "Read-only, no-content-read, write-action, and scope-risk declaration."),
    ("api-inventory.json", "Endpoint-level API call ledger and safety classification."),
    ("audit-plan.json", "Expected collectors, scope gates, blockers, and quality gate."),
    ("live-readiness.json", "Trusted and untrusted collector surfaces with blocker summary."),
    ("reports/report-pack.json", "Executive report pack, findings, proof table, limitations, and QA."),
    ("validation.json", "Bundle contract validation result."),
    ("ai_context.json", "AI-safe bundle context and artifact index."),
)


def _copy_source_artifact(run_path: Path, output_root: Path, relative: str, purpose: str) -> dict[str, Any]:
    source = run_path / relative
    destination = output_root / relative
    row: dict[str, Any] = {
        "source_path": relative,
        "purpose": purpose,
        "present": source.exists(),
        "customer_safe": True,
    }
    if not source.exists():
        return row
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    row.update(
        {
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256": _sha256_file(destination),
        }
    )
    return row


def _pack_relative(pack_dir: Path, path: str | Path) -> str:
    try:
        return str(Path(path).relative_to(pack_dir))
    except ValueError:
        return str(path)


def _pack_file_path(pack_dir: Path, manifest_output_dir: Path, value: Any) -> Path | None:
    if not value:
        return None
    path = Path(str(value))
    if path.is_absolute():
        try:
            return pack_dir / path.relative_to(manifest_output_dir)
        except ValueError:
            return path
    try:
        return pack_dir / path.relative_to(manifest_output_dir)
    except ValueError:
        pass
    return pack_dir / path


def _render_pack_readme(manifest: Mapping[str, Any]) -> str:
    source = _mapping(manifest.get("source"))
    tenant = _mapping(source.get("tenant"))
    safety = _mapping(source.get("safety"))
    quality = _mapping(source.get("quality"))
    counts = _mapping(source.get("counts"))
    generated = _dict_rows(manifest.get("generated_files"))
    sources = _dict_rows(manifest.get("source_artifacts"))
    lines = [
        "# Auditex Customer Pack",
        "",
        f"- Status: {_markdown_cell(manifest.get('handoff_status'))}",
        f"- Tenant: {_markdown_cell(tenant.get('name'))}",
        f"- Platform: {_markdown_cell(tenant.get('platform'))}",
        f"- Read-only: {_markdown_cell(safety.get('read_only'))}",
        f"- No content reads: {_markdown_cell(safety.get('no_content_reads'))}",
        f"- Audit quality: {_markdown_cell(quality.get('audit_plan_status'))}",
        f"- Findings: {_markdown_cell(counts.get('findings'))}",
        f"- API calls: {_markdown_cell(counts.get('api_calls'))}",
        "",
        "## Start Here",
        "",
        "1. Read `handoff.md`.",
        "2. Review `report.md` for the client-ready report.",
        "3. Review `api-calls.md` for every observed API call.",
        "4. Review `permissions.md` for required and missing scopes.",
        "5. Review `proof-table.md` for finding-to-evidence rows.",
        "6. Run `auditex report verify-pack <pack-dir>` or use `checksums.sha256` to verify file integrity.",
        "",
        "## Generated Files",
        "",
        "| File | SHA-256 |",
        "| --- | --- |",
    ]
    pack_dir = Path(str(manifest.get("output_dir") or "."))
    for row in generated:
        lines.append(f"| {_markdown_cell(_pack_relative(pack_dir, row.get('path')))} | {_markdown_cell(row.get('sha256'))} |")
    lines.extend(["", "## Source Artifacts", "", "| File | Present | SHA-256 | Purpose |", "| --- | --- | --- | --- |"])
    for row in sources:
        file_path = row.get("path") or row.get("source_path")
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_cell(_pack_relative(pack_dir, file_path)),
                    _markdown_cell(row.get("present")),
                    _markdown_cell(row.get("sha256")),
                    _markdown_cell(row.get("purpose")),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def _write_checksums(pack_dir: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    lines = []
    for row in rows:
        digest = row.get("sha256")
        path = row.get("path")
        if digest and path:
            lines.append(f"{digest}  {_pack_relative(pack_dir, path)}")
    lines.sort()
    return _write_text_artifact(pack_dir / "checksums.sha256", "\n".join(lines) + ("\n" if lines else ""))


def write_enterprise_handoff_pack(run_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    handoff_payload = enterprise_handoff(run_path)
    api_payload = api_call_inventory(run_path)
    permissions_payload = permissions_ledger(run_path)
    proof_payload = proof_table(run_path)
    rendered_report = preview_report(run_dir=str(run_path), format_name="md")["content"]

    generated = [
        _write_text_artifact(target_dir / "handoff.md", render_enterprise_handoff_markdown(handoff_payload)),
        _write_text_artifact(target_dir / "handoff.json", _json(handoff_payload) + "\n"),
        _write_text_artifact(target_dir / "report.md", rendered_report),
        _write_text_artifact(target_dir / "api-calls.md", render_api_call_inventory_markdown(api_payload)),
        _write_text_artifact(target_dir / "api-calls.json", _json(api_payload) + "\n"),
        _write_text_artifact(target_dir / "permissions.md", render_permissions_ledger_markdown(permissions_payload)),
        _write_text_artifact(target_dir / "permissions.json", _json(permissions_payload) + "\n"),
        _write_text_artifact(target_dir / "proof-table.md", render_proof_table_markdown(proof_payload)),
        _write_text_artifact(target_dir / "proof-table.json", _json(proof_payload) + "\n"),
    ]
    source_dir = target_dir / "source-artifacts"
    source_artifacts = [
        _copy_source_artifact(run_path, source_dir, relative, purpose)
        for relative, purpose in _CUSTOMER_SAFE_SOURCE_ARTIFACTS
    ]
    manifest = {
        "schema_version": "2026-04-21",
        "kind": "auditex_enterprise_handoff_pack",
        "run_dir": str(run_path),
        "output_dir": str(target_dir),
        "handoff_status": handoff_payload.get("handoff_status"),
        "source": {
            "tenant": handoff_payload.get("tenant"),
            "contract": handoff_payload.get("contract"),
            "safety": handoff_payload.get("safety"),
            "quality": handoff_payload.get("quality"),
                "counts": handoff_payload.get("counts"),
                "permissions": {
                    "counts": permissions_payload.get("counts"),
                    "missing_permissions": permissions_payload.get("missing_permissions"),
                },
            },
        "generated_files": generated,
        "source_artifacts": source_artifacts,
    }
    readme = _write_text_artifact(target_dir / "README.md", _render_pack_readme(manifest))
    manifest["generated_files"].append(readme)
    checksum = _write_checksums(
        target_dir,
        [*manifest["generated_files"], *[row for row in source_artifacts if row.get("present")]],
    )
    manifest["generated_files"].append(checksum)
    manifest_path = target_dir / "pack-manifest.json"
    manifest["pack_manifest_path"] = str(manifest_path)
    manifest_path.write_text(_json(manifest) + "\n", encoding="utf-8")
    return manifest


def verify_enterprise_handoff_pack(pack_dir: str | Path) -> dict[str, Any]:
    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack-manifest.json"
    manifest = _mapping(_read_json(manifest_path, {}))
    issues: list[dict[str, Any]] = []
    checked_files: set[str] = set()

    def add_issue(code: str, message: str, **details: Any) -> None:
        issue = {"code": code, "message": message}
        issue.update({key: value for key, value in details.items() if value is not None})
        issues.append(issue)

    def check_file(path: Path | None, expected: str | None, *, source: str) -> None:
        if path is None:
            add_issue("missing_path", "Manifest row has no file path.", source=source)
            return
        checked_files.add(str(path))
        if not path.exists():
            add_issue("missing_file", "Expected pack file is missing.", path=str(path), source=source)
            return
        if not expected:
            add_issue("missing_expected_hash", "Expected SHA-256 is missing.", path=str(path), source=source)
            return
        actual = _sha256_file(path)
        if actual != expected:
            add_issue(
                "checksum_mismatch",
                "Pack file SHA-256 does not match the manifest.",
                path=str(path),
                expected=expected,
                actual=actual,
                source=source,
            )

    if not manifest_path.exists():
        add_issue("missing_pack_manifest", "pack-manifest.json is missing.", path=str(manifest_path))
    elif not manifest:
        add_issue("invalid_pack_manifest", "pack-manifest.json is not valid JSON.", path=str(manifest_path))
    elif manifest.get("kind") != "auditex_enterprise_handoff_pack":
        add_issue(
            "invalid_pack_kind",
            "pack-manifest.json is not an Auditex enterprise handoff pack.",
            path=str(manifest_path),
            kind=manifest.get("kind"),
        )

    manifest_output_dir = Path(str(manifest.get("output_dir") or pack_path))
    generated = _dict_rows(manifest.get("generated_files"))
    sources = _dict_rows(manifest.get("source_artifacts"))

    for row in generated:
        check_file(
            _pack_file_path(pack_path, manifest_output_dir, row.get("path")),
            _text(row.get("sha256")) or None,
            source=f"manifest.generated:{row.get('name') or row.get('path')}",
        )

    for row in sources:
        if row.get("present") is False:
            continue
        check_file(
            _pack_file_path(pack_path, manifest_output_dir, row.get("path")),
            _text(row.get("sha256")) or None,
            source=f"manifest.source:{row.get('source_path') or row.get('path')}",
        )

    checksum_path = pack_path / "checksums.sha256"
    checksum_line_count = 0
    if not checksum_path.exists():
        add_issue("missing_checksum_file", "checksums.sha256 is missing.", path=str(checksum_path))
    else:
        for line_number, line in enumerate(checksum_path.read_text(encoding="utf-8").splitlines(), start=1):
            text = line.strip()
            if not text:
                continue
            checksum_line_count += 1
            parts = text.split(None, 1)
            if len(parts) != 2:
                add_issue(
                    "invalid_checksum_line",
                    "checksums.sha256 line is not '<sha256>  <path>'.",
                    path=str(checksum_path),
                    line=line_number,
                )
                continue
            expected, relative = parts[0], parts[1].strip()
            relative_path = Path(relative)
            if relative_path.is_absolute():
                add_issue(
                    "absolute_checksum_path",
                    "checksums.sha256 must use paths relative to the pack directory.",
                    path=relative,
                    line=line_number,
                )
                continue
            candidate = (pack_path / relative_path).resolve()
            try:
                candidate.relative_to(pack_path.resolve())
            except ValueError:
                add_issue(
                    "checksum_path_outside_pack",
                    "checksums.sha256 references a path outside the pack directory.",
                    path=relative,
                    line=line_number,
                )
                continue
            check_file(candidate, expected, source=f"checksums.sha256:{line_number}")

    return {
        "pack_dir": str(pack_path),
        "pack_manifest_path": str(manifest_path),
        "valid": not issues,
        "issue_count": len(issues),
        "checked_file_count": len(checked_files),
        "checksum_line_count": checksum_line_count,
        "generated_file_count": len(generated),
        "source_artifact_count": len(sources),
        "issues": issues,
    }


def _select_sections(
    bundle: dict[str, Any],
    *,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
) -> dict[str, Any]:
    sections = _mapping(bundle.get("sections"))
    if include_sections is None:
        include = [key for key in _SECTION_ORDER if key in sections]
        include.extend(key for key in sections if key not in include)
    else:
        include = list(include_sections)
    blocked = set(exclude_sections or [])

    selected: dict[str, Any] = {}
    for key in include:
        if key in sections and key not in blocked:
            selected[key] = sections[key]
    return selected


def _default_output_path(run_path: Path, format_name: str) -> Path:
    return run_path / "reports" / f"rendered-report{FORMAT_EXTENSIONS[format_name]}"


def _render_json(selected_sections: dict[str, Any]) -> str:
    # D5 contract: 2-space indent, sort_keys (via _json), trailing newline so
    # POSIX tools (sha256sum, diff, git) treat the file as line-terminated and
    # downstream concatenation doesn't run files together.
    return _json({"sections": selected_sections}) + "\n"


def _markdown_cell(value: Any) -> str:
    return _text(value, "").replace("|", "\\|").replace("\n", " ").strip()


def _markdown_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return _markdown_cell(json.dumps(value, sort_keys=True, default=str))
    return _markdown_cell(value)


def _append_mapping_markdown(lines: list[str], title: str, payload: Mapping[str, Any]) -> None:
    if not payload:
        return
    lines.extend(["", f"## {title}", "", "| Field | Value |", "| --- | --- |"])
    for key in sorted(payload):
        lines.append(f"| {_markdown_cell(key)} | {_markdown_value(payload[key])} |")


def _append_rows_markdown(
    lines: list[str],
    title: str,
    rows: list[dict[str, Any]],
    columns: tuple[tuple[str, str], ...],
) -> None:
    lines.extend(["", f"## {title}", ""])
    headers = [header for header, _ in columns]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in columns) + " |")
    if not rows:
        lines.append("| " + " | ".join(["No rows", *("" for _ in columns[1:])]) + " |")
        return
    for row in rows:
        lines.append("| " + " | ".join(_markdown_value(row.get(field)) for _, field in columns) + " |")


def _render_markdown(selected_sections: dict[str, Any]) -> str:
    summary = _mapping(selected_sections.get("summary"))
    findings = _dict_rows(selected_sections.get("findings"))
    proof_rows = _dict_rows(selected_sections.get("proof_table"))
    risk = _mapping(summary.get("risk"))
    assurance = _mapping(summary.get("assurance"))
    provider_scorecard = _mapping(summary.get("provider_scorecard"))
    live_readiness = _mapping(summary.get("live_readiness"))
    api_inventory = _mapping(selected_sections.get("api_inventory"))
    api_calls = _dict_rows(api_inventory.get("observed_calls"))
    surface_coverage = _dict_rows(summary.get("surface_coverage"))
    coverage_gaps = _dict_rows(summary.get("coverage_gaps"))

    lines = [
        "# Auditex Report",
        "",
        f"- Tenant: {_text(summary.get('tenant_name'), 'unknown')}",
        f"- Status: {_text(summary.get('overall_status'), 'unknown')}",
        f"- Findings: {_text(summary.get('finding_count'), str(len(findings)))}",
        f"- Open: {_text(summary.get('open_count'), '0')}",
        f"- Risk: {_text(risk.get('grade'), 'unknown')} / {_text(risk.get('score'), '0')}",
        f"- Assurance: {_text(assurance.get('grade'), 'unknown')} / {_text(assurance.get('score'), '0')}",
        f"- Scorecard: {_text(provider_scorecard.get('grade'), 'unknown')} / {_text(provider_scorecard.get('score'), '0')}",
    ]
    if live_readiness:
        lines.append(f"- Live readiness: {_text(live_readiness.get('trust_level'), 'unknown')}")
        cannot_trust = live_readiness.get("cannot_trust") or []
        if cannot_trust:
            lines.append("- Cannot trust: " + ", ".join(_text(item) for item in cannot_trust[:5]))
    lines.append("")
    if surface_coverage:
        lines.append("- Coverage: " + ", ".join(f"{_text(row.get('surface'))}: {_text(row.get('status'))}" for row in surface_coverage))
        lines.append("")
    _append_mapping_markdown(lines, "Executive Summary", _mapping(selected_sections.get("executive_summary")))
    _append_mapping_markdown(lines, "Technical Appendix", _mapping(selected_sections.get("technical_appendix")))
    if "limitations" in selected_sections:
        _append_rows_markdown(
            lines,
            "Limitations",
            _dict_rows(selected_sections.get("limitations")),
            (("Surface", "surface"), ("Status", "status"), ("Message", "message"), ("Collectors", "collectors")),
        )
    if "next_actions" in selected_sections:
        _append_rows_markdown(
            lines,
            "Next Actions",
            _dict_rows(selected_sections.get("next_actions")),
            (("ID", "id"), ("Severity", "severity"), ("Title", "title"), ("Remediation", "remediation")),
        )
    _append_mapping_markdown(lines, "License Profile", _mapping(selected_sections.get("license_profile")))
    _append_mapping_markdown(lines, "Auditor Score", _mapping(selected_sections.get("auditor_score")))
    if "attack_paths" in selected_sections:
        _append_rows_markdown(
            lines,
            "Attack Paths",
            _dict_rows(selected_sections.get("attack_paths")),
            (("ID", "id"), ("Severity", "severity"), ("Summary", "summary"), ("Stages", "stage_count")),
        )
    _append_mapping_markdown(lines, "Control Simulator", _mapping(selected_sections.get("control_simulator")))
    _append_mapping_markdown(lines, "Report QA", _mapping(selected_sections.get("report_qa")))
    if coverage_gaps:
        lines.extend(["## Coverage Gaps", ""])
        for gap in coverage_gaps:
            error_classes = ", ".join(_text(item) for item in gap.get("error_classes") or [])
            detail = f" ({error_classes})" if error_classes else ""
            lines.append(f"- {_markdown_cell(gap.get('severity'))}: {_markdown_cell(gap.get('message'))}{_markdown_cell(detail)}")
        lines.append("")
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| ID | Rule | Severity | Status | Title | Impact | Remediation |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    if findings:
        for row in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("id")),
                        _markdown_cell(row.get("rule_id")),
                        _markdown_cell(row.get("severity")),
                        _markdown_cell(row.get("status")),
                        _markdown_cell(row.get("title")),
                        _markdown_cell(row.get("impact")),
                        _markdown_cell(row.get("remediation")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  |  |  |  | No findings in the selected report sections. |  |  |")

    if "proof_table" in selected_sections:
        lines.extend(
            [
                "",
                "## Proof Table",
                "",
                "| Finding | Rule | Proof | Collector | Artifact | Record | Pointer |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        if proof_rows:
            for row in proof_rows:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _markdown_cell(row.get("finding_id") or row.get("id")),
                            _markdown_cell(row.get("rule_id")),
                            _markdown_cell(row.get("proof_status")),
                            _markdown_cell(row.get("collector")),
                            _markdown_cell(row.get("artifact_path")),
                            _markdown_cell(row.get("record_key")),
                            _markdown_cell(row.get("json_pointer")),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("|  |  | No proof rows in this bundle. |  |  |  |  |")

    if api_inventory:
        safety = _mapping(api_inventory.get("safety"))
        counts = _mapping(api_inventory.get("counts"))
        lines.extend(
            [
                "",
                "## API Calls",
                "",
                f"- Observed calls: {_markdown_cell(counts.get('observed_calls', len(api_calls)))}",
                f"- Read-only: {_markdown_cell(safety.get('read_only'))}",
                f"- No content reads: {_markdown_cell(safety.get('no_content_reads'))}",
                "",
                "| Collector | Method | Endpoint | Status | Items | Data class |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        if api_calls:
            for call in api_calls:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _markdown_cell(call.get("collector")),
                            _markdown_cell(call.get("method")),
                            _markdown_cell(call.get("endpoint")),
                            _markdown_cell(call.get("status")),
                            _markdown_cell(call.get("item_count")),
                            _markdown_cell(call.get("data_class")),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("|  |  | No observed calls in this bundle. |  |  |  |")

    if "blockers" in selected_sections and _dict_rows(selected_sections.get("blockers")):
        lines.extend(["", "## Blockers", ""])
        for blocker in _dict_rows(selected_sections.get("blockers")):
            lines.append(f"- {_markdown_cell(blocker.get('collector') or blocker.get('id') or 'blocker')}: {_markdown_cell(blocker.get('message') or blocker.get('error'))}")
    _append_mapping_markdown(lines, "Replay Context", _mapping(selected_sections.get("replay_context")))

    return "\n".join(lines) + "\n"


def _csv_sort_key(row: Mapping[str, Any]) -> tuple:
    """Deterministic sort key for CSV rows.

    Severity desc (critical → high → medium → low → info → unknown), then
    rule_id, then record_key (from the first evidence_ref), then id. This
    keeps the CSV byte-stable across runs of the same input — D4
    contract.
    """
    severity = str(row.get("severity") or "").strip().lower()
    severity_rank = _SEVERITY_RANK.get(severity, 99)
    rule_id = str(row.get("rule_id") or "")
    record_key = ""
    refs = row.get("evidence_refs")
    if isinstance(refs, list) and refs:
        first = refs[0]
        if isinstance(first, Mapping):
            record_key = str(first.get("record_key") or "")
    finding_id = str(row.get("id") or "")
    return (severity_rank, rule_id, record_key, finding_id)


def _render_csv(selected_sections: dict[str, Any]) -> str:
    rows = _dict_rows(selected_sections.get("findings")) or _dict_rows(selected_sections.get("action_plan"))
    rows = sorted(rows, key=_csv_sort_key)
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_CSV_COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: _csv_value(row.get(column, "")) for column in _CSV_COLUMNS})
    return buffer.getvalue()


def _csv_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return _text(value, "")


def _html(value: Any) -> str:
    return html.escape(_text(value, ""), quote=True)


def _render_key_values(title: str, values: Mapping[str, Any]) -> str:
    rows = []
    for key in sorted(values):
        value = values[key]
        if isinstance(value, (dict, list)):
            value = _json(value)
        rows.append(f"<tr><th scope=\"row\">{_html(key)}</th><td>{_html(value)}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan=\"2\">No data</td></tr>")
    return f"<section><h2>{_html(title)}</h2><table><tbody>{''.join(rows)}</tbody></table></section>"


def _render_findings_table(title: str, rows: Iterable[Mapping[str, Any]]) -> str:
    body = []
    for item in rows:
        body.append(
            "<tr>"
            f"<td>{_html(item.get('id'))}</td>"
            f"<td>{_html(item.get('rule_id'))}</td>"
            f"<td>{_html(item.get('severity'))}</td>"
            f"<td>{_html(item.get('status'))}</td>"
            f"<td>{_html(item.get('title'))}</td>"
            f"<td>{_html(item.get('impact'))}</td>"
            f"<td>{_html(item.get('remediation'))}</td>"
            "</tr>"
        )
    if not body:
        body.append("<tr><td colspan=\"7\">No rows</td></tr>")
    return (
        f"<section><h2>{_html(title)}</h2>"
        "<table><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Status</th><th>Title</th><th>Impact</th><th>Remediation</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></section>"
    )


def _render_proof_table(rows: Iterable[Mapping[str, Any]]) -> str:
    body = []
    for item in rows:
        body.append(
            "<tr>"
            f"<td>{_html(item.get('finding_id') or item.get('id'))}</td>"
            f"<td>{_html(item.get('rule_id'))}</td>"
            f"<td>{_html(item.get('proof_status'))}</td>"
            f"<td>{_html(item.get('collector'))}</td>"
            f"<td>{_html(item.get('artifact_path'))}</td>"
            f"<td>{_html(item.get('record_key'))}</td>"
            f"<td>{_html(item.get('json_pointer'))}</td>"
            "</tr>"
        )
    if not body:
        body.append("<tr><td colspan=\"7\">No rows</td></tr>")
    return (
        "<section><h2>Proof Table</h2>"
        "<table><thead><tr><th>Finding</th><th>Rule</th><th>Proof</th><th>Collector</th><th>Artifact</th><th>Record</th><th>Pointer</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></section>"
    )


def _render_json_section(title: str, payload: Any) -> str:
    return f"<section><h2>{_html(title)}</h2><pre>{_html(_json(payload))}</pre></section>"


def _render_html(selected_sections: dict[str, Any]) -> str:
    summary = _mapping(selected_sections.get("summary"))
    sections = [
        "<!doctype html>",
        "<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Auditex Report</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;padding:.45rem;text-align:left;vertical-align:top}pre{white-space:pre-wrap;background:#f6f6f6;padding:1rem;overflow:auto}</style>",
        "</head><body>",
        "<h1>Auditex Report</h1>",
        f"<p><strong>Tenant:</strong> {_html(summary.get('tenant_name') or 'unknown')}</p>",
        f"<p><strong>Status:</strong> {_html(summary.get('overall_status') or 'unknown')}</p>",
    ]

    if "summary" in selected_sections:
        sections.append(_render_key_values("Summary", summary))
    for key, title in (
        ("executive_summary", "Executive Summary"),
        ("technical_appendix", "Technical Appendix"),
        ("license_profile", "License Profile"),
        ("auditor_score", "Auditor Score"),
        ("control_simulator", "Control Simulator"),
        ("report_qa", "Report QA"),
    ):
        if key in selected_sections:
            sections.append(_render_key_values(title, _mapping(selected_sections.get(key))))
    if "limitations" in selected_sections:
        sections.append(_render_json_section("Limitations", selected_sections.get("limitations")))
    if "next_actions" in selected_sections:
        sections.append(_render_findings_table("Next Actions", _dict_rows(selected_sections.get("next_actions"))))
    if "attack_paths" in selected_sections:
        sections.append(_render_json_section("Attack Paths", selected_sections.get("attack_paths")))
    if "findings" in selected_sections:
        sections.append(_render_findings_table("Findings", _dict_rows(selected_sections.get("findings"))))
    if "proof_table" in selected_sections:
        sections.append(_render_proof_table(_dict_rows(selected_sections.get("proof_table"))))
    if "action_plan" in selected_sections:
        sections.append(_render_findings_table("Action Plan", _dict_rows(selected_sections.get("action_plan"))))
    if "blockers" in selected_sections:
        sections.append(_render_json_section("Blockers", selected_sections.get("blockers")))
    if "api_inventory" in selected_sections:
        sections.append(_render_json_section("API Calls", selected_sections.get("api_inventory")))
    if "normalized" in selected_sections:
        sections.append(_render_json_section("Normalized Evidence", selected_sections.get("normalized")))
    if "replay_context" in selected_sections:
        sections.append(_render_key_values("Replay Context", _mapping(selected_sections.get("replay_context"))))
    if "manifest" in selected_sections:
        sections.append(_render_json_section("Manifest", selected_sections.get("manifest")))

    sections.append("</body></html>\n")
    return "".join(sections)


def _sarif_rule_help_markdown(finding: Mapping[str, Any]) -> str:
    """Build a Markdown help block for a SARIF rule.

    GitHub Code Scanning surfaces ``help.markdown`` in the Security UI;
    a structured block (description / impact / remediation / mapped controls /
    references) makes findings actionable inline rather than forcing operators
    to open the auditex bundle to figure out what a rule means.
    """
    parts: list[str] = []
    title = _text(finding.get("title")) or _text(finding.get("rule_id")) or "Auditex finding"
    parts.append(f"## {title}")
    description = _text(finding.get("description"))
    if description:
        parts.append(f"**Description:** {description}")
    impact = _text(finding.get("impact"))
    if impact:
        parts.append(f"**Impact:** {impact}")
    remediation = _text(finding.get("remediation"))
    if remediation:
        parts.append(f"**Remediation:** {remediation}")
    severity = _text(finding.get("severity"))
    if severity:
        parts.append(f"**Severity:** {severity}")
    framework_mappings = (
        finding.get("framework_mappings")
        if isinstance(finding.get("framework_mappings"), Mapping)
        else {}
    )
    if framework_mappings:
        rows: list[str] = []
        for framework, controls in sorted(framework_mappings.items()):
            if isinstance(controls, list) and controls:
                control_text = ", ".join(_text(c) for c in controls if _text(c))
                if control_text:
                    rows.append(f"- **{framework}**: {control_text}")
        if rows:
            parts.append("**Mapped controls:**\n\n" + "\n".join(rows))
    references = finding.get("references")
    if isinstance(references, list) and references:
        ref_lines = "\n".join(f"- {_text(ref)}" for ref in references if _text(ref))
        if ref_lines:
            parts.append("**References:**\n\n" + ref_lines)
    return "\n\n".join(parts)


def _sarif_help_uri(rule_id: str, *, platform: str = "") -> str:
    """Per-rule help URI surfaced by GitHub Code Scanning.

    Until per-rule docs pages exist on a stable site, point at the canonical
    rule catalog. URL is deterministic per rule_id so dedup is stable.
    """
    if platform == "google_workspace" or rule_id.startswith("google."):
        return f"{AUDITEX_SARIF_TOOL_URI}/blob/main/src/auditex/google_workspace/findings.py#{rule_id}"
    return f"{AUDITEX_SARIF_TOOL_URI}/blob/main/configs/finding-templates.json#{rule_id}"


def _sarif_finding_fingerprint(finding: Mapping[str, Any]) -> str:
    """Stable, content-derived SHA-256 hex digest for SARIF dedup.

    Includes ``rule_id``, the finding ``id``, and the first evidence_ref's
    ``record_key`` (when present). All three are stable across runs of the
    same tenant — re-running auditex against the same posture should
    produce the same fingerprints, which is what GitHub Code Scanning's
    dedup contract requires for its alert tracking.

    Excludes wall-clock and run-derived fields so a re-run against a
    static bundle yields byte-identical fingerprints.
    """
    rule_id = _text(finding.get("rule_id"))
    finding_id = _text(finding.get("id"))
    record_key = ""
    refs = finding.get("evidence_refs")
    if isinstance(refs, list) and refs:
        first = refs[0]
        if isinstance(first, Mapping):
            record_key = _text(first.get("record_key"))
    payload = f"{rule_id}|{finding_id}|{record_key}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def render_sarif(
    *,
    findings: list[dict[str, Any]] | None,
    summary: Mapping[str, Any] | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    findings_rows = [dict(item) for item in (findings or []) if isinstance(item, Mapping)]
    summary_dict = _mapping(summary)
    manifest_dict = _mapping(manifest)
    platform = _provider_platform(summary_dict, manifest_dict)
    platform_label = _provider_label(platform)

    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for finding in findings_rows:
        rule_id = _text(finding.get("rule_id") or finding.get("id"))
        if not rule_id or rule_id in rule_index:
            continue
        rule_index[rule_id] = len(rules)
        framework_mappings = finding.get("framework_mappings") if isinstance(finding.get("framework_mappings"), Mapping) else {}
        tags: list[str] = []
        for framework, controls in framework_mappings.items():
            if not isinstance(controls, list):
                continue
            for control in controls:
                control_text = _text(control).strip()
                if control_text:
                    tags.append(f"{framework}:{control_text}")
        category = _text(finding.get("category"))
        if category:
            tags.append(f"category:{category}")
        help_text = (
            _text(finding.get("remediation"))
            or _text(finding.get("description"))
            or "See Auditex finding for remediation guidance."
        )
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "_"),
                "shortDescription": {"text": _text(finding.get("title")) or rule_id},
                "fullDescription": {"text": _text(finding.get("description")) or _text(finding.get("title")) or rule_id},
                "help": {
                    "text": help_text,
                    "markdown": _sarif_rule_help_markdown(finding),
                },
                "helpUri": _sarif_help_uri(rule_id, platform=platform),
                "defaultConfiguration": {"level": _SARIF_LEVELS.get(_text(finding.get("severity")).lower(), "warning")},
                "properties": {"tags": sorted(set(tags))} if tags else {"tags": []},
            }
        )

    results: list[dict[str, Any]] = []
    for finding in findings_rows:
        rule_id = _text(finding.get("rule_id") or finding.get("id"))
        if not rule_id:
            continue
        affected = finding.get("affected_objects")
        if isinstance(affected, list) and affected:
            partial_fingerprints = {"affected": ",".join(_text(item) for item in affected)}
        else:
            partial_fingerprints = {}
        result_entry = {
            "ruleId": rule_id,
            "ruleIndex": rule_index.get(rule_id, 0),
            "level": _SARIF_LEVELS.get(_text(finding.get("severity")).lower(), "warning"),
            "message": {
                "text": _text(finding.get("title")) or _text(finding.get("description")) or rule_id,
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": _text(target),
                            "kind": _text(finding.get("category"), "cloud-resource"),
                        }
                        for target in (affected if isinstance(affected, list) else [])
                    ]
                    or [
                        {
                            "name": _text(finding.get("collector"), "auditex"),
                            "kind": _text(finding.get("category"), "cloud-resource"),
                        }
                    ],
                }
            ],
            # Stable per-finding fingerprint for GitHub Code Scanning dedup
            # across runs. Content-derived (rule_id + id + record_key); the
            # ``auditex/v1`` key is the version sentinel — bumping the
            # algorithm in a future release means a new key.
            "fingerprints": {"auditex/v1": _sarif_finding_fingerprint(finding)},
            "properties": {
                "auditex.finding_id": _text(finding.get("id")),
                "auditex.severity": _text(finding.get("severity")),
                "auditex.collector": _text(finding.get("collector")),
                "auditex.category": _text(finding.get("category")),
            },
        }
        if partial_fingerprints:
            result_entry["partialFingerprints"] = partial_fingerprints
        results.append(result_entry)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "auditex",
                        "informationUri": AUDITEX_SARIF_TOOL_URI,
                        "version": _text(manifest_dict.get("schema_contract_version") or summary_dict.get("schema_version")),
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": _text(manifest_dict.get("run_id") or summary_dict.get("run_id") or "auditex-run"),
                    "description": {
                        "text": f"Auditex {platform_label} audit run for tenant {_text(summary_dict.get('tenant_name'), 'unknown')}",
                    },
                },
                "properties": {"auditex.platform": platform},
                "results": results,
            }
        ],
    }


def render_oscal(
    *,
    findings: list[dict[str, Any]] | None,
    summary: Mapping[str, Any] | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    import uuid as _uuid
    from datetime import datetime, timezone

    findings_rows = [dict(item) for item in (findings or []) if isinstance(item, Mapping)]
    summary_dict = _mapping(summary)
    manifest_dict = _mapping(manifest)
    platform = _provider_platform(summary_dict, manifest_dict)
    platform_label = _provider_label(platform)

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assessment_uuid = _text(manifest_dict.get("run_id") or summary_dict.get("run_id"))
    if not assessment_uuid:
        assessment_uuid = str(_uuid.uuid4())

    observations: list[dict[str, Any]] = []
    findings_oscal: list[dict[str, Any]] = []
    for finding in findings_rows:
        observation_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/observation/{_text(finding.get('id'))}"))
        finding_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/finding/{_text(finding.get('id'))}"))
        framework_mappings = finding.get("framework_mappings") if isinstance(finding.get("framework_mappings"), Mapping) else {}
        target_ids: list[str] = []
        for framework in sorted(framework_mappings):
            controls = framework_mappings.get(framework)
            if not isinstance(controls, list):
                continue
            for control in controls:
                control_text = _text(control).strip()
                if not control_text:
                    continue
                target_ids.append(control_text)
                target_ids.append(f"{framework}:{control_text}")
        observations.append(
            {
                "uuid": observation_uuid,
                "title": _text(finding.get("title")) or _text(finding.get("rule_id")) or _text(finding.get("id")),
                "description": _text(finding.get("description")) or _text(finding.get("title")) or "",
                "methods": ["EXAMINE"],
                "collected": now,
                "subjects": [
                    {"uuid-ref": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/subject/{_text(item)}")), "title": _text(item)}
                    for item in (finding.get("affected_objects") or [])
                ],
                "props": [
                    {"name": "auditex.finding_id", "value": _text(finding.get("id"))},
                    {"name": "auditex.severity", "value": _text(finding.get("severity"))},
                    {"name": "auditex.collector", "value": _text(finding.get("collector"))},
                ],
            }
        )
        findings_oscal.append(
            {
                "uuid": finding_uuid,
                "title": _text(finding.get("title")) or _text(finding.get("rule_id")) or _text(finding.get("id")),
                "description": _text(finding.get("description")) or _text(finding.get("title")) or "",
                "target-ids": sorted(set(target_ids)),
                "remediation": _text(finding.get("remediation")) or "",
                "related-observations": [{"observation-uuid": observation_uuid}],
                "props": [
                    {"name": "auditex.finding_id", "value": _text(finding.get("id"))},
                    {"name": "auditex.severity", "value": _text(finding.get("severity"))},
                    {"name": "auditex.rule_id", "value": _text(finding.get("rule_id"))},
                ],
            }
        )

    return {
        "assessment-results": {
            "uuid": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/assessment/{assessment_uuid}")),
            "metadata": {
                "title": f"Auditex {platform_label} Assessment Results for {_text(summary_dict.get('tenant_name'), 'unknown tenant')}",
                "version": _text(manifest_dict.get("schema_contract_version") or summary_dict.get("schema_version") or "0"),
                "oscal-version": "1.1.2",
                "last-modified": now,
                "props": [{"name": "auditex.platform", "value": platform}],
            },
            "import-ap": {"href": "#auditex-assessment-plan"},
            "results": [
                {
                    "uuid": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/result/{assessment_uuid}")),
                    "title": "Auditex audit findings",
                    "description": "Findings produced by Auditex collectors and rules.",
                    "start": now,
                    "end": now,
                    # OSCAL Assessment Results 1.1.2 requires ``reviewed-controls``
                    # on each result. ``include-all: {}`` is the canonical "all
                    # controls in scope" selector — auditex's findings are not
                    # scoped per-control at the result level, the framework
                    # mappings on each finding handle that.
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": "Controls reviewed by Auditex collectors and rules",
                                "include-all": {},
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings_oscal,
                }
            ],
        }
    }


def _render_sarif(selected_sections: dict[str, Any]) -> str:
    findings = _dict_rows(selected_sections.get("findings"))
    summary = _mapping(selected_sections.get("summary"))
    manifest = _mapping(selected_sections.get("manifest"))
    return _json(render_sarif(findings=findings, summary=summary, manifest=manifest))


def _render_oscal(selected_sections: dict[str, Any]) -> str:
    findings = _dict_rows(selected_sections.get("findings"))
    summary = _mapping(selected_sections.get("summary"))
    manifest = _mapping(selected_sections.get("manifest"))
    return _json(render_oscal(findings=findings, summary=summary, manifest=manifest))


def preview_report(
    *,
    run_dir: str,
    format_name: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
) -> dict[str, Any]:
    if format_name not in FORMAT_EXTENSIONS:
        raise ValueError(f"Unsupported report format: {format_name}")

    bundle = load_report_bundle(run_dir)
    selected = _select_sections(bundle, include_sections=include_sections, exclude_sections=exclude_sections)
    renderers = {
        "json": _render_json,
        "md": _render_markdown,
        "csv": _render_csv,
        "html": _render_html,
        "sarif": _render_sarif,
        "oscal": _render_oscal,
    }
    return {"format": format_name, "content": renderers[format_name](selected), "sections": list(selected.keys())}


def render_report(
    *,
    run_dir: str,
    format_name: str,
    include_sections: list[str] | None = None,
    exclude_sections: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    preview = preview_report(
        run_dir=run_dir,
        format_name=format_name,
        include_sections=include_sections,
        exclude_sections=exclude_sections,
    )
    target = Path(output_path) if output_path else _default_output_path(Path(run_dir), format_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(preview["content"], encoding="utf-8")
    return {"format": format_name, "output_path": str(target), "sections": preview["sections"]}
