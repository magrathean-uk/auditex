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
from azure_tenant_audit.citations import build_citation_summary, dedupe_citations
from azure_tenant_audit.resources import resolve_resource_path
from azure_tenant_audit.waivers import accepted_risk_summary

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
    "reviewer_index",
    "citation_summary",
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


def _scope_risk_limitation(
    *,
    platform: str,
    scope_risk: str | None,
    write_capable_scopes: list[str],
) -> dict[str, Any] | None:
    if not scope_risk:
        return None
    provider = _provider_label(platform)
    if scope_risk == "write_capable_scope_present":
        message = (
            f"{provider} auth included write-capable scopes. Auditex still stayed read-only, "
            "but reviewers should treat the scope set as a higher-trust limitation."
        )
    else:
        message = (
            f"{provider} read settings can require broad scopes. Auditex still stayed read-only, "
            "but reviewers should confirm the scope set matches the intended audit surface."
        )
    limitation = {
        "surface": "scope_risk",
        "status": scope_risk,
        "message": message,
    }
    if write_capable_scopes:
        limitation["write_capable_scopes"] = write_capable_scopes
    return limitation


def _permission_limitation(permissions_payload: Mapping[str, Any]) -> dict[str, Any] | None:
    missing_permissions = [str(item) for item in permissions_payload.get("missing_permissions") or [] if str(item)]
    if not missing_permissions:
        return None
    affected_collectors = [
        str(row.get("collector"))
        for row in _dict_rows(permissions_payload.get("collectors"))
        if row.get("collector") and [str(item) for item in row.get("missing_permissions") or [] if str(item)]
    ]
    collector_text = ", ".join(sorted(set(affected_collectors))) or "unknown collectors"
    permission_text = ", ".join(missing_permissions)
    return {
        "surface": "permissions",
        "status": "missing_permissions",
        "message": f"Missing permissions affect {collector_text}: {permission_text}.",
        "collectors": sorted(set(affected_collectors)),
        "missing_permissions": missing_permissions,
    }


def _blocked_collectors_limitation(blockers: list[dict[str, Any]]) -> dict[str, Any] | None:
    blocked_collectors = [str(row.get("collector") or row.get("id")) for row in blockers if str(row.get("collector") or row.get("id"))]
    if not blocked_collectors:
        return None
    return {
        "surface": "blocked_collectors",
        "status": "blocked",
        "message": f"Blocked collectors require reviewer attention: {', '.join(sorted(set(blocked_collectors)))}.",
        "collectors": sorted(set(blocked_collectors)),
    }


def _collector_issue_limitations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    limitations: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if not rule_id.endswith("collector_issue"):
            continue
        collector = str(finding.get("collector") or "unknown")
        finding_id = str(finding.get("id") or "")
        returned_value = finding.get("returned_value")
        message = str(finding.get("description") or "Collector evidence is incomplete for this surface.")
        limitation = {
            "surface": "collector_issue",
            "status": "evidence_incomplete",
            "collector": collector,
            "finding_id": finding_id,
            "message": message,
        }
        if isinstance(returned_value, Mapping):
            if returned_value.get("surface"):
                limitation["subsurface"] = returned_value.get("surface")
            if returned_value.get("error_class"):
                limitation["error_class"] = returned_value.get("error_class")
        limitations.append(limitation)
    return limitations


def _citation(
    artifact_path: str,
    *,
    reason: str,
    record_key: str | None = None,
    json_pointer: str | None = None,
) -> dict[str, Any]:
    payload = {"artifact_path": artifact_path, "reason": reason}
    if record_key:
        payload["record_key"] = record_key
    if json_pointer:
        payload["json_pointer"] = json_pointer
    return payload


def _dedupe_citations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return dedupe_citations(rows)


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


def _preview_section_citations(
    *,
    run_path: Path,
    bundle: RunBundle,
    selected_sections: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    citations: list[dict[str, Any]] = []
    missing: list[str] = []

    manifest_path = bundle.path("run-manifest.json")
    if "manifest" in selected_sections:
        if manifest_path.exists():
            citations.append(_citation("run-manifest.json", reason="Run identity and artifact pointers for this preview."))
        else:
            missing.append("run-manifest.json")

    summary_path = bundle._artifact_path("summary_path", "summary.json")
    if "summary" in selected_sections:
        if summary_path.exists():
            citations.append(_citation(_relative_source(summary_path, run_path), reason="Top-level run summary for this preview."))
        else:
            missing.append("summary.json")

    report_pack_path, report_pack_payload = bundle.report_pack()
    report_pack = _mapping(report_pack_payload)
    report_pack_sections = {
        "executive_summary",
        "technical_appendix",
        "reviewer_index",
        "citation_summary",
        "limitations",
        "next_actions",
        "license_profile",
        "auditor_score",
        "attack_paths",
        "control_simulator",
        "report_qa",
        "replay_context",
    }
    if report_pack_sections.intersection(selected_sections) or "proof_table" in selected_sections:
        if report_pack_path is not None:
            citations.append(_citation(_relative_source(report_pack_path, run_path), reason="Report pack sections used in this preview."))
        else:
            missing.append("reports/report-pack.json")

    findings_path, _ = bundle.findings()
    if "findings" in selected_sections:
        if findings_path is not None:
            citations.append(_citation(_relative_source(findings_path, run_path), reason="Finding register used in this preview."))
        elif report_pack_path is None:
            missing.append("findings/findings.json")

    action_plan_path, _ = bundle.action_plan()
    if "action_plan" in selected_sections:
        if action_plan_path is not None:
            citations.append(_citation(_relative_source(action_plan_path, run_path), reason="Action-plan rows used in this preview."))
        elif report_pack_path is None:
            missing.append("reports/action-plan.json")

    api_inventory_path, _ = bundle.api_inventory()
    if "api_inventory" in selected_sections:
        if api_inventory_path is not None:
            citations.append(_citation(_relative_source(api_inventory_path, run_path), reason="API inventory used in this preview."))
        else:
            missing.append("api-inventory.json")

    blockers_path, _ = bundle.blockers()
    if "blockers" in selected_sections:
        if blockers_path is not None:
            citations.append(_citation(_relative_source(blockers_path, run_path), reason="Blocker rows used in this preview."))
        else:
            missing.append("blockers/blockers.json")

    if "normalized" in selected_sections:
        normalized_dir = run_path / "normalized"
        normalized_paths = sorted(normalized_dir.glob("*.json"), key=lambda item: item.name) if normalized_dir.is_dir() else []
        if normalized_paths:
            citations.extend(
                _citation(_relative_source(path, run_path), reason="Normalized evidence section used in this preview.")
                for path in normalized_paths
            )
        else:
            missing.append("normalized/*.json")

    return _dedupe_citations(citations), sorted(set(missing))


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
        "reviewer_index",
        "citation_summary",
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
    report_pack_path, report_pack_payload = bundle.report_pack()
    report_pack = _mapping(report_pack_payload)
    findings_path, _ = bundle.findings()
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
    citations = _dedupe_citations(
        (
            [_citation(_relative_source(report_pack_path, run_path), reason="Report-pack summary and evidence paths analyzed for this run.")]
            if report_pack_path is not None
            else []
        )
        + (
            [_citation(_relative_source(findings_path, run_path), reason="Finding register analyzed for this run.")]
            if findings_path is not None and report_pack_path is None
            else []
        )
    )
    evidence_missing: list[str] = []
    if report_pack_path is None:
        evidence_missing.append("reports/report-pack.json")
    if not findings and findings_path is None and report_pack_path is None:
        evidence_missing.append("findings/findings.json")
    return {
        "run_dir": str(run_path),
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
        "evidence_missing": sorted(set(evidence_missing)),
        **intelligence,
    }


def api_call_inventory(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    path, payload = bundle.api_inventory()
    inventory = _mapping(payload)
    citations = (
        [_citation(_relative_source(path, run_path), reason="API call ledger for this completed run.")]
        if path is not None
        else []
    )
    return {
        "run_dir": str(run_path),
        "api_inventory_path": str(path) if path is not None else str(bundle.path("api-inventory.json")),
        "present": path is not None,
        "evidence_missing": path is None,
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
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
                "minimum_role_hints": [str(item) for item in declaration.get("minimum_role_hints") or [] if str(item)],
                "tool_requirements": [str(item) for item in declaration.get("tool_requirements") or [] if str(item)],
                "observed_call_count": declaration.get("observed_call_count", 0),
                "blocker_kind": gate.get("blocker_kind"),
                "blocker_reason": gate.get("blocker_reason"),
                "next_step": gate.get("next_step"),
            }
        )
    citations = _dedupe_citations(
        (
            [_citation(_relative_source(Path(api["api_inventory_path"]), run_path), reason="Declared collector permissions for this run.")]
            if api.get("present")
            else []
        )
        + (
            [_citation(_relative_source(bundle.audit_plan()[0], run_path), reason="Evidence gate and missing-permission plan.")]
            if bundle.audit_plan()[0] is not None
            else []
        )
    )
    return {
        "run_dir": str(run_path),
        "platform": api.get("platform") or audit_plan.get("platform") or bundle.metadata().get("platform"),
        "api_inventory_path": api.get("api_inventory_path"),
        "audit_plan_path": str(bundle.audit_plan()[0]) if bundle.audit_plan()[0] is not None else str(bundle.path("audit-plan.json")),
        "evidence_missing": not api.get("present") or bundle.audit_plan()[0] is None,
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
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
    citations = (
        [_citation(_relative_source(path, run_path), reason="Proof table source for finding-to-evidence mapping.")]
        if path is not None
        else []
    )
    for row in rows:
        artifact_path = _text(row.get("artifact_path")).strip()
        if not artifact_path:
            continue
        citations.append(
            _citation(
                artifact_path,
                reason="Artifact referenced by proof row.",
                record_key=_text(row.get("record_key")).strip() or None,
                json_pointer=_text(row.get("json_pointer")).strip() or None,
            )
        )
    citations = _dedupe_citations(citations)
    return {
        "run_dir": str(run_path),
        "report_pack_path": str(path) if path is not None else str(bundle.path("reports/report-pack.json")),
        "present": path is not None,
        "evidence_missing": path is None or not rows,
        "summary": bundle.report_summary(),
        "counts": counts,
        "unsupported_claims": sorted(set(unsupported_claims)),
        "evidence_paths": [str(item) for item in report_pack.get("evidence_paths") or [] if str(item)],
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
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


def _validation_summary(validation: Mapping[str, Any], *, path: str) -> dict[str, Any]:
    valid = validation.get("valid") if isinstance(validation, Mapping) else None
    issue_count = int(validation.get("issue_count") or 0) if isinstance(validation, Mapping) else 0
    error_count = int(validation.get("error_count") or 0) if isinstance(validation, Mapping) else 0
    warning_count = int(validation.get("warning_count") or 0) if isinstance(validation, Mapping) else 0
    status = "pass"
    if valid is False or error_count:
        status = "fail"
    elif warning_count or issue_count:
        status = "warn"
    return {
        "status": status,
        "valid": valid,
        "issue_count": issue_count,
        "error_count": error_count,
        "warning_count": warning_count,
        "path": path,
    }


def _reviewer_summary(
    *,
    report_pack: Mapping[str, Any],
    proof_rows: list[dict[str, Any]],
    limitations: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    unsupported_claims: list[str],
    stale_accepted: list[dict[str, Any]],
) -> dict[str, Any]:
    reviewer_index = _mapping(report_pack.get("reviewer_index"))
    start_here = _dict_rows(reviewer_index.get("start_here"))
    if not start_here:
        start_here = [
            {
                "section": "handoff",
                "artifact_path": "handoff.json",
                "reason": "Start with overall handoff status, safety, contract, and review commands.",
            },
            {
                "section": "executive_summary",
                "artifact_path": "reports/report-pack.json",
                "reason": "Review top findings and overall posture before drilling into proof.",
            },
            {
                "section": "proof_table",
                "artifact_path": "reports/report-pack.json",
                "reason": "Verify important claims against exact artifacts and record keys.",
            },
            {
                "section": "validation",
                "artifact_path": "validation.json",
                "reason": "Confirm contract validation result before customer handoff.",
            },
        ]
    prove_this = _dict_rows(reviewer_index.get("prove_this"))
    if not prove_this:
        seen: set[str] = set()
        prove_this = []
        for row in proof_rows:
            finding_id = str(row.get("finding_id") or row.get("id") or "").strip()
            if not finding_id or finding_id in seen:
                continue
            seen.add(finding_id)
            prove_this.append(
                {
                    "finding_id": finding_id,
                    "severity": row.get("severity"),
                    "proof_status": row.get("proof_status"),
                    "artifact_path": row.get("artifact_path"),
                    "record_key": row.get("record_key"),
                    "json_pointer": row.get("json_pointer"),
                }
            )
            if len(prove_this) >= 5:
                break
    known_limits = _dict_rows(reviewer_index.get("known_limits"))
    if not known_limits:
        known_limits = [
            {
                "surface": row.get("surface"),
                "status": row.get("status"),
                "message": row.get("message"),
            }
            for row in limitations
        ]
    if blockers:
        known_limits.append(
            {
                "surface": "collection",
                "status": "blocked",
                "message": f"{len(blockers)} collector blocker(s) need reviewer attention.",
            }
        )
    if unsupported_claims:
        known_limits.append(
            {
                "surface": "proof",
                "status": "unsupported_claim",
                "message": "Some findings are not fully supported by proof rows yet.",
                "finding_ids": unsupported_claims,
            }
        )
    if stale_accepted:
        known_limits.append(
            {
                "surface": "accepted_risk",
                "status": "stale",
                "message": "One or more accepted risks have expired and need renewed review.",
                "finding_ids": [row.get("id") for row in stale_accepted if row.get("id")],
            }
        )
    return {
        "counts": {
            "start_here": len(start_here),
            "prove_this": len(prove_this),
            "known_limits": len(known_limits),
        },
        "start_here": start_here,
        "prove_this": prove_this,
        "known_limits": known_limits,
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
    permissions = permissions_ledger(run_path)
    report_pack_path, report_pack_payload = bundle.report_pack()
    report_pack = _mapping(report_pack_payload)
    blockers = bundle.blocker_rows()
    accepted_risks = accepted_risk_summary(bundle.finding_rows())
    coverage_gaps = _dict_rows(summary.get("coverage_gaps")) or _dict_rows(metadata.get("coverage_gaps"))
    api_safety = _mapping(api.get("safety"))
    proof_counts = _mapping(proof.get("counts"))
    scope_risk = str(data_handling.get("scope_risk") or api_safety.get("scope_risk") or "").strip() or None
    write_capable_scopes = [
        str(item)
        for item in (data_handling.get("write_capable_scopes") or api_safety.get("write_capable_scopes") or [])
        if str(item)
    ]
    limitations = [dict(item) for item in coverage_gaps if isinstance(item, dict)]
    scope_risk_limitation = _scope_risk_limitation(
        platform=_provider_platform(summary, manifest),
        scope_risk=scope_risk,
        write_capable_scopes=write_capable_scopes,
    )
    if scope_risk_limitation:
        limitations.append(scope_risk_limitation)
    permission_limitation = _permission_limitation(permissions)
    if permission_limitation:
        limitations.append(permission_limitation)
    blocked_collectors_limitation = _blocked_collectors_limitation(blockers)
    if blocked_collectors_limitation:
        limitations.append(blocked_collectors_limitation)
    limitations.extend(_collector_issue_limitations(bundle.finding_rows()))

    validation_valid = validation.get("valid") if validation else None
    read_only = data_handling.get("read_only") is not False and api_safety.get("read_only") is not False
    no_content_reads = data_handling.get("content_reads") is not True and api_safety.get("no_content_reads") is not False
    write_actions = data_handling.get("write_actions") is True or api_safety.get("write_actions") is True
    unsupported_claims = [str(item) for item in proof.get("unsupported_claims") or [] if str(item)]

    if validation_valid is False or not read_only or not no_content_reads or write_actions:
        status = "unusable"
    elif validation_valid is None or not api.get("present") or not proof.get("present"):
        status = "incomplete"
    elif limitations or blockers or unsupported_claims or int(accepted_risks.get("stale_count") or 0) > 0:
        status = "ready_with_limitations"
    else:
        status = "ready"

    data_handling_relative = str(manifest.get("data_handling_path") or "data-handling.json")
    api_relative = str(manifest.get("api_inventory_path") or "api-inventory.json")
    audit_plan_relative = str(manifest.get("audit_plan_path") or "audit-plan.json")
    live_readiness_relative = str(manifest.get("live_readiness_path") or "live-readiness.json")
    report_pack_relative = str(manifest.get("report_pack_path") or "reports/report-pack.json")
    validation_relative = str(manifest.get("validation_path") or "validation.json")
    validation_summary = _validation_summary(
        validation,
        path=str(validation_path) if validation_path is not None else str(run_path / validation_relative),
    )
    reviewer_summary = _reviewer_summary(
        report_pack=report_pack,
        proof_rows=_dict_rows(proof.get("proof_table")),
        limitations=limitations,
        blockers=blockers,
        unsupported_claims=unsupported_claims,
        stale_accepted=_dict_rows(accepted_risks.get("stale")),
    )
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
    citations = _dedupe_citations(
        [_citation(data_handling_relative, reason="Read-only and no-content-read declaration.")]
        + (
            [_citation(api_relative, reason="API call ledger reviewed for handoff.")]
            if api.get("present")
            else []
        )
        + (
            [_citation(report_pack_relative, reason="Report pack reviewed for findings and proof.")]
            if report_pack_path is not None
            else []
        )
        + (
            [_citation(validation_relative, reason="Bundle contract validation result.")]
            if validation_path is not None
            else []
        )
    )

    return {
        "run_dir": str(run_path),
        "handoff_status": status,
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
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
        "validation_summary": validation_summary,
        "safety": {
            "read_only": read_only,
            "no_content_reads": no_content_reads,
            "write_actions": write_actions,
            "scope_risk": scope_risk,
            "write_capable_scopes": write_capable_scopes,
        },
        "quality": {
            "audit_plan_status": _mapping(audit_plan.get("quality_gate")).get("status"),
            "live_readiness": live_readiness.get("trust_level"),
            "coverage_gap_count": len(limitations),
            "blocker_count": len(blockers),
            "unsupported_claim_count": len(unsupported_claims),
            "accepted_risk_count": int(accepted_risks.get("count") or 0),
            "stale_accepted_risk_count": int(accepted_risks.get("stale_count") or 0),
            "expiring_accepted_risk_count": int(accepted_risks.get("expiring_soon_count") or 0),
        },
        "counts": {
            "findings": int(proof_counts.get("findings") or len(bundle.finding_rows())),
            "proof_rows": int(proof_counts.get("proof_rows") or 0),
            "supported_proof_rows": int(proof_counts.get("supported") or 0),
            "api_calls": int(_mapping(api.get("counts")).get("observed_calls") or len(_dict_rows(api.get("observed_calls")))),
        },
        "reviewer_summary": reviewer_summary,
        "accepted_risks": accepted_risks,
        "artifacts": artifacts,
        "review_commands": {
            "render_report": f"auditex report render {run_path} --format md",
            "api_calls": f"auditex report api-calls {run_path} --format md",
            "proof_table": f"auditex report proof-table {run_path} --format md",
            "handoff": f"auditex report handoff {run_path} --format md",
        },
        "limitations": limitations,
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
    validation_summary = _mapping(payload.get("validation_summary"))
    safety = _mapping(payload.get("safety"))
    quality = _mapping(payload.get("quality"))
    counts = _mapping(payload.get("counts"))
    reviewer_summary = _mapping(payload.get("reviewer_summary"))
    accepted_risks = _mapping(payload.get("accepted_risks"))
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
        f"- Validation: {_markdown_cell(validation_summary.get('status'))} / {_markdown_cell(validation_summary.get('issue_count'))} issues",
        f"- Read-only: {_markdown_cell(safety.get('read_only'))}",
        f"- No content reads: {_markdown_cell(safety.get('no_content_reads'))}",
        f"- Audit quality: {_markdown_cell(quality.get('audit_plan_status'))}",
        f"- Live readiness: {_markdown_cell(quality.get('live_readiness'))}",
        f"- Findings: {_markdown_cell(counts.get('findings'))}",
        f"- Proof rows: {_markdown_cell(counts.get('proof_rows'))}",
        f"- API calls: {_markdown_cell(counts.get('api_calls'))}",
        f"- Accepted risks: {_markdown_cell(accepted_risks.get('count'))}",
        f"- Stale accepted risks: {_markdown_cell(accepted_risks.get('stale_count'))}",
        "",
        "## Review Commands",
        "",
    ]
    for key in ("render_report", "api_calls", "proof_table", "handoff"):
        if commands.get(key):
            lines.append(f"- `{_markdown_cell(commands.get(key))}`")
    start_here = _dict_rows(reviewer_summary.get("start_here"))
    if start_here:
        lines.extend(["", "## Start Here", ""])
        for row in start_here:
            lines.append(f"- `{_markdown_cell(row.get('section'))}`: {_markdown_cell(row.get('reason'))}")
    prove_this = _dict_rows(reviewer_summary.get("prove_this"))
    if prove_this:
        lines.extend(["", "## Prove This", "", "| Finding | Severity | Proof | Artifact | Record |", "| --- | --- | --- | --- | --- |"])
        for row in prove_this:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("finding_id")),
                        _markdown_cell(row.get("severity")),
                        _markdown_cell(row.get("proof_status")),
                        _markdown_cell(row.get("artifact_path")),
                        _markdown_cell(row.get("record_key")),
                    ]
                )
                + " |"
            )
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
    stale_accepted = _dict_rows(accepted_risks.get("stale"))
    expiring_accepted = _dict_rows(accepted_risks.get("expiring_soon"))
    if stale_accepted or expiring_accepted:
        lines.extend(["", "## Accepted Risk Review", ""])
        for item in stale_accepted:
            lines.append(
                f"- Stale: {_markdown_cell(item.get('id'))} expires {_markdown_cell(item.get('expires_on'))}"
            )
        for item in expiring_accepted:
            lines.append(
                f"- Expiring soon: {_markdown_cell(item.get('id'))} expires {_markdown_cell(item.get('expires_on'))}"
            )
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
    validation_summary = _mapping(source.get("validation_summary"))
    safety = _mapping(source.get("safety"))
    quality = _mapping(source.get("quality"))
    counts = _mapping(source.get("counts"))
    reviewer_summary = _mapping(source.get("reviewer_summary"))
    generated = _dict_rows(manifest.get("generated_files"))
    sources = _dict_rows(manifest.get("source_artifacts"))
    lines = [
        "# Auditex Customer Pack",
        "",
        f"- Status: {_markdown_cell(manifest.get('handoff_status'))}",
        f"- Tenant: {_markdown_cell(tenant.get('name'))}",
        f"- Platform: {_markdown_cell(tenant.get('platform'))}",
        f"- Validation: {_markdown_cell(validation_summary.get('status'))}",
        f"- Read-only: {_markdown_cell(safety.get('read_only'))}",
        f"- No content reads: {_markdown_cell(safety.get('no_content_reads'))}",
        f"- Audit quality: {_markdown_cell(quality.get('audit_plan_status'))}",
        f"- Findings: {_markdown_cell(counts.get('findings'))}",
        f"- API calls: {_markdown_cell(counts.get('api_calls'))}",
        f"- Reviewer prove-this rows: {_markdown_cell(_mapping(reviewer_summary.get('counts')).get('prove_this'))}",
        "",
        "## Start Here",
        "",
        "1. Read `handoff.md`.",
        "2. Check `validation.json` and the validation summary before trusting the pack.",
        "3. Review `report.md` for the client-ready report and reviewer index.",
        "4. Review `api-calls.md` for every observed API call.",
        "5. Review `permissions.md` for required and missing scopes.",
        "6. Review `proof-table.md` for finding-to-evidence rows.",
        "7. Run `auditex report verify-pack <pack-dir>` or use `checksums.sha256` to verify file integrity.",
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
            "validation_summary": handoff_payload.get("validation_summary"),
            "safety": handoff_payload.get("safety"),
            "quality": handoff_payload.get("quality"),
            "counts": handoff_payload.get("counts"),
            "reviewer_summary": handoff_payload.get("reviewer_summary"),
            "accepted_risks": handoff_payload.get("accepted_risks"),
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
    source_payload = _mapping(manifest.get("source"))
    manifest_validation_summary = _mapping(source_payload.get("validation_summary"))
    manifest_reviewer_summary = _mapping(source_payload.get("reviewer_summary"))
    accepted_risks = _mapping(source_payload.get("accepted_risks"))

    if int(accepted_risks.get("stale_count") or 0) > 0:
        add_issue(
            "stale_accepted_risk",
            "Customer pack includes accepted risks whose expiry date has passed.",
            stale_count=int(accepted_risks.get("stale_count") or 0),
            findings=[row.get("id") for row in _dict_rows(accepted_risks.get("stale")) if row.get("id")],
        )

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

    generated_by_name = {
        str(row.get("name") or Path(str(row.get("path") or "")).name): row
        for row in generated
        if row.get("name") or row.get("path")
    }
    handoff_row = generated_by_name.get("handoff.json")
    handoff_payload = _mapping(
        _read_json(
            _pack_file_path(pack_path, manifest_output_dir, handoff_row.get("path")) if handoff_row else Path("missing"),
            {},
        )
    )
    if not manifest_validation_summary:
        add_issue(
            "missing_manifest_validation_summary",
            "pack-manifest.json source is missing validation_summary.",
            path=str(manifest_path),
        )
    elif manifest_validation_summary != _mapping(handoff_payload.get("validation_summary")):
        add_issue(
            "invalid_manifest_validation_summary",
            "pack-manifest.json validation_summary does not match handoff.json.",
            path=str(manifest_path),
        )
    if not manifest_reviewer_summary:
        add_issue(
            "missing_manifest_reviewer_summary",
            "pack-manifest.json source is missing reviewer_summary.",
            path=str(manifest_path),
        )
    elif manifest_reviewer_summary != _mapping(handoff_payload.get("reviewer_summary")):
        add_issue(
            "invalid_manifest_reviewer_summary",
            "pack-manifest.json reviewer_summary does not match handoff.json.",
            path=str(manifest_path),
        )

    def verify_generated_helper_citations(helper_name: str) -> None:
        row = generated_by_name.get(helper_name)
        if not row:
            return
        helper_file = _pack_file_path(pack_path, manifest_output_dir, row.get("path"))
        helper_payload = _mapping(_read_json(helper_file, {}))
        if "citations" not in helper_payload:
            add_issue(
                "missing_generated_helper_citations",
                f"Generated helper {helper_name} is missing citations.",
                path=str(helper_file) if helper_file is not None else None,
                helper=helper_name,
            )
            return
        citations = _dict_rows(helper_payload.get("citations"))
        citation_summary = _mapping(helper_payload.get("citation_summary"))
        if not citation_summary:
            add_issue(
                "missing_generated_helper_citation_summary",
                f"Generated helper {helper_name} is missing citation_summary.",
                path=str(helper_file) if helper_file is not None else None,
                helper=helper_name,
            )
            return
        expected_summary = build_citation_summary(citations)
        for key in ("citation_count", "artifact_count", "record_key_count", "json_pointer_count", "evidence_missing"):
            if citation_summary.get(key) != expected_summary.get(key):
                add_issue(
                    "invalid_generated_helper_citation_summary",
                    f"Generated helper {helper_name} has a citation_summary that does not match citations.",
                    path=str(helper_file) if helper_file is not None else None,
                    helper=helper_name,
                    field=key,
                    expected=expected_summary.get(key),
                    actual=citation_summary.get(key),
                )
                return
        if [str(item) for item in citation_summary.get("artifacts") or []] != [str(item) for item in expected_summary.get("artifacts") or []]:
            add_issue(
                "invalid_generated_helper_citation_summary",
                f"Generated helper {helper_name} has citation_summary artifacts that do not match citations.",
                path=str(helper_file) if helper_file is not None else None,
                helper=helper_name,
            )
            return
        if helper_name != "proof-table.json":
            return
        cited_artifacts = {str(citation.get("artifact_path") or "").strip() for citation in citations if str(citation.get("artifact_path") or "").strip()}
        cited_artifact_keys = {
            (
                str(citation.get("artifact_path") or "").strip(),
                str(citation.get("record_key") or "").strip(),
            )
            for citation in citations
            if str(citation.get("artifact_path") or "").strip()
        }
        cited_artifact_json_pointers = {
            (
                str(citation.get("artifact_path") or "").strip(),
                str(citation.get("json_pointer") or "").strip(),
            )
            for citation in citations
            if str(citation.get("artifact_path") or "").strip()
        }
        for proof_row in _dict_rows(helper_payload.get("proof_table")):
            artifact_path = str(proof_row.get("artifact_path") or "").strip()
            if not artifact_path:
                continue
            if artifact_path not in cited_artifacts:
                add_issue(
                    "missing_generated_helper_proof_citation",
                    "Generated helper proof-table.json references an artifact not covered by citations.",
                    path=str(helper_file) if helper_file is not None else None,
                    helper=helper_name,
                    artifact_path=artifact_path,
                    finding_id=proof_row.get("finding_id") or proof_row.get("id"),
                )
                return
            record_key = str(proof_row.get("record_key") or "").strip()
            if record_key and (artifact_path, record_key) not in cited_artifact_keys:
                add_issue(
                    "missing_generated_helper_proof_record_key_citation",
                    "Generated helper proof-table.json record_key is not covered by citations.",
                    path=str(helper_file) if helper_file is not None else None,
                    helper=helper_name,
                    artifact_path=artifact_path,
                    record_key=record_key,
                    finding_id=proof_row.get("finding_id") or proof_row.get("id"),
                )
                return
            json_pointer = str(proof_row.get("json_pointer") or "").strip()
            if json_pointer and (artifact_path, json_pointer) not in cited_artifact_json_pointers:
                add_issue(
                    "missing_generated_helper_proof_json_pointer_citation",
                    "Generated helper proof-table.json json_pointer is not covered by citations.",
                    path=str(helper_file) if helper_file is not None else None,
                    helper=helper_name,
                    artifact_path=artifact_path,
                    json_pointer=json_pointer,
                    finding_id=proof_row.get("finding_id") or proof_row.get("id"),
                )
                return

    for helper_name in ("handoff.json", "api-calls.json", "permissions.json", "proof-table.json"):
        verify_generated_helper_citations(helper_name)

    report_pack_source = next(
        (
            row
            for row in sources
            if str(row.get("source_path") or row.get("path") or "").endswith("reports/report-pack.json")
        ),
        None,
    )
    if report_pack_source and report_pack_source.get("present") is not False:
        report_pack_file = _pack_file_path(pack_path, manifest_output_dir, report_pack_source.get("path"))
        report_pack_payload = _mapping(_read_json(report_pack_file, {}))
        citations = _dict_rows(report_pack_payload.get("citations"))
        if not citations:
            add_issue(
                "missing_report_pack_citations",
                "Customer pack source report-pack.json is missing citations.",
                path=str(report_pack_file) if report_pack_file is not None else None,
            )
        citation_summary = _mapping(report_pack_payload.get("citation_summary"))
        if not citation_summary:
            add_issue(
                "missing_report_pack_citation_summary",
                "Customer pack source report-pack.json is missing citation_summary.",
                path=str(report_pack_file) if report_pack_file is not None else None,
            )
        else:
            expected_summary = build_citation_summary(citations)
            for key in ("citation_count", "artifact_count", "record_key_count", "json_pointer_count", "evidence_missing"):
                if citation_summary.get(key) != expected_summary.get(key):
                    add_issue(
                        "invalid_report_pack_citation_summary",
                        "Customer pack source report-pack.json has a citation_summary that does not match citations.",
                        path=str(report_pack_file) if report_pack_file is not None else None,
                        field=key,
                        expected=expected_summary.get(key),
                        actual=citation_summary.get(key),
                    )
                    break
            else:
                if [str(item) for item in citation_summary.get("artifacts") or []] != [str(item) for item in expected_summary.get("artifacts") or []]:
                    add_issue(
                        "invalid_report_pack_citation_summary",
                        "Customer pack source report-pack.json has citation_summary artifacts that do not match citations.",
                        path=str(report_pack_file) if report_pack_file is not None else None,
                    )

        cited_artifacts = {str(row.get("artifact_path") or "").strip() for row in citations if str(row.get("artifact_path") or "").strip()}
        cited_artifact_keys = {
            (
                str(row.get("artifact_path") or "").strip(),
                str(row.get("record_key") or "").strip(),
            )
            for row in citations
            if str(row.get("artifact_path") or "").strip()
        }
        cited_artifact_json_pointers = {
            (
                str(row.get("artifact_path") or "").strip(),
                str(row.get("json_pointer") or "").strip(),
            )
            for row in citations
            if str(row.get("artifact_path") or "").strip()
        }
        for proof_row in _dict_rows(report_pack_payload.get("proof_table")):
            artifact_path = str(proof_row.get("artifact_path") or "").strip()
            if not artifact_path:
                continue
            if artifact_path not in cited_artifacts:
                add_issue(
                    "missing_report_pack_proof_citation",
                    "Customer pack source report-pack.json proof_table references an artifact not covered by citations.",
                    path=str(report_pack_file) if report_pack_file is not None else None,
                    artifact_path=artifact_path,
                    finding_id=proof_row.get("finding_id") or proof_row.get("id"),
                )
                break
            record_key = str(proof_row.get("record_key") or "").strip()
            if record_key and (artifact_path, record_key) not in cited_artifact_keys:
                add_issue(
                    "missing_report_pack_proof_record_key_citation",
                    "Customer pack source report-pack.json proof_table record_key is not covered by citations.",
                    path=str(report_pack_file) if report_pack_file is not None else None,
                    artifact_path=artifact_path,
                    record_key=record_key,
                    finding_id=proof_row.get("finding_id") or proof_row.get("id"),
                )
                break
            json_pointer = str(proof_row.get("json_pointer") or "").strip()
            if json_pointer and (artifact_path, json_pointer) not in cited_artifact_json_pointers:
                add_issue(
                    "missing_report_pack_proof_json_pointer_citation",
                    "Customer pack source report-pack.json proof_table json_pointer is not covered by citations.",
                    path=str(report_pack_file) if report_pack_file is not None else None,
                    artifact_path=artifact_path,
                    json_pointer=json_pointer,
                    finding_id=proof_row.get("finding_id") or proof_row.get("id"),
                )
                break

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


def _append_reviewer_index_markdown(lines: list[str], payload: Mapping[str, Any]) -> None:
    reviewer_index = dict(payload) if isinstance(payload, Mapping) else {}
    if not reviewer_index:
        return
    lines.extend(["", "## Reviewer Index", ""])
    start_here = _dict_rows(reviewer_index.get("start_here"))
    if start_here:
        lines.append("### Start Here")
        lines.append("")
        for row in start_here:
            lines.append(
                f"- `{_markdown_cell(row.get('section'))}`: {_markdown_cell(row.get('reason'))}"
            )
        lines.append("")
    prove_this = _dict_rows(reviewer_index.get("prove_this"))
    if prove_this:
        lines.append("### Prove This")
        lines.append("")
        lines.append("| Finding | Severity | Proof | Artifact | Record |")
        lines.append("| --- | --- | --- | --- | --- |")
        for row in prove_this:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_value(row.get("finding_id")),
                        _markdown_value(row.get("severity")),
                        _markdown_value(row.get("proof_status")),
                        _markdown_value(row.get("artifact_path")),
                        _markdown_value(row.get("record_key")),
                    ]
                )
                + " |"
            )
        lines.append("")
    known_limits = _dict_rows(reviewer_index.get("known_limits"))
    if known_limits:
        lines.append("### Known Limits")
        lines.append("")
        for row in known_limits:
            lines.append(f"- {_markdown_cell(row.get('status'))}: {_markdown_cell(row.get('message'))}")
        lines.append("")


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
    _append_reviewer_index_markdown(lines, _mapping(selected_sections.get("reviewer_index")))
    _append_mapping_markdown(lines, "Citation Summary", _mapping(selected_sections.get("citation_summary")))
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
        ("citation_summary", "Citation Summary"),
        ("license_profile", "License Profile"),
        ("auditor_score", "Auditor Score"),
        ("control_simulator", "Control Simulator"),
        ("report_qa", "Report QA"),
    ):
        if key in selected_sections:
            sections.append(_render_key_values(title, _mapping(selected_sections.get(key))))
    if "reviewer_index" in selected_sections:
        sections.append(_render_json_section("Reviewer Index", selected_sections.get("reviewer_index")))
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
    run_path = Path(run_dir)
    citations, evidence_missing = _preview_section_citations(
        run_path=run_path,
        bundle=RunBundle(run_path),
        selected_sections=selected,
    )
    renderers = {
        "json": _render_json,
        "md": _render_markdown,
        "csv": _render_csv,
        "html": _render_html,
        "sarif": _render_sarif,
        "oscal": _render_oscal,
    }
    return {
        "format": format_name,
        "content": renderers[format_name](selected),
        "sections": list(selected.keys()),
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
        "evidence_missing": evidence_missing,
    }


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
