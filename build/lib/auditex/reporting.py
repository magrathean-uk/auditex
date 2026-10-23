from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import re
import shutil
from collections.abc import Iterable, Mapping
from io import StringIO
from pathlib import Path
from typing import Any

from azure_tenant_audit.autopilot import build_basic_license_intelligence
from azure_tenant_audit.bundle_integrity import (
    BUNDLE_HASHES_SCHEMA_VERSION,
    integrity_failed,
    is_post_finalization_output,
    listed_artifact_paths,
)
from azure_tenant_audit.citations import build_citation_summary, dedupe_citations
from azure_tenant_audit.private_io import copy_private_file, harden_tree, make_private_dirs, write_private_text
from azure_tenant_audit.resources import resolve_resource_path
from azure_tenant_audit.waivers import accepted_risk_summary

from .run_bundle import RunBundle, summarize_recomputed_validation

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
class BundleIntegrityError(RuntimeError):
    """A customer pack was requested for a bundle that changed since it was finalized or no longer validates.

    ``integrity`` is the hash check; ``validation`` is the recomputed validation (empty when it passed).
    """

    def __init__(self, message: str, integrity: Mapping[str, Any], validation: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.integrity = dict(integrity)
        self.validation = dict(validation or {})


class PackOutputError(RuntimeError):
    """A customer pack was requested into a directory that already holds something that is not a pack."""


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
    "baseline_alignment",
    "report_qa",
    "findings",
    "proof_table",
    "action_plan",
    "api_inventory",
    "normalized",
    "blockers",
    "replay_context",
    "detection_coverage",
    "public_footprint",
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
    "framework_mappings",
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


_TRANSPORT_BASIS = "transport_audit_log"
_DECLARED_BASIS = "coverage_ledger_only"
_REPLAY_BASIS = "offline_replay"


def _observation_basis(safety: Mapping[str, Any]) -> str:
    """``transport_audit_log`` when the safety flags were re-derived from the run's audit log, ``offline_replay``
    when the run replayed a saved sample (no tenant, so nothing was observed), else the declared basis."""
    basis = str(safety.get("observation_basis") or "")
    return basis if basis in {_TRANSPORT_BASIS, _REPLAY_BASIS} else _DECLARED_BASIS


def _replay_text(safety: Mapping[str, Any]) -> str:
    """What an offline replay says about itself: where the evidence came from and that no tenant was contacted."""
    source = _text(safety.get("replay_source")).strip()
    origin = f"replayed from {source}" if source else "replayed from an offline sample file"
    return f"{origin}, no tenant contact"


def _flag_text(value: Any, basis: str, safety: Mapping[str, Any] | None = None) -> str:
    """A safety flag with what it rests on, so a declaration or a replay never reads as an observed fact."""
    if basis == _TRANSPORT_BASIS:
        qualifier = "observed in the transport audit log"
    elif basis == _REPLAY_BASIS:
        qualifier = _replay_text(safety or {})
    else:
        qualifier = "declared, not observed"
    return f"{_markdown_cell(value)} ({qualifier})"


def _basis_text(basis: str, safety: Mapping[str, Any] | None = None) -> str:
    if basis == _TRANSPORT_BASIS:
        return (
            "transport_audit_log: Graph requests and tenant commands only. DNS, exposure and Power Platform "
            "lookups are outside the ledger."
        )
    if basis == _REPLAY_BASIS:
        return (
            f"offline_replay: the evidence was {_replay_text(safety or {})}. No transport ledger observed any "
            "call, so the flags describe the replay and say nothing about how a tenant was read."
        )
    return (
        "coverage_ledger_only: the flags rest on declared collector rows and scopes. No transport ledger "
        "observed these calls."
    )


def _safety_lines(safety: Mapping[str, Any]) -> list[str]:
    basis = _observation_basis(safety)
    return [
        f"- Read-only: {_flag_text(safety.get('read_only'), basis, safety)}",
        f"- No content reads: {_flag_text(safety.get('no_content_reads'), basis, safety)}",
        f"- Observation basis: {_basis_text(basis, safety)}",
    ]


def _scope_risk_limitation(
    *,
    platform: str,
    scope_risk: str | None,
    write_capable_scopes: list[str],
    safety: Mapping[str, Any] | None = None,
    read_only: bool | None = None,
) -> dict[str, Any] | None:
    if not scope_risk:
        return None
    provider = _provider_label(platform)
    basis = _observation_basis(safety or {})
    if scope_risk == "write_capable_scope_present":
        subject = f"{provider} auth included write-capable scopes."
        closing = "reviewers should treat the scope set as a higher-trust limitation."
    elif scope_risk == "content_capable_scope_present":
        subject = f"{provider} auth included scopes that can read content (for example Drive readonly); Auditex uses metadata and list endpoints only."
        closing = "reviewers should confirm the scope set matches the intended audit surface."
    else:
        subject = f"{provider} read settings can require broad scopes."
        closing = "reviewers should confirm the scope set matches the intended audit surface."
    if read_only is False:
        observation = "The recorded safety flags say the run was not read-only, so do not rely on read-only behaviour;"
    elif basis == _REPLAY_BASIS:
        observation = (
            f"The evidence was {_replay_text(safety or {})}, so nothing was observed about calls to a tenant "
            "and the scope set describes the replayed sample;"
        )
    elif basis == _TRANSPORT_BASIS:
        observation = (
            "The transport audit log recorded no write, refused or content-reading Graph request or tenant command "
            "(DNS, exposure and Power Platform lookups are outside it);"
        )
    else:
        observation = (
            "Whether Auditex stayed read-only was not observed for this run (only declared collector rows and "
            "scopes exist);"
        )
    limitation = {
        "surface": "scope_risk",
        "status": scope_risk,
        "message": f"{subject} {observation} {closing}",
        "observation_basis": basis,
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
        "baseline_alignment",
        "report_qa",
        "replay_context",
        "detection_coverage",
        "public_footprint",
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
        "baseline_alignment",
        "report_qa",
        "replay_context",
        "detection_coverage",
        "public_footprint",
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


def _replay_source_file(bundle: RunBundle, inventory: Mapping[str, Any] | None = None) -> str | None:
    """The sample file name an offline run was replayed from (``""`` when the run was a replay but it is not recorded).

    ``None`` for a run that was not a replay. Taken from ``run-manifest.json`` (``replay_source``), then the
    ledger's safety block, then the audit log's ``run.started`` event, so a bundle written before the manifest
    recorded it still says what it was replayed from.
    """
    manifest = bundle.manifest()
    source = _mapping(manifest.get("replay_source"))
    if _text(manifest.get("mode")) != "offline" and not source:
        return None
    name = _text(source.get("file")) or _text(_mapping(_mapping(inventory).get("safety")).get("replay_source"))
    if not name:
        from azure_tenant_audit.api_inventory import read_audit_events

        for event in read_audit_events(bundle.path("audit-log.jsonl")):
            if event.get("event") == "run.started":
                name = Path(_text(_mapping(event.get("details")).get("sample"))).name
                break
    return Path(name).name if name else ""


def api_call_inventory(run_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    bundle = RunBundle(run_path)
    path, payload = bundle.api_inventory()
    inventory = _mapping(payload)
    replay_file = _replay_source_file(bundle, inventory)
    if replay_file is not None and inventory:
        # A replay has no tenant traffic: whatever basis an older bundle recorded, it never counts as observed.
        inventory = {
            **inventory,
            "safety": {**_mapping(inventory.get("safety")), "observation_basis": _REPLAY_BASIS, "replay_source": replay_file},
        }
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


def _integrity_summary(result: Mapping[str, Any]) -> dict[str, Any]:
    """The hash check as the handoff and the customer pack carry it."""
    status = str(result.get("status") or "absent")
    modified = [str(row.get("path")) for row in result.get("modified") or [] if isinstance(row, Mapping)]
    missing = [str(item) for item in result.get("missing") or []]
    symlinks = [str(item) for item in result.get("symlinks") or []]
    unexpected = [str(item) for item in result.get("unexpected") or []]
    if status == "verified":
        text = f"{result.get('checked_count')} artifact(s) match the hashes recorded when the run was finalized."
    elif status == "mismatch":
        sentences = []
        if result.get("modified_count") or result.get("missing_count") or not (symlinks or unexpected):
            sentences.append(
                f"{result.get('modified_count')} artifact(s) changed and {result.get('missing_count')} are missing "
                "since the run was finalized."
            )
        if result.get("symlink_count"):
            sentences.append(f"{result.get('symlink_count')} symbolic link(s) sit in the run; links are never followed or trusted.")
        if result.get("unexpected_count"):
            sentences.append(
                f"{result.get('unexpected_count')} file(s) that the hash manifest does not list sit at paths the product reads."
            )
        text = " ".join(sentences)
    elif status == "invalid":
        text = str(result.get("message") or "The bundle hash manifest cannot be read.")
    else:
        text = "No bundle hash manifest: this run was finalized before one was written, so its artifacts cannot be checked."
    return {
        "status": status,
        "summary": text,
        "path": result.get("path"),
        "algorithm": result.get("algorithm"),
        "checked_count": result.get("checked_count"),
        "modified_count": result.get("modified_count"),
        "missing_count": result.get("missing_count"),
        "unlisted_count": result.get("unlisted_count"),
        "symlink_count": result.get("symlink_count"),
        "unexpected_count": result.get("unexpected_count"),
        "manifest_missing": bool(result.get("manifest_missing")),
        "modified_paths": modified,
        "missing_paths": missing,
        "unlisted_paths": [str(item) for item in result.get("unlisted") or []],
        "symlink_paths": symlinks,
        "unexpected_paths": unexpected,
        "manifest_sha256": result.get("manifest_sha256"),
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
        safety=api_safety,
        read_only=data_handling.get("read_only") is not False and api_safety.get("read_only") is not False,
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

    integrity = _integrity_summary(bundle.integrity())
    if integrity_failed(integrity):
        limitations.append(
            {
                "surface": "bundle_integrity",
                "status": integrity["status"],
                "message": integrity["summary"],
                "paths": [
                    *integrity["modified_paths"],
                    *integrity["missing_paths"],
                    *integrity["symlink_paths"],
                    *integrity["unexpected_paths"],
                ][:10],
            }
        )
    # Reports the tooling wrote into the run after it was finalized (the explorer page, rendered reports, the
    # handoff and its companions) are readable by an assessor but not hashed: writing them into the manifest
    # would change its digest after it was handed over. They are named so nobody mistakes them for evidence.
    unhashed_outputs = [path for path in integrity["unlisted_paths"] if is_post_finalization_output(path)]
    if unhashed_outputs:
        limitations.append(
            {
                "surface": "bundle_integrity",
                "status": "unhashed_outputs",
                "message": (
                    f"{len(unhashed_outputs)} report file(s) in the run were written after it was finalized and are not "
                    f"in bundle-hashes.json ({', '.join(unhashed_outputs[:5])}"
                    + (f" and {len(unhashed_outputs) - 5} more" if len(unhashed_outputs) > 5 else "")
                    + "): nothing proves they match the run's evidence, and they are not copied into a customer pack. "
                    "Regenerate them from the run before relying on them."
                ),
                "paths": unhashed_outputs[:10],
            }
        )
    if not integrity_failed(integrity):
        # Files the hash manifest does not name, other than the outputs the tooling writes on request, were not
        # checked and are not copied into a customer pack.
        unlisted_files = [path for path in integrity["unlisted_paths"] if not is_post_finalization_output(path)]
        if unlisted_files:
            limitations.append(
                {
                    "surface": "bundle_integrity",
                    "status": "unlisted_files",
                    "message": (
                        f"{len(unlisted_files)} file(s) in the run are not in bundle-hashes.json, so they were not "
                        "checked and are not copied into a customer pack."
                    ),
                    "paths": unlisted_files[:10],
                }
            )
    recomputed = _mapping(bundle.recomputed_validation())
    recomputed_summary = summarize_recomputed_validation(recomputed, validation)
    recomputed_failed = recomputed.get("valid") is False
    if recomputed_failed:
        limitations.append(
            {
                "surface": "contract_validation",
                "status": "legacy_unresolved_refs" if recomputed_summary["only_legacy_unresolved_refs"] else "recomputed_invalid",
                "message": recomputed_summary["summary"],
                "error_count": recomputed_summary["error_count"],
                "legacy_unresolved_ref_count": recomputed_summary["legacy_unresolved_ref_count"],
            }
        )
    validation_valid = validation.get("valid") if validation else None
    read_only = data_handling.get("read_only") is not False and api_safety.get("read_only") is not False
    no_content_reads = data_handling.get("content_reads") is not True and api_safety.get("no_content_reads") is not False
    write_actions = data_handling.get("write_actions") is True or api_safety.get("write_actions") is True
    unsupported_claims = [str(item) for item in proof.get("unsupported_claims") or [] if str(item)]

    status_reasons = [
        reason
        for reason, failed in (
            ("validation_invalid", validation_valid is False),
            (
                "legacy_unresolved_refs" if recomputed_summary["only_legacy_unresolved_refs"] else "recomputed_validation_failed",
                recomputed_failed,
            ),
            (f"bundle_integrity_{integrity['status']}", integrity_failed(integrity)),
            ("not_read_only", not read_only),
            ("content_reads", not no_content_reads),
            ("write_actions", write_actions),
        )
        if failed
    ]
    if status_reasons:
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
        "status_reasons": status_reasons,
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
            "recomputed": recomputed_summary,
        },
        "integrity": integrity,
        "validation_summary": validation_summary,
        "safety": {
            "read_only": read_only,
            "no_content_reads": no_content_reads,
            "write_actions": write_actions,
            "scope_risk": scope_risk,
            "write_capable_scopes": write_capable_scopes,
            "observation_basis": _observation_basis(api_safety),
            "replay_source": api_safety.get("replay_source") if _observation_basis(api_safety) == _REPLAY_BASIS else None,
            "observed_log_complete": api_safety.get("observed_log_complete"),
        },
        "quality": {
            "audit_plan_status": _mapping(audit_plan.get("quality_gate")).get("status"),
            "live_readiness": live_readiness.get("trust_level") or _offline_live_readiness(manifest, summary, metadata),
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
            # ``api_calls`` keeps its meaning: the declared call rows. The observed figures come from the transport ledger.
            "api_calls": int(_mapping(api.get("counts")).get("observed_calls") or len(_dict_rows(api.get("observed_calls")))),
            "declared_calls": int(_mapping(api.get("counts")).get("observed_calls") or len(_dict_rows(api.get("observed_calls")))),
            "observed_graph_requests": _mapping(api.get("counts")).get("observed_graph_requests"),
            "observed_commands": _mapping(api.get("counts")).get("observed_commands"),
            "observed_outside_declared": _mapping(api.get("counts")).get("observed_outside_declared"),
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


def _status_counts_text(statuses: Any) -> str:
    if not isinstance(statuses, Mapping) or not statuses:
        return ""
    return ", ".join(f"{key}: {statuses[key]}" for key in sorted(statuses, key=str))


def _ledger_summary_lines(inventory: Mapping[str, Any]) -> list[str]:
    """The headline figures of the transport-observed ledger, or a plain statement that there is none."""
    ledger = _mapping(inventory.get("observed_ledger"))
    counts = _mapping(inventory.get("counts"))
    safety = _mapping(inventory.get("safety"))
    if _observation_basis(safety) == _REPLAY_BASIS:
        return [f"- Observed calls: none ({_replay_text(safety)}; there was no tenant traffic to observe)"]
    if not ledger:
        return ["- Observed calls: no transport ledger in this bundle (the call list is declared, not observed)"]
    if _observation_basis(safety) != _TRANSPORT_BASIS:
        return ["- Observed calls: none (this provider's calls are not instrumented; the call list is declared, not observed)"]
    return [
        f"- Observed Graph requests: {_markdown_cell(counts.get('observed_graph_requests'))}",
        f"- Observed commands: {_markdown_cell(counts.get('observed_commands'))}",
        f"- Observed calls outside the declared set: {_markdown_cell(counts.get('observed_outside_declared'))}",
        f"- Refused calls: {_markdown_cell(counts.get('refused_calls'))}",
    ]


def _observed_ledger_markdown(inventory: Mapping[str, Any], *, level: str = "##") -> list[str]:
    """The transport-observed ledger as Markdown: what the audit log shows was sent, not what collectors declared."""
    ledger = _mapping(inventory.get("observed_ledger"))
    safety = _mapping(inventory.get("safety"))
    lines = ["", f"{level} Observed calls (transport ledger)", ""]
    if _observation_basis(safety) == _REPLAY_BASIS:
        lines.append(
            f"No transport ledger applies: the evidence was {_replay_text(safety)}. The declared call list above is "
            "what the collectors report for the replayed sample, not a record of requests sent."
        )
        return lines
    if not ledger:
        lines.append(
            "No transport ledger in this bundle: the call list above is declared by the collectors, not observed. "
            "Do not read it as a record of what was sent."
        )
        return lines
    log = _mapping(ledger.get("log"))
    graph = _mapping(ledger.get("graph"))
    commands = _mapping(ledger.get("commands"))
    outside = _mapping(ledger.get("outside_declared"))
    basis = str(ledger.get("basis") or "")
    lines.append(f"- Basis: {_markdown_cell(basis)}")
    if basis != "transport_audit_log":
        lines.append(
            "- This provider's calls are not instrumented. Nothing below was observed; the declared call list is the "
            "only record, and it is declared, not observed."
        )
        return lines
    lines.extend(
        [
            f"- Audit log complete: {_markdown_cell(safety.get('observed_log_complete'))}"
            f" (readable: {_markdown_cell(log.get('readable'))}, malformed lines: {_markdown_cell(log.get('malformed_lines'))})",
            f"- Graph requests attempted: {_markdown_cell(graph.get('request_attempts'))}"
            f" (batch requests: {_markdown_cell(graph.get('batch_requests'))},"
            f" inner calls: {_markdown_cell(graph.get('batch_inner_requests'))},"
            f" unverified batches: {_markdown_cell(graph.get('unverified_batch_requests'))})",
            f"- Methods seen: {_markdown_cell(', '.join(str(item) for item in graph.get('methods_seen') or []))}",
            f"- Commands executed: {_markdown_cell(sum(int(row.get('count') or 0) for row in _dict_rows(commands.get('executed'))))}",
            f"- Refused calls: {_markdown_cell(int(graph.get('refused_count') or 0) + int(commands.get('refused_count') or 0))}",
            f"- Calls outside the declared set: {_markdown_cell(outside.get('count'))}",
        ]
    )
    lines.extend(["", f"{level}# Graph requests", "", "| Method | Endpoint | API version | Count | Statuses |", "| --- | --- | --- | --- | --- |"])
    graph_rows = _dict_rows(graph.get("endpoints"))
    if graph_rows:
        for row in graph_rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("method")),
                        _markdown_cell(row.get("endpoint")),
                        _markdown_cell(row.get("api_version")),
                        _markdown_cell(row.get("count")),
                        _markdown_cell(_status_counts_text(row.get("statuses"))),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  |  |  | No Graph requests in the audit log. |  |")
    lines.extend(["", f"{level}# Commands", "", "| Adapter | Command | Count | Statuses | Read-only |", "| --- | --- | --- | --- | --- |"])
    command_rows = _dict_rows(commands.get("executed"))
    if command_rows:
        for row in command_rows:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _markdown_cell(row.get("adapter")),
                        _markdown_cell(row.get("command")),
                        _markdown_cell(row.get("count")),
                        _markdown_cell(_status_counts_text(row.get("statuses"))),
                        _markdown_cell(row.get("read_only")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("|  | No commands in the audit log. |  |  |  |")
    refused = [
        *({"kind": "graph", "call": f"{row.get('method')} {row.get('endpoint')}", "reason": row.get("reason")} for row in _dict_rows(graph.get("refused"))),
        *({"kind": "command", "call": f"{row.get('adapter')} {row.get('command')}", "reason": row.get("reason")} for row in _dict_rows(commands.get("refused"))),
    ]
    outside_rows = [
        *({"kind": "graph", "call": f"{row.get('method')} {row.get('endpoint')}"} for row in _dict_rows(outside.get("graph"))),
        *({"kind": "command", "call": f"{row.get('adapter')} {row.get('command')}"} for row in _dict_rows(outside.get("commands"))),
    ]
    if refused:
        lines.extend(["", f"{level}# Refused calls", "", "| Kind | Call | Reason |", "| --- | --- | --- |"])
        for row in refused:
            lines.append(f"| {_markdown_cell(row['kind'])} | {_markdown_cell(row['call'])} | {_markdown_cell(row['reason'])} |")
    if outside_rows:
        lines.extend(["", f"{level}# Calls outside the declared set", "", "| Kind | Call |", "| --- | --- |"])
        for row in outside_rows:
            lines.append(f"| {_markdown_cell(row['kind'])} | {_markdown_cell(row['call'])} |")
    return lines


def render_api_call_inventory_markdown(inventory: Mapping[str, Any]) -> str:
    calls = _dict_rows(inventory.get("observed_calls"))
    counts = _mapping(inventory.get("counts"))
    safety = _mapping(inventory.get("safety"))
    lines = [
        "# Auditex API Call Inventory",
        "",
        f"- Run: {_markdown_cell(inventory.get('run_dir'))}",
        f"- Platform: {_markdown_cell(inventory.get('platform'))}",
        f"- Declared calls: {_markdown_cell(counts.get('observed_calls', len(calls)))} (collector coverage rows: what the collectors report having run)",
        f"- Beta Graph calls: {_markdown_cell(counts.get('beta_calls', sum(1 for call in calls if call.get('api_version') == 'beta')))}",
        *_safety_lines(safety),
        *_ledger_summary_lines(inventory),
        "",
        "## Declared calls",
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
        lines.append("|  |  | No declared calls in this bundle. |  |  |  |")
    lines.extend(_observed_ledger_markdown(inventory))
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


def _handoff_call_lines(counts: Mapping[str, Any], safety: Mapping[str, Any]) -> list[str]:
    declared = counts.get("declared_calls", counts.get("api_calls"))
    lines = [f"- Declared calls: {_markdown_cell(declared)} (collector coverage rows, not a record of what was sent)"]
    if _observation_basis(safety) == _REPLAY_BASIS:
        lines.append(f"- Observed calls: none ({_replay_text(safety)})")
    elif _observation_basis(safety) == _TRANSPORT_BASIS and counts.get("observed_graph_requests") is not None:
        lines.extend(
            [
                f"- Observed Graph requests: {_markdown_cell(counts.get('observed_graph_requests'))}",
                f"- Observed commands: {_markdown_cell(counts.get('observed_commands'))}",
                f"- Observed calls outside the declared set: {_markdown_cell(counts.get('observed_outside_declared'))}",
            ]
        )
    else:
        lines.append("- Observed calls: none recorded (the declared calls are declared, not observed)")
    return lines


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
        f"- Status: {_markdown_cell(payload.get('handoff_status'))}"
        + (f" ({_markdown_cell(', '.join(payload.get('status_reasons') or []))})" if payload.get("status_reasons") else ""),
        f"- Tenant: {_markdown_cell(tenant.get('name'))}",
        f"- Platform: {_markdown_cell(tenant.get('platform'))}",
        f"- Contract valid: {_markdown_cell(contract.get('valid'))}",
        f"- Validation: {_markdown_cell(validation_summary.get('status'))} / {_markdown_cell(validation_summary.get('issue_count'))} issues",
        f"- Recomputed validation: {_markdown_cell(_mapping(contract.get('recomputed')).get('valid'))}",
        f"- Bundle integrity: {_markdown_cell(_mapping(payload.get('integrity')).get('status'))}",
        *_safety_lines(safety),
        f"- Audit quality: {_markdown_cell(quality.get('audit_plan_status'))}",
        f"- Live readiness: {_markdown_cell(quality.get('live_readiness')) or 'not recorded'}",
        f"- Findings: {_markdown_cell(counts.get('findings'))}",
        f"- Proof rows: {_markdown_cell(counts.get('proof_rows'))}",
        *_handoff_call_lines(counts, safety),
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
    write_private_text(path, content)
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
    ("bundle-hashes.json", "SHA-256 of every run artifact as it was when the run was finalized."),
)


def _plain_run_file(run_path: Path, relative: str) -> tuple[Path | None, str | None]:
    """The regular file ``relative`` names in the run, or ``(None, reason)``. A link, or a link anywhere on the path, is refused."""
    root = Path(os.path.realpath(run_path))
    candidate = root / relative
    if os.path.islink(candidate) or Path(os.path.realpath(candidate)) != candidate:
        return None, "symbolic_link"
    if not candidate.is_file():
        return None, "missing"
    return candidate, None


# The one source artifact that records where the operator ran the audit. It is copied with those paths made
# pack-relative, and says so (``transformed``), so ``verify-pack`` can still tie it to ``bundle-hashes.json``.
_PACK_RELATIVE_PATHS = "pack_relative_paths"
_LOCAL_PATH_LABEL = "<local-path>"


_LOCAL_ABSOLUTE_PATH = re.compile(r"^(?:/|[A-Za-z]:[\\/])")


def _local_path_label(value: Any) -> Any:
    """An absolute path of the operator's machine as ``<local-path>/<name>``; anything else unchanged."""
    if isinstance(value, str) and _LOCAL_ABSOLUTE_PATH.match(value):
        name = re.split(r"[\\/]", value.rstrip("\\/"))[-1]
        return f"{_LOCAL_PATH_LABEL}/{name}" if name else _LOCAL_PATH_LABEL
    return value


def _pack_relative_run_manifest(payload: Mapping[str, Any], run_path: Path) -> dict[str, Any]:
    """``run-manifest.json`` for a customer: no absolute path of the machine that ran the audit.

    Paths below the run become run-relative and ``run_dir`` the run folder name (as in the handoff). Paths the
    run was given elsewhere (the waiver file, the command line) keep only their file name.
    """
    safe = _pack_payload(payload, run_path)
    if "run_dir" in payload:
        safe["run_dir"] = run_path.name
    if isinstance(safe.get("waiver_path"), str):
        safe["waiver_path"] = _local_path_label(safe["waiver_path"])
    if isinstance(safe.get("command_line"), list):
        safe["command_line"] = [_local_path_label(item) for item in safe["command_line"]]
    return safe


def _copy_source_artifact(
    run_path: Path,
    output_root: Path,
    relative: str,
    purpose: str,
    listed: set[str] | None = None,
) -> dict[str, Any]:
    """Copy one run artifact into the pack as a private file.

    A link is never followed. When the run has a hash manifest (``listed`` is its path set), only a file the
    manifest names is copied: the pack vouches for what the run produced, not for what was added later.
    ``run-manifest.json`` is the exception to "byte for byte": it records the operator's absolute run path, which
    a pack for a customer must not carry, so the copy has paths made pack-relative. Its row then has
    ``transformed: "pack_relative_paths"`` and ``source_sha256``, the digest of the run's own file (the one
    ``bundle-hashes.json`` lists), and ``sha256``, the digest of the copy.
    """
    source, reason = _plain_run_file(run_path, relative)
    row: dict[str, Any] = {
        "source_path": relative,
        "purpose": purpose,
        "present": False,
        "customer_safe": True,
    }
    if source is None:
        if reason != "missing":
            row["skipped_reason"] = reason
        return row
    if listed is not None and relative != "bundle-hashes.json" and relative not in listed:
        row["skipped_reason"] = "not_in_bundle_hashes"
        return row
    destination = output_root / relative
    payload = _read_json(source, None) if relative == "run-manifest.json" else None
    if isinstance(payload, Mapping):
        row["source_sha256"] = _sha256_file(source)
        row["transformed"] = _PACK_RELATIVE_PATHS
        write_private_text(destination, json.dumps(_pack_relative_run_manifest(payload, run_path), indent=2, ensure_ascii=False) + "\n")
    else:
        copy_private_file(source, destination)
    row.update(
        {
            "present": True,
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
    """Where a manifest row's file sits in the pack now.

    Packs write pack-relative paths (``handoff.md``) with ``output_dir`` ``.``. Packs written before that
    carry the paths as the writer was given them, absolute or relative to its working directory; they are
    re-rooted on ``pack_dir`` so a pack that was moved still verifies.
    """
    if not value:
        return None
    path = Path(str(value))
    if path.is_absolute():
        try:
            return pack_dir / path.relative_to(manifest_output_dir)
        except ValueError:
            return path
    if ".." in path.parts:
        return None
    if manifest_output_dir.parts:
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
        f"- Bundle integrity: {_markdown_cell(_mapping(source.get('integrity')).get('status'))}",
        *_safety_lines(safety),
        f"- Audit quality: {_markdown_cell(quality.get('audit_plan_status'))}",
        f"- Findings: {_markdown_cell(counts.get('findings'))}",
        *_handoff_call_lines(counts, safety),
        f"- Reviewer prove-this rows: {_markdown_cell(_mapping(reviewer_summary.get('counts')).get('prove_this'))}",
        "",
        "## Start Here",
        "",
        "1. Read `handoff.md`.",
        "2. Check `validation.json` and the validation summary before trusting the pack.",
        "3. Review `report.md` for the client-ready report and reviewer index.",
        "4. Review `api-calls.md`: the declared calls and, where the run has a transport ledger, every Graph request and command the audit log observed, with any call outside the declared set.",
        "5. Review `permissions.md` for required and missing scopes.",
        "6. Review `proof-table.md` for finding-to-evidence rows.",
        "7. Run `auditex report verify-pack <pack-dir>` or use `checksums.sha256` to verify file integrity. "
        "The pack carries its own checksums, so where origin matters compare the `digests` that command prints with values you "
        "received through a separate channel, or pass them as `--expect-manifest-sha256` and `--expect-checksums-sha256`.",
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
    transformed = [row for row in sources if row.get("transformed")]
    if transformed:
        lines.extend(
            [
                "",
                "`source-artifacts/run-manifest.json` is the run's manifest with the paths of the machine that ran the audit "
                "made pack-relative. `pack-manifest.json` records the SHA-256 of the run's own file as `source_sha256` (the "
                "value `bundle-hashes.json` lists); as copied, the file is covered by `checksums.sha256`.",
            ]
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


_PACK_KIND = "auditex_enterprise_handoff_pack"
_RUN_DIR_PLACEHOLDER = "<run-dir>"


def _run_path_roots(run_path: Path) -> list[str]:
    """Every spelling of the run directory a payload may carry, longest first."""
    roots = {str(run_path), os.path.abspath(run_path), os.path.realpath(run_path)}
    return sorted((root.rstrip(os.sep) for root in roots if root and root != os.sep), key=len, reverse=True)


def _scrub_run_path(text: str, roots: list[str]) -> str:
    """Remove the operator's local run path from text: paths below the run become run-relative, the run ``<run-dir>``."""
    for root in roots:
        if text == root:
            return _RUN_DIR_PLACEHOLDER
        if text.startswith(root + os.sep):
            return text[len(root) + 1 :]
    for root in roots:
        text = text.replace(root, _RUN_DIR_PLACEHOLDER)
    return text


def _pack_safe(value: Any, run_path: Path, *, roots: list[str] | None = None) -> Any:
    """A copy of ``value`` with no absolute path of the operator's machine in it (the pack goes to a customer)."""
    roots = roots if roots is not None else _run_path_roots(run_path)
    if isinstance(value, str):
        return _scrub_run_path(value, roots)
    if isinstance(value, Mapping):
        return {key: _pack_safe(item, run_path, roots=roots) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_pack_safe(item, run_path, roots=roots) for item in value]
    return value


def _pack_payload(payload: Mapping[str, Any], run_path: Path) -> dict[str, Any]:
    safe = _pack_safe(dict(payload), run_path)
    if "run_dir" in safe:
        safe["run_dir"] = run_path.name
    return safe


def _prepare_pack_directory(target_dir: Path) -> None:
    """Create the pack directory, or reuse one that is empty or holds a pack written earlier.

    Anything else is refused: files a previous owner left would sit next to the pack's own and look like
    part of it. A previous pack's ``source-artifacts`` are removed, so a file the new run no longer has
    does not stay behind.
    """
    if target_dir.is_symlink() or (target_dir.exists() and not target_dir.is_dir()):
        raise PackOutputError(f"refusing to write a customer pack to {target_dir}: it is not a directory.")
    if not target_dir.exists():
        make_private_dirs(target_dir)
        return
    if not any(target_dir.iterdir()):
        return
    previous = _mapping(_read_json(target_dir / "pack-manifest.json", {}))
    if previous.get("kind") != _PACK_KIND:
        raise PackOutputError(
            f"refusing to write a customer pack into {target_dir}: it is not empty and holds no earlier pack "
            "(no pack-manifest.json). Use a new directory."
        )
    stale = target_dir / "source-artifacts"
    if stale.is_symlink():
        stale.unlink()
    elif stale.is_dir():
        shutil.rmtree(stale)


def write_enterprise_handoff_pack(run_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    run_path = Path(run_dir)
    target_dir = Path(output_dir)

    handoff_payload = enterprise_handoff(run_path)
    integrity = _mapping(handoff_payload.get("integrity"))
    recomputed = _mapping(_mapping(handoff_payload.get("contract")).get("recomputed"))
    # A pack vouches for the bundle it was built from: refuse one that changed since it was finalized
    # (a link, or an unlisted file where the product reads, counts as a change), and one that does not
    # validate as it stands (whatever validation.json recorded).
    if integrity_failed(integrity):
        raise BundleIntegrityError(
            f"refusing to create a customer pack from {run_path}: {integrity.get('summary')}",
            integrity,
            recomputed if recomputed.get("valid") is False else None,
        )
    if recomputed.get("valid") is False:
        raise BundleIntegrityError(
            f"refusing to create a customer pack from {run_path}: {recomputed.get('summary')}",
            integrity,
            recomputed,
        )
    _prepare_pack_directory(target_dir)
    # Everything the pack carries is pack-relative and free of the operator's local paths.
    handoff_payload = _pack_payload(handoff_payload, run_path)
    integrity = _mapping(handoff_payload.get("integrity"))
    api_payload = _pack_payload(api_call_inventory(run_path), run_path)
    permissions_payload = _pack_payload(permissions_ledger(run_path), run_path)
    proof_payload = _pack_payload(proof_table(run_path), run_path)
    rendered_report = _pack_safe(preview_report(run_dir=str(run_path), format_name="md")["content"], run_path)

    def generated_row(name: str, content: str) -> dict[str, Any]:
        row = _write_text_artifact(target_dir / name, content)
        row["path"] = name
        return row

    generated = [
        generated_row("handoff.md", render_enterprise_handoff_markdown(handoff_payload)),
        generated_row("handoff.json", _json(handoff_payload) + "\n"),
        generated_row("report.md", rendered_report),
        generated_row("api-calls.md", render_api_call_inventory_markdown(api_payload)),
        generated_row("api-calls.json", _json(api_payload) + "\n"),
        generated_row("permissions.md", render_permissions_ledger_markdown(permissions_payload)),
        generated_row("permissions.json", _json(permissions_payload) + "\n"),
        generated_row("proof-table.md", render_proof_table_markdown(proof_payload)),
        generated_row("proof-table.json", _json(proof_payload) + "\n"),
    ]
    source_dir = target_dir / "source-artifacts"
    listed = listed_artifact_paths(run_path)
    source_artifacts = []
    for relative, purpose in _CUSTOMER_SAFE_SOURCE_ARTIFACTS:
        row = _copy_source_artifact(run_path, source_dir, relative, purpose, listed)
        if row.get("path"):
            row["path"] = f"source-artifacts/{relative}"
        source_artifacts.append(row)
    manifest = {
        "schema_version": "2026-10-22",
        "kind": _PACK_KIND,
        "path_style": "pack_relative",
        "run_dir": run_path.name,
        "output_dir": ".",
        "handoff_status": handoff_payload.get("handoff_status"),
        "source": {
            "tenant": handoff_payload.get("tenant"),
            "contract": handoff_payload.get("contract"),
            "integrity": integrity,
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
    readme["path"] = "README.md"
    manifest["generated_files"].append(readme)
    checksum = _write_checksums(
        target_dir,
        [*manifest["generated_files"], *[row for row in source_artifacts if row.get("present")]],
    )
    checksum["path"] = "checksums.sha256"
    manifest["generated_files"].append(checksum)
    manifest_path = target_dir / "pack-manifest.json"
    manifest["pack_manifest_path"] = "pack-manifest.json"
    write_private_text(manifest_path, _json(manifest) + "\n")
    harden_tree(target_dir)
    # The caller gets the pack's location; the file on disk keeps pack-relative paths only.
    return {**manifest, "pack_dir": str(target_dir), "pack_manifest_path": str(manifest_path)}


def _bundle_hash_rows(path: Path) -> dict[str, str] | None:
    """``path -> sha256`` from a copied ``bundle-hashes.json``, or ``None`` when it is not a hash manifest."""
    payload = _read_json(path, None)
    rows = payload.get("artifacts") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list):
        return None
    result: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("path"), str) or not isinstance(row.get("sha256"), str):
            return None
        result[row["path"]] = row["sha256"]
    return result


def _merge_pack_issues(issues: list[dict[str, Any]], pack_path: Path) -> list[dict[str, Any]]:
    """Report each problem once, with pack-relative paths, listing every check that caught it."""
    pack_root = pack_path.resolve()
    pack_spelled = Path(os.path.abspath(pack_path))
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for issue in issues:
        path = issue.get("path")
        if isinstance(path, str) and path:
            try:
                # As spelled first, so a symbolic link is reported where it sits and not as the file it points to.
                issue = {**issue, "path": Path(os.path.abspath(path)).relative_to(pack_spelled).as_posix()}
            except ValueError:
                try:
                    issue = {**issue, "path": Path(path).resolve().relative_to(pack_root).as_posix()}
                except ValueError:
                    pass
        key = (issue.get("code"), issue.get("path"), issue.get("expected"), issue.get("actual"))
        if issue.get("path") is None or key not in merged:
            merged[key if issue.get("path") is not None else (len(merged), id(issue))] = issue
            continue
        existing = merged[key]
        sources = existing.setdefault("sources", [existing["source"]] if existing.get("source") else [])
        if issue.get("source") and issue["source"] not in sources:
            sources.append(issue["source"])
    return list(merged.values())


def verify_enterprise_handoff_pack(
    pack_dir: str | Path,
    *,
    expect_manifest_sha256: str | None = None,
    expect_checksums_sha256: str | None = None,
) -> dict[str, Any]:
    """Check a customer pack against its own manifest, checksums and copied hash manifest.

    ``expect_manifest_sha256`` is the SHA-256 of the run's ``bundle-hashes.json`` and
    ``expect_checksums_sha256`` the SHA-256 of the pack's ``checksums.sha256``, each received over a separate
    channel. The pack carries its own copies of both, so a pack edited and re-hashed by someone who can write to
    it agrees with itself and only these two values (see ``digests`` in the result) can say otherwise.
    """
    pack_path = Path(pack_dir)
    manifest_path = pack_path / "pack-manifest.json"
    manifest = _mapping(_read_json(manifest_path, {}))
    issues: list[dict[str, Any]] = []
    checked_files: set[str] = set()
    listed_paths: set[Path] = {manifest_path.resolve()}

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
        generated_file = _pack_file_path(pack_path, manifest_output_dir, row.get("path"))
        if generated_file is not None:
            listed_paths.add(generated_file.resolve())
        check_file(
            generated_file,
            _text(row.get("sha256")) or None,
            source=f"manifest.generated:{row.get('name') or row.get('path')}",
        )

    for row in sources:
        if row.get("present") is False:
            continue
        source_file = _pack_file_path(pack_path, manifest_output_dir, row.get("path"))
        if source_file is not None:
            listed_paths.add(source_file.resolve())
        check_file(
            source_file,
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
    manifest_integrity = _mapping(source_payload.get("integrity"))
    if manifest_integrity and manifest_integrity != _mapping(handoff_payload.get("integrity")):
        add_issue(
            "invalid_manifest_integrity",
            "pack-manifest.json integrity does not match handoff.json.",
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

    if checksum_path.exists():
        listed_paths.add(checksum_path.resolve())

    # The hash manifest the pack carries says what every run artifact was when the run was finalized. The pack's
    # own manifest and checksums sit in the same directory and can be re-hashed together; this cannot, without
    # also changing the manifest digest that was sent separately. It is checked whenever the pack carries it,
    # whatever status the (editable) pack manifest and handoff.json claim: otherwise a pack edited to say its run
    # was "absent" or "mismatch" would skip the one check that the genuine digest makes decisive.
    integrity_status = str(_mapping(source_payload.get("integrity")).get("status") or _mapping(handoff_payload.get("integrity")).get("status") or "")
    bundle_hashes_path = pack_path / "source-artifacts" / "bundle-hashes.json"
    bundle_hashes_sha256 = _sha256_file(bundle_hashes_path) if bundle_hashes_path.is_file() else None
    transformed_sources: list[str] = []
    if bundle_hashes_sha256 is None:
        copied_manifest = _mapping(_read_json(pack_path / "source-artifacts" / "run-manifest.json", {}))
        copied_version = copied_manifest.get("schema_contract_version")
        if integrity_status == "verified":
            add_issue(
                "missing_bundle_hashes",
                "The run was verified against bundle-hashes.json, but the pack carries no copy of it.",
                path=str(bundle_hashes_path),
            )
        elif isinstance(copied_version, str) and copied_version >= BUNDLE_HASHES_SCHEMA_VERSION:
            add_issue(
                "missing_bundle_hashes",
                f"The run was finalized under contract {copied_version}, which writes bundle-hashes.json, "
                "but the pack carries no copy of it.",
                path=str(bundle_hashes_path),
            )
    else:
        if integrity_status != "verified":
            add_issue(
                "source_integrity_status_inconsistent",
                f"The pack carries bundle-hashes.json but its manifest says the run's integrity was "
                f"{integrity_status or 'not recorded'}, not verified.",
                path=str(manifest_path),
                actual=integrity_status or None,
            )
        recorded_digest = _text(
            _mapping(source_payload.get("integrity")).get("manifest_sha256")
            or _mapping(handoff_payload.get("integrity")).get("manifest_sha256")
        )
        if recorded_digest and bundle_hashes_sha256 != recorded_digest:
            add_issue(
                "bundle_hashes_digest_mismatch",
                "source-artifacts/bundle-hashes.json is not the manifest the run was verified against.",
                path=str(bundle_hashes_path),
                expected=recorded_digest,
                actual=bundle_hashes_sha256,
            )
        hash_rows = _bundle_hash_rows(bundle_hashes_path)
        if hash_rows is None:
            add_issue(
                "invalid_bundle_hashes",
                "source-artifacts/bundle-hashes.json cannot be read as a hash manifest.",
                path=str(bundle_hashes_path),
            )
        else:
            source_root = pack_path / "source-artifacts"
            rows_by_file = {
                file.resolve(): row
                for row in sources
                if (file := _pack_file_path(pack_path, manifest_output_dir, row.get("path"))) is not None
            }
            # Every file under source-artifacts/ is checked, by where it sits and not by what the pack manifest
            # says it is: a copy is the run's artifact only when its bytes are the ones the run was finalized with.
            for current, directories, names in os.walk(str(source_root), followlinks=False):
                directories.sort()
                for name in sorted(names):
                    copied = Path(current) / name
                    if copied.is_symlink() or copied.resolve() not in listed_paths:
                        continue  # a link or an unlisted file is reported as unexpected_file
                    relative = copied.relative_to(source_root).as_posix()
                    if relative == "bundle-hashes.json":
                        continue
                    expected_hash = hash_rows.get(relative)
                    if expected_hash is None:
                        add_issue(
                            "source_artifact_not_in_bundle_hashes",
                            "A copied source artifact is not listed in the pack's bundle-hashes.json.",
                            path=str(copied),
                            source_path=relative,
                        )
                        continue
                    actual_hash = _sha256_file(copied)
                    if actual_hash == expected_hash:
                        continue
                    row = rows_by_file.get(copied.resolve(), {})
                    if (
                        relative == "run-manifest.json"
                        and row.get("transformed") == _PACK_RELATIVE_PATHS
                        and row.get("source_sha256") == expected_hash
                    ):
                        # The copy has its local paths made pack-relative; the run's own file is the one hashed.
                        # The copy itself is bound only by checksums.sha256 (see --expect-checksums-sha256).
                        transformed_sources.append(relative)
                        continue
                    add_issue(
                        "source_artifact_bundle_hash_mismatch",
                        "A copied source artifact differs from the hash recorded when the run was finalized.",
                        path=str(copied),
                        source_path=relative,
                        expected=expected_hash,
                        actual=actual_hash,
                    )
    checksums_sha256 = _sha256_file(checksum_path) if checksum_path.is_file() else None
    for label, expected_digest, actual_digest, code in (
        ("bundle-hashes.json", expect_manifest_sha256, bundle_hashes_sha256, "expected_manifest_sha256_mismatch"),
        ("checksums.sha256", expect_checksums_sha256, checksums_sha256, "expected_checksums_sha256_mismatch"),
    ):
        if expected_digest and (actual_digest or "") != str(expected_digest).strip().lower():
            add_issue(
                code,
                f"The SHA-256 of {label} is not the value that was supplied for it.",
                expected=str(expected_digest).strip().lower(),
                actual=actual_digest,
            )

    # Nothing may sit in the pack that its manifest does not list: a planted file needs no re-hashing at all.
    if generated or sources:
        for current, directories, names in os.walk(str(pack_path), followlinks=False):
            directories.sort()
            for name in sorted([*directories, *names]):
                candidate = Path(current) / name
                if name == ".DS_Store" or (candidate.is_dir() and not candidate.is_symlink()):
                    continue
                if candidate.is_symlink():
                    add_issue("unexpected_file", "A symbolic link sits in the pack.", path=str(candidate))
                elif candidate.resolve() not in listed_paths:
                    add_issue("unexpected_file", "A file in the pack is not listed in pack-manifest.json.", path=str(candidate))

    issues = _merge_pack_issues(issues, pack_path)
    return {
        "pack_dir": str(pack_path),
        "pack_manifest_path": str(manifest_path),
        "valid": not issues,
        "issue_count": len(issues),
        "checked_file_count": len(checked_files),
        "checksum_line_count": checksum_line_count,
        "generated_file_count": len(generated),
        "source_artifact_count": len(sources),
        "source_integrity_status": integrity_status or None,
        # Source artifacts copied with their local paths made pack-relative: tied to the run's file by
        # ``source_sha256`` and, as copied, covered by ``checksums.sha256`` only.
        "transformed_source_artifacts": transformed_sources,
        # Send these through a separate channel; pass them back as --expect-manifest-sha256 / --expect-checksums-sha256.
        "digests": {
            "bundle_hashes_sha256": bundle_hashes_sha256,
            "checksums_sha256": checksums_sha256,
            "pack_manifest_sha256": _sha256_file(manifest_path) if manifest_path.is_file() else None,
        },
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


def _offline_live_readiness(*sources: Mapping[str, Any]) -> str | None:
    """Offline bundles never write live-readiness.json; say so instead of leaving the field blank."""
    for source in sources:
        if str(_mapping(source).get("mode") or "").strip().lower() == "offline":
            return "n/a (offline)"
    return None


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


def _append_baseline_alignment_markdown(lines: list[str], payload: Mapping[str, Any]) -> None:
    if not payload:
        return
    frameworks = _mapping(payload.get("frameworks"))
    framework_rows = []
    for key in sorted(frameworks):
        entry = _mapping(frameworks.get(key))
        counts = _mapping(entry.get("status_counts"))
        framework_rows.append(
            {
                "framework": key,
                "version": entry.get("version"),
                "fail": counts.get("fail", 0),
                "accepted_risk": counts.get("accepted_risk", 0),
                "pass": counts.get("pass", 0),
                "not_assessed": counts.get("not_assessed", 0),
            }
        )
    _append_rows_markdown(
        lines,
        "Baseline Alignment",
        framework_rows,
        (
            ("Framework", "framework"),
            ("Version", "version"),
            ("Fail", "fail"),
            ("Accepted risk", "accepted_risk"),
            ("Pass", "pass"),
            ("Not assessed", "not_assessed"),
        ),
    )
    _append_cyber_essentials_markdown(lines, _mapping(frameworks.get("cyber_essentials")))
    secure_score = _mapping(payload.get("secure_score"))
    if secure_score:
        _append_rows_markdown(
            lines,
            "Secure Score Reconciliation",
            _dict_rows(secure_score.get("controls")),
            (
                ("Control profile", "control_profile_id"),
                ("Microsoft score", "microsoft_score"),
                ("Max", "microsoft_max_score"),
                ("Microsoft state", "microsoft_state"),
                ("Auditex", "auditex_state"),
                ("Agreement", "agreement"),
            ),
        )


def _append_cyber_essentials_markdown(lines: list[str], section: Mapping[str, Any]) -> None:
    """Per-requirement table for the ``cyber_essentials`` baseline. Requirements Auditex cannot judge show their status, never a verdict."""
    if not section:
        return
    rows = []
    for control in _dict_rows(section.get("controls")):
        evidence = _mapping(control.get("evidence"))
        supporting = {
            str(status.get("rule_id"))
            for status in _dict_rows(control.get("rule_statuses"))
            if status.get("confidence") == "supporting"
        }
        # A row whose rules were not evaluated says why, so an empty reason never hides a collector that did not complete.
        reasons = [str(item) for item in control.get("not_assessed_reasons") or []]
        reason = ": ".join(part for part in (_text(control.get("reason")), ", ".join(reasons)) if part)
        limits = " ".join(
            part
            for part in (
                _text(control.get("evidence_limits")),
                f"CE+ test: {_text(control.get('ce_plus_test'))}." if control.get("ce_plus_test") else "",
            )
            if part
        )
        rows.append(
            {
                "requirement": control.get("control_id"),
                "title": control.get("title"),
                "requirement_status": control.get("requirement_status"),
                "status": control.get("status"),
                "reason": reason,
                "rules": ", ".join(
                    f"{rule} (supporting)" if rule in supporting else str(rule) for rule in control.get("rule_ids") or []
                )
                or "none",
                "evaluated": f"{evidence.get('rules_evaluated', 0)}/{evidence.get('rules_mapped', 0)}",
                "open_findings": control.get("open_finding_count", 0),
                # Only a failure carries a confidence: whether a rule that tests the named condition fails it.
                "confidence": control.get("confidence") or "",
                "evidence_limits": limits,
                "citation": control.get("citation"),
            }
        )
    _append_rows_markdown(
        lines,
        "Cyber Essentials Requirements",
        rows,
        (
            ("Requirement", "requirement"),
            ("Title", "title"),
            ("Requirement status", "requirement_status"),
            ("Status", "status"),
            ("Reason", "reason"),
            ("Rules", "rules"),
            ("Rules evaluated", "evaluated"),
            ("Open findings", "open_findings"),
            ("Confidence", "confidence"),
            ("Evidence limits", "evidence_limits"),
            ("Document heading", "citation"),
        ),
    )
    lines.extend(
        [
            "",
            "Confidence applies to a failing requirement: `full` when a failing rule tests the condition the requirement "
            "names for the audited tenant, `partial` when every failing rule is a proxy or a subset of it. Rules marked "
            "supporting in the rule list never decide a requirement.",
        ]
    )
    document = " ".join(
        part
        for part in (
            _text(section.get("document_title")) or _text(section.get("title")),
            f"(effective {_text(section.get('effective_date'))})" if section.get("effective_date") else "",
            _text(section.get("document_url")),
        )
        if part
    )
    lines.extend(["", f"Source: {_markdown_cell(document)}", "", _markdown_cell(section.get("disclaimer"))])


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
    if "baseline_alignment" in selected_sections:
        _append_baseline_alignment_markdown(lines, _mapping(selected_sections.get("baseline_alignment")))
    _append_mapping_markdown(lines, "Report QA", _mapping(selected_sections.get("report_qa")))
    if "detection_coverage" in selected_sections:
        detection = _mapping(selected_sections.get("detection_coverage"))
        _append_rows_markdown(
            lines,
            f"Detection Coverage (score {_text(detection.get('score'), 'n/a')})",
            _dict_rows(detection.get("signals")),
            (("Signal", "title"), ("Status", "status"), ("Reason", "reason"), ("Why it matters", "why_it_matters")),
        )
    if "public_footprint" in selected_sections:
        footprint = _mapping(selected_sections.get("public_footprint"))
        _append_rows_markdown(
            lines,
            "Public Footprint (informational)",
            _dict_rows(footprint.get("domains")),
            (("Domain", "domain"), ("Authentication", "authentication_type"), ("Discovery", "discovery_status")),
        )
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
                f"- Declared calls: {_markdown_cell(counts.get('observed_calls', len(api_calls)))} (collector coverage rows: what the collectors report having run)",
                *_safety_lines(safety),
                *_ledger_summary_lines(api_inventory),
                "",
                "### Declared calls",
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
            lines.append("|  |  | No declared calls in this bundle. |  |  |  |")
        lines.extend(_observed_ledger_markdown(api_inventory, level="###"))

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
    if "baseline_alignment" in selected_sections:
        sections.append(_render_json_section("Baseline Alignment", selected_sections.get("baseline_alignment")))
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
    if "detection_coverage" in selected_sections:
        sections.append(_render_json_section("Detection Coverage", selected_sections.get("detection_coverage")))
    if "public_footprint" in selected_sections:
        sections.append(_render_json_section("Public Footprint", selected_sections.get("public_footprint")))
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
        confidence = _text(finding.get("confidence"))
        if confidence:
            result_entry["properties"]["auditex.confidence"] = confidence
        evidence = [
            {
                key: ref[key]
                for key in ("artifact_path", "record_key", "json_pointer", "content_hash", "resolved")
                if ref.get(key) not in (None, "")
            }
            for ref in (finding.get("evidence_refs") or [])[:10]
            if isinstance(ref, Mapping)
        ]
        if evidence:
            result_entry["properties"]["auditex.evidence"] = evidence
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


def _oscal_timestamp(value: Any) -> str | None:
    """An ISO 8601 time as the OSCAL ``date-time-with-timezone`` the schema expects, or ``None``."""
    from datetime import datetime, timezone

    text = _text(value).strip()
    if not text:
        return None
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _oscal_token(value: str) -> str:
    """An OSCAL token (an XML NCName): letters, digits, ``.``, ``-`` and ``_``, not starting with a digit."""
    token = re.sub(r"[^\w.\-]", "_", value.strip(), flags=re.UNICODE)
    if not token or not (token[0].isalpha() or token[0] == "_"):
        token = f"_{token}"
    return token


def _oscal_props(*pairs: tuple[str, str], **extra: str) -> list[dict[str, str]]:
    """OSCAL properties, leaving out any with an empty value (the schema allows none)."""
    return [{"name": name, "value": value, **extra} for name, value in pairs if value and value.strip()]


def _oscal_evidence(refs: Any) -> list[dict[str, Any]]:
    """``relevant-evidence`` for an observation: where in the bundle the finding's records are."""
    from urllib.parse import quote

    evidence: list[dict[str, Any]] = []
    for ref in refs if isinstance(refs, list) else []:
        if not isinstance(ref, Mapping) or not _text(ref.get("artifact_path")).strip():
            continue
        href = quote(_text(ref.get("artifact_path")).strip(), safe="/")
        pointer = _text(ref.get("json_pointer")).strip()
        if pointer.startswith("/"):
            href = f"{href}#{quote(pointer, safe='/')}"
        resolved = ref.get("resolved")
        props = _oscal_props(
            ("record-key", _text(ref.get("record_key"))),
            ("sha256", _text(ref.get("content_hash"))),
            ("resolved", "true" if resolved is True else "false" if resolved is False else ""),
        )
        row: dict[str, Any] = {
            "href": href,
            "description": f"{_text(ref.get('artifact_kind'), 'artifact')} {_text(ref.get('record_key'))}".strip(),
        }
        if props:
            row["props"] = props
        evidence.append(row)
        if len(evidence) >= 10:
            break
    return evidence


def render_oscal(
    *,
    findings: list[dict[str, Any]] | None,
    summary: Mapping[str, Any] | None,
    manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """OSCAL Assessment Results 1.1.2 for the findings of a run.

    The collection time is the run manifest's ``created_utc`` (an observation takes the earliest
    ``collected_at`` of its own evidence); only a bundle with no usable ``created_utc`` falls back
    to the export time, and says so in the result's ``auditex.collection_time_basis`` property.
    """
    import uuid as _uuid
    from datetime import datetime, timedelta, timezone

    findings_rows = [dict(item) for item in (findings or []) if isinstance(item, Mapping)]
    summary_dict = _mapping(summary)
    manifest_dict = _mapping(manifest)
    platform = _provider_platform(summary_dict, manifest_dict)
    platform_label = _provider_label(platform)

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    collected = _oscal_timestamp(manifest_dict.get("created_utc") or summary_dict.get("created_utc"))
    time_basis = "run_manifest_created_utc" if collected else "export_time"
    collected = collected or now
    ended = collected
    duration = manifest_dict.get("duration_seconds")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration > 0:
        ended = (
            datetime.strptime(collected, "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=float(duration))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    assessment_uuid = _text(manifest_dict.get("run_id") or summary_dict.get("run_id"))
    if not assessment_uuid:
        assessment_uuid = str(_uuid.uuid4())

    observations: list[dict[str, Any]] = []
    findings_oscal: list[dict[str, Any]] = []
    for finding in findings_rows:
        finding_key = _text(finding.get("id")) or _text(finding.get("rule_id"))
        observation_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/observation/{_text(finding.get('id'))}"))
        finding_uuid = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/finding/{_text(finding.get('id'))}"))
        framework_mappings = finding.get("framework_mappings") if isinstance(finding.get("framework_mappings"), Mapping) else {}
        control_props: list[dict[str, str]] = []
        for framework in sorted(framework_mappings):
            controls = framework_mappings.get(framework)
            if not isinstance(controls, list):
                continue
            for control in sorted({_text(item).strip() for item in controls if _text(item).strip()}):
                control_props.append(
                    {"name": "framework-control", "class": _oscal_token(_text(framework)), "value": control}
                )
        evidence_times = sorted(
            stamp
            for stamp in (
                _oscal_timestamp(ref.get("collected_at"))
                for ref in (finding.get("evidence_refs") or [])
                if isinstance(ref, Mapping)
            )
            if stamp
        )
        title = _text(finding.get("title")) or _text(finding.get("rule_id")) or _text(finding.get("id")) or "Auditex finding"
        description = _text(finding.get("description")) or title
        observation: dict[str, Any] = {
            "uuid": observation_uuid,
            "title": title,
            "description": description,
            "methods": ["EXAMINE"],
            "collected": evidence_times[0] if evidence_times else collected,
            "props": _oscal_props(
                ("auditex.finding_id", _text(finding.get("id"))),
                ("auditex.severity", _text(finding.get("severity"))),
                ("auditex.collector", _text(finding.get("collector"))),
                ("auditex.confidence", _text(finding.get("confidence"))),
            ),
        }
        subjects = [
            {
                "subject-uuid": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/subject/{_text(item)}")),
                "type": "inventory-item",
                "title": _text(item),
            }
            for item in (finding.get("affected_objects") or [])
            if _text(item).strip()
        ]
        if subjects:
            observation["subjects"] = subjects
        evidence = _oscal_evidence(finding.get("evidence_refs"))
        if evidence:
            observation["relevant-evidence"] = evidence
        observations.append(observation)
        finding_entry: dict[str, Any] = {
            "uuid": finding_uuid,
            "title": title,
            "description": description,
            "props": [
                *_oscal_props(
                    ("auditex.finding_id", _text(finding.get("id"))),
                    ("auditex.severity", _text(finding.get("severity"))),
                    ("auditex.rule_id", _text(finding.get("rule_id"))),
                ),
                *control_props,
            ],
            # OSCAL ties a finding to one objective: the Auditex rule. The framework controls the rule
            # maps to are the ``framework-control`` properties above.
            "target": {
                "type": "objective-id",
                "target-id": _oscal_token(_text(finding.get("rule_id")) or finding_key or "auditex"),
                "title": title,
                "status": {"state": "not-satisfied", "reason": "fail"},
            },
            "related-observations": [{"observation-uuid": observation_uuid}],
        }
        remediation = _text(finding.get("remediation")).strip()
        if remediation:
            finding_entry["remarks"] = remediation
        findings_oscal.append(finding_entry)

    result: dict[str, Any] = {
        "uuid": str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{AUDITEX_OSCAL_NS}/result/{assessment_uuid}")),
        "title": "Auditex audit findings",
        "description": "Findings produced by Auditex collectors and rules.",
        "start": collected,
        "end": ended,
        "props": _oscal_props(("auditex.collection_time_basis", time_basis)),
        # OSCAL Assessment Results 1.1.2 requires ``reviewed-controls``
        # on each result. ``include-all: {}`` is the canonical "all
        # controls in scope" selector: auditex's findings are not
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
    }
    if observations:
        result["observations"] = observations
    if findings_oscal:
        result["findings"] = findings_oscal
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
            "results": [result],
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
    # A rendered report holds the same tenant metadata as the bundle: 0600 in a 0700 directory whatever the umask.
    write_private_text(target, preview["content"])
    return {"format": format_name, "output_path": str(target), "sections": preview["sections"]}
