from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from azure_tenant_audit.tenant_identity import IDENTITY_FIELDS, reconcile_tenant_identity


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return fallback


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        rows = value.get("findings") or value.get("blockers") or value.get("items") or value.get("actions")
        if isinstance(rows, list):
            return [dict(item) for item in rows if isinstance(item, Mapping)]
    return []


def _coverage_gaps(*values: Any) -> list[dict[str, Any]]:
    for value in values:
        gaps = _dict_rows(value)
        if gaps:
            return gaps
    return []


def _scorecard(*values: Any) -> dict[str, Any]:
    for value in values:
        if isinstance(value, Mapping):
            return dict(value)
    return {}


def _action_rows(value: Any) -> list[dict[str, Any]]:
    rows = _dict_rows(value)
    if rows:
        return rows
    if not isinstance(value, Mapping):
        return []

    combined: list[dict[str, Any]] = []
    for key in ("open_findings", "actions", "recommended_actions", "blocked", "waived_findings"):
        section = value.get(key)
        if isinstance(section, list):
            combined.extend(dict(item) for item in section if isinstance(item, Mapping))
    return combined


def _path_text(path: Path) -> str:
    return str(path)


def summarize_recomputed_validation(recomputed: Mapping[str, Any], recorded: Mapping[str, Any]) -> dict[str, Any]:
    """The recomputed validation as the handoff carries it, with legacy citations told apart.

    A ``legacy_unresolved_ref`` is a citation written by a version older than the contract that
    required references to resolve; it fails validation but is not evidence the bundle was edited.
    """
    errors = [
        issue
        for issue in recomputed.get("issues") or []
        if isinstance(issue, Mapping) and issue.get("severity") == "error"
    ]
    legacy = [issue for issue in errors if issue.get("code") == "legacy_unresolved_ref"]
    only_legacy = bool(errors) and len(legacy) == len(errors)
    if recomputed.get("valid") is not False:
        text = "The bundle validates as it stands."
    elif only_legacy:
        text = (
            f"{len(legacy)} evidence reference(s) do not resolve; they were written by a version older than the "
            "contract that requires references to resolve, so this is a legacy bundle, not a sign of editing."
        )
    else:
        text = f"The bundle does not validate as it stands ({len(errors)} error(s))."
    return {
        "valid": recomputed.get("valid"),
        "issue_count": recomputed.get("issue_count"),
        "error_count": recomputed.get("error_count"),
        "warning_count": recomputed.get("warning_count"),
        # False when validation.json records a different verdict than the bundle gives now.
        "matches_validation_json": (recomputed.get("valid") == recorded.get("valid")) if recomputed and recorded else None,
        "legacy_unresolved_ref_count": len(legacy),
        "only_legacy_unresolved_refs": only_legacy,
        "issue_codes": sorted({str(issue.get("code")) for issue in errors})[:20],
        "summary": text,
    }


class RunBundle:
    def __init__(self, run_dir: str | Path) -> None:
        self.run_dir = Path(run_dir)
        self._integrity: dict[str, Any] | None = None
        self._recomputed_validation: dict[str, Any] | None = None

    def path(self, relative: str) -> Path:
        return self.run_dir / relative

    def _candidate_path(self, key: str, fallback: str) -> Path:
        manifest = self.manifest()
        relative = manifest.get(key)
        return self.path(str(relative)) if relative else self.path(fallback)

    def _artifact_path(self, key: str, fallback: str) -> Path:
        candidate = self._candidate_path(key, fallback)
        default = self.path(fallback)
        if candidate.exists() or not default.exists():
            return candidate
        return default

    def _artifact_json(self, key: str, fallback: str, default: Any) -> tuple[Path | None, Any]:
        path = self._artifact_path(key, fallback)
        return (path, _read_json(path, default)) if path.exists() else (None, None)

    def manifest(self) -> dict[str, Any]:
        return _mapping(_read_json(self.path("run-manifest.json"), {}))

    def summary(self) -> dict[str, Any]:
        path = self._artifact_path("summary_path", "summary.json")
        return _mapping(_read_json(path, {}))

    def summary_md(self) -> str | None:
        return _read_text(self._artifact_path("summary_md_path", "summary.md"))

    def diagnostics(self) -> Any:
        return _read_json(self.path("diagnostics.json"), None)

    def capability_matrix(self) -> tuple[Path | None, Any]:
        root_path = self.path("capability-matrix.json")
        normalized_path = self.path("normalized/capability_matrix.json")
        if root_path.exists():
            return root_path, _read_json(root_path, [])
        if normalized_path.exists():
            return normalized_path, _read_json(normalized_path, {})
        return None, None

    def toolchain_readiness(self) -> tuple[Path | None, Any]:
        path = self.path("toolchain-readiness.json")
        return (path, _read_json(path, {})) if path.exists() else (None, None)

    def live_readiness(self) -> tuple[Path | None, Any]:
        return self._artifact_json("live_readiness_path", "live-readiness.json", {})

    def audit_plan(self) -> tuple[Path | None, Any]:
        return self._artifact_json("audit_plan_path", "audit-plan.json", {})

    def api_inventory(self) -> tuple[Path | None, Any]:
        return self._artifact_json("api_inventory_path", "api-inventory.json", {})

    def data_handling(self) -> tuple[Path | None, Any]:
        return self._artifact_json("data_handling_path", "data-handling.json", {})

    def auth_context(self) -> tuple[Path | None, Any]:
        path = self._candidate_path("auth_context_path", "auth-context.json")
        normalized_path = self.path("normalized/auth_context.json")
        if path.exists():
            return path, _read_json(path, {})
        if normalized_path.exists():
            return normalized_path, _read_json(normalized_path, {})
        return None, None

    def coverage_ledger(self) -> tuple[Path | None, Any]:
        path = self.path("normalized/coverage_ledger.json")
        return (path, _read_json(path, {})) if path.exists() else (None, None)

    def collector_coverage(self) -> dict[str, dict[str, Any]]:
        """Per-collector completion: ``{collector: {"complete": bool, "status": str}}``.

        Reads the coverage ledger; a bundle without one falls back to the collector
        statuses in ``summary.json``. ``complete`` means the collector finished
        with full coverage, so its findings (or their absence) can be trusted.
        """
        _, ledger = self.coverage_ledger()
        records = ledger.get("records") if isinstance(ledger, Mapping) else None
        coverage: dict[str, dict[str, Any]] = {}
        for row in records if isinstance(records, list) else []:
            if isinstance(row, Mapping) and row.get("collector"):
                status = str(row.get("coverage_status") or "unknown")
                coverage[str(row["collector"])] = {"complete": status.startswith("complete"), "status": status}
        if coverage:
            return coverage
        for row in self._summary_section_stats(self.summary()):
            if row["name"]:
                status = str(row.get("status") or "unknown")
                coverage[row["name"]] = {"complete": status == "ok", "status": status}
        return coverage

    def ai_context(self) -> tuple[Path | None, Any]:
        path = self.path("ai_context.json")
        return (path, _read_json(path, {})) if path.exists() else (None, None)

    def validation(self) -> tuple[Path | None, Any]:
        return self._artifact_json("validation_path", "validation.json", {})

    def blockers(self) -> tuple[Path | None, Any]:
        return self._artifact_json("blockers_path", "blockers/blockers.json", [])

    def findings(self) -> tuple[Path | None, Any]:
        return self._artifact_json("findings_path", "findings/findings.json", [])

    def report_pack(self) -> tuple[Path | None, Any]:
        return self._artifact_json("report_pack_path", "reports/report-pack.json", {})

    def action_plan(self) -> tuple[Path | None, Any]:
        return self._artifact_json("action_plan_path", "reports/action-plan.json", [])

    def integrity(self) -> dict[str, Any]:
        """Recompute the artifact hashes and compare them with ``bundle-hashes.json``."""
        from azure_tenant_audit.bundle_integrity import verify_bundle_hashes

        if self._integrity is None:
            self._integrity = verify_bundle_hashes(self.run_dir)
        return self._integrity

    def recomputed_validation(self) -> dict[str, Any]:
        """Validate the bundle as it stands now, whatever ``validation.json`` recorded at finalization."""
        from azure_tenant_audit.contracts import build_validation_report

        if self._recomputed_validation is None:
            self._recomputed_validation = build_validation_report(run_dir=self.run_dir, read_only=True)
        return self._recomputed_validation

    def evidence_db_path(self) -> Path | None:
        path = self._artifact_path("evidence_db_path", "index/evidence.sqlite")
        return path if path.exists() else None

    def report_summary(self) -> dict[str, Any]:
        _, report_pack = self.report_pack()
        pack_summary = _mapping(_mapping(report_pack).get("summary"))
        fallback = self.summary()
        return {**fallback, **pack_summary} if pack_summary else fallback

    def finding_rows(self) -> list[dict[str, Any]]:
        _, report_pack = self.report_pack()
        rows = _dict_rows(_mapping(report_pack).get("findings"))
        if rows:
            return rows
        _, payload = self.findings()
        return _dict_rows(payload)

    def action_plan_rows(self) -> list[dict[str, Any]]:
        _, report_pack = self.report_pack()
        rows = _action_rows(_mapping(report_pack).get("action_plan"))
        if rows:
            return rows
        _, payload = self.action_plan()
        return _action_rows(payload)

    def proof_table_rows(self) -> list[dict[str, Any]]:
        _, report_pack = self.report_pack()
        rows = _dict_rows(_mapping(report_pack).get("proof_table"))
        if rows:
            return rows
        try:
            from azure_tenant_audit.autopilot import build_proof_table
        except ImportError:
            return []
        return build_proof_table(self.finding_rows())

    def blocker_rows(self) -> list[dict[str, Any]]:
        _, payload = self.blockers()
        return _dict_rows(payload)

    def metadata(self) -> dict[str, Any]:
        indexed = self._index_metadata()
        manifest = self.manifest()
        summary = self.summary()
        report_summary = self.report_summary()
        platform = manifest.get("platform") or report_summary.get("platform") or summary.get("platform") or "m365"
        _, report_pack = self.report_pack()
        _, ai_context = self.ai_context()
        identity_surfaces = {
            "run-manifest.json": manifest,
            "summary.json": summary,
            "reports/report-pack.json#/summary": _mapping(_mapping(report_pack).get("summary")),
            "ai_context.json#/run": _mapping(_mapping(ai_context).get("run")),
        }
        if any(key in _mapping(report_pack) for key in IDENTITY_FIELDS):
            identity_surfaces["reports/report-pack.json"] = _mapping(report_pack)
        if indexed:
            identity_surfaces["index/evidence.sqlite#run_meta"] = indexed
        identity_fields = reconcile_tenant_identity(self.run_dir, identity_surfaces, platform=str(platform))
        section_stats = indexed.get("section_stats") or self._summary_section_stats(summary)
        item_count = indexed.get("item_count")
        if item_count is None:
            item_count = sum(int(row.get("item_count") or 0) for row in section_stats)

        return {
            "path": str(self.run_dir),
            "run_id": indexed.get("run_id") or manifest.get("run_id") or summary.get("run_id"),
            "platform": platform,
            "tenant_name": manifest.get("tenant_name")
            or indexed.get("tenant_name")
            or report_summary.get("tenant_name")
            or summary.get("tenant_name"),
            **identity_fields,
            "workspace_domain": manifest.get("workspace_domain"),
            "customer_id": manifest.get("customer_id"),
            "created_utc": indexed.get("created_utc") or manifest.get("created_utc") or summary.get("created_utc"),
            "overall_status": indexed.get("overall_status")
            or report_summary.get("overall_status")
            or manifest.get("overall_status")
            or summary.get("overall_status"),
            "auditor_profile": indexed.get("auditor_profile")
            or manifest.get("auditor_profile")
            or summary.get("auditor_profile"),
            "section_stats": section_stats,
            "item_count": item_count or 0,
            "risk": report_summary.get("risk") or summary.get("risk") or {},
            "assurance": manifest.get("assurance") or summary.get("assurance") or {},
            "live_readiness": _mapping(self.live_readiness()[1]),
            "autopilot_quality": manifest.get("autopilot_quality") or summary.get("autopilot_quality") or {},
            "provider_scorecard": _scorecard(
                report_summary.get("provider_scorecard"),
                manifest.get("provider_scorecard"),
                summary.get("provider_scorecard"),
            ),
            "coverage_gaps": _coverage_gaps(
                report_summary.get("coverage_gaps"),
                manifest.get("coverage_gaps"),
                summary.get("coverage_gaps"),
            ),
            "evidence_db_path": str(self.evidence_db_path()) if self.evidence_db_path() is not None else None,
        }

    def _index_metadata(self) -> dict[str, Any]:
        try:
            from azure_tenant_audit.evidence_db import load_run_index_summary
        except ImportError:
            return {}
        return _mapping(load_run_index_summary(self.run_dir))

    def _summary_section_stats(self, summary: Mapping[str, Any]) -> list[dict[str, Any]]:
        collector_rows = summary.get("collectors", [])
        if not isinstance(collector_rows, list):
            return []

        rows: list[dict[str, Any]] = []
        for row in collector_rows:
            if not isinstance(row, Mapping):
                continue
            rows.append(
                {
                    "name": str(row.get("name") or ""),
                    "status": row.get("status"),
                    "item_count": int(row.get("item_count") or 0),
                    "message": row.get("message"),
                }
            )
        return rows

    def read(self) -> dict[str, Any]:
        manifest_path = self.path("run-manifest.json")
        summary_path = self._artifact_path("summary_path", "summary.json")
        summary_md_path = self._artifact_path("summary_md_path", "summary.md")
        diagnostics_path = self.path("diagnostics.json")
        result: dict[str, Any] = {
            "run_dir": _path_text(self.run_dir),
            "manifest_path": _path_text(manifest_path),
            "summary_path": _path_text(summary_path),
            "summary_md_path": _path_text(summary_md_path),
            "diagnostics_path": _path_text(diagnostics_path),
        }

        if manifest_path.exists():
            result["manifest"] = self.manifest()
        if summary_path.exists():
            result["summary"] = self.summary()
        summary_md = self.summary_md()
        if summary_md is not None:
            result["summary_md"] = summary_md
        diagnostics = self.diagnostics()
        if diagnostics is not None:
            result["diagnostics"] = diagnostics

        for key, loader in (
            ("capability_matrix", self.capability_matrix),
            ("toolchain_readiness", self.toolchain_readiness),
            ("live_readiness", self.live_readiness),
            ("audit_plan", self.audit_plan),
            ("api_inventory", self.api_inventory),
            ("data_handling", self.data_handling),
            ("auth_context", self.auth_context),
            ("coverage_ledger", self.coverage_ledger),
            ("ai_context", self.ai_context),
            ("validation", self.validation),
            ("blockers", self.blockers),
            ("findings", self.findings),
            ("report_pack", self.report_pack),
            ("action_plan", self.action_plan),
        ):
            path, payload = loader()
            if path is not None:
                result[f"{key}_path"] = _path_text(path)
                result[key] = payload

        if "validation" in result and isinstance(result["validation"], Mapping):
            result["contract_validation"] = {
                "valid": result["validation"].get("valid"),
                "issue_count": result["validation"].get("issue_count", 0),
                "contract_version": result["validation"].get("contract_version"),
            }

        evidence_db_path = self.evidence_db_path()
        if evidence_db_path is not None:
            result["evidence_db_path"] = _path_text(evidence_db_path)
        gaps = _coverage_gaps(
            self.report_summary().get("coverage_gaps"),
            self.manifest().get("coverage_gaps"),
            self.summary().get("coverage_gaps"),
        )
        if gaps:
            result["coverage_gaps"] = gaps
        scorecard = _scorecard(
            self.report_summary().get("provider_scorecard"),
            self.manifest().get("provider_scorecard"),
            self.summary().get("provider_scorecard"),
        )
        if scorecard:
            result["provider_scorecard"] = scorecard
        result["metadata"] = self.metadata()
        return result
