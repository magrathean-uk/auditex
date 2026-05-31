from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import time

from .assurance import build_assurance_summary, build_coverage_gap_summary, build_provider_scorecard, build_surface_coverage_map
from .findings import apply_coverage_gaps_to_report_pack

LOG = logging.getLogger("azure_tenant_audit.output")
RUN_MANIFEST_SCHEMA_VERSION = "2026-04-21"
SUMMARY_SCHEMA_VERSION = "2026-04-21"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditLogger:
    """Persistent event logger for a run."""

    _command_events = frozenset({"command.started", "command.completed", "command.failed"})

    def __init__(self, run_dir: Path, listener: Any = None) -> None:
        self.jsonl_path = run_dir / "audit-log.jsonl"
        self.command_log_path = run_dir / "audit-command-log.jsonl"
        self.debug_path = run_dir / "audit-debug.log"
        self.listener = listener
        self.jsonl_path.touch(exist_ok=True)
        self.command_log_path.touch(exist_ok=True)
        self.debug_path.touch(exist_ok=True)

    def log(self, event: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        payload = {
            "ts_utc": _now_iso(),
            "event": event,
            "message": message,
            "details": details or {},
        }
        line = json.dumps(payload, default=str, ensure_ascii=False)
        with self.jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        if event in self._command_events:
            with self.command_log_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        with self.debug_path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{payload['ts_utc']}] {payload['event']}: {payload['message']} {payload['details']}\n")
        LOG.debug("%s: %s", payload["event"], payload["message"])
        if self.listener is not None:
            try:
                self.listener(payload)
            except Exception:  # noqa: BLE001
                LOG.exception("Failed to dispatch audit event listener.")


class AuditWriter:
    def __init__(
        self,
        base_dir: Path,
        tenant_name: str,
        run_name: Optional[str] = None,
        *,
        run_dir: Path | None = None,
        event_listener: Any = None,
    ):
        self.base_dir = base_dir
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        created_utc = _now_iso()
        if run_dir is None:
            self.run_id = run_name or f"run_{ts}"
            self.run_dir = base_dir / f"{tenant_name}-{self.run_id}"
        else:
            self.run_dir = run_dir
            normalized = run_dir.name
            prefix = f"{tenant_name}-"
            if normalized.startswith(prefix):
                self.run_id = normalized[len(prefix) :] if len(normalized) > len(prefix) else f"run_{ts}"
            else:
                self.run_id = normalized
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.resume_from_path = None
        self.raw_dir = self.run_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.chunks_dir = self.run_dir / "chunks"
        self.chunks_dir.mkdir(parents=True, exist_ok=True)
        self.index_dir = self.run_dir / "index"
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir = self.run_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.blockers_dir = self.run_dir / "blockers"
        self.blockers_dir.mkdir(parents=True, exist_ok=True)
        self.normalized_dir = self.run_dir / "normalized"
        self.normalized_dir.mkdir(parents=True, exist_ok=True)
        self.ai_safe_dir = self.run_dir / "ai_safe"
        self.ai_safe_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir = self.run_dir / "findings"
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir = self.run_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoints_dir = self.run_dir / "checkpoints"
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_state_path = self.checkpoints_dir / "checkpoint-state.json"
        existing_manifest_path = self.run_dir / "run-manifest.json"
        existing_manifest = self._safe_load_json(existing_manifest_path)
        self._checkpoint_state: dict[str, dict[str, Any]] = self._load_checkpoint_state()
        self.coverage_index_path = self.index_dir / "coverage.jsonl"
        self.summary: dict[str, Any] = {"schema_version": SUMMARY_SCHEMA_VERSION, "tenant_name": tenant_name, "run_id": self.run_id, "collectors": []}
        self.coverage: list[dict[str, Any]] = []
        self._seed_existing_run_artifacts(existing_manifest)
        self.audit = AuditLogger(self.run_dir, listener=event_listener)
        self._manifest = {
            "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
            "tenant_name": tenant_name,
            "run_id": self.run_id,
            "created_utc": created_utc,
            "collectors": [],
            "artifacts": [
                "raw/",
                "chunks/",
                "index/",
                "blockers/",
                "normalized/",
                "ai_safe/",
                "findings/",
                "reports/",
                "checkpoints/",
                "checkpoints/checkpoint-state.json",
                "audit-log.jsonl",
                "audit-command-log.jsonl",
                "audit-debug.log",
            ],
        }
        if isinstance(existing_manifest, dict):
            for key, value in existing_manifest.items():
                if key in {"created_utc", "run_dir", "audit_log_path", "audit_command_log_path", "debug_log_path", "collectors"}:
                    continue
                self._manifest[key] = value
            if existing_manifest.get("tenant_name"):
                self._manifest["tenant_name"] = existing_manifest["tenant_name"]

    def _safe_load_json(self, path: Path) -> Any:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def _write_text_atomic(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.tmp")
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, path)

    def _write_json_atomic(self, path: Path, payload: Any) -> None:
        self._write_text_atomic(path, json.dumps(payload, indent=2))

    def _seed_existing_run_artifacts(self, existing_manifest: Any) -> None:
        existing_summary = self._safe_load_json(self.run_dir / "summary.json")
        if isinstance(existing_summary, dict):
            for key in ("schema_version", "tenant_name", "run_id", "overall_status", "duration_seconds"):
                if existing_summary.get(key) is not None:
                    self.summary[key] = existing_summary[key]
            existing_collectors = existing_summary.get("collectors")
            if isinstance(existing_collectors, list):
                self.summary["collectors"] = [item for item in existing_collectors if isinstance(item, dict)]

        existing_coverage = self._safe_load_json(self.run_dir / "coverage.json")
        if isinstance(existing_coverage, list):
            self.coverage = [item for item in existing_coverage if isinstance(item, dict)]

        existing_state = self._safe_load_json(self.checkpoint_state_path)
        if isinstance(existing_state, dict):
            self._checkpoint_state = self._normalize_checkpoint_payload(existing_state)

    @staticmethod
    def _normalize_checkpoint_payload(payload: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(payload, dict):
            return {"collectors": {}, "operations": {}}

        raw_collectors = payload.get("collectors")
        raw_operations = payload.get("operations")
        collectors: dict[str, dict[str, Any]] = {}
        operations: dict[str, dict[str, Any]] = {}

        if isinstance(raw_collectors, dict):
            for key, value in raw_collectors.items():
                if isinstance(value, dict):
                    collectors[str(key)] = value

        if isinstance(raw_operations, dict):
            for collector_name, collector_ops in raw_operations.items():
                if not isinstance(collector_ops, dict):
                    continue
                normalized_ops: dict[str, Any] = {}
                for op_name, op_state in collector_ops.items():
                    if isinstance(op_state, dict):
                        normalized_ops[str(op_name)] = op_state
                if normalized_ops:
                    operations[str(collector_name)] = normalized_ops

        # Backward compatibility for older payloads that only store collector rows at root.
        if not collectors and not operations and all(
            isinstance(key, str) and isinstance(value, dict) and "status" in value for key, value in payload.items()
        ):
            collectors = {
                str(key): value
                for key, value in payload.items()
                if isinstance(value, dict) and "status" in value
            }

        return {"collectors": collectors, "operations": operations}

    def _record_artifact(self, target: Path) -> None:
        relative = str(target.relative_to(self.run_dir))
        if relative not in self._manifest["artifacts"]:
            self._manifest["artifacts"].append(relative)

    def record_artifact(self, target: Path) -> None:
        self._record_artifact(target)

    def artifact_paths(self) -> list[str]:
        return list(self._manifest.get("artifacts", []))

    def _load_checkpoint_state(self) -> dict[str, dict[str, Any]]:
        if not self.checkpoint_state_path.exists():
            return {"collectors": {}, "operations": {}}
        try:
            payload = json.loads(self.checkpoint_state_path.read_text(encoding="utf-8"))
            return self._normalize_checkpoint_payload(payload)
        except (OSError, json.JSONDecodeError, ValueError):
            return {"collectors": {}, "operations": {}}

    def load_checkpoint_state(self) -> dict[str, dict[str, Any]]:
        return self._checkpoint_state

    def load_collector_checkpoint_state(self) -> dict[str, dict[str, Any]]:
        return dict(self._checkpoint_state.get("collectors", {}))

    def load_operation_checkpoint_state(self) -> dict[str, dict[str, Any]]:
        return dict(self._checkpoint_state.get("operations", {}))

    def write_export_checkpoint(
        self,
        collector_name: str,
        operation: str,
        status: str,
        item_count: int,
        message: str,
        error: str | None = None,
        error_class: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> Path:
        state = self.load_checkpoint_state()
        collectors = state.setdefault("collectors", {})
        operations = state.setdefault("operations", {})
        operations.setdefault(str(collector_name), {})
        operations[str(collector_name)][str(operation)] = {
            "status": status,
            "item_count": item_count,
            "message": message,
            "error": error,
            "error_class": error_class,
            "ts_utc": _now_iso(),
        }
        if extra:
            operations[str(collector_name)][str(operation)].update(extra)
        self._checkpoint_state = {
            "collectors": collectors,
            "operations": operations,
        }
        checkpoint_payload = {
            "run_dir": str(self.run_dir),
            "run_id": self.run_id,
            "collectors": collectors,
            "operations": operations,
        }
        path = self.checkpoint_state_path
        self._write_json_atomic(path, checkpoint_payload)
        self._record_artifact(path)
        self._manifest["checkpoint_state_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_checkpoint(self, collector_name: str, payload: dict[str, Any]) -> Path:
        state = self.load_checkpoint_state()
        collectors = state.setdefault("collectors", {})
        operations = state.setdefault("operations", {})
        collectors[str(collector_name)] = {
            "status": payload.get("status"),
            "item_count": payload.get("item_count"),
            "message": payload.get("message"),
            "error": payload.get("error"),
            "error_class": payload.get("error_class"),
            "ts_utc": _now_iso(),
        }
        self._checkpoint_state = {"collectors": collectors, "operations": operations}
        checkpoint_payload = {
            "run_dir": str(self.run_dir),
            "run_id": self.run_id,
            "collectors": collectors,
            "operations": operations,
        }
        path = self.checkpoint_state_path
        self._write_json_atomic(path, checkpoint_payload)
        self._record_artifact(path)
        self._manifest["checkpoint_state_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_json_artifact(self, relative_path: str, payload: Any) -> Path:
        target = self.run_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(target, payload)
        self._record_artifact(target)
        return target

    def write_raw(self, name: str, payload: dict[str, Any]) -> Path:
        target = self.raw_dir / f"{name}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        self._write_json_atomic(target, payload)
        self._record_artifact(target)
        return target

    def write_chunk_records(
        self,
        collector: str,
        name: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: Optional[dict[str, Any]] = None,
    ) -> Path:
        collector_dir = self.chunks_dir / collector
        collector_dir.mkdir(parents=True, exist_ok=True)
        target = collector_dir / f"{name}-{page_number:05d}.jsonl"
        with target.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, default=str) + "\n")
        if metadata:
            meta_path = collector_dir / f"{name}-{page_number:05d}.meta.json"
            self._write_json_atomic(meta_path, metadata)
            self._record_artifact(meta_path)
        self._record_artifact(target)
        return target

    def write_export_records(
        self,
        collector: str,
        operation: str,
        page_number: int,
        records: list[dict[str, Any]],
        metadata: Optional[dict[str, Any]] = None,
    ) -> Path:
        section_dir = self.raw_dir / collector / operation
        section_dir.mkdir(parents=True, exist_ok=True)
        target = section_dir / f"part-{page_number:05d}.jsonl"
        with target.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record, default=str) + "\n")
        if metadata:
            meta_path = section_dir / f"part-{page_number:05d}.meta.json"
            self._write_json_atomic(meta_path, metadata)
            self._record_artifact(meta_path)
        self._record_artifact(target)
        return target

    def write_export_summary(self, collector: str, operation: str, payload: dict[str, Any]) -> Path:
        section_dir = self.raw_dir / collector / operation
        section_dir.mkdir(parents=True, exist_ok=True)
        target = section_dir / "summary.json"
        self._write_json_atomic(target, payload)
        self._record_artifact(target)
        return target

    def write_index_records(self, records: list[dict[str, Any]], filename: str = "coverage.jsonl") -> None:
        if not records:
            return
        index_path = self.index_dir / filename
        with index_path.open("a", encoding="utf-8") as handle:
            for record in records:
                self.coverage.append(record)
                handle.write(json.dumps(record, default=str) + "\n")
        self._record_artifact(index_path)

    def log_event(self, event: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        self.audit.log(event, message, details=details)

    def write_diagnostics(self, diagnostics: list[dict[str, Any]]) -> Path:
        path = self.run_dir / "diagnostics.json"
        self._write_json_atomic(path, diagnostics)
        self._record_artifact(path)
        self._manifest["diagnostics_path"] = "diagnostics.json"
        self._manifest["diagnostics_count"] = len(diagnostics)
        return path

    def write_blockers(self, blockers: list[dict[str, Any]]) -> Path:
        path = self.blockers_dir / "blockers.json"
        self._write_json_atomic(path, blockers)
        self._record_artifact(path)
        self._manifest["blocker_count"] = len(blockers)
        self._manifest["blockers_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_normalized(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.normalized_dir / f"{name}.json"
        self._write_json_atomic(path, payload)
        self._record_artifact(path)
        return path

    def write_ai_safe(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.ai_safe_dir / f"{name}.json"
        self._write_json_atomic(path, payload)
        self._record_artifact(path)
        return path

    def write_findings(self, findings: list[dict[str, Any]]) -> Path:
        path = self.findings_dir / "findings.json"
        self._write_json_atomic(path, findings)
        self._record_artifact(path)
        self._manifest["findings_count"] = len(findings)
        self._manifest["findings_path"] = str(path.relative_to(self.run_dir))
        return path

    def write_report_pack(self, payload: dict[str, Any]) -> Path:
        path = self.reports_dir / "report-pack.json"
        self._write_json_atomic(path, payload)
        self._record_artifact(path)
        self._manifest["report_pack_path"] = str(path.relative_to(self.run_dir))
        action_plan = payload.get("action_plan")
        if isinstance(action_plan, list):
            action_plan_path = self.reports_dir / "action-plan.json"
            self._write_json_atomic(action_plan_path, action_plan)
            self._record_artifact(action_plan_path)
            self._manifest["action_plan_path"] = str(action_plan_path.relative_to(self.run_dir))
        return path

    def write_summary(self, item: dict[str, Any]) -> None:
        self.summary["collectors"].append(item)

    def write_bundle(self, metadata: dict[str, Any]) -> None:
        self._manifest["executed_by"] = metadata.get("executed_by")
        self._manifest["schema_version"] = RUN_MANIFEST_SCHEMA_VERSION
        selected_collectors = metadata.get("collectors", [])
        self._manifest["selected_collectors"] = selected_collectors
        self._manifest["collectors"] = selected_collectors
        self._manifest["overall_status"] = metadata.get("overall_status", "partial")
        self._manifest["duration_seconds"] = metadata.get("duration_seconds", 0)
        self._manifest["mode"] = metadata.get("mode", "live")
        self._manifest["auditor_profile"] = metadata.get("auditor_profile", "auto")
        if metadata.get("tenant_id") is not None:
            self._manifest["tenant_id"] = metadata.get("tenant_id")
        self._manifest["plane"] = metadata.get("plane", "inventory")
        self._manifest["session_context"] = metadata.get("session_context", {})
        self._manifest["command_line"] = metadata.get("command_line", [])
        self._manifest["time_window"] = {
            "since": metadata.get("since"),
            "until": metadata.get("until"),
        }
        for key in (
            "probe_mode",
            "probe_surface",
            "capability_matrix_path",
            "live_readiness_path",
            "coverage_ledger_path",
            "preflight_path",
            "throttle_mode",
            "collector_preset",
            "waiver_path",
            "toolchain_readiness_path",
            "evidence_index_path",
            "evidence_db_path",
            "auth_path",
            "auth_context_path",
            "data_handling_events",
            "data_handling_path",
            "audit_plan_path",
            "api_inventory_path",
            "autopilot_quality",
            "lab_guard_state",
            "platform",
            "workspace_domain",
            "customer_id",
            "privacy",
            "ai_context_path",
            "validation_path",
            "contract_status",
            "contract_issue_count",
            "schema_contract_version",
            "provider_adapter_version",
            "api_inventory_recorder_version",
            "fixture_provenance",
            "top_limit",
            "sample_truncated",
            "truncated_sections",
        ):
            value = metadata.get(key)
            if value is not None:
                self._manifest[key] = value
        self._manifest["run_dir"] = str(self.run_dir)
        self._manifest["audit_log_path"] = "audit-log.jsonl"
        self._manifest["debug_log_path"] = "audit-debug.log"
        if self.audit.command_log_path.exists() and self.audit.command_log_path.stat().st_size > 0:
            self._manifest["audit_command_log_path"] = "audit-command-log.jsonl"
        else:
            self._manifest["artifacts"] = [
                item for item in self._manifest["artifacts"] if item != "audit-command-log.jsonl"
            ]
        if self._manifest.get("session_context"):
            session_context_path = self.run_dir / "session-context.json"
            self._write_json_atomic(session_context_path, self._manifest["session_context"])
            self._manifest["session_context_path"] = str(session_context_path.relative_to(self.run_dir))
            self._record_artifact(session_context_path)

        if self.coverage:
            coverage_path = self.run_dir / "coverage.json"
            self._write_json_atomic(coverage_path, self.coverage)
            self._manifest["coverage_path"] = str(coverage_path.relative_to(self.run_dir))
            self._record_artifact(coverage_path)
            self._manifest["coverage_count"] = len(self.coverage)

        assurance = build_assurance_summary(
            collector_rows=[dict(row) for row in self.summary.get("collectors", []) if isinstance(row, dict)],
            coverage_rows=[dict(row) for row in self.coverage if isinstance(row, dict)],
            sample_truncated=bool(metadata.get("sample_truncated")),
        )
        surface_coverage = build_surface_coverage_map(
            collector_rows=[dict(row) for row in self.summary.get("collectors", []) if isinstance(row, dict)],
            platform=str(metadata.get("platform") or self._manifest.get("platform") or "m365"),
        )
        coverage_gaps = build_coverage_gap_summary(
            surface_coverage=surface_coverage,
            collector_rows=[dict(row) for row in self.summary.get("collectors", []) if isinstance(row, dict)],
            coverage_rows=[dict(row) for row in self.coverage if isinstance(row, dict)],
        )
        provider_scorecard = build_provider_scorecard(
            platform=str(metadata.get("platform") or self._manifest.get("platform") or "m365"),
            surface_coverage=surface_coverage,
            coverage_gaps=coverage_gaps,
        )
        self._manifest["assurance"] = assurance
        self._manifest["surface_coverage"] = surface_coverage
        self._manifest["coverage_gaps"] = coverage_gaps
        self._manifest["provider_scorecard"] = provider_scorecard
        if coverage_gaps:
            report_pack_path = self.run_dir / str(self._manifest.get("report_pack_path") or "reports/report-pack.json")
            report_pack = self._safe_load_json(report_pack_path)
            if isinstance(report_pack, dict):
                self.write_report_pack(apply_coverage_gaps_to_report_pack(report_pack, coverage_gaps))
        self.summary["schema_version"] = SUMMARY_SCHEMA_VERSION
        self.summary["tenant_name"] = self._manifest["tenant_name"]
        self.summary["run_id"] = self.run_id
        self.summary["overall_status"] = self._manifest.get("overall_status")
        self.summary["duration_seconds"] = self._manifest.get("duration_seconds", 0)
        self.summary["assurance"] = assurance
        self.summary["surface_coverage"] = surface_coverage
        self.summary["coverage_gaps"] = coverage_gaps
        self.summary["provider_scorecard"] = provider_scorecard
        if self._manifest.get("autopilot_quality"):
            self.summary["autopilot_quality"] = self._manifest["autopilot_quality"]
        summary_json_path = self.run_dir / "summary.json"
        summary_md_path = self.run_dir / "summary.md"
        self._write_json_atomic(summary_json_path, self.summary)
        self._record_artifact(summary_json_path)

        lines = [
            "# Audit Summary",
            f"- Run ID: {self.run_id}",
            f"- Tenant: {self._manifest['tenant_name']}",
            f"- Mode: {self._manifest['mode']}",
            "",
            "| Collector | Status | Items | Details |",
            "| --- | --- | --- | --- |",
        ]
        for row in self.summary.get("collectors", []):
            lines.append(
                f"| {row.get('name')} | {row.get('status')} | {row.get('item_count', 0)} | {row.get('message', '')} |"
            )
        if coverage_gaps:
            lines.extend(["", "## Coverage Gaps", ""])
            for gap in coverage_gaps:
                error_classes = ", ".join(gap.get("error_classes") or [])
                detail = f" ({error_classes})" if error_classes else ""
                lines.append(f"- {gap.get('severity')}: {gap.get('message')}{detail}")
        self._write_text_atomic(summary_md_path, "\n".join(lines))
        self._record_artifact(summary_md_path)

        manifest_path = self.run_dir / "run-manifest.json"
        self._write_json_atomic(manifest_path, self._manifest)

        if not metadata.get("_suppress_completion_log"):
            self.log_event(
                "run.completed",
                "Run complete",
                {
                    "overall_status": self._manifest["overall_status"],
                    "collector_count": len(self.summary.get("collectors", [])),
                    "duration_seconds": self._manifest["duration_seconds"],
                    "contract_status": self._manifest.get("contract_status"),
                    "contract_issue_count": self._manifest.get("contract_issue_count"),
                },
            )
