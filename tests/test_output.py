from __future__ import annotations

import json
import re
from pathlib import Path

from azure_tenant_audit.output import AuditWriter


def test_writer(tmp_path: Path):
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="baseline")
    payload = {"value": [{"id": "1"}]}
    raw_path = writer.write_raw("identity", payload)
    writer.log_event("test.event", "writer test")
    writer.write_index_records(
        [
            {"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1},
            {"collector": "identity", "name": "groups", "type": "graph", "status": "ok", "item_count": 2},
        ]
    )
    writer.write_summary(
        {
            "name": "identity",
            "status": "ok",
            "item_count": 1,
            "message": "ok",
            "coverage_rows": 2,
        }
    )
    writer.write_summary(
        {
            "name": "mail",
            "status": "partial",
            "item_count": 0,
            "message": "partial",
            "coverage_rows": 0,
        }
    )
    writer.write_bundle(
        {
            "collectors": ["identity"],
            "duration_seconds": 1.2,
            "overall_status": "partial",
            "collector_preset": "identity-only",
            "waiver_path": "configs/waivers.json",
            "session_context": {"user_principal_name": "admin@contoso.com"},
            "sample_truncated": True,
        }
    )

    assert raw_path.exists()
    assert (writer.run_dir / "run-manifest.json").exists()
    assert (writer.run_dir / "summary.json").exists()
    assert (writer.run_dir / "audit-log.jsonl").exists()
    assert (writer.run_dir / "audit-command-log.jsonl").exists()
    assert (writer.run_dir / "audit-debug.log").exists()
    assert (writer.run_dir / "coverage.json").exists()
    assert (writer.run_dir / "index" / "coverage.jsonl").exists()
    assert (writer.run_dir / "session-context.json").exists()
    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "2026-04-21"
    assert re.match(r"^\d{4}-\d{2}-\d{2}T", manifest["created_utc"])
    assert manifest["collector_preset"] == "identity-only"
    assert manifest["waiver_path"] == "configs/waivers.json"
    assert manifest["assurance"]["grade"] == "usable"
    assert manifest["assurance"]["sample_truncated"] is True
    surfaces = {row["surface"]: row for row in manifest["surface_coverage"]}
    assert surfaces["identity"]["status"] == "complete"
    assert surfaces["mail"]["status"] == "partial"
    assert manifest["coverage_gaps"] == [
        {
            "surface": "mail",
            "status": "partial",
            "severity": "medium",
            "collectors": ["mail"],
            "error_classes": [],
            "message": "mail coverage is partial; affected collectors: mail",
        }
    ]
    assert "summary.json" in manifest["artifacts"]
    assert "summary.md" in manifest["artifacts"]
    summary = json.loads((writer.run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["assurance"]["grade"] == "usable"
    assert summary["surface_coverage"] == manifest["surface_coverage"]
    assert summary["coverage_gaps"] == manifest["coverage_gaps"]
    assert manifest["provider_scorecard"]["score"] == 80
    assert manifest["provider_scorecard"]["surfaces"][0]["surface"] == "identity"
    assert summary["provider_scorecard"] == manifest["provider_scorecard"]

    json_lines = (writer.run_dir / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()
    assert any('"run.completed"' in line for line in json_lines)


def test_checkpoint_round_trip_preserves_collectors_and_operations(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="checkpoint")

    writer.write_checkpoint(
        "identity",
        {
            "status": "ok",
            "item_count": 7,
            "message": "identity complete",
            "error": None,
            "error_class": None,
        },
    )
    writer.write_export_checkpoint(
        "purview",
        "auditLogJobs",
        status="ok",
        item_count=12,
        message="export complete",
        extra={"summary_path": "raw/purview/auditLogJobs/summary.json"},
    )

    checkpoint_payload = json.loads((writer.run_dir / "checkpoints" / "checkpoint-state.json").read_text(encoding="utf-8"))
    assert checkpoint_payload["collectors"]["identity"]["status"] == "ok"
    assert checkpoint_payload["collectors"]["identity"]["item_count"] == 7
    assert checkpoint_payload["operations"]["purview"]["auditLogJobs"]["status"] == "ok"
    assert checkpoint_payload["operations"]["purview"]["auditLogJobs"]["summary_path"] == "raw/purview/auditLogJobs/summary.json"

    reloaded = AuditWriter(tmp_path, tenant_name="acme", run_dir=writer.run_dir)
    assert reloaded.load_collector_checkpoint_state()["identity"]["item_count"] == 7
    assert reloaded.load_operation_checkpoint_state()["purview"]["auditLogJobs"]["item_count"] == 12


def test_run_manifest_schema_documents_assurance_coverage_fields() -> None:
    schema = json.loads(Path("schemas/run_manifest.schema.json").read_text(encoding="utf-8"))

    properties = schema["properties"]
    assert {"assurance", "surface_coverage", "coverage_gaps", "provider_scorecard", "data_handling_path", "api_inventory_path"}.issubset(properties)


def test_writer_promotes_coverage_gaps_into_report_pack(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="coverage-gap-report")
    writer.write_summary({"name": "google_reports", "status": "failed", "item_count": 0, "error_class": "unauthorized_client"})
    writer.write_report_pack(
        {
            "schema_version": "2026-04-21",
            "summary": {"tenant_name": "acme", "overall_status": "partial", "finding_count": 0, "risk": {"score": 0, "grade": "clean"}},
            "findings": [],
            "action_plan": [],
            "evidence_paths": [],
        }
    )
    writer.write_bundle(
        {
            "duration_seconds": 1,
            "overall_status": "partial",
            "mode": "offline",
            "auditor_profile": "google-workspace",
            "platform": "google_workspace",
            "selected_collectors": ["google_reports"],
            "evidence_db_path": "index/evidence.sqlite",
            "ai_context_path": "ai_context.json",
            "validation_path": "validation.json",
        }
    )

    report_pack = json.loads((writer.run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    assert report_pack["summary"]["coverage_gap_count"] == 1
    assert report_pack["summary"]["risk"]["coverage_gap_weight"] == 4
    assert report_pack["action_plan"][0]["id"] == "coverage_gap:audit_logs"


def test_write_checkpoint_serializes_collectors_map_directly(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="checkpoint-shape")

    writer.write_checkpoint(
        "identity",
        {
            "status": "ok",
            "item_count": 3,
            "message": "done",
            "error": None,
            "error_class": None,
        },
    )

    checkpoint_payload = json.loads((writer.run_dir / "checkpoints" / "checkpoint-state.json").read_text(encoding="utf-8"))
    assert checkpoint_payload["collectors"]["identity"]["status"] == "ok"
    assert checkpoint_payload["collectors"]["identity"]["item_count"] == 3
    assert "collectors" not in checkpoint_payload["collectors"]
