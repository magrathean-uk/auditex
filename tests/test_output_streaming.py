from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit.guarded_io import UnsafeRunFileError
from azure_tenant_audit.output import AuditWriter


def test_writer_supports_chunk_blocker_and_report_artifacts(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="acme", run_name="streaming")
    chunk_path = writer.write_chunk_records(
        "security",
        "signIns",
        page_number=1,
        records=[{"id": "signin-1"}, {"id": "signin-2"}],
        metadata={"endpoint": "/auditLogs/signIns"},
    )
    blockers_path = writer.write_blockers(
        [
            {
                "collector": "security",
                "status": "failed",
                "endpoint": "/security/alerts",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
                "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
            }
        ]
    )
    findings_path = writer.write_findings(
        [
            {
                "id": "security-alerts-blocked",
                "severity": "medium",
                "title": "Security alerts blocked",
                "status": "open",
                "affected_objects": ["/security/alerts"],
            }
        ]
    )
    ai_safe_path = writer.write_ai_safe(
        "run_summary",
        {"tenant_name": "acme", "overall_status": "partial"},
    )
    report_path = writer.write_report_pack(
        {
            "summary": {"overall_status": "partial"},
            "findings": [{"id": "security-alerts-blocked"}],
            "action_plan": [{"id": "security-alerts-blocked", "title": "Security alerts blocked"}],
            "evidence_paths": [str(chunk_path.relative_to(writer.run_dir))],
        }
    )
    writer.write_bundle(
        {
            "collectors": ["security"],
            "overall_status": "partial",
            "duration_seconds": 2,
            "mode": "azure_cli",
            "command_line": [],
        }
    )

    assert chunk_path.exists()
    assert blockers_path.exists()
    assert findings_path.exists()
    assert ai_safe_path.exists()
    assert report_path.exists()

    manifest = json.loads((writer.run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert "chunks/security/signIns-00001.jsonl" in manifest["artifacts"]
    assert "blockers/blockers.json" in manifest["artifacts"]
    assert "findings/findings.json" in manifest["artifacts"]
    assert "ai_safe/run_summary.json" in manifest["artifacts"]
    assert "reports/report-pack.json" in manifest["artifacts"]
    assert "reports/action-plan.json" in manifest["artifacts"]


def test_discard_chunk_records_without_metadata_is_idempotent(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="constructed", run_name="discard")
    path = writer.write_chunk_records("constructed", "users", 1, [{"id": "constructed-user"}])
    relative = str(path.relative_to(writer.run_dir))
    writer.discard_chunk_records([relative])
    writer.discard_chunk_records([relative])
    assert not path.exists() and relative not in writer.artifact_paths()


@pytest.mark.parametrize("relative", ["raw/users.json", "chunks/../outside.jsonl", "/chunks/c/users.jsonl"])
def test_discard_chunk_records_rejects_non_chunk_paths(tmp_path: Path, relative: str) -> None:
    writer = AuditWriter(tmp_path, tenant_name="constructed", run_name="discard")
    with pytest.raises(ValueError, match="chunk path"):
        writer.discard_chunk_records([relative])


def test_discard_chunk_records_rejects_symlinked_collector_directory(tmp_path: Path) -> None:
    writer = AuditWriter(tmp_path, tenant_name="constructed", run_name="discard")
    outside = tmp_path / "outside"
    outside.mkdir()
    path = outside / "users-00001.jsonl"
    path.write_text('{"id": "constructed-user"}\n', encoding="utf-8")
    (writer.chunks_dir / "constructed").symlink_to(outside, target_is_directory=True)
    artifacts_before = list(writer._manifest["artifacts"])
    # The guarded remover refuses the linked directory with its fixed error (not a ValueError that echoes
    # the escape); it neither follows the link nor falls back to an unguarded unlink.
    with pytest.raises(UnsafeRunFileError) as caught:
        writer.discard_chunk_records(["chunks/constructed/users-00001.jsonl"])
    assert "constructed-user" not in str(caught.value) and str(outside) not in str(caught.value)
    assert path.exists()
    assert path.read_text(encoding="utf-8") == '{"id": "constructed-user"}\n'
    assert sorted(item.name for item in outside.iterdir()) == ["users-00001.jsonl"]
    assert writer._manifest["artifacts"] == artifacts_before
    assert (writer.chunks_dir / "constructed").is_symlink()
