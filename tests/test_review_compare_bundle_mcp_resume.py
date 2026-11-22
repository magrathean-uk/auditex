"""Review lane compare-bundle-mcp: resuming a run folder (R051, R052, R114)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# R051 / R052 / R114: resuming a run folder


def _first_session(tmp_path: Path, **metadata: Any) -> Path:
    from azure_tenant_audit.output import AuditWriter

    writer = AuditWriter(tmp_path, "lab", "r1")
    writer.write_bundle({"collectors": [], "mode": "offline", **metadata})
    return writer.run_dir


def _manifest(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))


def test_live_resume_of_an_offline_replay_folder_drops_the_replay_and_other_session_keys(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    run_dir = _first_session(
        tmp_path,
        replay_source={"file": "sample_result.json"},
        waiver_path="waivers.json",
        top_limit=5,
        sample_truncated=True,
        truncated_sections=["users"],
        fixture_provenance={"source": "sample"},
    )
    assert _manifest(run_dir)["replay_source"] == {"file": "sample_result.json"}

    AuditWriter(tmp_path, "lab", run_dir=run_dir).write_bundle({"collectors": [], "mode": "app"})

    manifest = _manifest(run_dir)
    assert manifest["mode"] == "app"
    for key in ("replay_source", "waiver_path", "top_limit", "sample_truncated", "truncated_sections", "fixture_provenance"):
        assert key not in manifest, key


def test_resume_removes_the_earlier_sessions_post_finalisation_answers(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    run_dir = _first_session(tmp_path)
    stale = ["model_assessment.json", "local_answer.json", "reports/handoff.md", "reports/explorer.html"]
    for relative in stale:
        (run_dir / relative).write_text("{}", encoding="utf-8")

    AuditWriter(tmp_path, "lab", run_dir=run_dir)

    assert [relative for relative in stale if (run_dir / relative).exists()] == []


def test_resume_under_another_tenant_name_keeps_one_run_id(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    run_dir = _first_session(tmp_path)

    AuditWriter(tmp_path, "Other", run_dir=run_dir).write_bundle({"collectors": [], "mode": "app"})

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert _manifest(run_dir)["run_id"] == "r1"
    assert summary["run_id"] == "r1"
    assert summary["tenant_name"] == "lab"


def test_resume_of_a_renamed_folder_keeps_the_manifest_run_id(tmp_path: Path) -> None:
    from azure_tenant_audit.output import AuditWriter

    run_dir = _first_session(tmp_path)
    renamed = run_dir.rename(run_dir.with_name("lab-r1-copy"))

    AuditWriter(tmp_path, "lab", run_dir=renamed).write_bundle({"collectors": [], "mode": "app"})

    summary = json.loads((renamed / "summary.json").read_text(encoding="utf-8"))
    assert summary["run_id"] == _manifest(renamed)["run_id"] == "r1"
