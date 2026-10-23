"""Run bundles are created 0700 (directories) and 0600 (files) whatever the caller's umask."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.output import AuditWriter, harden_bundle

SAMPLE = Path("examples/sample_audit_bundle/sample_result.json")


@pytest.fixture
def umask_022():
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def _modes(root: Path) -> tuple[dict[str, int], dict[str, int]]:
    dirs = {".": stat.S_IMODE(root.stat().st_mode)}
    files: dict[str, int] = {}
    for current, directories, names in os.walk(root):
        for name in directories:
            path = Path(current) / name
            dirs[str(path.relative_to(root))] = stat.S_IMODE(path.stat().st_mode)
        for name in names:
            path = Path(current) / name
            files[str(path.relative_to(root))] = stat.S_IMODE(path.lstat().st_mode)
    return dirs, files


def test_offline_run_bundle_is_private_under_umask_022(tmp_path: Path, umask_022) -> None:
    rc = run_offline(SAMPLE, tmp_path, "contoso", "perm-run")
    assert rc == 0
    run_dir = tmp_path / "contoso-perm-run"

    dirs, files = _modes(run_dir)

    assert files, "the run wrote no files"
    assert {name: mode for name, mode in dirs.items() if mode != 0o700} == {}
    assert {name: mode for name, mode in files.items() if mode != 0o600} == {}
    for expected in ("audit-log.jsonl", "run-manifest.json", "api-inventory.json", "index/evidence.sqlite", "validation.json"):
        assert files[expected] == 0o600, expected


def test_writer_creates_private_files_and_nested_directories(tmp_path: Path, umask_022) -> None:
    writer = AuditWriter(tmp_path / "out" / "deep", tenant_name="contoso", run_name="w1")
    writer.write_raw("response/message_trace/attempt-1", {"a": 1})
    writer.write_chunk_records("users", "all", 1, [{"id": "1"}], {"page": 1})
    writer.write_export_records("purview", "auditLogJobs", 1, [{"id": "1"}], {"page": 1})
    writer.write_export_summary("purview", "auditLogJobs", {"n": 1})
    writer.write_index_records([{"collector": "c", "name": "n", "status": "ok"}])
    writer.log_event("x", "y", {"k": "v"})

    dirs, files = _modes(writer.run_dir)

    assert {name for name, mode in dirs.items() if mode != 0o700} == set()
    assert {name for name, mode in files.items() if mode != 0o600} == set()
    assert "raw/response/message_trace" in dirs
    # Only the run directory and below are tightened; the parents the caller named keep the default mode.
    assert stat.S_IMODE((tmp_path / "out").stat().st_mode) == 0o755


def test_writer_tightens_an_existing_run_directory_and_files(tmp_path: Path, umask_022) -> None:
    run_dir = tmp_path / "contoso-old"
    (run_dir / "raw").mkdir(parents=True)
    os.chmod(run_dir, 0o755)
    os.chmod(run_dir / "raw", 0o755)
    leftover = run_dir / "raw" / "sample_input.json"
    leftover.write_text("{}", encoding="utf-8")
    os.chmod(leftover, 0o644)

    writer = AuditWriter(tmp_path, tenant_name="contoso", run_name="old")
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((run_dir / "raw").stat().st_mode) == 0o700

    writer.write_bundle({"collectors": [], "overall_status": "ok"})

    assert stat.S_IMODE(leftover.stat().st_mode) == 0o600


def test_harden_bundle_leaves_symlinks_alone(tmp_path: Path, umask_022) -> None:
    run_dir = tmp_path / "bundle"
    run_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    os.chmod(outside, 0o644)
    (run_dir / "link.txt").symlink_to(outside)
    (run_dir / "file.txt").write_text("x", encoding="utf-8")

    harden_bundle(run_dir)

    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert stat.S_IMODE((run_dir / "file.txt").stat().st_mode) == 0o600
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700


def test_google_offline_bundle_is_private_and_marked_not_instrumented(tmp_path: Path, umask_022) -> None:
    import json

    from auditex.google_workspace.run import run_google_offline

    rc = run_google_offline(
        sample_path=Path("examples/google_workspace_sample.json"),
        out=tmp_path,
        tenant_name="Example",
        run_name="google-perm",
        domain="example.com",
        customer_id="C123",
    )
    assert rc == 0
    run_dir = tmp_path / "Example-google-perm"

    dirs, files = _modes(run_dir)

    assert {name for name, mode in dirs.items() if mode != 0o700} == set()
    assert {name for name, mode in files.items() if mode != 0o600} == set()
    inventory = json.loads((run_dir / "api-inventory.json").read_text(encoding="utf-8"))
    # A replay has no tenant traffic, so its basis says so; the provider is still not instrumented.
    assert inventory["safety"]["observation_basis"] == "offline_replay"
    assert inventory["safety"]["replay_source"] == "google_workspace_sample.json"
    assert inventory["observed_ledger"]["basis"] == "offline_replay"
    assert inventory["observed_ledger"]["instrumentation"] == {"graph": False, "commands": False, "google_api": False}
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert validation["valid"] is True, validation["issues"]
