from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import ROOT_REQUIRED_ARTIFACTS, build_validation_report


REPO_ROOT = Path(__file__).resolve().parents[1]


def _offline_contract_run(tmp_path: Path) -> Path:
    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "contract",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-contract"


def test_offline_bundle_satisfies_frozen_contract(tmp_path: Path) -> None:
    run_dir = _offline_contract_run(tmp_path)

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))

    assert manifest["schema_contract_version"] == "2026-10-22"
    assert manifest["contract_status"] == "valid"
    assert manifest["contract_issue_count"] == 0
    assert summary["schema_version"] == "2026-04-21"
    assert validation["valid"] is True, validation["issues"]
    assert validation["issues"] == []
    for relative in ROOT_REQUIRED_ARTIFACTS:
        assert (run_dir / relative).exists(), relative

    with sqlite3.connect(run_dir / "index" / "evidence.sqlite") as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"run_meta", "section_stats", "normalized_records"}.issubset(tables)
        assert conn.execute("SELECT COUNT(*) FROM normalized_records").fetchone()[0] > 0


def test_contract_validation_fails_loudly_for_missing_artifacts(tmp_path: Path) -> None:
    run_dir = _offline_contract_run(tmp_path)
    (run_dir / "ai_context.json").unlink()

    report = build_validation_report(run_dir=run_dir)
    issue_codes = {item["code"] for item in report["issues"]}

    assert report["valid"] is False
    assert "missing_required_artifact" in issue_codes
    assert "invalid_json_artifact" in issue_codes


def _bundle_hashes(run_dir: Path) -> dict[str, str]:
    return {
        str(path.relative_to(run_dir)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in run_dir.rglob("*")
        if path.is_file()
    }


def test_read_only_validation_preserves_original_wal_database_and_uses_committed_wal(
    tmp_path: Path, monkeypatch,
) -> None:
    run_dir = _offline_contract_run(tmp_path)
    scratch = tmp_path / "validation-scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    expected = build_validation_report(run_dir=run_dir)
    assert expected["valid"] is True
    db_path = run_dir / "index" / "evidence.sqlite"
    writer = sqlite3.connect(db_path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")
        schema = writer.execute("SELECT sql FROM sqlite_master WHERE name='normalized_records'").fetchone()[0]
        writer.execute("DROP TABLE normalized_records")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # The required table now exists only in a committed, uncheckpointed WAL
        # transaction. Copying the main database alone must fail validation.
        writer.execute(schema)
        writer.commit()
        assert db_path.with_name("evidence.sqlite-wal").stat().st_size > 0
        before = _bundle_hashes(run_dir)

        report = build_validation_report(run_dir=run_dir, read_only=True)

        assert report == expected
        assert _bundle_hashes(run_dir) == before
        assert list(scratch.iterdir()) == []
    finally:
        writer.close()


def test_read_only_validation_detects_corrupt_database_without_changing_bundle(tmp_path: Path, monkeypatch) -> None:
    run_dir = _offline_contract_run(tmp_path)
    scratch = tmp_path / "validation-scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    db_path = run_dir / "index" / "evidence.sqlite"
    # A valid WAL can recover the main file; this case has no recovery data.
    for suffix in ("-wal", "-shm"):
        db_path.with_name(db_path.name + suffix).unlink(missing_ok=True)
    db_path.write_bytes(b"not a SQLite database")
    before = _bundle_hashes(run_dir)

    report = build_validation_report(run_dir=run_dir, read_only=True)

    assert report["valid"] is False
    assert "invalid_evidence_sqlite" in {issue["code"] for issue in report["issues"]}
    assert _bundle_hashes(run_dir) == before
    assert list(scratch.iterdir()) == []


def test_read_only_validation_reports_missing_database_without_creating_it(tmp_path: Path) -> None:
    run_dir = _offline_contract_run(tmp_path)
    db_path = run_dir / "index" / "evidence.sqlite"
    db_path.unlink()
    before = _bundle_hashes(run_dir)

    report = build_validation_report(run_dir=run_dir, read_only=True)

    assert report["valid"] is False
    assert any(
        issue["code"] == "missing_required_artifact" and issue["path"] == "index/evidence.sqlite"
        for issue in report["issues"]
    )
    assert not db_path.exists()
    assert _bundle_hashes(run_dir) == before
