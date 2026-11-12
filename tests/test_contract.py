from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import (
    ROOT_REQUIRED_ARTIFACTS,
    build_validation_report,
)
from azure_tenant_audit.evidence_db import _IN_PLACE_NOTICE

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

    assert manifest["schema_contract_version"] == "2026-11-11"
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


def _assert_only_producer_notice_added(run_dir: Path, before_files: dict[str, bytes]) -> None:
    """Every file is byte-identical, except that the producing process may append the one constant notice.

    The in-process ``run_offline`` registered this run as produced here, so E1 lets its own audit-debug.log
    take exactly one constant line when the index is read in place. Nothing else may change, and no
    other file may appear or vanish.
    """
    after = {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}
    assert after.keys() == before_files.keys()
    for name, data in before_files.items():
        if name == "audit-debug.log":
            assert after[name].startswith(data)
            assert after[name][len(data):] in (b"", _IN_PLACE_NOTICE + b"\n")
        else:
            assert after[name] == data, name


def _bundle_bytes(run_dir: Path) -> dict[str, bytes]:
    return {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}


def test_read_only_validation_treats_an_unhashed_committed_wal_as_untrusted_and_never_replays_it(
    tmp_path: Path, monkeypatch,
) -> None:
    """E1: a non-empty WAL beside an unhashed legacy index is untrusted, never replayed or copied.

    The committed table that exists only in the WAL must not make the bundle valid. The index is
    reported as ``invalid_evidence_sqlite`` (plus the identity cross-check, which has no index
    metadata to compare against), the main file, the WAL and every other artifact stay as they were.
    When ``bundle-hashes.json`` lists the index, a sidecar is not read at all; see
    ``test_integrity_gate_followups.py`` for that case.
    """
    run_parent = tmp_path / "runs"
    run_parent.mkdir()
    run_dir = _offline_contract_run(run_parent)
    (run_dir / "bundle-hashes.json").unlink()
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
        before = _bundle_bytes(run_dir)
        wal_size = db_path.with_name("evidence.sqlite-wal").stat().st_size

        report = build_validation_report(run_dir=run_dir, read_only=True)

        codes = {issue["code"] for issue in report["issues"]}
        assert report["valid"] is False
        assert report != expected
        assert "invalid_evidence_sqlite" in codes
        # No replay: the WAL-only table never satisfies the schema check.
        assert "invalid_evidence_sqlite_schema" not in codes
        assert codes <= {"invalid_evidence_sqlite", "identity_metadata_mismatch", "tenant_identity_conflict"}
        assert db_path.with_name("evidence.sqlite-wal").stat().st_size == wal_size
        _assert_only_producer_notice_added(run_dir, before)
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
    before = _bundle_bytes(run_dir)

    report = build_validation_report(run_dir=run_dir, read_only=True)

    assert report["valid"] is False
    assert "invalid_evidence_sqlite" in {issue["code"] for issue in report["issues"]}
    # The corrupt database itself is untouched; only the producing run's own log may take the constant notice.
    assert db_path.read_bytes() == b"not a SQLite database"
    _assert_only_producer_notice_added(run_dir, before)
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
