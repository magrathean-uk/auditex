from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

import pytest


@pytest.fixture
def small_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import run_files

    monkeypatch.setattr(run_files, "MAX_RUN_FILE_BYTES", 64)
    monkeypatch.setattr(run_files, "MAX_RUN_DATA_BYTES", 256, raising=False)


def test_data_limit_matches_projection_scan_ceiling() -> None:
    from auditex.scuba_projection import DEFAULT_SCAN_MAX_BYTES
    from azure_tenant_audit.run_files import MAX_RUN_DATA_BYTES

    assert MAX_RUN_DATA_BYTES >= DEFAULT_SCAN_MAX_BYTES


@pytest.mark.parametrize("relative", (
    "run-manifest.json", "summary.json", "summary.md", "pack-manifest.json",
    "source-artifacts/bundle-hashes.json", "validation.json", "ai_context.json", "salt.bin", "redaction_salt.key",
    "checksums.sha256",
))
def test_control_file_limit(tmp_path: Path, small_limits: None, relative: str) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * 65)
    with pytest.raises(UnsafeRunFileError) as caught:
        read_run_file(tmp_path, relative)
    assert caught.value.reason == "oversize"


@pytest.mark.parametrize("relative", (
    "normalized/users.json", "raw/sample_input.json", "index/evidence.sqlite",
    "reports/report-pack.json", "audit-log.jsonl", "reports/api-calls.json",
    "api-inventory.json",
))
def test_data_files_have_larger_bounded_limit(tmp_path: Path, small_limits: None, relative: str) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * 65)
    assert read_run_file(tmp_path, relative) == b"x" * 65
    path.write_bytes(b"x" * 257)
    with pytest.raises(UnsafeRunFileError) as caught:
        read_run_file(tmp_path, relative)
    assert caught.value.reason == "oversize"


@pytest.mark.parametrize("fallback", (False, True))
def test_reader_rejects_hard_link_before_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    outside = tmp_path / "outside"
    outside.write_text("private", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    os.link(outside, run / "summary.md")
    if fallback:
        monkeypatch.setattr(os, "supports_dir_fd", set())
    with pytest.raises(UnsafeRunFileError) as caught:
        read_run_file(run, "summary.md")
    assert caught.value.reason == (None if fallback else "hardlink")
    assert isinstance(caught.value, OSError)


def test_reader_rejects_unlinked_open_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError, read_run_file

    (tmp_path / "summary.json").write_text("{}", encoding="utf-8")
    original_fstat = os.fstat

    def unlinked_file(descriptor: int) -> os.stat_result:
        info = original_fstat(descriptor)
        if stat.S_ISREG(info.st_mode):
            values = list(info)
            values[stat.ST_NLINK] = 0
            return os.stat_result(values)
        return info

    monkeypatch.setattr(os, "fstat", unlinked_file)
    with pytest.raises(UnsafeRunFileError) as caught:
        read_run_file(tmp_path, "summary.json")
    assert caught.value.reason == "hardlink"


def test_evidence_path_checks_type_without_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.run_bundle import RunBundle

    index = tmp_path / "index" / "evidence.sqlite"
    index.parent.mkdir()
    with index.open("wb") as handle:
        handle.truncate(300 * 1024 * 1024)

    def no_read(*args: object, **kwargs: object) -> bytes:
        pytest.fail("type check read index data")

    monkeypatch.setattr(os, "read", no_read)
    assert RunBundle(tmp_path).evidence_db_path() == index


def test_finalization_hashes_guarded_file_without_size_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_limits: None,
) -> None:
    from azure_tenant_audit import bundle_integrity

    data = b"x" * 257
    (tmp_path / "summary.json").write_bytes(data)

    def no_path_open(*args: object, **kwargs: object) -> str:
        pytest.fail("finalization hashed through an unguarded path")

    monkeypatch.setattr(bundle_integrity, "file_sha256", no_path_open, raising=False)
    row = bundle_integrity.build_bundle_hash_manifest(tmp_path)["artifacts"][0]
    assert row == {"path": "summary.json", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def test_finalization_reads_large_identity_evidence_without_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_limits: None,
) -> None:
    from azure_tenant_audit.tenant_identity import resolve_tenant_identity

    raw = tmp_path / "raw"
    raw.mkdir()
    tenant_id = "11111111-1111-4111-8111-111111111111"
    (raw / "sample_input.json").write_text(json.dumps({
        "identity": {"organization": {"value": [{"id": tenant_id}]}},
        "padding": "x" * 300,
    }), encoding="utf-8")
    result = resolve_tenant_identity(tmp_path, unbounded=True)
    assert result["tenant_id"] == tenant_id


def test_offline_finalization_ignores_reader_caps(tmp_path: Path, small_limits: None) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = Path(__file__).resolve().parents[1] / "examples/sample_audit_bundle/sample_result.json"
    assert run_offline(sample, tmp_path, "synthetic", "uncapped", plane="inventory") == 0
    validation = json.loads((tmp_path / "synthetic-uncapped/validation.json").read_text(encoding="utf-8"))
    assert validation["valid"], validation["issues"]


def test_customer_pack_skips_non_json_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.reporting import _copy_source_artifact

    run = tmp_path / "run"
    source = run / "normalized/users.json"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"synthetic evidence")
    pack = tmp_path / "pack"
    original_open = Path.open

    def no_path_read(path: Path, *args: object, **kwargs: object):
        if path == source:
            pytest.fail("source reopened by path")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_path_read)
    row = _copy_source_artifact(run, pack, "normalized/users.json", "test")
    copied = pack / "normalized/users.json"
    assert not row["present"] and row["skipped_reason"] == "not_redactable_json"
    assert not copied.exists()


def test_customer_pack_copy_refuses_hardlinked_source(tmp_path: Path) -> None:
    from auditex.reporting import _copy_source_artifact

    run = tmp_path / "run"
    source = run / "normalized/users.json"
    source.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_bytes(b'{"secret":"private"}')
    os.link(outside, source)
    pack = tmp_path / "pack"
    row = _copy_source_artifact(run, pack, "normalized/users.json", "test")
    assert not row["present"] and row["skipped_reason"] == "not_redactable_json"
    assert not (pack / "normalized/users.json").exists()


def test_customer_pack_manifest_from_relative_run_is_transformed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from auditex.reporting import _copy_source_artifact

    monkeypatch.chdir(tmp_path)
    run = Path("run")
    run.mkdir()
    (run / "run-manifest.json").write_text(json.dumps({"run_dir": str(run.resolve())}), encoding="utf-8")
    row = _copy_source_artifact(run, Path("pack"), "run-manifest.json", "test")
    assert row["transformed"] == "pack_relative_paths"
    copied = json.loads(Path("pack/run-manifest.json").read_text(encoding="utf-8"))
    assert copied["run_dir"] == "run"
    assert str(tmp_path) not in json.dumps(copied)


def test_unsafe_oserror_never_falls_back_to_an_empty_summary(tmp_path: Path) -> None:
    from auditex.run_bundle import RunBundle
    from azure_tenant_audit.run_files import UnsafeRunFileError

    outside = tmp_path / "outside"
    outside.write_text('{"secret":"private"}', encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    os.link(outside, run / "summary.json")
    with pytest.raises(UnsafeRunFileError):
        RunBundle(run).summary()


@pytest.mark.parametrize("kind", ("fifo", "directory", "symlink", "hardlink"))
def test_verifier_reports_unsafe_listed_artifact(tmp_path: Path, kind: str) -> None:
    from azure_tenant_audit.bundle_integrity import verify_bundle_hashes

    relative = "summary.json"
    path = tmp_path / relative
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs unavailable")
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        path.symlink_to("outside")
    elif kind == "hardlink":
        outside = tmp_path.parent / (tmp_path.name + "-outside")
        outside.write_text("private", encoding="utf-8")
        os.link(outside, path)
    (tmp_path / "bundle-hashes.json").write_text(json.dumps({
        "artifacts": [{"path": relative, "sha256": "a" * 64}],
    }), encoding="utf-8")

    result = verify_bundle_hashes(tmp_path)
    assert result["status"] == "mismatch"
    assert relative in result["missing"]


@pytest.mark.parametrize("relative", ("normalized/users.json", "summary.md"))
def test_verifier_streams_files_above_reader_limits(
    tmp_path: Path, small_limits: None, monkeypatch: pytest.MonkeyPatch, relative: str,
) -> None:
    from azure_tenant_audit.bundle_integrity import verify_bundle_hashes
    from azure_tenant_audit import run_files

    monkeypatch.setattr(run_files, "MAX_RUN_FILE_BYTES", 256)
    artifact = tmp_path / relative
    artifact.parent.mkdir(exist_ok=True)
    data = b"x" * 257
    artifact.write_bytes(data)
    (tmp_path / "bundle-hashes.json").write_text(json.dumps({
        "artifacts": [{"path": relative, "sha256": hashlib.sha256(data).hexdigest()}],
    }), encoding="utf-8")
    original_read = os.read
    artifact_id = (artifact.stat().st_dev, artifact.stat().st_ino)
    read_sizes: list[int] = []

    def guarded_read(descriptor: int, count: int) -> bytes:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) == artifact_id:
            read_sizes.append(count)
        return original_read(descriptor, count)

    monkeypatch.setattr(os, "read", guarded_read)
    result = verify_bundle_hashes(tmp_path)
    assert result["status"] == "verified", result
    assert read_sizes and max(read_sizes) <= 1024 * 1024


def test_section_registry_is_not_a_run_file(tmp_path: Path) -> None:
    from auditex.reporting import load_section_registry

    registry = tmp_path / "sections.json"
    registry.write_text('{"sections": [{"id": "example", "title": "Example"}]}', encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(registry.name)
    assert load_section_registry(link)[0]["id"] == "example"


@pytest.mark.parametrize("fail_open", (False, True))
def test_closed_index_uses_private_streamed_copy_and_cleans_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_open: bool,
) -> None:
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.contracts import _validate_evidence_db

    run = tmp_path / "run-parent" / "run"
    index = run / "index/evidence.sqlite"
    index.parent.mkdir(parents=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    with closing(sqlite3.connect(index)) as writer:
        writer.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        writer.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        writer.execute("CREATE TABLE normalized_records (record TEXT)")
        writer.execute("INSERT INTO run_meta VALUES ('tenant_name', 'SYNTHETIC')")
        writer.commit()

    original = evidence_db.open_index_read_only
    seen: list[Path] = []

    def inspect_copy(path: Path, *, immutable: bool = True) -> sqlite3.Connection:
        path = Path(path)
        seen.append(path)
        assert path.parent.parent == scratch
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert immutable
        if fail_open:
            raise OSError("synthetic failure")
        return original(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "open_index_read_only", inspect_copy)
    before = sorted(path.name for path in index.parent.iterdir())
    previous_umask = os.umask(0o777)
    try:
        summary = evidence_db.load_run_index_summary(run)
        issues: list[dict[str, object]] = []
        _validate_evidence_db(run, issues, read_only=True)
    finally:
        os.umask(previous_umask)
    assert len(seen) == 2
    if fail_open:
        assert summary == {}
    else:
        assert summary["tenant_name"] == "SYNTHETIC"
    assert [issue["code"] for issue in issues] == (["invalid_evidence_sqlite"] if fail_open else [])
    assert list(scratch.iterdir()) == []
    assert sorted(path.name for path in index.parent.iterdir()) == before
    assert sorted(path.name for path in run.parent.iterdir()) == ["run"]


@pytest.mark.parametrize("scratch_failure", ("directory", "copy", "destination_missing"))
def test_closed_index_copy_failure_refuses_without_pathname_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scratch_failure: str,
) -> None:
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.contracts import _validate_evidence_db
    from azure_tenant_audit.run_files import UnsafeRunFileError

    parent = tmp_path / "run-parent"
    run = parent / "run"
    index = run / "index/evidence.sqlite"
    index.parent.mkdir(parents=True)
    with closing(sqlite3.connect(index)) as writer:
        writer.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        writer.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        writer.execute("CREATE TABLE normalized_records (record TEXT)")
        writer.execute("INSERT INTO run_meta VALUES ('tenant_name', 'SYNTHETIC')")
        writer.commit()
    monkeypatch.setenv("TMPDIR", str(parent))

    def fail(*args: object, **kwargs: object) -> None:
        if scratch_failure == "destination_missing":
            raise FileNotFoundError("synthetic temporary destination disappeared")
        raise OSError("synthetic scratch failure")

    if scratch_failure == "directory":
        monkeypatch.setattr(evidence_db.tempfile, "TemporaryDirectory", fail)
    else:
        monkeypatch.setattr(evidence_db, "_copy_index_descriptor", fail)
    original = evidence_db.open_index_read_only
    seen: list[Path] = []

    def inspect(path: Path, *, immutable: bool = True) -> sqlite3.Connection:
        seen.append(Path(path))
        assert immutable
        return original(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "open_index_read_only", inspect)
    before = index.read_bytes()
    with pytest.raises(UnsafeRunFileError):
        evidence_db.load_run_index_summary(run)
    issues: list[dict[str, object]] = []
    with pytest.raises(UnsafeRunFileError):
        _validate_evidence_db(run, issues, read_only=True)
    assert issues == []
    assert seen == []
    assert index.read_bytes() == before
    assert sorted(path.name for path in index.parent.iterdir()) == ["evidence.sqlite"]
    assert sorted(path.name for path in parent.iterdir()) == ["run"]


@pytest.mark.parametrize("kind", ("symlink", "hardlink"))
def test_closed_index_fallback_still_refuses_links(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.run_files import UnsafeRunFileError

    run = tmp_path / "run"
    index = run / "index/evidence.sqlite"
    index.parent.mkdir(parents=True)
    outside = tmp_path / "outside.sqlite"
    outside.write_bytes(b"private")
    if kind == "symlink":
        index.symlink_to(outside)
    else:
        os.link(outside, index)
    monkeypatch.setenv("TMPDIR", str(tmp_path / "missing"))
    with pytest.raises(UnsafeRunFileError):
        with evidence_db.open_private_run_index(run, include_sidecars=False):
            pytest.fail("opened an unsafe index")


def test_closed_index_copy_is_not_subject_to_data_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_limits: None,
) -> None:
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.contracts import _validate_evidence_db

    run = tmp_path / "runs" / "run"
    index = run / "index/evidence.sqlite"
    index.parent.mkdir(parents=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    with closing(sqlite3.connect(index)) as writer:
        writer.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        writer.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        writer.execute("CREATE TABLE normalized_records (record TEXT)")
        writer.execute("INSERT INTO run_meta VALUES ('tenant_name', 'SYNTHETIC')")
        writer.commit()
    assert index.stat().st_size > 256
    assert evidence_db.load_run_index_summary(run)["tenant_name"] == "SYNTHETIC"
    issues: list[dict[str, object]] = []
    _validate_evidence_db(run, issues, read_only=True)
    assert issues == []
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("parent_readonly", (True, False))
@pytest.mark.parametrize("scratch_available", (True, False))
def test_legacy_wal_copy_uses_private_tmpdir_and_preserves_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, small_limits: None,
    scratch_available: bool, parent_readonly: bool,
) -> None:
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.contracts import _validate_evidence_db
    from azure_tenant_audit.evidence_db import load_run_index_summary

    # Both the index and committed WAL exceed the lowered read limit. The
    # private copy is streamed, or the read is refused if scratch is absent.
    monkeypatch.setattr(evidence_db, "MAX_RUN_DATA_BYTES", 256, raising=False)
    parent = tmp_path / "run-parent"
    run = parent / "run"
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir(parents=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch if scratch_available else scratch / "unavailable"))
    writer = sqlite3.connect(index)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        writer.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        writer.execute("CREATE TABLE normalized_records (record TEXT)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("INSERT INTO run_meta VALUES ('tenant_name', 'WALNAME')")
        writer.commit()
        if parent_readonly:
            parent.chmod(0o500)
        before = sorted(path.name for path in index.parent.iterdir())
        issues: list[dict[str, object]] = []
        if scratch_available:
            assert load_run_index_summary(run)["tenant_name"] == "WALNAME"
            _validate_evidence_db(run, issues, read_only=True)
        else:
            with pytest.raises(evidence_db.UnsafeRunFileError):
                load_run_index_summary(run)
            with pytest.raises(evidence_db.UnsafeRunFileError):
                _validate_evidence_db(run, issues, read_only=True)
        assert issues == []
        assert sorted(path.name for path in index.parent.iterdir()) == before
        assert list(scratch.iterdir()) == []
        assert sorted(path.name for path in tmp_path.iterdir()) == ["run-parent", "scratch"]
        assert sorted(path.name for path in parent.iterdir()) == ["run"]
    finally:
        parent.chmod(0o700)
        writer.close()


@pytest.mark.parametrize("nested", (False, True))
def test_legacy_wal_never_copies_under_run_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nested: bool,
) -> None:
    from azure_tenant_audit import evidence_db
    from azure_tenant_audit.contracts import _validate_evidence_db

    parent = tmp_path / "outputs"
    run = parent / "run"
    index = run / "index/evidence.sqlite"
    index.parent.mkdir(parents=True)
    scratch = parent / "scratch" if nested else parent
    scratch.mkdir(exist_ok=True)
    monkeypatch.setenv("TMPDIR", str(scratch))

    def no_copy(*args: object, **kwargs: object) -> None:
        pytest.fail("attempted a temporary evidence copy under the run parent")

    writer = sqlite3.connect(index)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        writer.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        writer.execute("CREATE TABLE normalized_records (record TEXT)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("INSERT INTO run_meta VALUES ('tenant_name', 'WALNAME')")
        writer.commit()
        monkeypatch.setattr(evidence_db.tempfile, "TemporaryDirectory", no_copy)
        with pytest.raises(evidence_db.UnsafeRunFileError):
            evidence_db.load_run_index_summary(run)
        issues: list[dict[str, object]] = []
        with pytest.raises(evidence_db.UnsafeRunFileError):
            _validate_evidence_db(run, issues, read_only=True)
        assert issues == []
    finally:
        writer.close()


@pytest.mark.parametrize("kind", ("fifo", "directory", "symlink", "hardlink"))
def test_legacy_wal_sidecars_require_guarded_regular_files(tmp_path: Path, kind: str) -> None:
    from azure_tenant_audit.contracts import _validate_evidence_db
    from azure_tenant_audit.evidence_db import load_run_index_summary
    from azure_tenant_audit.run_files import UnsafeRunFileError

    run = tmp_path / "run"
    index = run / "index/evidence.sqlite"
    index.parent.mkdir(parents=True)
    with closing(sqlite3.connect(index)) as writer:
        writer.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
        writer.execute("CREATE TABLE section_stats (section_name TEXT, item_count INTEGER, source_path TEXT)")
        writer.execute("CREATE TABLE normalized_records (record TEXT)")
        writer.commit()
    sidecar = index.with_name(index.name + "-wal")
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs unavailable")
        os.mkfifo(sidecar)
    elif kind == "directory":
        sidecar.mkdir()
    else:
        outside = tmp_path / "outside"
        outside.write_bytes(b"private")
        if kind == "symlink":
            sidecar.symlink_to(outside)
        else:
            os.link(outside, sidecar)
    with pytest.raises(UnsafeRunFileError):
        load_run_index_summary(run)
    issues: list[dict[str, object]] = []
    with pytest.raises(UnsafeRunFileError):
        _validate_evidence_db(run, issues, read_only=True)
    assert issues == []
