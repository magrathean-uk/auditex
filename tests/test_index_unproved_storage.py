"""Index reads on private and unproved temporary storage, using synthetic data."""
from __future__ import annotations

from pathlib import Path
import json
import shutil
import sqlite3

import pytest

from azure_tenant_audit import evidence_db
from support import RunBundleBuilder


def _run_with_index(tmp_path: Path) -> tuple[Path, Path]:
    run = RunBundleBuilder(tmp_path / "runs").build()
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir()
    with sqlite3.connect(index) as conn:
        conn.execute("CREATE TABLE items (value TEXT)")
        conn.execute("INSERT INTO items VALUES ('ordinary')")
    (run / "audit-debug.log").write_text("", encoding="utf-8")
    return run, index


@pytest.mark.parametrize("proved", [False, True])
def test_snapshot_or_in_place_depends_on_storage_proof(tmp_path, monkeypatch, capsys, proved):
    run, index = _run_with_index(tmp_path)
    scratch = tmp_path / "index-scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: proved)
    original_open = evidence_db.open_index_read_only
    original_copy = evidence_db._copy_index_descriptor
    opened = []
    copies = []

    def checked_open(path, *, immutable=True):
        opened.append((Path(path), immutable))
        return original_open(path, immutable=immutable)

    def checked_copy(descriptor, destination):
        copies.append(destination)
        return original_copy(descriptor, destination)

    monkeypatch.setattr(evidence_db, "open_index_read_only", checked_open)
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", checked_copy)
    if not proved:
        evidence_db.register_run_log(run)  # this process produces the run, so it may note the route once
    with evidence_db.open_private_run_index(run, hashed=False) as conn:
        assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)

    assert len(opened) == 1 and opened[0][1] is True
    if proved:
        assert opened[0][0] != index and len(copies) == 1
        assert "in place" not in (run / "audit-debug.log").read_text().lower()
    else:
        assert opened[0][0] == index and not copies
        with evidence_db.open_private_run_index(run, hashed=False) as conn:
            assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)
        assert opened == [(index, True), (index, True)]
        notices = [line for line in (run / "audit-debug.log").read_text().splitlines()
                   if "in place" in line.lower()]
        assert len(notices) == 1 and "info" in notices[0].lower()
    assert list(scratch.iterdir()) == []
    captured = capsys.readouterr()
    assert "in place" not in captured.out.lower() + captured.err.lower()


def test_in_place_refuses_a_swap_before_sqlite_open(tmp_path, monkeypatch):
    run, index = _run_with_index(tmp_path)
    other = tmp_path / "other.sqlite"
    with sqlite3.connect(other) as conn:
        conn.execute("CREATE TABLE items (value TEXT)")
        conn.execute("INSERT INTO items VALUES ('swapped')")
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: False)
    original_open = evidence_db.open_index_read_only
    swapped = False

    def swap_then_open(path, *, immutable=True):
        nonlocal swapped
        assert Path(path) == index and immutable is True
        index.rename(index.with_name("held.sqlite"))
        other.rename(index)
        swapped = True
        return original_open(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "open_index_read_only", swap_then_open)
    with pytest.raises(evidence_db.UnsafeRunFileError, match="Refusing evidence index: unsafe input"):
        with evidence_db.open_private_run_index(run, hashed=False):
            pytest.fail("a swapped SQLite file was admitted")
    assert swapped


def test_in_place_is_used_when_proved_temp_copy_fails(tmp_path, monkeypatch):
    run, index = _run_with_index(tmp_path)
    scratch = tmp_path / "index-scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: True)
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", lambda *args: (_ for _ in ()).throw(OSError("full")))
    original_open = evidence_db.open_index_read_only
    opened = []

    def checked_open(path, *, immutable=True):
        opened.append((Path(path), immutable))
        return original_open(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "open_index_read_only", checked_open)
    with evidence_db.open_private_run_index(run, hashed=False) as conn:
        assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)
    assert opened == [(index, True)]
    assert list(scratch.iterdir()) == []


def test_copy_requires_proof_for_created_private_directory(tmp_path, monkeypatch):
    run, _ = _run_with_index(tmp_path)
    scratch = tmp_path / "index-scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    proofs = iter((True, False))
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: next(proofs))
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", lambda *args: pytest.fail("unproved directory used"))
    with evidence_db.open_private_run_index(run, hashed=False) as conn:
        assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)
    assert list(scratch.iterdir()) == []


def test_copy_does_not_use_a_writable_temporary_parent(tmp_path, monkeypatch):
    run, index = _run_with_index(tmp_path)
    scratch = tmp_path / "index-scratch"
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o777)
    monkeypatch.setenv("TMPDIR", str(scratch))
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: True)
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", lambda *args: pytest.fail("unsafe parent used"))
    try:
        with evidence_db.open_private_run_index(run, hashed=False) as conn:
            assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)
        assert index.is_file() and list(scratch.iterdir()) == []
    finally:
        scratch.chmod(0o700)


@pytest.mark.parametrize("simulated", [False, True])
def test_no_input_demo_and_mocktenant_on_unproved_storage(tmp_path, monkeypatch, capsys, simulated):
    from auditex.cli import main as auditex_main
    from auditex.demo import DEMO_AS_OF
    from auditex.rule_assessment import assess_run, assess_scubagear_export
    from azure_tenant_audit.cli import run_offline

    scratch = tmp_path / "index-scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    if simulated:
        monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: False)
    elif evidence_db._encrypted_internal_storage(scratch):
        pytest.skip("this case requires genuinely unproved temporary storage")
    root = Path(__file__).resolve().parents[1]
    assert auditex_main(["demo", "--no-pause", "--no-html", "--out", str(tmp_path / "demo")]) == 0
    output = tmp_path / "mock"
    sample = root / "examples/demo_tenant/demo_tenant.json"
    assert run_offline(sample, output, "synthetic", "mocktenant", plane="full", as_of=DEMO_AS_OF) == 0
    assess_run(output / "synthetic-mocktenant")
    fixtures = root / "tests/fixtures/scubagear-export"
    for name in ("mocktenant-provider-export.json", "mocktenant-realformat-export.json"):
        for with_results in (False, True):
            kwargs = {"results_path": fixtures / "mocktenant-scubaresults.json"} if with_results else {}
            assess_scubagear_export(fixtures / name, output / (name + str(with_results)), **kwargs)
    assert list(scratch.rglob("*")) == []
    captured = capsys.readouterr()
    assert "in place" not in captured.out.lower() + captured.err.lower()


# ---- key-guard repair: index authority, consumers, notice ownership, torn reads --------------------------------

_HONEST = "2026-04-21T10:00:00Z"
_LATER = "2999-12-31T23:59:59Z"


def _open_index(run: Path, *, hashed: bool = False):
    """Open the index through the reader, whichever keyword the reader currently takes."""
    try:
        return evidence_db.open_private_run_index(run, hashed=hashed)
    except TypeError:
        return evidence_db.open_private_run_index(run, include_sidecars=False)


def _summary_run(tmp_path: Path, *, hashed: bool = False) -> tuple[Path, Path]:
    run = RunBundleBuilder(tmp_path / "runs").build()
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir()
    conn = sqlite3.connect(index)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE run_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE section_stats (section_name TEXT PRIMARY KEY, item_count INTEGER NOT NULL, source_path TEXT NOT NULL)")
        conn.execute("CREATE TABLE normalized_records (record_key TEXT)")
        conn.executemany("INSERT INTO run_meta VALUES (?, ?)", [
            ("run_id", "run-1"), ("tenant_name", "acme"), ("tenant_id", "tenant-1"),
            ("created_utc", _HONEST), ("overall_status", "pass"),
        ])
        conn.execute("INSERT INTO section_stats VALUES ('users', 1, 'normalized/users.json')")
        conn.commit()
    finally:
        conn.close()
    if hashed:
        (run / "bundle-hashes.json").write_text(
            json.dumps({"artifacts": [{"path": "index/evidence.sqlite"}]}), encoding="utf-8")
    return run, index


def _plant_wal(index: Path, sql: str) -> Path:
    work = index.parent.parent.parent / "wal-work"
    work.mkdir(exist_ok=True)
    shutil.copy(index, work / index.name)
    conn = sqlite3.connect(work / index.name)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute(sql)
        conn.commit()
        planted = index.with_name(index.name + "-wal")
        shutil.copy(work / (index.name + "-wal"), planted)
    finally:
        conn.close()
    return planted


def _snapshot(run: Path) -> dict[str, tuple[int, int]]:
    return {
        str(path.relative_to(run)): (path.stat().st_size, path.stat().st_mtime_ns)
        for path in sorted(run.rglob("*")) if path.is_file()
    }


def _proof(monkeypatch, tmp_path, proved: bool) -> Path:
    scratch = tmp_path / "index-scratch"
    scratch.mkdir(exist_ok=True)
    monkeypatch.setenv("TMPDIR", str(scratch))
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: proved)
    return scratch


def _validation_codes(run: Path) -> list[str]:
    from azure_tenant_audit.contracts import _validate_evidence_db

    issues: list[dict] = []
    _validate_evidence_db(run, issues, read_only=True)
    return [issue["code"] for issue in issues]


_REWRITE = f"UPDATE run_meta SET value = '{_LATER}' WHERE key = 'created_utc'"


@pytest.mark.parametrize("proved", [False, True])
def test_unhashed_index_with_a_non_empty_wal_is_untrusted_without_replay(tmp_path, monkeypatch, proved):
    from auditex.run_bundle import RunBundle

    run, index = _summary_run(tmp_path)
    _plant_wal(index, _REWRITE)
    scratch = _proof(monkeypatch, tmp_path, proved)
    before_bytes = index.read_bytes()
    before_listing = sorted(path.name for path in index.parent.iterdir())
    before = _snapshot(run)

    assert evidence_db.load_run_index_summary(run) == {}
    assert _validation_codes(run) == ["invalid_evidence_sqlite"]
    assert RunBundle(run).metadata()["created_utc"] == _HONEST
    assert RunBundle(run).metadata()["created_utc"] != _LATER

    assert index.read_bytes() == before_bytes
    assert sorted(path.name for path in index.parent.iterdir()) == before_listing
    assert _snapshot(run) == before
    assert list(scratch.iterdir()) == []


def test_legacy_wal_verdict_is_the_same_on_every_host(tmp_path, monkeypatch):
    run, index = _summary_run(tmp_path)
    _plant_wal(index, _REWRITE)
    verdicts = []
    for proved in (False, True):
        _proof(monkeypatch, tmp_path, proved)
        verdicts.append((evidence_db.load_run_index_summary(run), _validation_codes(run)))
    assert verdicts[0] == verdicts[1] == ({}, ["invalid_evidence_sqlite"])


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("sidecar,content", [
    ("-wal", b""), ("-wal", b"frames"), ("-shm", b"x" * 32), ("-journal", b"journal"),
])
def test_hashed_index_ignores_a_planted_sidecar_and_never_copies_it(tmp_path, monkeypatch, proved, sidecar, content):
    run, index = _summary_run(tmp_path, hashed=True)
    planted = index.with_name(index.name + sidecar)
    planted.write_bytes(content)
    scratch = _proof(monkeypatch, tmp_path, proved)
    copied = []
    original_copy = evidence_db._copy_index_descriptor
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor",
                        lambda descriptor, destination: (copied.append(destination.name), original_copy(descriptor, destination))[1])

    assert evidence_db.load_run_index_summary(run) == {}
    assert _validation_codes(run) == []
    with _open_index(run, hashed=True) as conn:
        assert conn.execute("SELECT value FROM run_meta WHERE key='created_utc'").fetchone() == (_HONEST,)
    assert planted.read_bytes() == content
    assert all(not name.endswith(("-wal", "-shm", "-journal")) for name in copied)
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("sidecar", ["-wal", "-shm"])
def test_unhashed_index_with_only_an_empty_wal_or_shm_is_read(tmp_path, monkeypatch, proved, sidecar):
    run, index = _summary_run(tmp_path)
    index.with_name(index.name + sidecar).write_bytes(b"")
    _proof(monkeypatch, tmp_path, proved)
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
    assert _validation_codes(run) == []


@pytest.mark.parametrize("kind", ["fifo", "key-link", "hardlink"])
def test_unsafe_sidecar_types_still_get_the_fixed_refusal(tmp_path, monkeypatch, kind):
    import os

    run, index = _summary_run(tmp_path, hashed=True)
    target = index.with_name(index.name + "-wal")
    if kind == "fifo":
        os.mkfifo(target)
    elif kind == "key-link":
        secret = tmp_path / "secret.key"
        secret.write_text("canary", encoding="utf-8")
        target.symlink_to(secret)
    else:
        os.link(index, target)
    _proof(monkeypatch, tmp_path, False)
    with pytest.raises(evidence_db.UnsafeRunFileError, match="Refusing evidence index: unsafe input"):
        _validation_codes(run)


def test_consumers_of_an_unowned_bundle_leave_it_untouched(tmp_path, monkeypatch, capsys):
    from auditex.run_bundle import RunBundle

    run, _ = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, False)
    assert not (run / "audit-debug.log").exists()
    before = _snapshot(run)
    evidence_db.load_run_index_summary(run)
    evidence_db.load_run_index_summary(run)
    assert _validation_codes(run) == []
    RunBundle(run).metadata()
    assert _snapshot(run) == before
    assert not (run / "audit-debug.log").exists()
    captured = capsys.readouterr()
    assert "in place" not in captured.out.lower() + captured.err.lower()


def _notice_lines(run: Path) -> list[str]:
    return [line for line in (run / "audit-debug.log").read_text().splitlines() if "in place" in line.lower()]


def _register(run: Path) -> None:
    register = getattr(evidence_db, "register_run_log", None)
    if register is not None:
        register(run)


def test_an_owned_run_logs_one_notice_whatever_the_thread_count(tmp_path, monkeypatch):
    import threading

    run, _ = _summary_run(tmp_path)
    (run / "audit-debug.log").write_text("", encoding="utf-8")
    _proof(monkeypatch, tmp_path, False)
    _register(run)
    barrier = threading.Barrier(8)
    original = evidence_db.open_private_output

    def held_open(*args, **kwargs):
        try:
            barrier.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass
        return original(*args, **kwargs)

    monkeypatch.setattr(evidence_db, "open_private_output", held_open)
    errors = []

    def work():
        try:
            assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(_notice_lines(run)) == 1
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
    assert len(_notice_lines(run)) == 1


@pytest.mark.parametrize("mode", ["read-only", "symlink"])
def test_an_unwritable_or_unsafe_log_gets_no_line_and_does_not_fail_the_read(tmp_path, monkeypatch, capsys, mode):
    run, _ = _summary_run(tmp_path)
    log = run / "audit-debug.log"
    if mode == "read-only":
        log.write_text("", encoding="utf-8")
        log.chmod(0o400)
        target = log
    else:
        target = tmp_path / "elsewhere.log"
        target.write_text("", encoding="utf-8")
        log.symlink_to(target)
    _proof(monkeypatch, tmp_path, False)
    _register(run)
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
    assert target.read_text() == ""
    captured = capsys.readouterr()
    assert "in place" not in captured.out.lower() + captured.err.lower()


@pytest.mark.parametrize("failure", [OSError("open failed"), sqlite3.OperationalError("unable to open")])
def test_a_failing_sqlite_open_on_the_copy_route_is_not_a_refusal(tmp_path, monkeypatch, failure):
    run, index = _summary_run(tmp_path)
    scratch = _proof(monkeypatch, tmp_path, True)

    def failing_open(path, *, immutable=True):
        raise failure

    monkeypatch.setattr(evidence_db, "open_index_read_only", failing_open)
    assert evidence_db.load_run_index_summary(run) == {}
    assert _validation_codes(run) == ["invalid_evidence_sqlite"]
    assert list(scratch.iterdir()) == []


def test_an_index_rewritten_during_an_in_place_read_is_refused(tmp_path, monkeypatch):
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, False)
    with pytest.raises(evidence_db.UnsafeRunFileError) as error:
        with _open_index(run) as conn:
            assert conn.execute("SELECT count(*) FROM run_meta").fetchone() == (5,)
            with open(index, "r+b") as handle:  # same inode, new bytes
                handle.seek(0, 2)
                handle.write(b"\0" * 16)
    assert getattr(error.value, "reason", None) == "changed"
