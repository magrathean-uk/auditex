"""Index reads on private and unproved temporary storage, using synthetic data."""
from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from azure_tenant_audit import evidence_db
from support import RunBundleBuilder


def _run_with_index(tmp_path: Path) -> tuple[Path, Path]:
    run = RunBundleBuilder(tmp_path).build()
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
    with evidence_db.open_private_run_index(run, include_sidecars=False) as conn:
        assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)

    assert len(opened) == 1 and opened[0][1] is True
    if proved:
        assert opened[0][0] != index and len(copies) == 1
        assert "in place" not in (run / "audit-debug.log").read_text().lower()
    else:
        assert opened[0][0] == index and not copies
        with evidence_db.open_private_run_index(run, include_sidecars=False) as conn:
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
        with evidence_db.open_private_run_index(run, include_sidecars=False):
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
    with evidence_db.open_private_run_index(run, include_sidecars=False) as conn:
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
    with evidence_db.open_private_run_index(run, include_sidecars=False) as conn:
        assert conn.execute("SELECT value FROM items").fetchone() == ("ordinary",)
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("simulated", [False, True])
def test_no_input_demo_and_mocktenant_on_unproved_storage(tmp_path, monkeypatch, capsys, simulated):
    from auditex.cli import main as auditex_main
    from auditex.demo import DEMO_AS_OF
    from auditex.model_serving import assess_run, assess_scubagear_export
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
