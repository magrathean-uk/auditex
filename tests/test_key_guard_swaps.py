"""Forced swaps at the boundary between artifact selection and consumption."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import traceback

import pytest

from auditex import cli, mcp_server
from auditex.run_bundle import RunBundle
from azure_tenant_audit.sensitive_users import SensitiveUsers, verify_sensitive_users
from support import RunBundleBuilder


KEY = b"guard-key-canary-012345678901234"
ADDRESS = "guard-private@example.invalid"


@pytest.mark.parametrize("surface", ["mcp-summary", "mcp-probe", "cli-summary", "cli-probe"])
@pytest.mark.parametrize("swap", ["symlink", "hardlink", "parent-symlink"])
def test_summary_refuses_swap_after_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], surface: str, swap: str,
) -> None:
    """The swap occurs after the last path selection, just before the reader opens it."""
    run = RunBundleBuilder(tmp_path).summary_md().build()
    private = run / "operator-inputs"
    private.mkdir(mode=0o700)
    (private / "sensitive-users.key").write_bytes(KEY)
    (private / "sensitive-users.txt").write_text(ADDRESS + "\n", encoding="utf-8")
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["operator_inputs"] = {"sensitive_users": SensitiveUsers((ADDRESS,)).manifest(KEY)}
    if swap == "parent-symlink":
        public = run / "public"
        public.mkdir()
        (public / "sensitive-users.key").write_text("ordinary", encoding="utf-8")
        manifest["summary_md_path"] = "public/sensitive-users.key"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_sensitive_users(run)

    original = RunBundle._candidate_path
    selections = 0
    swapped = False

    def select_then_swap(self: RunBundle, key: str, fallback: str) -> Path:
        nonlocal selections, swapped
        selected = original(self, key, fallback)
        if key == "summary_md_path":
            selections += 1
            if selections == 2:
                if swap == "parent-symlink":
                    os.rename(run / "public", run / "public-before-swap")
                    (run / "public").symlink_to(private, target_is_directory=True)
                else:
                    os.rename(selected, run / "summary-before-swap.md")
                    if swap == "symlink":
                        selected.symlink_to(private / "sensitive-users.key")
                    else:
                        os.link(private / "sensitive-users.key", selected)
                swapped = True
        return selected

    monkeypatch.setattr(RunBundle, "_candidate_path", select_then_swap)
    result: object = None
    error: BaseException | None = None
    try:
        if surface.startswith("mcp-"):
            name = "auditex_summarize_run" if surface == "mcp-summary" else "auditex_probe_summarize"
            result = mcp_server.tool_handlers()[name](run_dir=str(run))
        else:
            command = ["summarize"] if surface == "cli-summary" else ["probe", "summarize"]
            result = cli.main([*command, str(run)])
    except (OSError, ValueError) as exc:
        error = exc
    captured = capsys.readouterr()
    output = repr(result) + captured.out + captured.err
    if error is not None:
        output += "".join(traceback.format_exception(error))
    assert swapped, "the test did not reach the selected/open boundary"
    assert KEY.decode() not in output
    assert hashlib.sha256(KEY).hexdigest() not in output
    assert ADDRESS not in output
    assert error is not None or (surface.startswith("cli-") and result == 2), output


@pytest.mark.parametrize("swap_target", ["index", "wal"])
def test_sqlite_copy_failure_never_reopens_source_after_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap_target: str,
) -> None:
    from azure_tenant_audit import evidence_db

    run = tmp_path / "run"
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir(parents=True)
    hostile = tmp_path / "hostile.sqlite"
    for path, name in ((index, "ordinary"), (hostile, "sqlite-swap-canary")):
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE run_meta (key TEXT, value TEXT)")
            conn.execute("INSERT INTO run_meta VALUES ('tenant_name', ?)", (name,))
    wal = index.with_name(index.name + "-wal")
    if swap_target == "wal":
        wal.write_bytes(b"ordinary-sidecar")
    copy_attempts = 0

    def fail_copy(*args: object, **kwargs: object) -> None:
        nonlocal copy_attempts
        copy_attempts += 1
        raise OSError("forced copy failure")

    sqlite_open = evidence_db.open_index_read_only
    opened_source = False

    def swap_then_open(path: str | Path, *, immutable: bool = True) -> sqlite3.Connection:
        nonlocal opened_source
        if Path(path) == index:
            opened_source = True
            target = index if swap_target == "index" else wal
            os.rename(target, target.with_name("held-" + target.name))
            target.symlink_to(hostile)
        return sqlite_open(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: True)
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", fail_copy)
    monkeypatch.setattr(evidence_db, "open_index_read_only", swap_then_open)
    with pytest.raises(OSError, match="Refusing evidence index: unsafe input") as error:
        with evidence_db.open_private_run_index(run, include_sidecars=swap_target == "wal") as conn:
            conn.execute("SELECT value FROM run_meta").fetchall()
    assert copy_attempts == 1
    assert not opened_source
    assert "sqlite-swap-canary" not in "".join(traceback.format_exception(error.value))


def test_sqlite_refuses_unproved_temporary_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import evidence_db

    run = tmp_path / "run"
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir(parents=True)
    index.write_bytes(b"ordinary")
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: False)
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", lambda *args: pytest.fail("unsafe snapshot copied"))
    with pytest.raises(OSError, match="Refusing evidence index: unsafe input"):
        with evidence_db.open_private_run_index(run, include_sidecars=False):
            pytest.fail("unsafe snapshot opened")


def test_sqlite_real_unproved_storage_refuses_without_changing_index(tmp_path: Path) -> None:
    from azure_tenant_audit import evidence_db

    temporary_root = Path(os.environ.get("TMPDIR", ""))
    if evidence_db._encrypted_internal_storage(temporary_root):
        pytest.skip("the test temporary directory is proved encrypted internal storage")
    run = RunBundleBuilder(tmp_path).build()
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir()
    original = b"constructed-index-must-remain"
    index.write_bytes(original)
    with pytest.raises(evidence_db.UnsafeRunFileError):
        evidence_db.build_run_evidence_index(run)
    assert index.read_bytes() == original
    with pytest.raises(evidence_db.UnsafeRunFileError):
        with evidence_db.open_private_run_index(run, include_sidecars=False):
            pytest.fail("unproved storage was used")
    assert index.read_bytes() == original


def test_sqlite_builder_does_not_reopen_admitted_output_by_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit import evidence_db

    run = RunBundleBuilder(tmp_path).build()
    destination = run / "index" / "evidence.sqlite"
    original_connect = sqlite3.connect

    def checked_connect(database: object, *args: object, **kwargs: object):
        if str(database) == str(destination):
            pytest.fail("SQLite reopened an admitted output path")
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: True)
    monkeypatch.setattr(evidence_db.sqlite3, "connect", checked_connect)
    evidence_db.build_run_evidence_index(run)
    assert destination.is_file()
    with original_connect(destination) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"run_meta", "section_stats", "normalized_records"} <= tables


def test_discovery_refuses_non_json_symlink_to_directory(tmp_path: Path) -> None:
    from azure_tenant_audit.output_redaction import ContextIncompleteError, snapshot_run

    normalized = tmp_path / "run" / "normalized"
    actual = normalized / "actual"
    actual.mkdir(parents=True)
    (actual / "data.json").write_text("{}", encoding="utf-8")
    (normalized / "linked-directory").symlink_to(actual, target_is_directory=True)
    with pytest.raises(ContextIncompleteError):
        snapshot_run(normalized.parent)


def test_declared_missing_artifact_does_not_fall_back_to_default(tmp_path: Path) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError

    run = RunBundleBuilder(tmp_path).manifest(summary_md_path="missing.md").summary_md("fallback").build()
    with pytest.raises(UnsafeRunFileError):
        RunBundle(run).summary_md()
