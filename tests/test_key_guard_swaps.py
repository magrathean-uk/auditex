"""Forced swaps at the boundary between artifact selection and consumption."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import traceback
from contextlib import closing

import pytest

from auditex import cli, mcp_server
from auditex.run_bundle import RunBundle
from azure_tenant_audit.sensitive_users import SensitiveUsers, verify_sensitive_users
from support import RunBundleBuilder


KEY = b"guard-key-canary-012345678901234"
ADDRESS = "guard-private@example.invalid"


def _private_summary_run(tmp_path: Path) -> Path:
    run = RunBundleBuilder(tmp_path).summary_md().build()
    private = run / "operator-inputs"
    private.mkdir(mode=0o700)
    (private / "sensitive-users.key").write_bytes(KEY)
    (private / "sensitive-users.txt").write_text(ADDRESS + "\n", encoding="utf-8")
    manifest_path = run / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["operator_inputs"] = {"sensitive_users": SensitiveUsers((ADDRESS,)).manifest(KEY)}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return run


@pytest.mark.parametrize("surface", ["mcp-summary", "mcp-probe", "cli-summary", "cli-probe"])
def test_summary_control_succeeds_without_a_swap(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], surface: str,
) -> None:
    run = _private_summary_run(tmp_path)
    if surface.startswith("mcp-"):
        name = "auditex_summarize_run" if surface == "mcp-summary" else "auditex_probe_summarize"
        result = mcp_server.tool_handlers()[name](run_dir=str(run))
        assert isinstance(result, dict)
    else:
        command = ["summarize"] if surface == "cli-summary" else ["probe", "summarize"]
        assert cli.main([*command, str(run)]) == 0
    captured = capsys.readouterr()
    assert KEY.decode() not in captured.out + captured.err
    assert ADDRESS not in captured.out + captured.err


@pytest.mark.parametrize("command", [["summarize"], ["probe", "summarize"]])
def test_summary_accepts_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: list[str],
) -> None:
    run = _private_summary_run(tmp_path)
    monkeypatch.chdir(run)
    assert cli.main([*command, "."]) == 0
    output = capsys.readouterr()
    assert KEY.decode() not in output.out + output.err


@pytest.mark.parametrize("surface", ["mcp-summary", "mcp-probe", "cli-summary", "cli-probe"])
def test_summary_refuses_single_link_registered_identity_at_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], surface: str,
) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError

    run = _private_summary_run(tmp_path)
    key = run / "operator-inputs/sensitive-users.key"
    original_open = os.open
    injected = False
    with key.open("rb") as private_fd:
        assert os.fstat(private_fd.fileno()).st_nlink == 1

        def open_selected(name: object, flags: int, *args: object, **kwargs: object) -> int:
            nonlocal injected
            if str(name) == "summary.md":
                injected = True
                return os.dup(private_fd.fileno())
            return original_open(name, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", open_selected)
        if surface.startswith("mcp-"):
            name = "auditex_summarize_run" if surface == "mcp-summary" else "auditex_probe_summarize"
            with pytest.raises(UnsafeRunFileError):
                mcp_server.tool_handlers()[name](run_dir=str(run))
        else:
            command = ["summarize"] if surface == "cli-summary" else ["probe", "summarize"]
            assert cli.main([*command, str(run)]) == 2
    captured = capsys.readouterr()
    assert injected
    assert KEY.decode() not in captured.out + captured.err
    assert hashlib.sha256(KEY).hexdigest() not in captured.out + captured.err
    assert ADDRESS not in captured.out + captured.err


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
    swapped = False
    original_copy = evidence_db._copy_index_descriptor

    def fail_copy(descriptor: int, destination: Path) -> None:
        nonlocal copy_attempts, swapped
        copy_attempts += 1
        if swap_target == "wal" and not str(destination).endswith("-wal"):
            original_copy(descriptor, destination)
            return
        target = index if swap_target == "index" else wal
        os.rename(target, target.with_name("held-" + target.name))
        target.symlink_to(hostile)
        swapped = True
        raise OSError("forced copy failure")

    sqlite_open = evidence_db.open_index_read_only
    opened_source = False

    def swap_then_open(path: str | Path, *, immutable: bool = True) -> sqlite3.Connection:
        nonlocal opened_source
        if Path(path) == index:
            opened_source = True
        return sqlite_open(path, immutable=immutable)

    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: True)
    monkeypatch.setattr(evidence_db, "_copy_index_descriptor", fail_copy)
    monkeypatch.setattr(evidence_db, "open_index_read_only", swap_then_open)
    with pytest.raises(OSError, match="Refusing evidence index: unsafe input") as error:
        with evidence_db.open_private_run_index(run, include_sidecars=swap_target == "wal") as conn:
            conn.execute("SELECT value FROM run_meta").fetchall()
    assert copy_attempts == (2 if swap_target == "wal" else 1)
    assert swapped
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


def test_sqlite_real_unproved_storage_refuses_read_without_changing_index(tmp_path: Path) -> None:
    from azure_tenant_audit import evidence_db

    temporary_root = Path(os.environ.get("TMPDIR", ""))
    if evidence_db._encrypted_internal_storage(temporary_root):
        pytest.skip("the test temporary directory is proved encrypted internal storage")
    run = RunBundleBuilder(tmp_path).build()
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir()
    index.write_bytes(b"constructed-old-index")
    evidence_db.build_run_evidence_index(run)
    original = index.read_bytes()
    assert original.startswith(b"SQLite format 3\0")
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
        assert Path(database).parent.parent == destination.parent
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: False)
    monkeypatch.setattr(evidence_db.sqlite3, "connect", checked_connect)
    evidence_db.build_run_evidence_index(run)
    assert destination.is_file()
    with closing(original_connect(destination)) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"run_meta", "section_stats", "normalized_records"} <= tables
    assert sorted(item.name for item in destination.parent.iterdir()) == ["evidence.sqlite"]


@pytest.mark.parametrize("change", ["none", "contents", "replace", "sidecar"])
def test_fresh_index_validation_does_not_read_sqlite_from_unproved_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    from azure_tenant_audit import contracts, evidence_db

    run = RunBundleBuilder(tmp_path).build()
    monkeypatch.setattr(evidence_db, "_encrypted_internal_storage", lambda path: False)
    proof: list = []
    index = evidence_db.build_run_evidence_index(run, _proof_out=proof)
    if change == "contents":
        index.write_bytes(b"changed")
    elif change == "replace":
        prior = index.read_bytes()
        index.rename(index.with_name("prior.sqlite"))
        index.write_bytes(prior)
    elif change == "sidecar":
        index.with_name(index.name + "-wal").write_bytes(b"untrusted")
    issues: list = []
    if change == "none":
        assert contracts._validate_evidence_db(run, issues, _fresh_index_proof=proof[0])
        assert not issues
    else:
        with pytest.raises(evidence_db.UnsafeRunFileError):
            contracts._validate_evidence_db(run, issues, _fresh_index_proof=proof[0])
    with pytest.raises(evidence_db.UnsafeRunFileError):
        contracts._validate_evidence_db(run, [], read_only=True, _fresh_index_proof=proof[0])


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


def test_declared_missing_auth_context_does_not_fall_back(tmp_path: Path) -> None:
    from azure_tenant_audit.run_files import UnsafeRunFileError

    run = RunBundleBuilder(tmp_path).manifest(auth_context_path="missing.json").build()
    (run / "normalized").mkdir()
    (run / "normalized/auth_context.json").write_text("{}")
    with pytest.raises(UnsafeRunFileError):
        RunBundle(run).auth_context()
