"""Composed guard regressions: optional-artifact refusals, torn index reads, stdin proof and the log notice.

Every case uses synthetic bundles. Each unsafe trigger has an ordinary control beside it so that a repair
cannot pass by refusing everything.
"""
from __future__ import annotations

import errno
import gc
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from azure_tenant_audit import contracts, evidence_db, guarded_io
from azure_tenant_audit.guarded_io import UnsafeRunFileError
from test_guarded_admission import ADDRESS, KEY, private_run  # noqa: F401 - shared fixture
from test_index_unproved_storage import _HONEST, _notice_lines, _open_index, _proof, _register, _summary_run

SOURCE = Path(__file__).resolve().parents[1] / "src"
REFUSAL = "Refusing run-file: unsafe input"


# ---- 1. an unsafe optional model assessment is a fixed refusal, through validation and the gate -----------


@pytest.fixture
def gate_run(tmp_path: Path) -> Path:
    from gate_support import offline_run

    return offline_run(tmp_path)


def _plant_assessment(run: Path, outside: Path, kind: str) -> None:
    target = run / "model_assessment.json"
    outside.mkdir(exist_ok=True)
    elsewhere = outside / "assessment.json"
    elsewhere.write_text("{}", encoding="utf-8")
    if kind == "fifo":
        os.mkfifo(target)
    elif kind == "symlink":
        target.symlink_to(elsewhere)
    elif kind == "dangling-symlink":
        target.symlink_to(outside / "absent.json")
    elif kind == "hardlink":
        os.link(elsewhere, target)
    else:  # pragma: no cover - parametrisation guard
        raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["fifo", "symlink", "dangling-symlink", "hardlink"])
def test_unsafe_optional_assessment_is_refused_by_validation_and_gate(gate_run, tmp_path, kind):
    from auditex.gate import gate_findings
    from azure_tenant_audit.contracts import build_validation_report

    _plant_assessment(gate_run, tmp_path / "outside", kind)
    for read_only in (True, False):
        with pytest.raises(UnsafeRunFileError, match=REFUSAL):
            build_validation_report(run_dir=gate_run, read_only=read_only)
    with pytest.raises(UnsafeRunFileError):
        gate_findings(run_dir=str(gate_run), fail_on="critical")
    assert (tmp_path / "outside" / "assessment.json").read_text(encoding="utf-8") == "{}"


@pytest.mark.parametrize("content", [None, "{", "[]", '{"run_id": "another-run"}', "﻿{}"])
def test_absent_or_malformed_optional_assessment_keeps_compatibility(gate_run, content):
    from auditex.gate import gate_findings
    from azure_tenant_audit.contracts import build_validation_report

    before = gate_findings(run_dir=str(gate_run), fail_on="critical")
    assert before["status"] != "blocked"
    if content is not None:
        (gate_run / "model_assessment.json").write_text(content, encoding="utf-8")
    report = build_validation_report(run_dir=gate_run, read_only=True)
    flagged = [issue for issue in report["issues"] if issue["code"] == "invalid_model_assessment"]
    if content is None:
        assert flagged == []
    else:
        assert [issue["severity"] for issue in flagged] == ["warning"]
    assert report["valid"] is True
    after = gate_findings(run_dir=str(gate_run), fail_on="critical")
    assert after["status"] == before["status"] and after["pass"] == before["pass"]


# ---- 2. a source rewritten during a read is refused even when the consumer's query then fails -------------


def _rewrite_in_place(index: Path) -> None:
    with open(index, "r+b") as handle:  # same inode, new bytes
        handle.seek(0, 2)
        handle.write(b"\0" * 16)


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("failure", [sqlite3.DatabaseError("database disk image is malformed"),
                                     sqlite3.OperationalError("no such table"), ValueError("consumer failed")])
def test_a_source_rewritten_before_a_failing_query_is_refused(tmp_path, monkeypatch, proved, failure):
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)
    with pytest.raises(UnsafeRunFileError) as error:
        with _open_index(run) as conn:
            assert conn.execute("SELECT count(*) FROM run_meta").fetchone() == (5,)
            _rewrite_in_place(index)
            raise failure
    assert error.value.reason == "changed"
    assert str(index) not in str(error.value)


@pytest.mark.parametrize("proved", [False, True])
def test_a_source_rewritten_during_a_clean_read_is_still_refused(tmp_path, monkeypatch, proved):
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)
    with pytest.raises(UnsafeRunFileError) as error:
        with _open_index(run) as conn:
            assert conn.execute("SELECT count(*) FROM run_meta").fetchone() == (5,)
            _rewrite_in_place(index)
    assert error.value.reason == "changed"


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("failure", [sqlite3.DatabaseError("ordinary corruption"),
                                     UnsafeRunFileError("evidence index", reason="type"), KeyError("value")])
def test_an_unchanged_source_keeps_the_consumers_own_exception(tmp_path, monkeypatch, proved, failure):
    run, _ = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)
    with pytest.raises(type(failure)) as error:
        with _open_index(run) as conn:
            assert conn.execute("SELECT count(*) FROM run_meta").fetchone() == (5,)
            raise failure
    assert error.value is failure


@pytest.mark.parametrize("proved", [False, True])
def test_an_unchanged_source_reads_normally(tmp_path, monkeypatch, proved):
    run, _ = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)
    with _open_index(run) as conn:
        assert dict(conn.execute("SELECT key, value FROM run_meta"))["created_utc"] == _HONEST
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST


@pytest.mark.parametrize("rewrite", [True, False])
def test_validation_never_reports_a_torn_index_as_ordinary_corruption(tmp_path, monkeypatch, rewrite):
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, False)

    def rewrite_then_fail(metadata):
        if rewrite:
            _rewrite_in_place(index)
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(contracts, "decode_identity_metadata", rewrite_then_fail)
    issues: list[dict] = []
    if rewrite:
        with pytest.raises(UnsafeRunFileError, match="Refusing evidence index: unsafe input") as error:
            contracts._validate_evidence_db(run, issues, read_only=True)
        assert error.value.reason == "changed"
    else:
        contracts._validate_evidence_db(run, issues, read_only=True)
        assert [issue["code"] for issue in issues] == ["invalid_evidence_sqlite"]


class _FailingConnection:
    """A connection whose first query can rewrite the admitted source before failing like corruption."""

    def __init__(self, real: sqlite3.Connection, index: Path, rewrite: bool) -> None:
        self._real = real
        self._index = index
        self._rewrite = rewrite

    def execute(self, *args, **kwargs):
        if self._rewrite:
            _rewrite_in_place(self._index)
        raise sqlite3.DatabaseError("file is not a database")

    def close(self) -> None:
        self._real.close()


@pytest.mark.parametrize("proved", [False, True])
@pytest.mark.parametrize("rewrite", [True, False])
def test_summary_never_falls_back_after_a_torn_read(tmp_path, monkeypatch, proved, rewrite):
    run, index = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, proved)
    original = evidence_db.open_index_read_only

    def failing_open(path, *, immutable=True):
        return _FailingConnection(original(path, immutable=immutable), index, rewrite)

    monkeypatch.setattr(evidence_db, "open_index_read_only", failing_open)
    if rewrite:
        with pytest.raises(UnsafeRunFileError) as error:
            evidence_db.load_run_index_summary(run)
        assert error.value.reason == "changed"
    else:
        assert evidence_db.load_run_index_summary(run) == {}


# ---- 3. stdin text-buffer proof decided at run time, never by an interpreter version list ----------------


_STDIN_CHILD = r'''
import json, os, sys, types
package = types.ModuleType("azure_tenant_audit")
package.__path__ = [os.path.join(sys.argv[1], "azure_tenant_audit")]
sys.modules["azure_tenant_audit"] = package
from azure_tenant_audit import guarded_io
mode, run = sys.argv[2], sys.argv[3]
if mode == "prebuffer-text":
    sys.stdin.read(1)
elif mode == "prebuffer-line":
    sys.stdin.readline()
with guarded_io.GuardContext() as context:
    if run != "-":
        context.bind_run(run)
    try:
        text = guarded_io.read_guarded_stdin()
    except guarded_io.UnsafeRunFileError:
        outcome = "REFUSED"
    else:
        outcome = "ACCEPTED:%d" % len(text)
print(json.dumps({"version": list(sys.version_info[:2]), "implementation": sys.implementation.name,
                  "outcome": outcome}))
'''


def _matrix_pythons() -> list[str]:
    """This interpreter, any python3.11..3.15 on PATH and AUDITEX_TEST_PYTHONS entries, once each."""
    candidates = [sys.executable, *(shutil.which(f"python3.{minor}") for minor in range(11, 16))]
    candidates.extend(os.environ.get("AUDITEX_TEST_PYTHONS", "").split(os.pathsep))
    unique: dict[str, str] = {}
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            unique.setdefault(os.path.realpath(candidate), candidate)
    return list(unique.values())


def _child(python: str, mode: str, run: str = "-", **stdin) -> dict:
    # -I -S: isolated and without site-packages, so the proof needs nothing beyond the standard library.
    result = subprocess.run([python, "-B", "-I", "-S", "-c", _STDIN_CHILD, str(SOURCE), mode, run],
                            capture_output=True, timeout=30, check=False, **stdin)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    payload = json.loads(result.stdout)
    if tuple(payload["version"]) < (3, 11):
        pytest.skip("interpreter is below the supported floor")
    assert KEY not in result.stdout + result.stderr and ADDRESS.encode() not in result.stdout + result.stderr
    return payload


def _expected(payload: dict, accepted: str) -> str:
    # Unsupported implementations stay fail-closed even for an otherwise valid input.
    return accepted if payload["implementation"] == "cpython" else "REFUSED"


@pytest.mark.parametrize("python", _matrix_pythons())
def test_fresh_pipe_and_file_stdin_are_admitted_on_every_runtime(python, tmp_path):
    data = b"ordinary\nsecond line\n"
    piped = _child(python, "plain", input=data)
    assert piped["outcome"] == _expected(piped, f"ACCEPTED:{len(data)}")
    source = tmp_path / "unseen"
    source.write_bytes(data)
    with source.open("rb") as handle:
        filed = _child(python, "plain", stdin=handle)
    assert filed["outcome"] == _expected(filed, f"ACCEPTED:{len(data)}")


@pytest.mark.parametrize("python", _matrix_pythons())
@pytest.mark.parametrize("mode", ["prebuffer-text", "prebuffer-line"])
def test_a_partially_read_text_buffer_is_refused_on_every_runtime(python, tmp_path, mode):
    data = b"first line\nsecond line\n" * 64
    assert _child(python, mode, input=data)["outcome"] == "REFUSED"
    source = tmp_path / "buffered"
    source.write_bytes(data)
    with source.open("rb") as handle:
        assert _child(python, mode, stdin=handle)["outcome"] == "REFUSED"


@pytest.mark.parametrize("python", _matrix_pythons())
@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt", "hardlink"])
def test_private_aliases_are_never_admitted_on_any_runtime(python, private_run, tmp_path, member):  # noqa: F811 - shared pytest fixture injected by name
    if member == "hardlink":
        original = tmp_path / "unrelated"
        original.write_text("ordinary input", encoding="utf-8")
        source = tmp_path / "alias"
        os.link(original, source)
    else:
        source = private_run / "operator-inputs" / member
    with source.open("rb") as handle:
        payload = _child(python, "plain", str(private_run), stdin=handle)
    assert payload["outcome"] == "REFUSED"
    with (tmp_path / "control").open("wb") as handle:
        handle.write(b"ordinary\n")
    with (tmp_path / "control").open("rb") as handle:
        control = _child(python, "plain", str(private_run), stdin=handle)
    assert control["outcome"] == _expected(control, "ACCEPTED:9")


@pytest.fixture
def pipe_stdin(monkeypatch):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"ordinary\nsecond\n")
    os.close(write_fd)
    stream = io.TextIOWrapper(io.BufferedReader(io.FileIO(read_fd, "rb", closefd=True)),
                              encoding="utf-8", errors="strict", newline="\n")
    monkeypatch.setattr(sys, "stdin", stream)
    yield stream
    stream.close()


@pytest.mark.skipif(sys.implementation.name != "cpython", reason="the proof is defined for CPython only")
@pytest.mark.parametrize("version", [None, (3, 15, 2, "final", 0), (3, 16, 0, "alpha", 1)])
def test_a_proved_layout_is_admitted_whatever_the_version_number(pipe_stdin, monkeypatch, version):
    if version is not None:
        monkeypatch.setattr(sys, "version_info", version)
    assert guarded_io._stdin_text_buffer_is_empty() is True
    pipe_stdin.read(1)
    assert guarded_io._stdin_text_buffer_is_empty() is False


def test_below_the_floor_or_another_implementation_stays_refused(pipe_stdin, monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 10, 14, "final", 0))
    assert guarded_io._stdin_text_buffer_is_empty() is False
    monkeypatch.undo()
    monkeypatch.setattr(sys, "stdin", pipe_stdin)
    monkeypatch.setattr(sys, "implementation", SimpleNamespace(name="pypy", cache_tag=None))
    assert guarded_io._stdin_text_buffer_is_empty() is False


def _layout(monkeypatch, referents) -> None:
    monkeypatch.setattr(guarded_io, "gc", SimpleNamespace(get_referents=referents, is_tracked=gc.is_tracked))


@pytest.mark.skipif(sys.implementation.name != "cpython", reason="the proof is defined for CPython only")
@pytest.mark.parametrize("version", [None, (3, 15, 2, "final", 0)])
def test_a_layout_that_hides_pending_text_fails_closed(pipe_stdin, monkeypatch, version):
    real = gc.get_referents

    def hidden(item):
        found = real(item)
        if not isinstance(item, io.TextIOWrapper):
            return found
        return [value for value in found if not isinstance(value, str) or value is item.encoding
                or value is item.errors or value in {"\n", "\r", "\r\n"}]

    if version is not None:
        monkeypatch.setattr(sys, "version_info", version)
    _layout(monkeypatch, hidden)
    assert guarded_io._text_buffer_is_empty(pipe_stdin) is True  # the stdin check alone is fooled ...
    assert guarded_io._stdin_text_buffer_is_empty() is False  # ... so the run-time proof must refuse


@pytest.mark.skipif(sys.implementation.name != "cpython", reason="the proof is defined for CPython only")
def test_a_layout_with_unexpected_strings_fails_closed(pipe_stdin, monkeypatch):
    real = gc.get_referents
    _layout(monkeypatch, lambda item: [*real(item), "unexpected-layout-field"])
    assert guarded_io._stdin_text_buffer_is_empty() is False


# ---- 4. the in-place notice appends to an existing owned log without any permission change -------------


def _refuse_permission_changes(monkeypatch) -> list[tuple]:
    calls: list[tuple] = []

    def refuse(*args, **kwargs):
        calls.append(args[:1])
        raise PermissionError(errno.EPERM, "permission change refused by test")

    for name in ("chmod", "fchmod", "lchmod"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, refuse)
    return calls


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_owned_notice_appends_without_any_permission_change(tmp_path, monkeypatch, capsys, mode):
    run, _ = _summary_run(tmp_path)
    log = run / "audit-debug.log"
    log.write_text("prior line\n", encoding="utf-8")
    log.chmod(mode)
    _proof(monkeypatch, tmp_path, False)
    _register(run)
    calls = _refuse_permission_changes(monkeypatch)
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST  # once per owned run
    assert calls == []
    assert stat.S_IMODE(log.stat().st_mode) == mode
    lines = log.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "prior line" and lines[1:] == _notice_lines(run) and len(lines) == 2
    assert lines[1].startswith("INFO:")
    captured = capsys.readouterr()
    assert "in place" not in (captured.out + captured.err).lower()


def test_owned_notice_never_creates_a_missing_log(tmp_path, monkeypatch, capsys):
    run, _ = _summary_run(tmp_path)
    _proof(monkeypatch, tmp_path, False)
    _register(run)
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
    assert not os.path.lexists(run / "audit-debug.log")
    captured = capsys.readouterr()
    assert "in place" not in (captured.out + captured.err).lower()


@pytest.mark.parametrize("kind", ["read-only", "hardlink", "fifo", "directory"])
def test_an_unsafe_or_unwritable_log_gets_no_line_and_keeps_its_state(tmp_path, monkeypatch, capsys, kind):
    run, _ = _summary_run(tmp_path)
    log = run / "audit-debug.log"
    outside = tmp_path / "elsewhere.log"
    if kind == "read-only":
        log.write_text("prior line\n", encoding="utf-8")
        log.chmod(0o400)
    elif kind == "hardlink":
        outside.write_text("prior line\n", encoding="utf-8")
        os.link(outside, log)
    elif kind == "fifo":
        os.mkfifo(log, 0o600)
    else:
        log.mkdir(mode=0o700)
    before = log.lstat()
    _proof(monkeypatch, tmp_path, False)
    _register(run)
    calls = _refuse_permission_changes(monkeypatch)
    assert evidence_db.load_run_index_summary(run)["created_utc"] == _HONEST
    assert calls == []
    after = log.lstat()
    assert (stat.S_IFMT(after.st_mode), stat.S_IMODE(after.st_mode)) == (stat.S_IFMT(before.st_mode),
                                                                       stat.S_IMODE(before.st_mode))
    if kind in ("read-only", "hardlink"):
        assert log.read_text(encoding="utf-8") == "prior line\n"
    captured = capsys.readouterr()
    assert "in place" not in (captured.out + captured.err).lower()


def _add_index(run: Path) -> None:
    index = run / "index" / "evidence.sqlite"
    index.parent.mkdir()
    conn = sqlite3.connect(index)
    try:
        conn.execute("CREATE TABLE run_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE section_stats (section_name TEXT PRIMARY KEY, item_count INTEGER NOT NULL, "
                     "source_path TEXT NOT NULL)")
        conn.execute("INSERT INTO run_meta VALUES ('created_utc', ?)", (_HONEST,))
        conn.commit()
    finally:
        conn.close()


def test_a_log_aliasing_a_private_key_refuses_the_append_but_not_the_read(private_run, tmp_path, monkeypatch):  # noqa: F811 - shared pytest fixture injected by name
    _add_index(private_run)
    key = private_run / "operator-inputs" / "sensitive-users.key"
    (private_run / "audit-debug.log").symlink_to(key)
    _proof(monkeypatch, tmp_path, False)
    _register(private_run)
    assert evidence_db.load_run_index_summary(private_run)["created_utc"] == _HONEST
    assert key.read_bytes() == KEY


def test_a_log_hardlinked_to_a_private_list_refuses_the_run_and_writes_nothing(private_run, tmp_path, monkeypatch):  # noqa: F811 - shared pytest fixture injected by name
    _add_index(private_run)
    private = private_run / "operator-inputs" / "sensitive-users.txt"
    os.link(private, private_run / "audit-debug.log")
    _proof(monkeypatch, tmp_path, False)
    _register(private_run)
    with pytest.raises(UnsafeRunFileError):
        evidence_db.load_run_index_summary(private_run)
    assert private.read_text(encoding="utf-8") == ADDRESS + "\n"
