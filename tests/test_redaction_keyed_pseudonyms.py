"""Keyed per-run pseudonyms (design M04-T01 revision 3 under DEC-004: key at collection, temporary key for keyless
runs until ``auditex report prepare-key``). Synthetic values only."""
from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import threading
import time
from pathlib import Path

import pytest
from test_reporting import _write_run
from test_sarif_oscal_exports import _schema_errors, oscal_validator, sarif_validator  # noqa: F401

import azure_tenant_audit.guarded_io as guarded_io
import azure_tenant_audit.private_io as private_io
from azure_tenant_audit import output_redaction as redaction
from azure_tenant_audit.bundle_integrity import (
    PRIVATE_ROW_MESSAGE,
    is_private_operator_input,
    verify_bundle_hashes,
)
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.guarded_io import (
    GuardContext,
    UnsafeRunFileError,
    open_private_output,
    read_guarded_bytes,
)
from azure_tenant_audit.output_redaction import (
    PSEUDONYM_KEY_BYTES,
    PSEUDONYM_KEY_PATH,
    PSEUDONYM_STRATEGY,
    TEMPORARY_KEY_NOTICE,
    PseudonymKeyError,
    RedactionContext,
    context_for_run,
    context_for_runs,
    ensure_pseudonym_key,
    new_pseudonym_key,
    pseudonym,
    read_pseudonym_key,
    redact_output,
    redact_payload,
    session_pseudonym_key,
)

ROOT = Path(__file__).resolve().parents[1]
NAME = "Priya Kovalenko"
UPN = "priya.kovalenko@contoso.example"
SEED = bytes(range(32))
TEMPORARY = re.compile(r"\.pseudonym\.key\.[0-9a-f]{24}\.tmp")


# -- helpers ------------------------------------------------------------------------------------------------------


def _keyless(root: Path, name: str = NAME, upn: str = UPN) -> Path:
    """A hand-built run as 1.4.0 left it: a manifest, a report pack naming ``name`` and no ``operator-inputs/``."""
    _write_run(root)
    report = root / "reports" / "report-pack.json"
    payload = json.loads(report.read_text())
    payload["executive_summary"]["narrative"] = f"Mailbox of {name} was shared"
    report.write_text(json.dumps(payload))
    user = {"kind": "user", "display_name": name, "principal_name": upn, "user_type": "Member"}
    (root / "normalized" / "users.json").write_text(json.dumps({"kind": "users", "records": [user]}))
    return root


def _keyed(root: Path, name: str = NAME) -> Path:
    run = _keyless(root, name)
    ensure_pseudonym_key(run)
    return run


def _seed(run: Path, key: bytes = SEED) -> None:
    """Replace the key by plain file I/O, as the contract smoke does."""
    folder = run / "operator-inputs"
    folder.mkdir(mode=0o700, exist_ok=True)
    path = folder / "pseudonym.key"
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.write(fd, key)
    os.close(fd)


def _key(run: Path) -> bytes:
    return (run / PSEUDONYM_KEY_PATH).read_bytes()


def _tree(root: Path) -> dict[str, tuple[int, int, int]]:
    """Every entry below ``root`` with its mode, size and modification time: proof that nothing was written."""
    found = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        found[str(path.relative_to(root))] = (info.st_mode, info.st_size, info.st_mtime_ns)
    return found


def _preview(run: Path, fmt: str = "md", profile: str = "shareable") -> dict:
    from auditex.reporting import preview_report

    return preview_report(run_dir=str(run), format_name=fmt, include_sections=["executive_summary"], profile=profile)


def _prose(key: bytes, name: str = NAME) -> str:
    return "User " + pseudonym(key, name)


def _temporaries(run: Path) -> list[str]:
    folder = run / "operator-inputs"
    return [name for name in os.listdir(folder) if TEMPORARY.fullmatch(name)] if folder.is_dir() else []


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests"), sysconfig.get_paths()["purelib"],
                                         env.get("PYTHONPATH", "")))
    return env


def _python(code: str, *args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", "-c", code, *args], env=_env(), capture_output=True, timeout=60,
                          check=False, **kwargs)


def _key_forms(key: bytes) -> tuple[str, ...]:
    return (key.hex(), base64.b64encode(key).decode(), base64.urlsafe_b64encode(key).decode().rstrip("="))


def _carries_key(text: str | bytes, key: bytes) -> bool:
    data = text.encode("utf-8", "surrogatepass") if isinstance(text, str) else text
    return key in data or any(form.encode() in data for form in _key_forms(key))


@pytest.fixture(scope="module")
def sealed_m365(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("keyed-m365")
    rc = run_offline(ROOT / "examples" / "sample_audit_bundle" / "sample_result.json", root, "ci", "keyed")
    assert rc in (0, 1)
    return root / "ci-keyed"


@pytest.fixture
def sealed(sealed_m365: Path, tmp_path: Path) -> Path:
    """A private copy of a run sealed by collection (its key travels with it)."""
    target = tmp_path / "ci-keyed"
    shutil.copytree(sealed_m365, target)
    return target


# -- 15. the function ----------------------------------------------------------------------------------------------


def test_15_function_vector_key_checks_and_names() -> None:
    assert pseudonym(bytes(range(32)), "Priya Kovalenko") == "0e36644ea492f352"
    assert pseudonym(SEED, NAME) == hmac.new(SEED, NAME.encode(), hashlib.sha256).hexdigest()[:16]
    for bad in ("k" * 32, b"", bytes(16), bytes(33), bytearray(32)):
        with pytest.raises(ValueError):
            pseudonym(bad, NAME)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            RedactionContext(key=bad)  # type: ignore[arg-type]
    assert redaction._PSEUDONYM_RE.match("User " + pseudonym(SEED, NAME))
    assert redaction._PSEUDONYM_RE.match("Id " + pseudonym(SEED, "immutable"))
    assert PSEUDONYM_KEY_PATH == f"{guarded_io.PRIVATE_DIRECTORY}/{guarded_io.PSEUDONYM_KEY_NAME}"
    assert PSEUDONYM_KEY_PATH == "operator-inputs/pseudonym.key" and PSEUDONYM_KEY_BYTES == 32
    assert PSEUDONYM_STRATEGY == "keyed-hmac-sha256-v1"
    assert len(new_pseudonym_key()) == 32 and new_pseudonym_key() != new_pseudonym_key()
    import pickle

    assert pickle.loads(pickle.dumps(PseudonymKeyError("busy"))).reason == "busy"
    with pytest.raises(ValueError):
        PseudonymKeyError("unexpected")


# -- 1. knowing the run path reproduces nothing ----------------------------------------------------------------------


def test_01_knowing_the_run_path_reproduces_no_pseudonym(tmp_path: Path) -> None:
    run = _keyed(tmp_path / "run")
    content = _preview(run)["content"]
    key = _key(run)
    assert _prose(key) in content and NAME not in content
    spellings = {str(run), os.path.abspath(run), os.path.realpath(run)}
    candidates = [NAME] + [f"Synthetic Person {index}" for index in range(99)]
    for spelling in spellings:
        salt = hashlib.sha256(spelling.encode()).hexdigest()
        for candidate in candidates:
            old = hashlib.sha256((salt + "\0" + candidate).encode()).hexdigest()[:16]
            keyed_with_path = [hmac.new(material, candidate.encode(), hashlib.sha256).hexdigest()[:16]
                               for material in (spelling.encode(), salt.encode(), bytes.fromhex(salt))]
            assert old not in content
            assert not any(value in content for value in keyed_with_path)
    assert _prose(key) == "User " + pseudonym(key, NAME)


# -- 2. collection seals the key (Q2 option A) -----------------------------------------------------------------------


def _assert_sealed_key(run: Path) -> bytes:
    folder = run / "operator-inputs"
    key_file = folder / "pseudonym.key"
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert stat.S_IMODE(key_file.lstat().st_mode) == 0o600 and key_file.lstat().st_size == 32
    assert (folder / ".gitignore").read_bytes() == b"*\n"
    assert not _temporaries(run)
    key = key_file.read_bytes()
    hashes = json.loads((run / "bundle-hashes.json").read_text())
    assert {"path": PSEUDONYM_KEY_PATH, "reason": "redacted_operator_input"} in hashes["excluded"]
    assert not any(row["path"] == PSEUDONYM_KEY_PATH for row in hashes["artifacts"])
    assert not _carries_key((run / "bundle-hashes.json").read_bytes(), key)
    for relative in ("index/evidence.sqlite", "validation.json", "run-manifest.json", "ai_context.json"):
        data = (run / relative).read_bytes()
        assert b"pseudonym.key" not in data and not _carries_key(data, key), relative
    assert verify_bundle_hashes(run)["status"] == "verified"
    return key


def test_02_collection_seals_a_private_key_in_every_provider(sealed: Path, tmp_path: Path) -> None:
    from auditex import cli as auditex_cli

    _assert_sealed_key(sealed)
    code = auditex_cli.main(["google", "run", "--offline", "--sample", str(ROOT / "examples" / "google_workspace_sample.json"),
                             "--domain", "example.com", "--tenant-name", "ci", "--run-name", "keyed",
                             "--out", str(tmp_path / "google")])
    assert code in (0, 1)
    _assert_sealed_key(tmp_path / "google" / "ci-keyed")


def test_02_refinalisation_keeps_the_same_key(tmp_path: Path) -> None:
    from test_tenant_identity import _prepare, write_provider_bundle

    writer, plan = _prepare(tmp_path)
    write_provider_bundle(writer=writer, plan=plan)
    first = _assert_sealed_key(writer.run_dir)
    write_provider_bundle(writer=writer, plan=plan)
    assert _assert_sealed_key(writer.run_dir) == first


# -- 3. a seeded key reproduces identical pseudonyms ---------------------------------------------------------------


def test_03_seeded_key_reproduces_identical_pseudonyms(tmp_path: Path) -> None:
    first, second = _keyed(tmp_path / "a"), _keyed(tmp_path / "b")
    assert _key(first) != _key(second)
    for run in (first, second):
        _seed(run)
    before = (first / PSEUDONYM_KEY_PATH).stat()
    one, again = _preview(first)["content"], _preview(first)["content"]
    assert one == again and _prose(SEED) in one
    assert _preview(second)["content"] == one  # same evidence, same seeded key: byte-identical
    after = (first / PSEUDONYM_KEY_PATH).stat()
    assert _key(first) == SEED and (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


# -- 4. a missing key yields a fresh random one --------------------------------------------------------------------


def test_04_missing_keys_are_fresh_and_random(tmp_path: Path) -> None:
    a, b = _keyless(tmp_path / "a"), _keyless(tmp_path / "b")
    key_a, key_b = ensure_pseudonym_key(a), ensure_pseudonym_key(b)
    assert key_a != key_b and pseudonym(key_a, NAME) != pseudonym(key_b, NAME)
    first, second = RedactionContext(), RedactionContext()
    assert first.key != second.key
    assert redact_output(NAME, context=RedactionContext(protected_names=frozenset({NAME}), key=first.key)) == _prose(first.key)
    context = RedactionContext(protected_names=frozenset({NAME}))
    assert redact_output({"a": NAME, "b": f"by {NAME}"}, context=context) == {"a": _prose(context.key),
                                                                              "b": f"by {_prose(context.key)}"}


# -- 5. concurrent creation converges ------------------------------------------------------------------------------

_ENSURE_CHILD = r'''
import sys
from azure_tenant_audit.output_redaction import ensure_pseudonym_key
print(ensure_pseudonym_key(sys.argv[1]).hex())
'''


def test_05_concurrent_creation_converges(tmp_path: Path) -> None:
    run = _keyless(tmp_path / "run")
    results: list[bytes] = []
    errors: list[BaseException] = []
    gate = threading.Barrier(8)

    def worker() -> None:
        try:
            gate.wait()
            results.append(ensure_pseudonym_key(run))
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    children = [subprocess.Popen([sys.executable, "-B", "-c", _ENSURE_CHILD, str(run)], env=_env(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    outputs = [child.communicate(timeout=60) for child in children]
    assert not errors, errors
    assert all(child.returncode == 0 for child in children), outputs
    keys = {*results, *(bytes.fromhex(out.decode().strip()) for out, _ in outputs)}
    assert keys == {_key(run)}
    assert sorted(os.listdir(run / "operator-inputs")) == [".gitignore", "pseudonym.key"]


# -- 6. damage, interrupted creation and failure paths ---------------------------------------------------------------


@pytest.mark.parametrize("size", [0, 1, 31, 33])
def test_06_wrong_sizes_are_damaged_and_never_regenerated(tmp_path: Path, size: int) -> None:
    run = _keyless(tmp_path / "run")
    _seed(run, b"\x01" * 32)
    (run / PSEUDONYM_KEY_PATH).write_bytes(b"\x02" * size)
    for call in (read_pseudonym_key, ensure_pseudonym_key, context_for_run):
        with pytest.raises(PseudonymKeyError) as caught:
            call(run)
        assert caught.value.reason == "damaged"
        assert str(run) not in str(caught.value) and "operator-inputs/pseudonym.key" in str(caught.value)
    assert _key(run) == b"\x02" * size


_PAUSED_CREATOR = r'''
import errno, os, stat, sys
real_fsync = os.fsync
def fsync(fd):
    info = os.fstat(fd)
    if stat.S_ISREG(info.st_mode) and info.st_size == 32:
        print("paused", flush=True)
        sys.stdin.readline()
        raise OSError(errno.EIO, "injected")
    return real_fsync(fd)
os.fsync = fsync
from azure_tenant_audit.output_redaction import PseudonymKeyError, ensure_pseudonym_key
try:
    ensure_pseudonym_key(sys.argv[1])
except PseudonymKeyError as exc:
    print("refused", exc.reason, flush=True)
else:
    print("created", flush=True)
'''

_STDIN_CHILD = r'''
import sys
from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError, admit_stdin
with GuardContext() as context:
    context.bind_run(sys.argv[1])
    try:
        admit_stdin(context)
    except UnsafeRunFileError:
        print("REFUSED")
    else:
        print("ADMITTED")
'''


def test_06_paused_creator_hides_its_temporary_and_publishes_nothing_on_failure(tmp_path: Path) -> None:
    from azure_tenant_audit.run_files import read_run_file

    run = _keyless(tmp_path / "run")
    child = subprocess.Popen([sys.executable, "-B", "-c", _PAUSED_CREATOR, str(run)], env=_env(),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "paused"
        assert read_pseudonym_key(run) is None  # nothing is visible under the published name
        [temporary] = _temporaries(run)
        with pytest.raises(UnsafeRunFileError):  # amendment 2: another process cannot read the temporary
            read_run_file(run, f"operator-inputs/{temporary}")
        with GuardContext() as context:
            context.bind_run(run)
            with pytest.raises(UnsafeRunFileError) as refused:
                read_guarded_bytes(run / "operator-inputs" / temporary)
            assert refused.value.reason == "private"
        with open(run / "operator-inputs" / temporary, "rb") as handle:
            assert _python(_STDIN_CHILD, str(run), stdin=handle).stdout == b"REFUSED\n"
        started = time.monotonic()
        with pytest.raises(PseudonymKeyError) as busy:
            ensure_pseudonym_key(run)
        assert busy.value.reason == "busy" and time.monotonic() - started >= 1.9
        child.stdin.write("go\n")
        child.stdin.flush()
        assert child.stdout.readline().strip() == "refused unwritable"
    finally:
        child.kill() if child.poll() is None else None
        child.communicate(timeout=30)
    assert not (run / PSEUDONYM_KEY_PATH).exists() and not _temporaries(run)
    assert len(ensure_pseudonym_key(run)) == 32  # a retry creates the key


def _fail_folder_sync(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    real = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode) and "pseudonym.key" in os.listdir(fd):
            raise OSError(code, "injected")
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)


def test_06_folder_sync_error_after_rename_keeps_the_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _keyless(tmp_path / "run")
    _fail_folder_sync(monkeypatch, errno.EIO)
    with pytest.raises(PseudonymKeyError) as caught:
        ensure_pseudonym_key(run)
    assert caught.value.reason == "unwritable"
    monkeypatch.undo()
    key = _key(run)
    assert read_pseudonym_key(run) == key and ensure_pseudonym_key(run) == key and not _temporaries(run)


@pytest.mark.parametrize("code", [errno.EINVAL, errno.EBADF, errno.ENOTSUP, errno.EOPNOTSUPP])
def test_06_unsupported_folder_sync_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    run = _keyless(tmp_path / "run")
    _fail_folder_sync(monkeypatch, code)
    assert ensure_pseudonym_key(run) == _key(run)


def _break_locks(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    import fcntl

    def flock(fd: int, operation: int) -> None:
        raise OSError(code, "injected")

    monkeypatch.setattr(fcntl, "flock", flock)


@pytest.mark.parametrize("code", [errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOLCK, errno.EBADF, errno.EINVAL, errno.EACCES])
def test_06_amendment_1_storage_without_locking_creates_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                 code: int) -> None:
    # EBADF and EINVAL are what Linux network storage answers (NFS emulates flock with write locks).
    run = _keyless(tmp_path / "run")
    keyed = _keyed(tmp_path / "keyed")
    before = _tree(run)
    _break_locks(monkeypatch, code)
    outcomes: list[str] = []

    def creator() -> None:
        try:
            ensure_pseudonym_key(run)
        except PseudonymKeyError as exc:
            outcomes.append(exc.reason)

    threads = [threading.Thread(target=creator) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert outcomes == ["nolock", "nolock"]
    assert _tree(run) == before and not (run / "operator-inputs").exists()
    assert read_pseudonym_key(keyed) == _key(keyed)  # an existing key still reads
    assert "storage does not support locking" in str(PseudonymKeyError("nolock"))


@pytest.mark.parametrize("code", [errno.EWOULDBLOCK, errno.EAGAIN, errno.EINTR])
def test_06_amendment_1_would_block_try_again_and_interrupted_are_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                                         code: int) -> None:
    import fcntl

    run = _keyless(tmp_path / "run")
    real = fcntl.flock
    calls: list[int] = []

    def flock(fd: int, operation: int) -> None:
        calls.append(operation)
        if len(calls) < 3:
            raise OSError(code, "injected")
        real(fd, operation)

    monkeypatch.setattr(fcntl, "flock", flock)
    assert ensure_pseudonym_key(run) == _key(run) and len(calls) == 3
    monkeypatch.setattr(guarded_io, "_LOCK_WAIT_SECONDS", 0.2)
    monkeypatch.setattr(fcntl, "flock", lambda fd, operation: (_ for _ in ()).throw(OSError(code, "injected")))
    with pytest.raises(PseudonymKeyError) as caught:
        ensure_pseudonym_key(_keyless(tmp_path / "other"))
    assert caught.value.reason == "busy"


def _fail_write(monkeypatch: pytest.MonkeyPatch, payload: bytes | None, size: int | None = None) -> None:
    real = private_io._write_all

    def write_all(fd: int, data: bytes) -> None:
        if data == payload or (size is not None and len(data) == size):
            raise OSError(errno.ENOSPC, "injected")
        real(fd, data)

    monkeypatch.setattr(private_io, "_write_all", write_all)


def test_06_gitignore_failure_then_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _keyless(tmp_path / "run")
    _fail_write(monkeypatch, b"*\n")
    with pytest.raises(PseudonymKeyError) as caught:
        ensure_pseudonym_key(run)
    assert caught.value.reason == "unwritable"
    assert sorted(os.listdir(run / "operator-inputs")) == []
    monkeypatch.undo()
    ensure_pseudonym_key(run)
    assert (run / "operator-inputs" / ".gitignore").read_bytes() == b"*\n"


@pytest.mark.parametrize("content", [b"", b"*\n# edited\n", b"secret\n"])
def test_06_wrong_gitignore_is_replaced_before_the_key(tmp_path: Path, content: bytes) -> None:
    run = _keyless(tmp_path / "run")
    (run / "operator-inputs").mkdir(mode=0o700)
    (run / "operator-inputs" / ".gitignore").write_bytes(content)
    os.chmod(run / "operator-inputs" / ".gitignore", 0o600)
    ensure_pseudonym_key(run)
    assert (run / "operator-inputs" / ".gitignore").read_bytes() == b"*\n"


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_06_unsafe_gitignore_is_refused_and_nothing_written(tmp_path: Path, kind: str) -> None:
    run = _keyless(tmp_path / "run")
    folder = run / "operator-inputs"
    folder.mkdir(mode=0o700)
    if kind == "symlink":
        (tmp_path / "elsewhere").write_text("*\n")
        os.symlink(tmp_path / "elsewhere", folder / ".gitignore")
    else:
        os.mkfifo(folder / ".gitignore", 0o600)
    with pytest.raises(UnsafeRunFileError):
        ensure_pseudonym_key(run)
    assert sorted(os.listdir(folder)) == [".gitignore"]


def test_06_key_write_failure_leaves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _keyless(tmp_path / "run")
    _fail_write(monkeypatch, None, size=32)
    with pytest.raises(PseudonymKeyError) as caught:
        ensure_pseudonym_key(run)
    assert caught.value.reason == "unwritable"
    assert not (run / PSEUDONYM_KEY_PATH).exists() and not _temporaries(run)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "hardlink"])
def test_06_unsafe_key_files_are_refused_and_left_alone(tmp_path: Path, kind: str) -> None:
    run = _keyless(tmp_path / "run")
    folder = run / "operator-inputs"
    folder.mkdir(mode=0o700)
    target = folder / "pseudonym.key"
    elsewhere = tmp_path / "elsewhere.key"
    elsewhere.write_bytes(SEED)
    os.chmod(elsewhere, 0o600)
    if kind == "symlink":
        os.symlink(elsewhere, target)
    elif kind == "fifo":
        os.mkfifo(target, 0o600)
    elif kind == "directory":
        target.mkdir(mode=0o700)
    else:
        os.link(elsewhere, target)
    before = _tree(run)
    started = time.monotonic()
    for call in (read_pseudonym_key, ensure_pseudonym_key):
        with pytest.raises(UnsafeRunFileError):
            call(run)
    assert time.monotonic() - started < 10 and _tree(run) == before and elsewhere.read_bytes() == SEED


def test_06_damaged_key_blocks_every_derivation(sealed: Path, tmp_path: Path) -> None:
    from auditex.mcp_server import preview_report as mcp_preview
    from auditex.notify import send_notification
    from auditex.reporting import load_report_bundle, write_enterprise_handoff_pack
    from auditex.rule_assessment import assess_run
    from auditex.scuba_projection import project_run

    unassessed = tmp_path / "unassessed"
    shutil.copytree(sealed, unassessed)
    (unassessed / PSEUDONYM_KEY_PATH).write_bytes(b"short")
    with pytest.raises(PseudonymKeyError):
        assess_run(unassessed)
    assert not (unassessed / "model_assessment.json").exists()
    assess_run(sealed)  # explanations exist, so even a local report needs the key
    assessment = (sealed / "model_assessment.json").read_bytes()
    (sealed / PSEUDONYM_KEY_PATH).write_bytes(b"short")
    calls = {
        "assess": lambda: assess_run(sealed, policies=["MS.POWERBI.1.1v1"]),
        "local bundle": lambda: load_report_bundle(str(sealed), shareable=False),
        "local preview": lambda: _preview(sealed, profile="local"),
        "shareable preview": lambda: _preview(sealed),
        "customer pack": lambda: write_enterprise_handoff_pack(sealed, tmp_path / "pack"),
        "notify": lambda: send_notification(run_dir=str(sealed), sink="teams", dry_run=True),
        "mcp preview": lambda: mcp_preview(str(sealed), "md"),
        "projection": lambda: project_run(sealed),
    }
    for label, call in calls.items():
        with pytest.raises(PseudonymKeyError) as caught:
            call()
        assert caught.value.reason == "damaged", label
    assert (sealed / "model_assessment.json").read_bytes() == assessment


def test_06_cli_report_on_a_damaged_key_exits_2_with_the_fixed_message(sealed: Path, capsys: pytest.CaptureFixture) -> None:
    from auditex import cli as auditex_cli
    from auditex.rule_assessment import assess_run

    assess_run(sealed)  # a local render masks the stored explanations with the run's key
    (sealed / PSEUDONYM_KEY_PATH).write_bytes(b"short")
    assert auditex_cli.main(["report", "render", str(sealed), "--format", "md",
                             "--output", str(sealed.parent / "out.md")]) == 2
    err = capsys.readouterr().err
    assert "Refusing" in err and str(sealed) not in err and str(sealed.parent) not in err


# -- 7. permissions ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("target,mode", [("key", 0o644), ("key", 0o640), ("folder", 0o755), ("folder", 0o750)])
def test_07_widened_key_or_folder_is_refused_and_left_alone(sealed: Path, target: str, mode: int) -> None:
    from auditex.reporting import load_report_bundle
    from auditex.rule_assessment import assess_run

    assess_run(sealed)  # explanations exist, so even a local report needs the key
    path = sealed / (PSEUDONYM_KEY_PATH if target == "key" else "operator-inputs")
    os.chmod(path, mode)
    for call in (lambda: load_report_bundle(str(sealed), shareable=False), lambda: _preview(sealed),
                 lambda: _preview(sealed, profile="local"), lambda: context_for_run(sealed)):
        with pytest.raises(PseudonymKeyError) as caught:
            call()
        assert caught.value.reason == "permissions"
    assert stat.S_IMODE(path.stat().st_mode) == mode
    os.chmod(path, 0o600 if target == "key" else 0o700)
    assert load_report_bundle(str(sealed), shareable=False)["sections"]["policy_explanations"]
    assert context_for_run(sealed).key == _key(sealed)


def test_07_copied_and_read_only_runs(tmp_path: Path) -> None:
    run = _keyed(tmp_path / "run")
    copy = tmp_path / "copy"
    shutil.copytree(run, copy)
    assert _preview(copy)["content"] == _preview(run)["content"]
    keyless = _keyless(tmp_path / "keyless")
    if os.geteuid() == 0:
        pytest.skip("root ignores the read-only mode")
    for folder in (run, keyless):
        os.chmod(folder, 0o500)
    try:
        before = _tree(keyless)
        assert _prose(_key(run)) in _preview(run)["content"]
        assert NAME in _preview(run, profile="local")["content"]
        assert _prose(session_pseudonym_key(keyless)) in _preview(keyless)["content"]
        assert NAME in _preview(keyless, profile="local")["content"]
        assert _tree(keyless) == before
    finally:
        for folder in (run, keyless):
            os.chmod(folder, 0o700)


# -- 8. the key never leaves the machine ----------------------------------------------------------------------------


def _run_tools() -> list[tuple[str, object, dict]]:
    import inspect

    from auditex.mcp_registry import TOOL_REGISTRY
    from auditex.mcp_server import tool_handlers

    handlers = tool_handlers()
    tools = []
    for entry in TOOL_REGISTRY:
        if not entry.read_only_hint or entry.name not in handlers:
            continue
        parameters = inspect.signature(handlers[entry.name]).parameters
        if not {"run_dir", "run_a", "run_b", "run_dirs"} & set(parameters):
            continue
        tools.append((entry.name, handlers[entry.name], dict(parameters)))
    return tools


def test_08_the_key_never_leaves_the_machine(sealed: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from auditex.notify import send_notification
    from auditex.reporting import write_enterprise_handoff_pack

    caplog.set_level(logging.DEBUG)
    key = _key(sealed)
    texts: list[str] = []
    for profile in ("shareable", "customer_pack"):
        for fmt in ("json", "md", "html"):
            texts.append(json.dumps(_preview(sealed, fmt, profile)))
    write_enterprise_handoff_pack(sealed, tmp_path / "pack")
    pack_files = [path for path in (tmp_path / "pack").rglob("*") if path.is_file()]
    assert pack_files and not any("pseudonym.key" == path.name for path in pack_files)
    texts.extend(path.read_text(errors="replace") for path in pack_files)
    texts.append(json.dumps(send_notification(run_dir=str(sealed), sink="teams", dry_run=True)))
    tools = _run_tools()
    assert {"auditex_summarize_run", "auditex_report_preview", "auditex_diff_runs"} <= {name for name, _, _ in tools}
    for _name, handler, parameters in tools:
        arguments = {"run_dir": str(sealed), "run_a": str(sealed), "run_b": str(sealed), "run_dirs": [str(sealed)] * 2,
                     "assessment_paths": []}
        kwargs = {key_name: value for key_name, value in arguments.items() if key_name in parameters}
        try:
            texts.append(json.dumps(handler(**kwargs), default=str))
        except Exception as exc:  # noqa: BLE001 - a refusal's message must not carry the key either
            texts.append(f"{type(exc).__name__}: {exc}")
    context = context_for_run(sealed)
    texts.append(repr(context))
    try:
        RedactionContext(key=key[:31])
    except ValueError as exc:
        texts.append(str(exc))
    for reason in ("damaged", "busy", "permissions", "unwritable", "nolock"):
        texts.append(str(PseudonymKeyError(reason)) + repr(PseudonymKeyError(reason)))
    texts.append(caplog.text)
    assert context.key == key and not re.search(r"(?<!_)\bkey=", repr(context))
    assert not any(_carries_key(text, key) for text in texts)
    hashes = json.loads((sealed / "bundle-hashes.json").read_text())
    assert [row for row in hashes["excluded"] if "pseudonym" in row["path"]] == [
        {"path": PSEUDONYM_KEY_PATH, "reason": "redacted_operator_input"}]


# -- 9. guard registration -----------------------------------------------------------------------------------------


def test_09_the_key_is_refused_as_any_ordinary_input(sealed: Path, tmp_path: Path) -> None:
    from auditex.mcp_server import tool_handlers

    key_path = sealed / PSEUDONYM_KEY_PATH
    key = _key(sealed)
    with GuardContext() as context:
        context.bind_run(sealed)
        for candidate in {key_path, sealed / "operator-inputs" / "PSEUDONYM.KEY"}:
            if candidate != key_path and not candidate.exists():
                continue  # case-sensitive file system: no alias to try
            with pytest.raises(UnsafeRunFileError) as refused:
                read_guarded_bytes(candidate)
            assert refused.value.reason == "private"
        with pytest.raises(UnsafeRunFileError) as refused:
            with open_private_output(key_path, field="output", context=context):
                pass
        assert refused.value.reason == "private"
    with pytest.raises(UnsafeRunFileError):
        read_guarded_bytes(key_path)  # discovery binds the run first
    with key_path.open("rb") as handle:
        assert _python(_STDIN_CHILD, str(sealed), stdin=handle).stdout == b"REFUSED\n"
    with pytest.raises(UnsafeRunFileError):
        tool_handlers()["auditex_normalize_external_assessment"]("scubagear", str(key_path))
    assert _key(sealed) == key
    loose = tmp_path / "loose" / "operator-inputs"
    loose.mkdir(parents=True, mode=0o700)
    (loose / "pseudonym.key").write_bytes(SEED)
    (loose / "notes.txt").write_text("ordinary")
    with pytest.raises(UnsafeRunFileError):
        read_guarded_bytes(loose / "notes.txt")  # a key below a manifest-less private folder


_HOLDER = r'''
import os, sys, time
from pathlib import Path
from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError, admit_stdin, open_private_output, read_guarded_bytes
run = Path(sys.argv[1])
key = run / "operator-inputs" / "pseudonym.key"
with GuardContext() as context:
    context.bind_run(run)
    print("bound", flush=True)
    deadline = time.monotonic() + 30
    while not (run / "created").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    results = []
    for candidate in (key, run / "operator-inputs" / "PSEUDONYM.KEY"):
        if candidate != key and not candidate.exists():
            results.append("private")
            continue
        try:
            read_guarded_bytes(candidate)
            results.append("read")
        except UnsafeRunFileError as exc:
            results.append(exc.reason)
    try:
        with open_private_output(key, field="output", context=context):
            pass
        results.append("opened")
    except UnsafeRunFileError as exc:
        results.append(exc.reason)
    os.dup2(os.open(key, os.O_RDONLY), 0)
    try:
        admit_stdin(context)
        results.append("admitted")
    except UnsafeRunFileError:
        results.append("refused")
    print(" ".join(results), flush=True)
'''


def test_09_a_key_created_by_another_process_is_refused_without_the_reader(tmp_path: Path) -> None:
    run = _keyless(tmp_path / "run")
    holder = subprocess.Popen([sys.executable, "-B", "-c", _HOLDER, str(run)], env=_env(), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "bound"
        key = ensure_pseudonym_key(run)
        (run / "created").write_text("")
        out, err = holder.communicate(timeout=60)
    finally:
        holder.kill() if holder.poll() is None else None
    assert out.strip() == "private private private refused", err
    assert _key(run) == key


# -- 10. bundle integrity ------------------------------------------------------------------------------------------


def test_10_bundle_integrity_with_added_key_leftovers_and_listed_rows(sealed: Path, tmp_path: Path) -> None:
    from auditex.reporting import write_enterprise_handoff_pack

    shutil.rmtree(sealed / "operator-inputs")  # a keyless legacy run, finalised without a key
    assert verify_bundle_hashes(sealed)["status"] == "verified"
    ensure_pseudonym_key(sealed)
    result = verify_bundle_hashes(sealed)
    assert result["status"] == "verified" and not result.get("unlisted")
    leftover = f".pseudonym.key.{'a' * 24}.tmp"
    (sealed / "operator-inputs" / leftover).write_bytes(b"\x00" * 7)
    assert is_private_operator_input(f"operator-inputs/{leftover}")
    assert verify_bundle_hashes(sealed)["status"] == "verified"
    write_enterprise_handoff_pack(sealed, tmp_path / "pack")
    hashes = json.loads((sealed / "bundle-hashes.json").read_text())
    hashes["artifacts"].append({"path": PSEUDONYM_KEY_PATH, "sha256": "0" * 64, "bytes": 32})
    (sealed / "bundle-hashes.json").write_text(json.dumps(hashes))
    listed = verify_bundle_hashes(sealed)
    assert listed["status"] == "invalid" and PRIVATE_ROW_MESSAGE in json.dumps(listed)


# -- 11 and 18 (Q3 option d). keyless runs: temporary key, nothing written --------------------------------------------


def test_11_legacy_bundle_renders_with_a_temporary_key_and_writes_nothing(tmp_path: Path) -> None:
    import jsonschema

    from azure_tenant_audit.scuba_assessment import validate_assessment

    run = _keyless(tmp_path / "legacy")
    before = _tree(run)
    temporary = session_pseudonym_key(run)
    shareable = _preview(run)
    assert _prose(temporary) in shareable["content"] and NAME not in shareable["content"]
    assert NAME in _preview(run, profile="local")["content"]
    assert _tree(run) == before and not (run / "operator-inputs").exists()
    from auditex.rule_assessment import assess_run

    assessment = assess_run(run, policies=["MS.POWERBI.1.1v1"])
    assert not (run / "operator-inputs").exists()
    assessment["projection"]["redaction"]["strategy"] = "run-salted-sha256-v1"  # as 1.4.0 wrote it
    validate_assessment(assessment)
    jsonschema.validate(assessment, json.loads((ROOT / "schemas/model_assessment.schema.json").read_text()))


def test_18_session_keys_are_per_process_and_a_later_key_file_wins(tmp_path: Path) -> None:
    run = _keyless(tmp_path / "run")
    before = _tree(run)
    first, second = context_for_run(run), context_for_run(run)
    assert first.key == second.key == session_pseudonym_key(run) and first.temporary_key
    child = _python("import sys; from azure_tenant_audit.output_redaction import context_for_run; "
                    "print(context_for_run(sys.argv[1]).key.hex())", str(run))
    assert child.returncode == 0 and bytes.fromhex(child.stdout.decode().strip()) != first.key
    assert _tree(run) == before
    key = ensure_pseudonym_key(run)
    later = context_for_run(run)
    assert later.key == key != first.key and not later.temporary_key


def test_18_prepare_key_prints_created_then_present(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    from auditex import cli as auditex_cli

    run = _keyless(tmp_path / "run")
    assert auditex_cli.main(["report", "prepare-key", str(run)]) == 0
    assert capsys.readouterr().out == "created\n"
    key = _key(run)
    assert auditex_cli.main(["report", "prepare-key", str(run)]) == 0
    assert capsys.readouterr().out == "present\n" and _key(run) == key
    assert _prose(key) in _preview(run)["content"]
    (run / PSEUDONYM_KEY_PATH).write_bytes(b"short")
    assert auditex_cli.main(["report", "prepare-key", str(run)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "damaged" in captured.err and str(run) not in captured.err
    bare = tmp_path / "bare"
    bare.mkdir()
    assert auditex_cli.main(["report", "prepare-key", str(bare)]) == 2
    assert not (bare / "operator-inputs").exists()
    with pytest.raises(SystemExit):
        auditex_cli.main(["report", "prepare-k", str(run)])


# -- 12. compare uses the first-listed run's key ---------------------------------------------------------------------


def test_12_several_runs_use_the_first_listed_runs_key(tmp_path: Path) -> None:
    a = _keyed(tmp_path / "a")
    b = _keyless(tmp_path / "b", "Kemi Rotax", "kemi.rotax@contoso.example")
    text = f"{NAME} and Kemi Rotax"
    assert redact_output(text, context=context_for_runs([a, b])) == f"{_prose(_key(a))} and {_prose(_key(a), 'Kemi Rotax')}"
    assert not (b / "operator-inputs").exists()
    _seed(b, b"\x07" * 3)  # a damaged key in the second run is never read
    assert redact_output(text, context=context_for_runs([a, b])).startswith(_prose(_key(a)))
    _seed(b, SEED)
    assert redact_output(text, context=context_for_runs([b, a])) == f"{_prose(SEED)} and {_prose(SEED, 'Kemi Rotax')}"


# -- 13. projection -------------------------------------------------------------------------------------------------


def test_13_projection_reads_the_key_and_never_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.scuba_projection as projection_module
    from auditex.scuba_projection import project_run

    monkeypatch.setattr(projection_module, "AREA_ADAPTER_MODULES", ())
    run = _bundle_with_admin(tmp_path / "bundle")
    before = _tree(run)
    keyless = project_run(run)
    assert keyless.report["redaction"]["strategy"] == "keyed-hmac-sha256-v1" and _tree(run) == before
    assert keyless["privileged_users"]["User1"]["DisplayName"] == "User " + pseudonym(session_pseudonym_key(run), "Synthetic Person")
    _seed(run)
    assert project_run(run)["privileged_users"]["User1"]["DisplayName"] == "User " + pseudonym(SEED, "Synthetic Person")
    (run / PSEUDONYM_KEY_PATH).write_bytes(b"short")
    with pytest.raises(PseudonymKeyError):
        project_run(run)
    assert project_run(run, redact=False).report["redaction"]["enabled"] is False  # the key is not opened


def _bundle_with_admin(root: Path) -> Path:
    """``test_scuba_projection``'s complete bundle: one privileged user, every built-in section collected."""
    import test_scuba_projection as t

    root.mkdir(parents=True)
    t.write(root, "run-manifest.json", {"run_id": "synthetic-run", "platform": "m365", "tenant_id": t.TENANT,
                                        "graph_endpoint": "https://graph.microsoft.com/v1.0"})
    t.operation(root, "identity", "organization", [{"id": t.TENANT}])
    t.operation(root, "identity", "users", [{"id": t.TENANT, "displayName": t.PERSON, "onPremisesImmutableId": None}])
    t.write(root, "normalized/effective_admin_set.json", {"records": [
        {"kind": "effective_admin_set_summary", "state": "complete", "unresolved_principal_count": 0, "admin_count": 1},
        {"kind": "effective_admin", "state": "complete", "is_user": True, "principal_id": t.TENANT,
         "role_names": ["Global Administrator"], "roles": [t.GLOBAL_ADMIN_ROLE]}]})
    t.write(root, "normalized/sharepoint_tenant_settings.json", {"records": [{
        "read_state": "collected", "sharing_capability": "externalUserAndGuestSharing",
        "onedrive_sharing_capability": "existingExternalUserSharingOnly"}]})
    t.operation(root, "sharepoint_access", "sharePointSettings", [t.SPO])
    t.operation(root, "conditional_access", "conditionalAccessPolicies", [t.graph(t.CA)])
    auth = t.graph(t.AUTH)
    assigned = auth.pop("permissionGrantPolicyIdsAssignedToDefaultUserRole")
    auth["defaultUserRolePermissions"]["permissionGrantPoliciesAssigned"] = assigned
    t.operation(root, "consent_policy", "authorizationPolicy", [auth])
    t.operation(root, "licensing", "subscribedSkus", [{"skuPartNumber": "SPE_E5", "servicePlans": [
        {**t.graph(t.EXPECTED["service_plans"][0]), "provisioningStatus": "Success"}]}])
    t.write(root, "normalized/privileged_roles.json", {"records": t.ROLES})
    for collector, name, row in t.PS.values():
        t.operation(root, collector, name, [row])
    for name in ("dmarc_records", "spf_records", "dkim_records"):
        t.operation(root, "dns_posture", name, t.EXPECTED[name])
    return root


# -- 14. moved and copied runs ---------------------------------------------------------------------------------------


def test_14_moved_runs_keep_and_copies_without_the_folder_change_pseudonyms(tmp_path: Path) -> None:
    run = _keyed(tmp_path / "run")
    original = _preview(run)["content"]
    moved = tmp_path / "elsewhere" / "renamed"
    moved.parent.mkdir()
    run.rename(moved)
    assert _preview(moved)["content"] == original
    copy = tmp_path / "copy"
    shutil.copytree(moved, copy, ignore=shutil.ignore_patterns("operator-inputs"))
    assert read_pseudonym_key(copy) is None
    assert pseudonym(ensure_pseudonym_key(copy), NAME) != pseudonym(_key(moved), NAME)


# -- 16. writers emit only the new label ------------------------------------------------------------------------------


def test_16_writers_emit_only_the_keyed_label(tmp_path: Path) -> None:
    from auditex.rule_assessment import assess_run, assess_scubagear_export

    run = _bundle_with_admin(tmp_path / "bundle")
    assert assess_run(run, policies=["MS.POWERBI.1.1v1"])["projection"]["redaction"]["strategy"] == PSEUDONYM_STRATEGY
    written = json.loads((run / "model_assessment.json").read_text())
    assert written["projection"]["redaction"]["strategy"] == PSEUDONYM_STRATEGY
    from test_scubagear_export import PROVIDER as export

    result = assess_scubagear_export(export, tmp_path / "export", policies=["MS.AAD.7.1v1"])
    assert result["projection"]["redaction"]["strategy"] == PSEUDONYM_STRATEGY
    assert "run-salted-sha256-v1" not in (tmp_path / "export" / "model_assessment.json").read_text()


# -- 17. manifest-less directory ---------------------------------------------------------------------------------------


def test_17_a_folder_without_a_manifest_gets_no_private_folder(tmp_path: Path) -> None:
    folder = tmp_path / "loose"
    (folder / "normalized").mkdir(parents=True)
    (folder / "normalized" / "users.json").write_text(json.dumps({"records": [
        {"kind": "user", "display_name": NAME, "principal_name": UPN}]}))
    context = context_for_run(folder)
    assert not context.temporary_key and not (folder / "operator-inputs").exists()
    assert redact_output(NAME, context=context) == _prose(context.key)


# -- 19. finalisation on storage without locking ---------------------------------------------------------------------


def test_19_finalisation_without_locking_seals_a_keyless_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from test_tenant_identity import _prepare, write_provider_bundle

    _break_locks(monkeypatch, errno.ENOTSUP)
    writer, plan = _prepare(tmp_path)
    write_provider_bundle(writer=writer, plan=plan)
    run = writer.run_dir
    assert not (run / PSEUDONYM_KEY_PATH).exists()
    events = [json.loads(line) for line in (run / "audit-log.jsonl").read_text().splitlines() if line.strip()]
    unavailable = [event for event in events if event.get("event") == "pseudonym_key.unavailable"]
    assert len(unavailable) == 1 and unavailable[0].get("details") == {"reason": "nolock"}
    assert verify_bundle_hashes(run)["status"] == "verified"
    monkeypatch.undo()
    assert context_for_run(run).temporary_key  # keyless: rendered with a temporary key


# -- amendment 3: a context keeps the first key it resolved -----------------------------------------------------------


def test_amendment_3_one_operation_keeps_its_first_key(tmp_path: Path) -> None:
    from azure_tenant_audit.guarded_io import guard_session

    run = _keyless(tmp_path / "run")
    with guard_session():
        first = context_for_run(run)
        created = _python(_ENSURE_CHILD, str(run))  # another process prepares the run meanwhile
        assert created.returncode == 0
        again = context_for_run(run)
        assert again.key == first.key and again.temporary_key
        assert redact_payload({"text": NAME}, run_dirs=[run])["text"] == _prose(first.key)
    assert context_for_run(run).key == bytes.fromhex(created.stdout.decode().strip())


# -- amendment 4: the run folder is flushed after the private folder is created ---------------------------------------


def test_amendment_4_run_folder_is_flushed_after_the_private_folder_appears(tmp_path: Path,
                                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    run = _keyless(tmp_path / "run")
    real = os.fsync
    synced: list[tuple[int, int]] = []

    def fsync(fd: int) -> None:
        info = os.fstat(fd)
        synced.append((info.st_dev, info.st_ino))
        real(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    ensure_pseudonym_key(run)
    run_identity = (run.stat().st_dev, run.stat().st_ino)
    folder = (run / "operator-inputs").stat()
    assert run_identity in synced and (folder.st_dev, folder.st_ino) in synced
    assert synced.index(run_identity) < synced.index((folder.st_dev, folder.st_ino))
    synced.clear()
    other = _keyless(tmp_path / "other")
    (other / "operator-inputs").mkdir(mode=0o700)  # an existing folder: the run folder is not flushed again
    ensure_pseudonym_key(other)
    assert (other.stat().st_dev, other.stat().st_ino) not in synced


# -- amendment 5: descriptions cover every keyless run and claim nothing about approval prompts -----------------------


def test_amendment_5_descriptions_cover_every_keyless_run() -> None:
    from auditex.cli import _build_report_parser

    contract = (ROOT / "docs" / "reference" / "output-contract.md").read_text()
    parser = _build_report_parser()
    help_text = " ".join(parser._subparsers._group_actions[0].choices["prepare-key"].format_help().split())
    for text in (contract, help_text):
        flat = " ".join(text.split())
        assert "1.4.0 or earlier" in flat and "without operator-inputs/" in flat and "without locking" in flat
    section = contract[contract.index("## Private pseudonym key"):contract.index("## Contract history")]
    history = contract[contract.index("Version `2026-11-11`"):contract.index("Version `2026-11-08`")]
    flat = " ".join((section + history).split())
    assert "auditex report prepare-key" in flat and "Linux network storage" in flat
    assert not re.search(r"approv|prompt|ask(?:s|ing)? (?:the user|for permission)", flat + help_text, re.IGNORECASE)


# -- amendment 6: output made with a temporary key says so -------------------------------------------------------------


def test_amendment_6_temporary_key_outputs_carry_the_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module
    from auditex.mcp_server import list_blockers, preview_report, summarize_run

    assert "auditex report prepare-key" in TEMPORARY_KEY_NOTICE and "not stable across sessions" in TEMPORARY_KEY_NOTICE
    keyless, keyed = _keyless(tmp_path / "keyless"), _keyed(tmp_path / "keyed")
    payload = {"tenant_name": "acme", "overall_status": "ok", "finding_count": 0, "open_count": 0, "blocker_count": 0}
    monkeypatch.setattr(notify_module, "_build_payload", lambda run_dir: dict(payload))
    sent: list[str] = []
    monkeypatch.setenv("AUDITEX_TEAMS_WEBHOOK_URL", "https://example.invalid/hook")
    monkeypatch.setattr(notify_module, "_send_webhook",
                        lambda sink, body: sent.append(notify_module._payload_text(body, sink)) or {"status": "sent"})
    for run, expected in ((keyless, True), (keyed, False)):
        outputs = {
            "report md": _preview(run, "md")["content"],
            "report html": _preview(run, "html")["content"],
            "preview": json.dumps(_preview(run, "json")),
            "mcp preview": json.dumps(preview_report(str(run), "md")),
            "mcp summary": json.dumps(summarize_run(str(run))),
            "mcp blockers": json.dumps(list_blockers(str(run))),
            "notification": json.dumps(notify_module.send_notification(run_dir=str(run), sink="teams", dry_run=True)),
        }
        for label, text in outputs.items():
            assert (TEMPORARY_KEY_NOTICE in text or html_escaped(TEMPORARY_KEY_NOTICE) in text) is expected, (label, run)
    notify_module.send_notification(run_dir=str(keyless), sink="teams", dry_run=False)
    assert sent and TEMPORARY_KEY_NOTICE in sent[-1]


def html_escaped(text: str) -> str:
    import html

    return html.escape(text)


def _keyless_copy(sealed: Path, tmp_path: Path) -> Path:
    """A sealed run copied without its private folder: a keyless run with real collected content."""
    keyless = tmp_path / "ci-keyless"
    shutil.copytree(sealed, keyless, ignore=shutil.ignore_patterns("operator-inputs"))
    return keyless


_CHECKSUM_LINE = re.compile(r"[0-9a-f]{64}  [\w./-]+")


def test_amendment_6_customer_pack_of_a_keyless_run_carries_the_notice(
    sealed: Path, tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    """DEC-023 B1: every file of a keyless run's pack that can hold a pseudonym says its key is temporary (the
    manifest, the README, the generated files and every redacted JSON copy under ``source-artifacts/``), and so does
    the result ``customer-pack`` prints. The two files left without it hold no pseudonym: ``checksums.sha256`` (digests
    and pack paths only) and the hash manifest, a byte-for-byte copy that ``verify-pack`` checks by digest."""
    from auditex import cli as auditex_cli
    from auditex.reporting import verify_enterprise_handoff_pack

    keyless = _keyless_copy(sealed, tmp_path)
    before = _tree(keyless)
    for run, expected in ((keyless, True), (sealed, False)):
        pack = tmp_path / f"pack-{run.name}"
        assert auditex_cli.main(["report", "customer-pack", str(run), "--output-dir", str(pack)]) == 0
        printed = json.loads(capsys.readouterr().out)
        assert (printed.get("pseudonym_notice") == TEMPORARY_KEY_NOTICE) is expected, run.name
        manifest = json.loads((pack / "pack-manifest.json").read_text())
        listed = {row["path"] for row in manifest["generated_files"]}
        listed |= {row["path"] for row in manifest["source_artifacts"] if row.get("present")}
        files = {path.relative_to(pack).as_posix() for path in pack.rglob("*") if path.is_file()}
        assert files == listed | {"pack-manifest.json"}  # every file is classified below
        copies = {name for name in files if name.startswith("source-artifacts/") and name.endswith(".json")}
        assert {"source-artifacts/run-manifest.json", "source-artifacts/summary.json",
                "source-artifacts/reports/report-pack.json", "source-artifacts/ai_context.json"} <= copies
        for name in sorted(files):
            text = (pack / name).read_text()
            if name == "checksums.sha256":
                assert all(_CHECKSUM_LINE.fullmatch(line) for line in text.splitlines()), name
            elif name == "source-artifacts/bundle-hashes.json":
                assert (pack / name).read_bytes() == (run / "bundle-hashes.json").read_bytes()
            elif name.endswith(".json"):
                assert (json.loads(text).get("pseudonym_notice") == TEMPORARY_KEY_NOTICE) is expected, (name, run.name)
                assert (TEMPORARY_KEY_NOTICE in text) is expected, (name, run.name)  # the whole file, not one field
            else:
                assert name.endswith(".md")
                assert (TEMPORARY_KEY_NOTICE in text) is expected, (name, run.name)
            if name in {"checksums.sha256", "source-artifacts/bundle-hashes.json"}:
                assert TEMPORARY_KEY_NOTICE not in text and "pseudonym_notice" not in text, name
        if expected:
            assert (pack / "README.md").read_text().rstrip("\n").endswith(TEMPORARY_KEY_NOTICE)
        assert verify_enterprise_handoff_pack(str(pack))["valid"] is True, run.name
    assert _tree(keyless) == before  # the keyless run was read, never written


@pytest.mark.parametrize("fmt", ["md", "html", "json", "csv", "sarif", "oscal"])
def test_amendment_6_every_written_report_format_carries_the_notice(
    sealed: Path, tmp_path: Path, request: pytest.FixtureRequest, fmt: str,
) -> None:
    import csv
    import io

    from auditex.reporting import _CSV_COLUMNS, render_report

    keyless = _keyless_copy(sealed, tmp_path)
    before = _tree(keyless)
    for run, expected in ((keyless, True), (sealed, False)):
        target = tmp_path / f"{run.name}.{fmt}"
        result = render_report(run_dir=str(run), format_name=fmt, output_path=str(target), profile="shareable")
        text = target.read_text()
        assert ("pseudonym_notice" in result) is expected
        assert (TEMPORARY_KEY_NOTICE in text or html_escaped(TEMPORARY_KEY_NOTICE) in text) is expected, run.name
        if fmt == "csv":
            rows = list(csv.reader(io.StringIO(text)))
            assert rows[0] == list(_CSV_COLUMNS) and {len(row) for row in rows} == {len(_CSV_COLUMNS)}
            assert (rows[-1][:2] == ["pseudonym_notice", TEMPORARY_KEY_NOTICE]) is expected
        elif fmt in {"json", "sarif", "oscal"}:
            document = json.loads(text)
            if fmt == "sarif":
                placed = document["runs"][0]["properties"].get("auditex.pseudonym_notice")
            elif fmt == "oscal":
                placed = document["assessment-results"]["metadata"].get("remarks")
            else:
                placed = document.get("pseudonym_notice")
            assert (placed == TEMPORARY_KEY_NOTICE) is expected, run.name
            if fmt != "json":
                assert _schema_errors(request.getfixturevalue(f"{fmt}_validator"), document) == [], run.name
    assert _tree(keyless) == before  # the keyless run was read, never written


@pytest.mark.parametrize("command", ["analyze", "api-calls", "permissions", "proof-table", "handoff"])
def test_amendment_6_cli_report_outputs_carry_the_notice(
    sealed: Path, tmp_path: Path, capsys: pytest.CaptureFixture, command: str,
) -> None:
    from auditex import cli as auditex_cli

    keyless = _keyless_copy(sealed, tmp_path)
    formats = ("json",) if command == "analyze" else ("json", "md")
    for run, expected in ((keyless, True), (sealed, False)):
        for fmt in formats:
            argv = ["report", command, str(run)] + ([] if command == "analyze" else ["--format", fmt])
            assert auditex_cli.main(argv) == 0
            printed = capsys.readouterr().out
            if command == "analyze":
                written = printed
            else:
                target = tmp_path / f"{run.name}-{command}.{fmt}"
                assert auditex_cli.main([*argv, "--output", str(target)]) == 0
                assert json.loads(capsys.readouterr().out)["output_path"] == str(target)
                written = target.read_text()
                assert written == printed  # stdout and the written file carry the same content
            assert (TEMPORARY_KEY_NOTICE in written) is expected, (command, fmt, run.name)
            if fmt == "json":
                assert (json.loads(written).get("pseudonym_notice") == TEMPORARY_KEY_NOTICE) is expected
            else:
                assert written.rstrip("\n").endswith(TEMPORARY_KEY_NOTICE) is expected
    assert not (keyless / "operator-inputs").exists()


# -- DEC-023: privacy review repair ------------------------------------------------------------------------------------


def _publish_between_discovery_and_open(monkeypatch: pytest.MonkeyPatch, run: Path, selected: Path,
                                        method: str = "_parent") -> list[bytes]:
    """Another process creates the run's key after the guard's first discovery of ``selected`` and before its open
    (the first call of ``GuardContext.<method>`` for ``selected``), the window REV-M04-T03-privacy A1 found. Returns
    the published key (one element once it ran)."""
    published: list[bytes] = []
    target = os.path.abspath(selected)
    real = getattr(guarded_io.GuardContext, method)

    def opener(self, path):
        if not published and self._absolute(path) == target:
            child = _python("import sys; from azure_tenant_audit.output_redaction import ensure_pseudonym_key; "
                            "ensure_pseudonym_key(sys.argv[1])", str(run))
            assert child.returncode == 0, child.stderr
            published.append(_key(run))
        return real(self, path)

    monkeypatch.setattr(guarded_io.GuardContext, method, opener)
    return published


def _read(path: Path) -> bytes:
    return read_guarded_bytes(path)


def _overwrite(path: Path) -> None:
    with guarded_io.guard_session() as context, open_private_output(path, field="output", context=context) as fd:
        os.write(fd, b"overwritten")


def _remove(path: Path) -> None:
    guarded_io.remove_guarded_output(path)


def _remove_folder(path: Path) -> None:
    guarded_io.remove_guarded_tree(path)


@pytest.mark.parametrize("operation,selected", [
    (_read, PSEUDONYM_KEY_PATH), (_overwrite, PSEUDONYM_KEY_PATH), (_remove, PSEUDONYM_KEY_PATH),
    (_remove_folder, "operator-inputs"),
], ids=["read", "overwrite", "remove", "remove-folder"])
def test_dec_023_a1_a_key_published_between_discovery_and_open_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation, selected: str,
) -> None:
    run = _keyless(tmp_path / "run")
    assert not (run / "operator-inputs").exists()  # nothing to bind at the first discovery
    published = _publish_between_discovery_and_open(monkeypatch, run, run / selected)
    with pytest.raises(UnsafeRunFileError):
        operation(run / selected)
    assert len(published) == 1 and _key(run) == published[0]  # never returned, truncated or removed
    assert stat.S_IMODE((run / PSEUDONYM_KEY_PATH).stat().st_mode) == 0o600


def test_dec_023_a3_a_reused_run_folder_with_another_run_id_gets_another_temporary_key(tmp_path: Path) -> None:
    """The temporary key is indexed by the run id as well as the folder's device and inode: a later keyless run that
    reuses a deleted run folder's inode (shown here by giving the same folder another run id) never shares the
    first run's key, so pseudonyms cannot link people across the two runs."""
    run = _keyless(tmp_path / "run")
    manifest = run / "run-manifest.json"
    payload = json.loads(manifest.read_text())
    first = session_pseudonym_key(run)
    assert session_pseudonym_key(run) == first  # one key per run per process
    identity = (run.stat().st_dev, run.stat().st_ino)
    manifest.write_text(json.dumps({**payload, "run_id": str(payload.get("run_id")) + "-another"}))
    assert (run.stat().st_dev, run.stat().st_ino) == identity
    other = session_pseudonym_key(run)
    assert other != first and context_for_run(run).key == other
    manifest.write_text(json.dumps(payload))
    assert session_pseudonym_key(run) == first


def test_dec_023_a4_the_projection_masker_never_rebinds_its_key() -> None:
    import ast
    import inspect

    from auditex import scuba_projection

    function = ast.parse(inspect.getsource(scuba_projection._redact)).body[0]
    assert [argument.arg for argument in function.args.args][1] == "key"
    rebound = [node.lineno for node in ast.walk(function)
               if isinstance(node, ast.Name) and node.id == "key" and isinstance(node.ctx, ast.Store)]
    assert rebound == []


# -- DEC-024: the class closure (every guarded entry point; result.md holds the table) -------------------------------


@pytest.mark.parametrize("layout", ["key-folder", "nested-run"])
def test_dec_024_a_run_file_read_re_discovers_after_the_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str,
) -> None:
    """``run_files.open_run_file`` binds only the run it is rooted at. A read rooted at the key's own folder, or at a
    folder that is not a run with the run nested below it, binds nothing at the first discovery while the run has no
    ``operator-inputs/``; the key another process publishes before the open is refused by the discovery that runs
    again after the open (REV-M04-T03 result 3, blocking A1)."""
    from azure_tenant_audit.run_files import read_run_file

    run = _keyless(tmp_path / "run")
    root, relative = ((run / "operator-inputs", "pseudonym.key") if layout == "key-folder"
                      else (tmp_path, "run/operator-inputs/pseudonym.key"))
    published = _publish_between_discovery_and_open(monkeypatch, run, root, method="_directory")
    with pytest.raises(UnsafeRunFileError) as refused:
        read_run_file(root, relative)
    assert refused.value.reason == "private"
    assert len(published) == 1 and _key(run) == published[0]


_UNBOUND_STDIN_CHILD = r'''
from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError, admit_stdin
with GuardContext() as context:
    try:
        admit_stdin(context)
    except UnsafeRunFileError:
        print("REFUSED")
    else:
        print("ADMITTED")
'''


def test_dec_024_stdin_from_a_key_is_refused_with_no_run_bound(sealed: Path, tmp_path: Path) -> None:
    """Standard input opened on a file is admitted only after discovery from the path its descriptor names, so the
    key is refused even when the command bound no run (the shell opened it before the process started)."""
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_text("not a key\n")
    with ordinary.open("rb") as handle:
        assert _python(_UNBOUND_STDIN_CHILD, stdin=handle).stdout == b"ADMITTED\n"
    with (sealed / PSEUDONYM_KEY_PATH).open("rb") as handle:
        assert _python(_UNBOUND_STDIN_CHILD, stdin=handle).stdout == b"REFUSED\n"


def test_dec_024_removing_a_tree_never_removes_a_nested_runs_key(tmp_path: Path) -> None:
    """``remove_guarded_tree`` discovers upwards from the tree it removes; a run nested inside the tree is bound by
    the discovery each file gets after its open, so the run's key refuses the removal and nothing is removed."""
    tree = tmp_path / "pack" / "source-artifacts"
    run = _keyed(tree / "run")
    key = _key(run)
    before = _tree(tree)
    with pytest.raises(UnsafeRunFileError):
        guarded_io.remove_guarded_tree(tree)
    assert _key(run) == key and _tree(tree) == before


_NO_RUN_ID = object()


@pytest.mark.parametrize("run_id", [_NO_RUN_ID, None, 7, ["run-1"], ""],
                         ids=["missing", "null", "number", "list", "empty"])
def test_dec_024_a_keyless_run_without_a_usable_run_id_never_shares_its_temporary_key(tmp_path: Path, run_id) -> None:
    """A keyless run whose manifest records no usable run id gets a temporary key for one operation only, kept
    nowhere for the process: another operation on the same folder (as a later run reusing its inode would be) never
    gets the same key, so pseudonyms cannot link people across two such runs (REV-M04-T03 result 3, blocking A3)."""
    run = _keyless(tmp_path / "run")
    manifest = run / "run-manifest.json"
    payload = json.loads(manifest.read_text())
    if run_id is _NO_RUN_ID:
        del payload["run_id"]
    else:
        payload["run_id"] = run_id
    manifest.write_text(json.dumps(payload))
    before = _tree(run)
    kept = dict(redaction._SESSION_KEYS)
    with guarded_io.guard_session():
        first = session_pseudonym_key(run)
        operation = context_for_run(run)
        assert session_pseudonym_key(run) == first == operation.key and operation.temporary_key
    later = session_pseudonym_key(run)
    assert later != first and context_for_run(run).key not in {first, later}
    assert redaction._SESSION_KEYS == kept and _tree(run) == before


@pytest.mark.parametrize("manifest_at_discovery", [True, False], ids=["bound-run", "manifest-later"])
def test_dec_024_write_private_cannot_overwrite_a_key_published_after_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manifest_at_discovery: bool,
) -> None:
    """Why ``private_io._write_private`` (behind ``write_private_bytes``, ``write_private_text`` and
    ``copy_private_file``) never replaces the key in its discovery-to-open window without a second discovery of its
    own. It creates the destination's folder before discovery, so ``operator-inputs/`` is there when discovery runs.
    With the run's manifest there too, discovery binds the run; the write's temporary then carries a key temporary's
    name in the key's folder and is refused at its first admission, and a key published afterwards is registered
    when the existing file is admitted (``_check_file`` resynchronises every bound run's key). With no manifest yet,
    discovery refuses every path inside a private folder that has none, before anything is opened. Either way the
    key published in the window is never replaced."""
    run = _keyless(tmp_path / "run")
    manifest = run / "run-manifest.json"
    aside = tmp_path / "run-manifest.json"
    if not manifest_at_discovery:
        manifest.rename(aside)
    target = run / PSEUDONYM_KEY_PATH
    published: list[bytes] = []
    real_parent = guarded_io.GuardContext._parent

    def parent(self, path):
        if not published and self._absolute(path) == os.path.abspath(target):
            if aside.exists():
                aside.rename(manifest)
            child = _python("import sys; from azure_tenant_audit.output_redaction import ensure_pseudonym_key; "
                            "ensure_pseudonym_key(sys.argv[1])", str(run))  # another process: nothing shared
            assert child.returncode == 0, child.stderr
            published.append(_key(run))
        return real_parent(self, path)

    monkeypatch.setattr(guarded_io.GuardContext, "_parent", parent)
    with pytest.raises(UnsafeRunFileError):
        private_io.write_private_bytes(target, bytes(range(32, 64)))
    if manifest_at_discovery:
        assert len(published) == 1 and _key(run) == published[0]
    else:
        assert published == [] and not target.exists()  # refused at discovery, before the window opens
    assert not _temporaries(run)  # the write's own temporary is gone too
