"""Descriptor admission for registered runs and standalone inputs."""
from __future__ import annotations

import json
import os
import shutil
import stat
import threading
import traceback
from pathlib import Path

import pytest
from support import RunBundleBuilder

from azure_tenant_audit.sensitive_users import SensitiveUsers

KEY = b"admission-canary-012345678901234"
ADDRESS = "private-admission@example.invalid"


@pytest.fixture
def private_run(tmp_path: Path) -> Path:
    run = RunBundleBuilder(tmp_path).summary_md().manifest(
        operator_inputs={"sensitive_users": SensitiveUsers((ADDRESS,)).manifest(KEY)},
    ).build()
    private = run / "operator-inputs"
    private.mkdir(mode=0o700)
    (private / "sensitive-users.key").write_bytes(KEY)
    (private / "sensitive-users.txt").write_text(ADDRESS + "\n", encoding="utf-8")
    return run


@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink", "devfd"])
def test_admission_refuses_registered_pair_and_aliases(private_run: Path, tmp_path: Path, member: str, alias: str) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    source = private_run / "operator-inputs" / member
    with GuardContext() as context:
        context.bind_run(private_run)
        fd = None
        if alias == "direct":
            candidate = source
        elif alias == "devfd":
            fd = os.open(source, os.O_RDONLY)
            candidate = Path(f"/DEV/fd/{fd}")
            if not candidate.exists():
                os.close(fd)
                pytest.skip("/DEV/fd is unavailable")
        else:
            candidate = tmp_path / "whitespace alias\u2003."
            if alias == "symlink":
                candidate.symlink_to(source)
            else:
                os.link(source, candidate)
        try:
            with pytest.raises(UnsafeRunFileError, match=r"^Refusing input: unsafe input\.$") as error:
                with open_guarded_file(candidate, field="input", context=context):
                    pytest.fail("private bytes became readable")
            rendered = "".join(traceback.format_exception(error.value))
            assert KEY.decode() not in rendered and ADDRESS not in rendered
        finally:
            if fd is not None:
                os.close(fd)


@pytest.mark.parametrize("directory", ["run", "private"])
def test_group_or_world_writable_run_directories_are_refused(private_run: Path, directory: str) -> None:
    from azure_tenant_audit.run_files import GuardContext, UnsafeRunFileError

    target = private_run if directory == "run" else private_run / "operator-inputs"
    target.chmod(0o770)
    try:
        with GuardContext() as context, pytest.raises(UnsafeRunFileError):
            context.bind_run(private_run)
    finally:
        target.chmod(0o700)


def test_admission_traceback_does_not_include_original_os_error(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    target = tmp_path / "argument-path-canary"
    target.write_text("ordinary", encoding="utf-8")
    original = os.open

    with GuardContext() as context:
        context.bind_run(private_run)

        def fail_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            if str(path) == target.name:
                raise PermissionError("argument-path-canary private-os-error")
            return original(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", fail_open)
        with pytest.raises(UnsafeRunFileError) as caught:
            with open_guarded_file(target, field="input", context=context):
                pytest.fail("unexpected open")
    rendered = "".join(traceback.format_exception(caught.value))
    assert "argument-path-canary" not in rendered
    assert "private-os-error" not in rendered
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_pinned_descriptor_failure_has_no_original_exception_or_argument(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_pinned_binary,
    )

    target = tmp_path / "pinned-argument-canary"
    target.write_bytes(b"public")
    with GuardContext() as context:
        context.bind_run(private_run)
        with open_pinned_binary(target, field="input", context=context):
            pass
        descriptor = context._pinned[context._absolute(target)][0]
        original_fstat = os.fstat

        def fail_fstat(fd: int) -> os.stat_result:
            if fd == descriptor:
                raise PermissionError("pinned-argument-canary private-os-error")
            return original_fstat(fd)

        monkeypatch.setattr(os, "fstat", fail_fstat)
        with pytest.raises(UnsafeRunFileError) as error:
            with open_pinned_binary(target, field="input", context=context):
                pytest.fail("unexpected open")
    rendered = "".join(traceback.format_exception(error.value))
    assert "pinned-argument-canary" not in rendered and "private-os-error" not in rendered
    assert error.value.__cause__ is None and error.value.__context__ is None


@pytest.mark.parametrize("target_kind", ["key", "list", "hardlink"])
def test_writer_refuses_before_truncating_private_or_multilink_file(
    private_run: Path, tmp_path: Path, target_kind: str,
) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_private_output,
    )

    key = private_run / "operator-inputs" / "sensitive-users.key"
    private_list = private_run / "operator-inputs" / "sensitive-users.txt"
    with GuardContext() as context:
        context.bind_run(private_run)
        target = key if target_kind == "key" else private_list
        if target_kind == "hardlink":
            target = tmp_path / "hardlinked-output"
            os.link(key, target)
        before = target.read_bytes()
        with pytest.raises(UnsafeRunFileError):
            with open_private_output(target, field="output", context=context) as fd:
                os.write(fd, b"overwritten")
        assert target.read_bytes() == before


def test_registered_run_does_not_block_an_independent_ordinary_file(private_run: Path, tmp_path: Path) -> None:
    from azure_tenant_audit.run_files import GuardContext, open_guarded_file

    target = tmp_path / "ordinary.txt"
    target.write_bytes(b"public")
    with GuardContext() as context:
        context.bind_run(private_run)
        with open_guarded_file(target, field="input", context=context) as fd:
            assert os.read(fd, 10) == b"public"


def test_independent_copy_recovers_from_hardlinked_backup(private_run: Path, tmp_path: Path) -> None:
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    linked_backup = tmp_path / "linked-backup"
    recovered = tmp_path / "independent-copy"
    shutil.copytree(private_run, linked_backup, copy_function=os.link)
    shutil.copytree(private_run, recovered, copy_function=shutil.copy2)
    with GuardContext() as context:
        with pytest.raises(UnsafeRunFileError):
            context.bind_run(private_run)
        with pytest.raises(UnsafeRunFileError):
            context.bind_run(linked_backup)
        context.bind_run(recovered)
        for member in ("sensitive-users.key", "sensitive-users.txt"):
            with pytest.raises(UnsafeRunFileError):
                with open_guarded_file(recovered / "operator-inputs" / member, field="input", context=context):
                    pytest.fail("copied private pair was admitted")


def test_private_registration_and_input_admission_are_serialised(
    private_run: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    pair_opened, release_registration = threading.Event(), threading.Event()
    reader_started, reader_finished = threading.Event(), threading.Event()
    failures: list[BaseException] = []
    original_open = os.open

    def hold_pair(path: object, flags: int, *args: object, **kwargs: object) -> int:
        descriptor = original_open(path, flags, *args, **kwargs)
        if str(path) == "sensitive-users.key":
            pair_opened.set()
            assert release_registration.wait(5)
        return descriptor

    monkeypatch.setattr(os, "open", hold_pair)
    with GuardContext() as context:
        def register() -> None:
            try:
                context.bind_run(private_run)
            except BaseException as exc:
                failures.append(exc)

        def read_private() -> None:
            reader_started.set()
            try:
                with open_guarded_file(private_run / "operator-inputs/sensitive-users.key",
                                       field="input", context=context):
                    failures.append(AssertionError("private key was admitted"))
            except UnsafeRunFileError:
                pass
            except BaseException as exc:
                failures.append(exc)
            finally:
                reader_finished.set()

        writer = threading.Thread(target=register)
        reader = threading.Thread(target=read_private)
        writer.start()
        try:
            assert pair_opened.wait(5)
            reader.start()
            assert reader_started.wait(5)
            assert not reader_finished.wait(0.05)
        finally:
            release_registration.set()
            writer.join(5)
            if reader.ident is not None:
                reader.join(5)
        assert not writer.is_alive() and not reader.is_alive()
        assert reader_finished.is_set() and failures == []


@pytest.mark.parametrize("suffix", [" ", ".", "\u00a0", "\u2003", "\u3000", "\u200b"])
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
@pytest.mark.parametrize("member", ["sensitive-users.key", "sensitive-users.txt"])
def test_whitespace_dot_and_unicode_alias_matrix(
    private_run: Path, tmp_path: Path, suffix: str, link: str, member: str,
) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    source = private_run / "operator-inputs" / member
    alias = tmp_path / ("seemingly-public.json" + suffix)
    with GuardContext() as context:
        context.bind_run(private_run)
        if link == "symlink":
            alias.symlink_to(source)
        else:
            os.link(source, alias)
        with pytest.raises(UnsafeRunFileError):
            with open_guarded_file(alias, field="input", context=context):
                pytest.fail("private alias was opened")


def test_equal_inode_numbers_on_different_devices_are_not_the_same_file(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.run_files import GuardContext, open_guarded_file

    private = private_run / "operator-inputs" / "sensitive-users.key"
    ordinary = tmp_path / "ordinary"
    ordinary.write_bytes(b"public")
    private_info, ordinary_info = private.stat(), ordinary.stat()
    original = os.fstat

    def same_inode_other_device(fd: int) -> os.stat_result:
        info = original(fd)
        identity = (info.st_dev, info.st_ino)
        if identity in {(private_info.st_dev, private_info.st_ino), (ordinary_info.st_dev, ordinary_info.st_ino)}:
            fields = list(info)
            fields[stat.ST_INO] = 12345
            fields[stat.ST_DEV] = 100 if identity == (private_info.st_dev, private_info.st_ino) else 200
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "fstat", same_inode_other_device)
    with GuardContext() as context:
        context.bind_run(private_run)
        with open_guarded_file(ordinary, field="input", context=context) as fd:
            assert os.read(fd, 10) == b"public"


@pytest.mark.skipif(not os.environ.get("AUDITEX_TEST_SECOND_RUN"),
                    reason="set AUDITEX_TEST_SECOND_RUN to a constructed run on a different volume")
def test_independent_private_pairs_are_registered_across_volumes(private_run: Path) -> None:
    """Bind an independently created synthetic run from a genuinely different device."""
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    second = Path(os.environ["AUDITEX_TEST_SECOND_RUN"])
    assert private_run.stat().st_dev != second.stat().st_dev
    with GuardContext() as context:
        context.bind_run(private_run)
        context.bind_run(second)
        for run in (private_run, second):
            for member in ("sensitive-users.key", "sensitive-users.txt"):
                with pytest.raises(UnsafeRunFileError):
                    with open_guarded_file(run / "operator-inputs" / member, field="input", context=context):
                        pytest.fail("a registered private pair was admitted")


@pytest.mark.parametrize("kind", ["directory", "fifo", "hardlink", "oversize"])
def test_standalone_inputs_refuse_unsafe_type_link_count_or_size(tmp_path: Path, kind: str) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    target = tmp_path / "input"
    if kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO creation unavailable")
        os.mkfifo(target)
    else:
        target.write_bytes(b"ordinary")
        if kind == "hardlink":
            os.link(target, tmp_path / "second-link")
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        with open_guarded_file(target, field="input", context=context, max_bytes=2 if kind == "oversize" else None):
            pytest.fail("unsafe input opened")


@pytest.mark.parametrize("target_kind", ["run", "private-file", "ordinary-file"])
def test_wrong_owner_is_refused(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target_kind: str,
) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    ordinary = tmp_path / "ordinary"
    ordinary.write_bytes(b"public")
    target = {"run": private_run, "private-file": private_run / "operator-inputs" / "sensitive-users.key",
              "ordinary-file": ordinary}[target_kind]
    expected = target.stat()
    original = os.fstat

    def wrong_owner(fd: int) -> os.stat_result:
        info = original(fd)
        if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
            values = list(info)
            values[stat.ST_UID] = os.geteuid() + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(os, "fstat", wrong_owner)
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        context.bind_run(private_run)
        if target_kind == "ordinary-file":
            with open_guarded_file(ordinary, field="input", context=context):
                pytest.fail("wrong-owner file opened")


@pytest.mark.parametrize("damage", ["missing-key", "missing-list", "missing-manifest", "invalid-hmac"])
def test_partial_or_unverified_pair_fails_closed(private_run: Path, damage: str) -> None:
    from azure_tenant_audit.run_files import GuardContext, UnsafeRunFileError

    manifest = private_run / "run-manifest.json"
    if damage == "invalid-hmac":
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["operator_inputs"]["sensitive_users"]["hmac_sha256"] = "0" * 64
        manifest.write_text(json.dumps(payload), encoding="utf-8")
    else:
        target = {"missing-key": private_run / "operator-inputs" / "sensitive-users.key",
                  "missing-list": private_run / "operator-inputs" / "sensitive-users.txt",
                  "missing-manifest": manifest}[damage]
        target.unlink()
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        context.bind_run(private_run)


def test_case_variant_private_directory_without_manifest_fails_closed(private_run: Path) -> None:
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    alias = private_run / "Operator-Inputs/sensitive-users.key"
    if not alias.exists():
        pytest.skip("case-sensitive filesystem has no such alias")
    (private_run / "run-manifest.json").unlink()
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        with open_guarded_file(alias, field="input", context=context):
            pytest.fail("unverified private key was admitted")


def test_any_selected_file_in_run_with_unmanifested_pair_is_refused(private_run: Path) -> None:
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    (private_run / "run-manifest.json").unlink()
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        with open_guarded_file(private_run / "summary.json", field="input", context=context):
            pytest.fail("file in an unverified run was admitted")


@pytest.mark.parametrize("outer_manifest", [True, False])
@pytest.mark.parametrize("decoy_private_dir", [True, False])
@pytest.mark.parametrize("private_name", ["sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("consumer", ["open", "hash"])
def test_nested_manifest_never_hides_enclosing_private_pair(
    private_run: Path, outer_manifest: bool, decoy_private_dir: bool, private_name: str, consumer: str,
) -> None:
    from azure_tenant_audit.evidence_refs import file_sha256
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    private = private_run / "operator-inputs"
    (private / "run-manifest.json").write_text("{}")
    if decoy_private_dir:
        (private / "operator-inputs").mkdir(mode=0o700)
    if not outer_manifest:
        (private_run / "run-manifest.json").unlink()
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        if consumer == "hash":
            file_sha256(private / private_name)
        else:
            with open_guarded_file(private / private_name, field="input", context=context):
                pytest.fail("nested marker hid the enclosing private pair")


@pytest.mark.parametrize("outer_manifest", [True, False])
@pytest.mark.parametrize("decoy_private_dir", [True, False])
@pytest.mark.parametrize("private_name", ["sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("consumer", ["read", "hash", "copy"])
@pytest.mark.parametrize("root_scope", ["private", "run", "parent"])
def test_run_file_root_inside_private_directory_never_admits_pair(
    private_run: Path, outer_manifest: bool, decoy_private_dir: bool, private_name: str, consumer: str,
    root_scope: str,
) -> None:
    from io import BytesIO

    from azure_tenant_audit.guarded_io import UnsafeRunFileError
    from azure_tenant_audit.run_files import copy_run_file, hash_run_file, read_run_file

    private = private_run / "operator-inputs"
    (private / "run-manifest.json").write_text("{}", encoding="utf-8")
    if decoy_private_dir:
        (private / "operator-inputs").mkdir(mode=0o700)
    if not outer_manifest:
        (private_run / "run-manifest.json").unlink()
    root = {"private": private, "run": private_run, "parent": private_run.parent}[root_scope]
    relative = (private / private_name).relative_to(root)
    destination = BytesIO()
    with pytest.raises(UnsafeRunFileError):
        if consumer == "read":
            read_run_file(root, relative)
        elif consumer == "hash":
            hash_run_file(root, relative)
        else:
            copy_run_file(root, relative, destination)
    assert destination.getvalue() == b""


@pytest.mark.parametrize("outer_manifest", [True, False])
@pytest.mark.parametrize("decoy_private_dir", [True, False])
@pytest.mark.parametrize("selected", ["all", "sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("root_scope", ["private", "parent"])
def test_bundle_hash_root_inside_private_directory_never_exposes_pair(
    private_run: Path, outer_manifest: bool, decoy_private_dir: bool, selected: str,
    root_scope: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit import bundle_integrity
    from azure_tenant_audit.guarded_io import UnsafeRunFileError

    private = private_run / "operator-inputs"
    (private / "run-manifest.json").write_text("{}", encoding="utf-8")
    if decoy_private_dir:
        (private / "operator-inputs").mkdir(mode=0o700)
    if not outer_manifest:
        (private_run / "run-manifest.json").unlink()
    root = private if root_scope == "private" else private_run.parent
    if selected != "all":
        relative = (private / selected).relative_to(root).as_posix()
        monkeypatch.setattr(bundle_integrity, "_bundle_files", lambda _root: [relative])
    with pytest.raises(UnsafeRunFileError):
        bundle_integrity.build_bundle_hash_manifest(root)


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("consumer", ["run", "standalone"])
def test_manifest_below_private_directory_is_not_a_trust_root(
    private_run: Path, nested: bool, consumer: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )
    from azure_tenant_audit.run_files import read_run_file

    private = private_run / "operator-inputs"
    root = private / "nested" if nested else private
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "run-manifest.json").write_text("{}", encoding="utf-8")
    decoy = root / "operator-inputs"
    decoy.mkdir(mode=0o700)
    (decoy / "sensitive-users.key").write_bytes(b"invalid partial pair")
    (root / "ordinary.txt").write_bytes(b"public")
    attempted: list[Path] = []
    original_bind = GuardContext.bind_run

    def record_bind(context: GuardContext, run_dir: str | Path, **kwargs: object) -> int:
        attempted.append(Path(context._absolute(run_dir)))
        return original_bind(context, run_dir, **kwargs)

    monkeypatch.setattr(GuardContext, "bind_run", record_bind)
    try:
        if consumer == "run":
            assert read_run_file(root, "ordinary.txt") == b"public"
        else:
            with GuardContext() as context:
                with open_guarded_file(root / "ordinary.txt", field="input", context=context) as fd:
                    assert os.read(fd, 6) == b"public"
    except UnsafeRunFileError:
        pass  # Refusing an unclassifiable nested pair is also safe.
    assert root not in attempted


@pytest.mark.parametrize("nested", [False, True])
def test_explicit_bind_refuses_manifest_below_private_directory(private_run: Path, nested: bool) -> None:
    from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError

    root = private_run / "operator-inputs"
    if nested:
        root /= "nested"
        root.mkdir(mode=0o700)
    (root / "run-manifest.json").write_text("{}", encoding="utf-8")
    with GuardContext() as context, pytest.raises(UnsafeRunFileError):
        context.bind_run(root)


@pytest.mark.parametrize("private_name", ["sensitive-users.key", "sensitive-users.txt"])
@pytest.mark.parametrize("consumer", ["open", "file-hash", "read", "hash", "bundle"])
def test_pair_under_ineligible_nested_run_is_never_admitted(
    private_run: Path, private_name: str, consumer: str,
) -> None:
    from azure_tenant_audit.bundle_integrity import build_bundle_hash_manifest
    from azure_tenant_audit.evidence_refs import file_sha256
    from azure_tenant_audit.guarded_io import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )
    from azure_tenant_audit.run_files import hash_run_file, read_run_file

    nested = RunBundleBuilder(private_run / "operator-inputs", name="nested").manifest(
        operator_inputs={"sensitive_users": SensitiveUsers((ADDRESS,)).manifest(KEY)},
    ).build()
    private = nested / "operator-inputs"
    private.mkdir(mode=0o700)
    (private / "sensitive-users.key").write_bytes(KEY)
    (private / "sensitive-users.txt").write_text(ADDRESS + "\n", encoding="utf-8")
    with pytest.raises(UnsafeRunFileError):
        if consumer == "open":
            with GuardContext() as context, open_guarded_file(private / private_name, field="input", context=context):
                pytest.fail("nested private pair was admitted")
        elif consumer == "file-hash":
            file_sha256(private / private_name)
        elif consumer == "read":
            read_run_file(private, private_name)
        elif consumer == "hash":
            hash_run_file(private, private_name)
        else:
            build_bundle_hash_manifest(private)


@pytest.mark.parametrize("root_scope", ["run", "parent"])
def test_discovered_manifest_limit_is_checked_before_read(
    private_run: Path, root_scope: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.guarded_io import UnsafeRunFileError
    from azure_tenant_audit.run_files import read_run_file

    manifest = private_run / "run-manifest.json"
    manifest_info = manifest.stat()
    original_read = os.read
    reads: list[int] = []

    def track_read(fd: int, count: int) -> bytes:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (manifest_info.st_dev, manifest_info.st_ino):
            reads.append(count)
        return original_read(fd, count)

    monkeypatch.setattr(os, "read", track_read)
    root = private_run if root_scope == "run" else private_run.parent
    with pytest.raises(UnsafeRunFileError) as error:
        read_run_file(root, manifest.relative_to(root), max_bytes=2)
    assert error.value.reason == "oversize"
    assert not reads


@pytest.mark.parametrize("private_name", ["sensitive-users.key", "sensitive-users.txt"])
def test_enclosing_pair_is_registered_before_selected_file_open(
    private_run: Path, private_name: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError
    from azure_tenant_audit.run_files import read_run_file

    private = private_run / "operator-inputs"
    (private / "run-manifest.json").write_text("{}", encoding="utf-8")
    private_info = private.stat()
    pair_ids = {(info.st_dev, info.st_ino) for info in (
        (private / "sensitive-users.key").stat(), (private / "sensitive-users.txt").stat(),
    )}
    original_open = os.open
    admitted_at_open: list[set[tuple[int, int]]] = []
    with GuardContext() as context:
        def track_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
            parent_fd = kwargs.get("dir_fd")
            if path == private_name and isinstance(parent_fd, int):
                parent_info = os.fstat(parent_fd)
                if (parent_info.st_dev, parent_info.st_ino) == (private_info.st_dev, private_info.st_ino):
                    admitted_at_open.append(set(context._identities))
            return original_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", track_open)
        with pytest.raises(UnsafeRunFileError):
            read_run_file(private, private_name)
    assert len(admitted_at_open) >= 2
    assert pair_ids <= admitted_at_open[-1]


def test_unrelated_operator_inputs_ancestor_does_not_capture_a_nested_run(tmp_path: Path) -> None:
    from azure_tenant_audit.guarded_io import GuardContext, open_guarded_file

    parent = tmp_path / "operator-inputs"
    parent.mkdir()
    run = RunBundleBuilder(parent, name="unrelated-run").summary_md().build()
    with GuardContext() as context:
        with open_guarded_file(run / "summary.md", field="input", context=context) as descriptor:
            assert os.read(descriptor, 64) == b"# Audit Summary"


def test_non_posix_without_descriptor_relative_open_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.run_files import (
        GuardContext,
        UnsafeRunFileError,
        open_guarded_file,
    )

    target = tmp_path / "ordinary"
    target.write_bytes(b"public")
    monkeypatch.setattr(os, "supports_dir_fd", set())
    with pytest.raises(UnsafeRunFileError):
        with GuardContext() as context:
            with open_guarded_file(target, field="input", context=context):
                pytest.fail("unproved confinement was accepted")


@pytest.mark.parametrize("kind", ["key", "hardlink"])
def test_atomic_writer_refuses_private_replacement(private_run: Path, tmp_path: Path, kind: str) -> None:
    from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError
    from azure_tenant_audit.private_io import write_private_bytes

    key = private_run / "operator-inputs" / "sensitive-users.key"
    with GuardContext() as context:
        context.bind_run(private_run)
        destination = key
        if kind == "hardlink":
            destination = tmp_path / "backup"
            os.link(key, destination)
        with pytest.raises(UnsafeRunFileError):
            write_private_bytes(destination, b"replacement")
        assert key.read_bytes() == KEY
        assert destination.read_bytes() == KEY


def test_atomic_writer_never_truncates_a_linked_temporary_sibling(
    private_run: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azure_tenant_audit import private_io
    from azure_tenant_audit.guarded_io import GuardContext, UnsafeRunFileError

    key = private_run / "operator-inputs" / "sensitive-users.key"
    target = tmp_path / "report.json"
    temporary = tmp_path / "temporary-sibling"
    with GuardContext() as context:
        context.bind_run(private_run)
        os.link(key, temporary)
        monkeypatch.setattr(private_io, "_temporary_sibling", lambda path: temporary)
        with pytest.raises(UnsafeRunFileError):
            private_io.write_private_bytes(target, b"replacement")
        assert key.read_bytes() == KEY
        assert temporary.read_bytes() == KEY


def test_atomic_writer_creates_a_new_private_file(tmp_path: Path) -> None:
    from azure_tenant_audit.private_io import write_private_bytes

    target = tmp_path / "new" / "output"
    write_private_bytes(target, b"ordinary")
    assert target.read_bytes() == b"ordinary"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_output_descriptor_is_not_inheritable(tmp_path: Path) -> None:
    from azure_tenant_audit.guarded_io import GuardContext, open_private_output

    with GuardContext() as context, open_private_output(tmp_path / "output", field="output", context=context) as fd:
        assert not os.get_inheritable(fd)
