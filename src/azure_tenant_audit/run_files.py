"""Guarded reads and streams of files in a run bundle."""
from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import BinaryIO

from .guarded_io import (
    GuardContext,  # noqa: F401 - re-exported for callers of this module
    UnsafeRunFileError,
    current_context,  # noqa: F401 - re-exported for callers of this module
    guard_session,
    open_guarded_file,  # noqa: F401 - re-exported for callers of this module
    open_private_output,
)

MAX_RUN_FILE_BYTES = 32 * 1024 * 1024
MAX_RUN_DATA_BYTES = 256 * 1024 * 1024
_DEFAULT_LIMIT = object()
_CHUNK_BYTES = 1024 * 1024
_WRITER_READS = ContextVar("auditex_uncapped_writer_reads", default=False)


def _limit_for(relative: str | Path) -> int:
    name = Path(relative).name.lower()
    salt_name = name.replace("_", "-")
    if (name in {"run-manifest.json", "pack-manifest.json", "bundle-hashes.json", "validation.json",
                 "ai_context.json", "checksums.sha256"}
            or salt_name in {"salt", "run-salt", "redaction-salt", "projection-salt"}
            or salt_name.startswith(("salt.", "run-salt.", "redaction-salt.", "projection-salt."))
            or (name.startswith("summary") and Path(name).suffix in {".json", ".md"})):
        return MAX_RUN_FILE_BYTES
    return MAX_RUN_DATA_BYTES


@contextmanager
def open_run_file(run_dir: str | Path, relative: str | Path, *, max_bytes: int | None = None,
                  field: str = "run-file") -> Iterator[int]:
    """Open once beneath a pinned root, with admission before any read."""
    path = Path(relative)
    if not path.parts or path.is_absolute() or path.drive or ".." in path.parts or (os.sep != "\\" and "\\" in str(relative)):
        raise UnsafeRunFileError(field, reason="outside")
    with guard_session() as context:
        descriptors: list[int] = []
        failed = False
        missing = False
        reason = None
        context._lock.acquire()
        try:
            root_path = context._absolute(run_dir)
            root = Path(root_path)
            context.discover_run(root / path, manifest_max_bytes=max_bytes)
            is_run = context._eligible_run_root(root) and (
                root_path in context._runs or os.path.lexists(root / "operator-inputs")
                or os.path.lexists(root / "run-manifest.json")
            )
            if is_run:
                manifest_limit = max_bytes if path == Path("run-manifest.json") else None
                parent = os.dup(context.bind_run(run_dir, manifest_max_bytes=manifest_limit))
            else:
                parent = context._directory(run_dir)
            descriptors.append(parent)
            if is_run and path == Path("run-manifest.json"):
                descriptor = os.dup(context._manifests[root_path])
                os.lseek(descriptor, 0, os.SEEK_SET)
            else:
                flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
                for part in path.parts[:-1]:
                    parent = os.open(part, flags, dir_fd=parent)
                    descriptors.append(parent)
                    if not stat.S_ISDIR(os.fstat(parent).st_mode):
                        raise UnsafeRunFileError(field, reason="type")
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
            descriptors.append(descriptor)
            context._check_file(os.fstat(descriptor), field, max_bytes)
        except FileNotFoundError:
            missing = True
        except UnsafeRunFileError as exc:
            failed = True
            reason = exc.reason
        except (OSError, ValueError, TypeError):
            failed = True
        if failed or missing:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            context._lock.release()
            if missing:
                raise FileNotFoundError("Input is absent.") from None
            raise UnsafeRunFileError(field, reason=reason) from None
        try:
            yield descriptor
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
            context._lock.release()


def _chunks(descriptor: int, max_bytes: int | None) -> Iterator[bytes]:
    total = 0
    while True:
        count = _CHUNK_BYTES if max_bytes is None else min(_CHUNK_BYTES, max_bytes + 1 - total)
        failed = False
        try:
            chunk = os.read(descriptor, count)
        except OSError:
            failed = True
        if failed:
            raise UnsafeRunFileError("run-file") from None
        if not chunk:
            return
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise UnsafeRunFileError("run-file", reason="oversize")
        yield chunk


def _effective_limit(relative: str | Path, max_bytes: int | None | object) -> int | None:
    if max_bytes is _DEFAULT_LIMIT:
        return None if _WRITER_READS.get() else _limit_for(relative)
    if max_bytes is not None and (not isinstance(max_bytes, int) or max_bytes < 0):
        raise ValueError("max_bytes must be a non-negative integer or None")
    return max_bytes


@contextmanager
def unbounded_writer_reads() -> Iterator[None]:
    """Disable size caps only within a writer's finalisation context."""
    token = _WRITER_READS.set(True)
    try:
        yield
    finally:
        _WRITER_READS.reset(token)


def read_run_file(run_dir: str | Path, relative: str | Path, *, max_bytes: int | None | object = _DEFAULT_LIMIT,
                  field: str = "run-file") -> bytes:
    """Read a guarded file with its class limit; ``None`` explicitly disables the size cap.

    Missing files raise FileNotFoundError. Unsafe paths or files raise
    UnsafeRunFileError, an OSError with a path-free message and a ``reason``.
    """
    limit = _effective_limit(relative, max_bytes)
    with open_run_file(run_dir, relative, max_bytes=limit, field=field) as descriptor:
        return b"".join(_chunks(descriptor, limit))


def hash_run_file(run_dir: str | Path, relative: str | Path, *, max_bytes: int | None | object = _DEFAULT_LIMIT) -> tuple[str, int]:
    """Hash a guarded descriptor without loading the artifact into memory."""
    limit = _effective_limit(relative, max_bytes)
    digest = hashlib.sha256()
    size = 0
    with open_run_file(run_dir, relative, max_bytes=limit) as descriptor:
        for chunk in _chunks(descriptor, limit):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def copy_run_file(run_dir: str | Path, relative: str | Path, destination: str | Path | BinaryIO, *,
                  max_bytes: int | None | object = _DEFAULT_LIMIT) -> None:
    """Copy a guarded descriptor in chunks, opening a destination only after the source."""
    limit = _effective_limit(relative, max_bytes)
    with open_run_file(run_dir, relative, max_bytes=limit) as descriptor:
        if isinstance(destination, (str, Path)):
            with guard_session() as context, open_private_output(
                destination, field="output", context=context, exclusive=True
            ) as output_fd:
                with os.fdopen(os.dup(output_fd), "wb") as output:
                    for chunk in _chunks(descriptor, limit):
                        output.write(chunk)
        else:
            for chunk in _chunks(descriptor, limit):
                destination.write(chunk)
