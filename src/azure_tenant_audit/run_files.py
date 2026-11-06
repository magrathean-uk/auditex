"""Guarded reads and streams of files in a run bundle."""
from __future__ import annotations

import errno
import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import stat
from typing import BinaryIO


MAX_RUN_FILE_BYTES = 32 * 1024 * 1024
MAX_RUN_DATA_BYTES = 256 * 1024 * 1024
_DEFAULT_LIMIT = object()
_CHUNK_BYTES = 1024 * 1024
_WRITER_READS = ContextVar("auditex_uncapped_writer_reads", default=False)


class UnsafeRunFileError(OSError):
    """A run artifact is not a usable regular file; ``reason`` identifies the rejection."""

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason


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


def _check_file(info: os.stat_result, max_bytes: int | None) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeRunFileError("Run file must be a regular file without symlinks", reason="type")
    if info.st_nlink != 1:
        raise UnsafeRunFileError("Run file must have exactly one link", reason="hardlink")
    if max_bytes is not None and info.st_size > max_bytes:
        raise UnsafeRunFileError(f"Run file exceeds the {max_bytes}-byte size limit", reason="oversize")


@contextmanager
def open_run_file(run_dir: str | Path, relative: str | Path, *, max_bytes: int | None = None) -> Iterator[int]:
    """Open a guarded descriptor, optionally checking its size, and close it on exit."""
    path = Path(relative)
    if not path.parts or path.is_absolute() or path.drive or ".." in path.parts or (os.sep != "\\" and "\\" in str(relative)):
        raise UnsafeRunFileError("Run file path must stay inside the run directory", reason="outside")
    root = Path(run_dir).resolve()
    file_flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    dir_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    descriptors: list[int] = []
    try:
        if (os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
                and os.stat in os.supports_follow_symlinks):
            parent = os.open(root, dir_flags)
            descriptors.append(parent)
            for part in path.parts[:-1]:
                entry = os.stat(part, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode):
                    raise UnsafeRunFileError("Run file path must contain only directories, without symlinks")
                parent = os.open(part, dir_flags, dir_fd=parent)
                descriptors.append(parent)
                opened = os.fstat(parent)
                if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                    raise UnsafeRunFileError("Run file path changed or is not a directory")
            entry = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            _check_file(entry, max_bytes)
            descriptor = os.open(path.name, file_flags, dir_fd=parent)
        else:
            # Platforms without descriptor-relative opens get pre-open link
            # checks and an identity comparison against the opened file.
            target = root
            for index, part in enumerate(path.parts):
                target = target / part
                entry = target.lstat()
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                if stat.S_ISLNK(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & reparse:
                    raise UnsafeRunFileError("Run file must be a regular file without symlinks")
                if index < len(path.parts) - 1 and not stat.S_ISDIR(entry.st_mode):
                    raise UnsafeRunFileError("Run file path must contain only directories, without symlinks")
            _check_file(entry, max_bytes)
            descriptor = os.open(target, file_flags)
        descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        _check_file(opened, max_bytes)
        if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
            raise UnsafeRunFileError("Run file changed or is not a regular file")
        yield descriptor
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise UnsafeRunFileError("Run file path must contain only directories, without symlinks") from exc
        raise
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _chunks(descriptor: int, max_bytes: int | None) -> Iterator[bytes]:
    total = 0
    while True:
        count = _CHUNK_BYTES if max_bytes is None else min(_CHUNK_BYTES, max_bytes + 1 - total)
        chunk = os.read(descriptor, count)
        if not chunk:
            return
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise UnsafeRunFileError(f"Run file exceeds the {max_bytes}-byte size limit", reason="oversize")
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


def read_run_file(run_dir: str | Path, relative: str | Path, *, max_bytes: int | None | object = _DEFAULT_LIMIT) -> bytes:
    """Read a guarded file with its class limit; ``None`` explicitly disables the size cap.

    Missing files raise FileNotFoundError. Unsafe paths or files raise
    UnsafeRunFileError, an OSError with a path-free message and a ``reason``.
    """
    limit = _effective_limit(relative, max_bytes)
    with open_run_file(run_dir, relative, max_bytes=limit) as descriptor:
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
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            output_fd = os.open(destination, flags, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(output_fd, 0o600)
                else:
                    os.chmod(destination, 0o600)
                with os.fdopen(output_fd, "wb", closefd=False) as output:
                    for chunk in _chunks(descriptor, limit):
                        output.write(chunk)
            finally:
                os.close(output_fd)
        else:
            for chunk in _chunks(descriptor, limit):
                destination.write(chunk)
