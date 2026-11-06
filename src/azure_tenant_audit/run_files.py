"""Bounded, no-follow reads of files in a run bundle."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import tempfile


MAX_RUN_FILE_BYTES = 32 * 1024 * 1024


class UnsafeRunFileError(RuntimeError):
    """A run artifact is not a usable, bounded regular file."""

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason


def temporary_run_data_dir(run_dir: str | Path) -> Path:
    """Keep any temporary evidence copy on the same volume as the run."""
    root = Path(run_dir).resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    device = root.stat().st_dev
    if temporary.stat().st_dev == device:
        return temporary
    if root.parent.stat().st_dev != device:
        raise OSError("No temporary directory on the run's volume")
    return root.parent


def read_run_file(run_dir: str | Path, relative: str | Path, *, max_bytes: int = MAX_RUN_FILE_BYTES) -> bytes:
    """Read one run file without following links, blocking on special files, or exceeding the cap.

    Missing files raise FileNotFoundError so callers can preserve optional-artifact
    fallbacks. Unsafe paths and files raise UnsafeRunFileError instead.
    """
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
            if not stat.S_ISREG(entry.st_mode):
                raise UnsafeRunFileError("Run file must be a regular file without symlinks")
            if entry.st_size > max_bytes:
                raise UnsafeRunFileError(f"Run file exceeds the {max_bytes}-byte size limit", reason="oversize")
            descriptor = os.open(path.name, file_flags, dir_fd=parent)
        else:
            # Windows does not provide descriptor-relative opens. Reject links
            # before opening and compare the opened file with the listed entry.
            target = root
            for index, part in enumerate(path.parts):
                target = target / part
                entry = target.lstat()
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                if stat.S_ISLNK(entry.st_mode) or getattr(entry, "st_file_attributes", 0) & reparse:
                    raise UnsafeRunFileError("Run file must be a regular file without symlinks")
                if index < len(path.parts) - 1 and not stat.S_ISDIR(entry.st_mode):
                    raise UnsafeRunFileError("Run file path must contain only directories, without symlinks")
            if not stat.S_ISREG(entry.st_mode):
                raise UnsafeRunFileError("Run file must be a regular file without symlinks")
            if entry.st_size > max_bytes:
                raise UnsafeRunFileError(f"Run file exceeds the {max_bytes}-byte size limit", reason="oversize")
            descriptor = os.open(target, file_flags)
        descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
            raise UnsafeRunFileError("Run file changed or is not a regular file")
        if opened.st_size > max_bytes:
            raise UnsafeRunFileError(f"Run file exceeds the {max_bytes}-byte size limit", reason="oversize")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise UnsafeRunFileError(f"Run file exceeds the {max_bytes}-byte size limit", reason="oversize")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise UnsafeRunFileError("Run file path must contain only directories, without symlinks") from exc
        raise
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
