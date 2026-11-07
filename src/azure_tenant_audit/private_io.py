"""Write local evidence to private files through admitted descriptors."""
from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Callable

from .guarded_io import UnsafeRunFileError, _DIR_FLAGS, _safe_directory, guard_session, open_pinned_binary

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def make_private_dirs(path: str | Path) -> Path:
    """Create missing output directories without following symlinks."""
    target = Path(path)
    failed = False
    with guard_session() as context:
        current = None
        try:
            value = os.path.expanduser(os.fspath(target))
            parsed = Path(value)
            parts = parsed.parts[1:] if parsed.is_absolute() else parsed.parts
            anchor = context._root_fd if parsed.is_absolute() else context._cwd_fd
            if anchor is None:
                raise OSError("closed context")
            current = os.dup(anchor)
            for part in parts:
                if part in ("", "."):
                    continue
                try:
                    child = os.open(part, _DIR_FLAGS, dir_fd=current)
                except FileNotFoundError:
                    try:
                        os.mkdir(part, PRIVATE_DIR_MODE, dir_fd=current)
                    except FileExistsError:
                        pass
                    child = os.open(part, _DIR_FLAGS, dir_fd=current)
                os.close(current)
                current = child
            if not _safe_directory(os.fstat(current)):
                raise UnsafeRunFileError("output-dir")
        except (OSError, ValueError, TypeError):
            failed = True
        finally:
            if current is not None:
                os.close(current)
    if failed:
        raise UnsafeRunFileError("output-dir") from None
    return target


def _temporary_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.{os.urandom(12).hex()}.tmp")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short write")
        view = view[count:]


def _write_private(path: str | Path, emit: Callable[[int], None]) -> Path:
    target = Path(path)
    make_private_dirs(target.parent)
    temporary = _temporary_sibling(target)
    failed = False
    parent = None
    fd = None
    created = False
    with guard_session() as context:
        try:
            with context._lock:
                context.discover_run(target)
                parent, name = context._parent(target)
                if not _safe_directory(os.fstat(parent)) or temporary.parent != target.parent:
                    raise UnsafeRunFileError("output")
                temp_name = temporary.name
                flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_CLOEXEC", 0))
                fd = os.open(temp_name, flags, PRIVATE_FILE_MODE, dir_fd=parent)
                created = True
                context._check_file(os.fstat(fd), "output", None)
                os.fchmod(fd, PRIVATE_FILE_MODE)
                emit(fd)
                context._check_file(os.fstat(fd), "output", None)
                existing = None
                try:
                    existing = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
                except FileNotFoundError:
                    pass
                if existing is not None:
                    try:
                        context._check_file(os.fstat(existing), "output", None)
                    finally:
                        os.close(existing)
                os.replace(temp_name, name, src_dir_fd=parent, dst_dir_fd=parent)
                created = False
                context._pinned.pop(context._absolute(target), None)
                if name == "run-manifest.json" and context._absolute(target.parent) in context._runs:
                    context.refresh_run(target.parent)
        except (OSError, ValueError, TypeError):
            failed = True
        finally:
            if fd is not None:
                os.close(fd)
            if created and parent is not None:
                try:
                    os.unlink(temporary.name, dir_fd=parent)
                except OSError:
                    pass
            if parent is not None:
                os.close(parent)
    if failed:
        raise UnsafeRunFileError("output") from None
    return target


def write_private_bytes(path: str | Path, data: bytes) -> Path:
    """Atomically write to an admitted destination, refusing links and private identities."""
    return _write_private(path, lambda fd: _write_all(fd, data))


def write_private_text(path: str | Path, content: str, *, encoding: str = "utf-8") -> Path:
    return write_private_bytes(path, content.encode(encoding))


def copy_private_file(source: str | Path, destination: str | Path) -> Path:
    """Copy only the admitted source descriptor to an admitted destination."""
    with guard_session() as context, open_pinned_binary(source, field="input", context=context) as reader:
        def emit(fd: int) -> None:
            while data := reader.read(1024 * 1024):
                _write_all(fd, data)
        return _write_private(destination, emit)


def harden_tree(root: str | Path) -> None:
    """Restrict admitted paths below ``root`` without following links."""
    from .guarded_io import open_guarded_file

    base = Path(root)
    with guard_session() as context:
        for current, directories, files in os.walk(base, followlinks=False):
            for name in (".", *directories):
                target = Path(current) / name if name != "." else Path(current)
                if target.is_symlink():
                    continue
                descriptor = context._directory(target)
                try:
                    if not _safe_directory(os.fstat(descriptor)):
                        raise UnsafeRunFileError("output-dir")
                    if stat.S_IMODE(os.fstat(descriptor).st_mode) != PRIVATE_DIR_MODE:
                        os.fchmod(descriptor, PRIVATE_DIR_MODE)
                finally:
                    os.close(descriptor)
            for name in files:
                target = Path(current) / name
                if target.is_symlink():
                    continue
                with open_guarded_file(target, field="output", context=context) as descriptor:
                    if stat.S_IMODE(os.fstat(descriptor).st_mode) != PRIVATE_FILE_MODE:
                        os.fchmod(descriptor, PRIVATE_FILE_MODE)
                        context._pinned.pop(context._absolute(target), None)
