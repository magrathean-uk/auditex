"""Write files that hold tenant evidence with owner-only modes, whatever the caller's umask.

Run bundles are written 0700/0600 by ``AuditWriter``. Everything the tool writes afterwards (a
rendered report, the explorer page, a customer pack, a report payload sent to ``--output``) holds the
same metadata, so it takes the same modes instead of whatever the umask of the caller allows.

* Directories this module creates are 0700, every missing one between the target and the first
  directory that exists. A directory that already exists is not touched: an ``--output`` below
  ``~/Documents`` must not tighten ``~/Documents``.
* A file is written to a private temporary file in its own directory and renamed into place, so an
  existing file (or a symbolic link planted at the target path) is replaced, never written through.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def make_private_dirs(path: str | Path) -> Path:
    """Create ``path`` and every missing parent as 0700; leave directories that exist alone."""
    target = Path(path)
    missing: list[Path] = []
    current = target
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=PRIVATE_DIR_MODE)
        except FileExistsError:
            continue
        try:
            os.chmod(directory, PRIVATE_DIR_MODE)
        except OSError:
            pass
    return target


def _temporary_sibling(path: Path) -> Path:
    return path.with_name(f".{path.name}.{os.getpid()}.tmp")


def write_private_bytes(path: str | Path, data: bytes) -> Path:
    """Write ``data`` to ``path`` as a 0600 file (parents 0700), replacing whatever was there."""
    target = Path(path)
    make_private_dirs(target.parent)
    temporary = _temporary_sibling(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, PRIVATE_FILE_MODE)
    try:
        try:
            os.fchmod(fd, PRIVATE_FILE_MODE)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return target


def write_private_text(path: str | Path, content: str, *, encoding: str = "utf-8") -> Path:
    """Write text without newline translation as a 0600 file (parents 0700)."""
    return write_private_bytes(path, content.encode(encoding))


def copy_private_file(source: str | Path, destination: str | Path) -> Path:
    """Copy a file's bytes to ``destination`` as a 0600 file (parents 0700)."""
    target = Path(destination)
    make_private_dirs(target.parent)
    temporary = _temporary_sibling(target)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    with Path(source).open("rb") as reader:
        fd = os.open(temporary, flags, PRIVATE_FILE_MODE)
        try:
            try:
                os.fchmod(fd, PRIVATE_FILE_MODE)
            except (AttributeError, OSError):
                pass
            with os.fdopen(fd, "wb") as writer:
                shutil.copyfileobj(reader, writer)
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    return target


def harden_tree(root: str | Path) -> None:
    """Set ``root`` and every directory below it to 0700 and every file to 0600; symbolic links are left alone."""
    base = Path(root)
    for current, directories, files in os.walk(base, followlinks=False):
        for name in (".", *directories, *files):
            target = Path(current) / name if name != "." else Path(current)
            try:
                if target.is_symlink():
                    continue
                wanted = PRIVATE_DIR_MODE if target.is_dir() else PRIVATE_FILE_MODE
                if (target.stat().st_mode & 0o777) != wanted:
                    os.chmod(target, wanted)
            except OSError:
                continue
