"""Descriptor-based admission for local inputs and private output destinations.

A context owns the descriptors which identify private inputs for one operation.
No global identity registry is persisted between operations.
"""
from __future__ import annotations

import errno
import gc
import hmac
import io
import json
import os
import re
import stat
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from functools import wraps
from pathlib import Path

_ORIGINAL_OPEN = os.open
_CURRENT: ContextVar[GuardContext | None] = ContextVar("auditex_guard_context", default=None)
_FIELDS = frozenset({
    "input", "run", "run-file", "manifest", "out", "output", "output-dir", "stdin", "evidence index",
    "sample", "config", "env", "permission-hints", "sensitive-users", "partner-domains", "waiver-file",
    "break-glass-accounts", "assessment", "baseline", "compare", "current", "run-dir", "resume-from", "expect-manifest-sha256", "source",
    "summary_path", "summary_md_path", "auth_context_path", "coverage_path", "report_pack_path",
    "findings_path", "blockers_path", "action_plan_path", "validation_path", "evidence_db_path",
    "pack-manifest", "evidence", "index", "private input",
})
_DIR_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
              | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
_MAX_MANIFEST = 32 * 1024 * 1024
_MAX_LIST = 256 * 1024


class UnsafeRunFileError(OSError):
    """A guarded input or destination could not be proved safe."""

    def __init__(self, field: str = "input", *, reason: str | None = None) -> None:
        self.field = field if field in _FIELDS else "run-file"
        self.reason = reason
        super().__init__(f"Refusing {self.field}: unsafe input.")


# The run's private pseudonym key (``output_redaction.PSEUDONYM_KEY_PATH`` names the same file): 32 random bytes in
# ``operator-inputs/pseudonym.key``. The guard registers it as a private input, so no ordinary guarded read, hash,
# copy, stdin admission or output destination accepts it; only ``GuardContext.pseudonym_key`` returns its bytes.
PRIVATE_DIRECTORY = "operator-inputs"
PSEUDONYM_KEY_NAME = "pseudonym.key"
_PSEUDONYM_KEY_BYTES = 32
# A creator's temporary (``.pseudonym.key.<24 hex>.tmp``) becomes the key's inode when it is renamed.
_PSEUDONYM_TEMPORARY = re.compile(r"\.pseudonym\.key\.[0-9a-f]{24}\.tmp")
_LOCK_WAIT_SECONDS = 2.0
_LOCK_STEP_SECONDS = 0.05
# Lock errors that mean "try again"; every other ``flock`` error means storage without locking (``nolock``).
_LOCK_RETRY = frozenset({errno.EWOULDBLOCK, errno.EAGAIN, errno.EINTR})
# Answers of file systems that cannot flush a directory; ignored (the durability limit in the output contract).
_SYNC_UNSUPPORTED = frozenset({errno.EINVAL, errno.EBADF, errno.ENOTSUP, errno.EOPNOTSUPP})
_PSEUDONYM_KEY_MESSAGES = {
    "damaged": (
        "Refusing private input: operator-inputs/pseudonym.key is damaged (it must hold exactly 32 bytes). "
        "Restore it from a copy of the run; removing it starts a new pseudonym series."
    ),
    "busy": "Refusing private input: another process is creating operator-inputs/pseudonym.key; try again.",
    "permissions": (
        "Refusing private input: operator-inputs/pseudonym.key or its folder can be used by other accounts; "
        "restrict the file to 0600 and the folder to 0700."
    ),
    "unwritable": "Refusing private input: operator-inputs/pseudonym.key could not be written.",
    "nolock": (
        "Refusing private input: the run's storage does not support locking, so operator-inputs/pseudonym.key "
        "cannot be created there; copy the run to local storage and run auditex report prepare-key."
    ),
}


class PseudonymKeyError(UnsafeRunFileError):
    """The run's pseudonym key cannot be used or created; ``reason`` is one of ``damaged``, ``busy``,
    ``permissions``, ``unwritable`` or ``nolock``. The message is fixed per reason: never a path or key bytes."""

    def __init__(self, reason: str) -> None:
        if reason not in _PSEUDONYM_KEY_MESSAGES:
            raise ValueError("unknown pseudonym key refusal")
        super().__init__("private input", reason=reason)
        self.args = (_PSEUDONYM_KEY_MESSAGES[reason],)

    def __reduce__(self):
        return type(self), (self.reason,)


def _sync_directory(fd: int) -> None:
    """Flush a directory where the storage supports it (``_SYNC_UNSUPPORTED`` answers are ignored)."""
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _SYNC_UNSUPPORTED:
            raise


def _supported() -> bool:
    return (os.name == "posix" and hasattr(os, "geteuid") and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY") and _ORIGINAL_OPEN in os.supports_dir_fd)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _safe_directory(info: os.stat_result) -> bool:
    return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022


def _read_bounded(fd: int, limit: int) -> bytes:
    parts: list[bytes] = []
    size = 0
    while size <= limit:
        data = os.read(fd, min(65536, limit + 1 - size))
        if not data:
            break
        parts.append(data)
        size += len(data)
    if size > limit:
        raise UnsafeRunFileError("private input", reason="oversize")
    return b"".join(parts)


def _parts(path: str | Path, *, allow_empty: bool = False) -> tuple[bool, tuple[str, ...]]:
    value = os.fspath(path)
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("invalid path")
    value = os.path.expanduser(value)
    parsed = Path(value)
    parts = parsed.parts[1:] if parsed.is_absolute() else parsed.parts
    if not parts and not allow_empty:
        raise ValueError("empty path")
    # Darwin's virtual /.vol inode paths can resolve as a whole while their
    # intermediate components cannot be opened with openat. Refuse that
    # namespace because component-by-component confinement cannot be proved.
    if parsed.is_absolute() and parts and parts[0].casefold() == ".vol":
        raise ValueError("virtual volume path")
    return parsed.is_absolute(), tuple(part for part in parts if part not in ("", "."))


class GuardContext:
    """Pin known runs and private identities for the lifetime of one operation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fds: list[int] = []
        self._identities: set[tuple[int, int]] = set()
        self._runs: dict[str, int] = {}
        self._manifests: dict[str, int] = {}
        self._verified: dict[str, tuple[str, ...] | None] = {}
        self._private_keys: dict[str, bytes] = {}
        self._verified_partner: dict[str, tuple[str, ...] | None] = {}
        self._partner_private_keys: dict[str, bytes] = {}
        self._pinned: dict[str, tuple[int, tuple[int, int, int, int, int]]] = {}
        # Per bound run: its pinned ``operator-inputs`` descriptor (``None`` when absent), the registered identity of
        # its pseudonym key, and the key this context resolved first (``None``: keyless), kept for the whole operation.
        self._private_dirs: dict[str, int | None] = {}
        self._pseudonym_keys: dict[str, tuple[int, int] | None] = {}
        self._pseudonym_bytes: dict[str, bytes | None] = {}
        # Per bound run: the ``run_id`` its pinned manifest records (``None`` when it is missing, null, not a string or
        # empty), and the temporary key of such a run for this context only (``output_redaction``; DEC-024).
        self._run_ids: dict[str, str | None] = {}
        self._operation_keys: dict[str, bytes] = {}
        self._token: Token | None = None
        self._cwd_path = os.getcwd()
        self._root_fd: int | None = None
        self._cwd_fd: int | None = None
        self._stdin_identity: tuple[int, int] | None = None

    def __enter__(self) -> GuardContext:
        failed = False
        try:
            if not _supported():
                raise OSError("descriptor-relative no-follow opens unavailable")
            self._root_fd = os.open("/", _DIR_FLAGS)
            self._fds.append(self._root_fd)
            self._cwd_fd = os.open(".", _DIR_FLAGS)
            self._fds.append(self._cwd_fd)
            self._token = _CURRENT.set(self)
        except (OSError, ValueError):
            failed = True
        if failed:
            self.close()
            raise UnsafeRunFileError("input") from None
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        if self._token is not None:
            _CURRENT.reset(self._token)
            self._token = None
        for fd in reversed(self._fds):
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds.clear()
        self._runs.clear()
        self._manifests.clear()
        self._verified.clear()
        self._private_keys.clear()
        self._verified_partner.clear()
        self._partner_private_keys.clear()
        self._pinned.clear()
        self._private_dirs.clear()
        self._pseudonym_keys.clear()
        self._pseudonym_bytes.clear()
        self._run_ids.clear()
        self._operation_keys.clear()
        self._identities.clear()
        self._root_fd = self._cwd_fd = None

    def _directory(self, path: str | Path) -> int:
        absolute, parts = _parts(path, allow_empty=True)
        anchor = self._root_fd if absolute else self._cwd_fd
        if anchor is None:
            raise OSError("guard context is closed")
        current = os.dup(anchor)
        try:
            for part in parts:
                child = os.open(part, _DIR_FLAGS, dir_fd=current)
                os.close(current)
                current = child
                if not stat.S_ISDIR(os.fstat(current).st_mode):
                    raise OSError("not a directory")
            return current
        except BaseException:
            os.close(current)
            raise

    def _absolute(self, path: str | Path) -> str:
        value = os.path.expanduser(os.fspath(path))
        return os.path.normpath(value if os.path.isabs(value) else os.path.join(self._cwd_path, value))

    def _eligible_run_root(self, path: str | Path) -> bool:
        # A marker inside a private directory is data, never a new trust root.
        return all(part.casefold() != "operator-inputs" for part in Path(self._absolute(path)).parts)

    def _parent(self, path: str | Path) -> tuple[int, str]:
        absolute, parts = _parts(path)
        if not parts or parts[-1] in (".", ".."):
            raise ValueError("invalid filename")
        anchor = self._root_fd if absolute else self._cwd_fd
        if anchor is None:
            raise OSError("guard context is closed")
        current = os.dup(anchor)
        try:
            for part in parts[:-1]:
                child = os.open(part, _DIR_FLAGS, dir_fd=current)
                os.close(current)
                current = child
                if not stat.S_ISDIR(os.fstat(current).st_mode):
                    raise OSError("not a directory")
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def _check_file(self, info: os.stat_result, field: str, max_bytes: int | None,
                    *, private_verifier: bool = False) -> None:
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeRunFileError(field, reason="type")
        if info.st_uid != os.geteuid():
            raise UnsafeRunFileError(field, reason="owner")
        if info.st_nlink != 1:
            raise UnsafeRunFileError(field, reason="hardlink")
        if not private_verifier:
            # A key (or a key temporary) another process created after the bind is registered before the comparison.
            self._sync_pseudonym_keys()
        if not private_verifier and _identity(info) in self._identities:
            raise UnsafeRunFileError(field, reason="private")
        if max_bytes is not None and info.st_size > max_bytes:
            raise UnsafeRunFileError(field, reason="oversize")

    def bind_run(self, run_dir: str | Path, *, manifest_max_bytes: int | None = None) -> int:
        """Verify and register the private pair before admitting other run files."""
        owned: list[int] = []
        failed = False
        reason = None
        result: int | None = None
        try:
            with self._lock:
                path = self._absolute(run_dir)
                if not self._eligible_run_root(path):
                    raise UnsafeRunFileError("run")
                if path in self._runs:
                    self._sync_pseudonym_keys()
                    return self._runs[path]
                root = self._directory(run_dir)
                owned.append(root)
                if not _safe_directory(os.fstat(root)):
                    raise UnsafeRunFileError("run", reason="owner")
                private_dir = None
                try:
                    private_dir = os.open("operator-inputs", _DIR_FLAGS, dir_fd=root)
                except FileNotFoundError:
                    pass
                if private_dir is not None:
                    owned.append(private_dir)
                    if not _safe_directory(os.fstat(private_dir)):
                        raise UnsafeRunFileError("private input", reason="owner")
                pairs: dict[str, list[int | None]] = {}
                for kind, names in (
                    ("sensitive_users", ("sensitive-users.txt", "sensitive-users.key")),
                    ("partner_domains", ("partner-domains.txt", "partner-domains.key")),
                ):
                    pair: list[int | None] = []
                    for name in names:
                        fd = None
                        if private_dir is not None:
                            try:
                                fd = os.open(name, _FILE_FLAGS, dir_fd=private_dir)
                            except FileNotFoundError:
                                pass
                        if fd is not None:
                            owned.append(fd)
                            self._check_file(os.fstat(fd), "private input", 32 if name.endswith(".key") else _MAX_LIST,
                                             private_verifier=True)
                        pair.append(fd)
                    if (pair[0] is None) != (pair[1] is None):
                        raise UnsafeRunFileError("private input")
                    pairs[kind] = pair
                key_identity = None
                if private_dir is not None:
                    key_fd = self._open_private_key(private_dir)
                    if key_fd is not None:
                        owned.append(key_fd)
                        key_info = os.fstat(key_fd)
                        self._check_file(key_info, "private input", None, private_verifier=True)
                        key_identity = _identity(key_info)
                manifest = os.open("run-manifest.json", _FILE_FLAGS, dir_fd=root)
                owned.append(manifest)
                manifest_info = os.fstat(manifest)
                manifest_limit = min(_MAX_MANIFEST, manifest_max_bytes) if manifest_max_bytes is not None else _MAX_MANIFEST
                self._check_file(manifest_info, "manifest", manifest_limit)
                pair_ids = {_identity(os.fstat(fd)) for pair in pairs.values() for fd in pair if fd is not None}
                if key_identity is not None:
                    pair_ids.add(key_identity)
                if _identity(manifest_info) in pair_ids:
                    raise UnsafeRunFileError("manifest", reason="private")
                payload = json.loads(_read_bounded(manifest, manifest_limit).decode("utf-8"))
                if not isinstance(payload, dict):
                    raise UnsafeRunFileError("manifest")
                operator = payload.get("operator_inputs", {})
                if not isinstance(operator, dict):
                    raise UnsafeRunFileError("manifest")
                from .partner_domains import (
                    parse_partner_domains,
                    partner_domains_digest,
                )
                from .sensitive_users import (
                    parse_sensitive_users,
                    sensitive_users_digest,
                )
                verified: dict[str, tuple[str, ...] | None] = {}
                keys: dict[str, bytes | None] = {}
                for kind, pair in pairs.items():
                    meta = operator.get(kind, {})
                    if not isinstance(meta, dict):
                        raise UnsafeRunFileError("manifest")
                    if pair[0] is None:
                        if meta not in ({}, {"supplied": False}):
                            raise UnsafeRunFileError("private input")
                        verified[kind] = None
                        keys[kind] = None
                        continue
                    assert pair[1] is not None
                    data = _read_bounded(pair[0], _MAX_LIST)
                    key = _read_bounded(pair[1], 32)
                    if kind == "sensitive_users":
                        entries = parse_sensitive_users(data).addresses
                        expected_digest = sensitive_users_digest(entries, key)
                    else:
                        entries = parse_partner_domains(data).domains
                        expected_digest = partner_domains_digest(entries, key)
                    canonical = ("\n".join(entries) + "\n").encode("utf-8")
                    digest = meta.get("hmac_sha256")
                    if (len(key) != 32 or data != canonical or meta.get("supplied") is not True
                            or set(meta) != {"supplied", "count", "hmac_sha256"}
                            or type(meta.get("count")) is not int or meta.get("count") != len(entries)
                            or not isinstance(digest, str) or len(digest) != 64
                            or not hmac.compare_digest(expected_digest, digest)):
                        raise UnsafeRunFileError("private input")
                    verified[kind] = entries
                    keys[kind] = key
                self._identities.update(pair_ids)
                self._fds.extend(owned)
                owned.clear()
                self._runs[path] = root
                self._manifests[path] = manifest
                self._private_dirs[path] = private_dir
                self._pseudonym_keys[path] = key_identity
                run_id = payload.get("run_id")
                self._run_ids[path] = run_id if isinstance(run_id, str) and run_id else None
                self._verified[path] = verified["sensitive_users"]
                self._verified_partner[path] = verified["partner_domains"]
                for kind, registry in (("sensitive_users", self._private_keys),
                                       ("partner_domains", self._partner_private_keys)):
                    if keys[kind] is not None:
                        registry[path] = keys[kind]
                    else:
                        registry.pop(path, None)
                result = root
        except UnsafeRunFileError as exc:
            failed = True
            reason = exc.reason
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            failed = True
        finally:
            for fd in reversed(owned):
                try:
                    os.close(fd)
                except OSError:
                    pass
        if failed or result is None:
            raise UnsafeRunFileError("run", reason=reason) from None
        return result

    def verified_sensitive_users(self, run_dir: str | Path) -> tuple[str, ...] | None:
        self.bind_run(run_dir)
        path = self._absolute(run_dir)
        return self._verified[path]

    def verified_sensitive_users_binding(self, run_dir: str | Path) -> tuple[tuple[str, ...], int, str] | None:
        """The admitted SensitiveUsers tuple with its count and manifest HMAC, or ``None`` when none was supplied.

        Derived from the state ``bind_run`` captured and verified: nothing is reread and the raw key never leaves
        this context (only its HMAC of the captured tuple, which equals the verified manifest digest).
        """
        self.bind_run(run_dir)
        with self._lock:
            path = self._absolute(run_dir)
            entries = self._verified.get(path)
            key = self._private_keys.get(path)
            if not entries or key is None:
                return None
            from .sensitive_users import sensitive_users_digest
            return entries, len(entries), sensitive_users_digest(entries, key)

    def verified_partner_domains(self, run_dir: str | Path) -> tuple[str, ...] | None:
        self.bind_run(run_dir)
        return self._verified_partner[self._absolute(run_dir)]

    def refresh_run(self, run_dir: str | Path) -> None:
        """Rebind a manifest published by the internal writer under the admission lock."""
        path = self._absolute(run_dir)
        with self._lock:
            self._runs.pop(path, None)
            self._manifests.pop(path, None)
            self._verified.pop(path, None)
            self._private_keys.pop(path, None)
            self._verified_partner.pop(path, None)
            self._partner_private_keys.pop(path, None)
            self._private_dirs.pop(path, None)
            self._pseudonym_keys.pop(path, None)
            self._pseudonym_bytes.pop(path, None)
            self._run_ids.pop(path, None)
            self._operation_keys.pop(path, None)
            self.bind_run(run_dir)

    # -- the run's pseudonym key (design M04-T01 sections 3.4-3.6) ---------------------------------------------------

    @staticmethod
    def _open_private_key(folder: int) -> int | None:
        """Open ``pseudonym.key`` below a private folder; ``None`` when absent. A link is refused as ``type`` and any
        other open failure as ``open``; the caller judges type, owner and links with ``_check_file``."""
        try:
            return os.open(PSEUDONYM_KEY_NAME, _FILE_FLAGS, dir_fd=folder)
        except FileNotFoundError:
            return None
        except OSError as exc:
            reason = "type" if exc.errno in (errno.ELOOP, errno.EMLINK) else "open"
            raise UnsafeRunFileError("private input", reason=reason) from None

    def _private_folder(self, path: str) -> int | None:
        """The bound run's pinned ``operator-inputs`` descriptor, opened relative to the pinned run descriptor when it
        appeared after the bind; ``None`` while it is absent. Call with the lock held and the run bound."""
        folder = self._private_dirs.get(path)
        if folder is not None:
            return folder
        try:
            folder = os.open(PRIVATE_DIRECTORY, _DIR_FLAGS, dir_fd=self._runs[path])
        except FileNotFoundError:
            return None
        except OSError:
            raise UnsafeRunFileError("private input", reason="type") from None
        try:
            if not _safe_directory(os.fstat(folder)):
                raise UnsafeRunFileError("private input", reason="owner")
        except BaseException:
            os.close(folder)
            raise
        self._fds.append(folder)
        self._private_dirs[path] = folder
        return folder

    def _sync_pseudonym_keys(self) -> None:
        """Register every bound run's key, and every key temporary, that this context has not seen yet: another
        process may create them after the bind. Temporaries are listed before the published name is looked up, so a
        rename during the listing still leaves the inode under the name looked up last."""
        with self._lock:
            for path in tuple(self._runs):
                folder = self._private_folder(path)
                if folder is None:
                    continue
                for name in os.listdir(folder):
                    if not _PSEUDONYM_TEMPORARY.fullmatch(name):
                        continue
                    try:
                        info = os.stat(name, dir_fd=folder, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISREG(info.st_mode):
                        self._identities.add(_identity(info))
                try:
                    named = os.stat(PSEUDONYM_KEY_NAME, dir_fd=folder, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(named.st_mode) or _identity(named) in self._identities:
                    continue  # a non-regular name is refused as ``type`` by every open of it
                fd = self._open_private_key(folder)
                if fd is None:
                    continue
                try:
                    info = os.fstat(fd)
                    if _identity(info) != _identity(named):
                        raise UnsafeRunFileError("private input", reason="changed")
                    self._check_file(info, "private input", None, private_verifier=True)
                except BaseException:
                    os.close(fd)
                    raise
                self._fds.append(fd)
                self._identities.add(_identity(info))
                self._pseudonym_keys[path] = _identity(info)

    def run_identity(self, run_dir: str | Path) -> tuple[int, int, str] | None:
        """Device and inode of the bound run's pinned descriptor, and the ``run_id`` its pinned manifest records: a
        folder whose inode is reused by another run (another ``run_id``) is never taken for the first one. ``None``
        when the manifest records no usable run id (missing, null, not a string or empty): such a run has no identity
        another run could not share, so nothing may be kept for it beyond this context."""
        with self._lock:
            device, inode = _identity(os.fstat(self.bind_run(run_dir)))
            run_id = self._run_ids[self._absolute(run_dir)]
            return None if run_id is None else (device, inode, run_id)

    def pseudonym_key(self, run_dir: str | Path) -> bytes | None:
        """The run's pseudonym key, or ``None`` for a keyless run. The first answer for a run is kept for the whole
        context (one command or tool call), so one output never mixes two keys. Takes no lock: a published key is
        complete and final. Raises ``PseudonymKeyError`` (``permissions``, ``damaged``) or the guard's refusal."""
        with self._lock:
            self.bind_run(run_dir)
            path = self._absolute(run_dir)
            if path not in self._pseudonym_bytes:
                folder = self._private_folder(path)
                self._pseudonym_bytes[path] = None if folder is None else self._read_pseudonym_key(path, folder)
            return self._pseudonym_bytes[path]

    def _read_pseudonym_key(self, path: str, folder: int) -> bytes | None:
        try:
            named = os.stat(PSEUDONYM_KEY_NAME, dir_fd=folder, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISREG(named.st_mode) and (named.st_mode | os.fstat(folder).st_mode) & 0o077:
            raise PseudonymKeyError("permissions")
        fd = self._open_private_key(folder)
        if fd is None:
            return None
        try:
            info = os.fstat(fd)
            self._check_file(info, "private input", None, private_verifier=True)
            if info.st_size != _PSEUDONYM_KEY_BYTES:
                raise PseudonymKeyError("damaged")
            key = os.pread(fd, _PSEUDONYM_KEY_BYTES + 1, 0)
            after = os.fstat(fd)
            if len(key) != _PSEUDONYM_KEY_BYTES or after.st_size != _PSEUDONYM_KEY_BYTES:
                raise PseudonymKeyError("damaged")
            if _identity(after) != _identity(named):
                raise UnsafeRunFileError("private input", reason="changed")
        except BaseException:
            os.close(fd)
            raise
        identity = _identity(info)
        if identity in self._identities:
            os.close(fd)
        else:
            self._fds.append(fd)
            self._identities.add(identity)
        self._pseudonym_keys[path] = identity
        return key

    @staticmethod
    def _lock_run(fd: int) -> None:
        """Take the creator's exclusive lock; ``busy`` after the wait, ``nolock`` for every other lock error."""
        import fcntl

        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in _LOCK_RETRY:
                    raise PseudonymKeyError("nolock") from None
            if time.monotonic() >= deadline:
                raise PseudonymKeyError("busy")
            time.sleep(_LOCK_STEP_SECONDS)

    @staticmethod
    def _remove_temporary(folder: int, name: str, identity: tuple[int, int]) -> None:
        """Remove this creator's own temporary by name, only while the name still holds its identity."""
        try:
            if _identity(os.stat(name, dir_fd=folder, follow_symlinks=False)) == identity:
                os.unlink(name, dir_fd=folder)
        except OSError:
            pass

    def _write_temporary(self, folder: int, name: str, data: bytes, *, private: bool) -> tuple[str, tuple[int, int]]:
        """Write ``data`` to a new ``.<name>.<24 hex>.tmp`` (0600) and flush it; a private one is registered before
        its bytes are written. On failure the temporary is removed and the error raised."""
        from .private_io import _write_all

        temporary = f".{name}.{os.urandom(12).hex()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(temporary, flags, 0o600, dir_fd=folder)
        identity = (-1, -1)
        try:
            identity = _identity(os.fstat(fd))
            if private:
                self._identities.add(identity)
            os.fchmod(fd, 0o600)
            _write_all(fd, data)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            self._remove_temporary(folder, temporary, identity)
            raise
        os.close(fd)
        return temporary, identity

    def _publish_gitignore(self, folder: int) -> None:
        """Keep a plain ``.gitignore`` holding exactly ``*``; replace any other content through a temporary."""
        try:
            fd = os.open(".gitignore", _FILE_FLAGS, dir_fd=folder)
        except FileNotFoundError:
            fd = None
        except OSError as exc:
            reason = "type" if exc.errno in (errno.ELOOP, errno.EMLINK) else "open"
            raise UnsafeRunFileError("private input", reason=reason) from None
        if fd is not None:
            try:
                self._check_file(os.fstat(fd), "private input", None, private_verifier=True)
                if os.read(fd, 64) == b"*\n":
                    return
            finally:
                os.close(fd)
        temporary, identity = self._write_temporary(folder, ".gitignore", b"*\n", private=False)
        try:
            os.replace(temporary, ".gitignore", src_dir_fd=folder, dst_dir_fd=folder)
        except BaseException:
            self._remove_temporary(folder, temporary, identity)
            raise

    def create_pseudonym_key(self, run_dir: str | Path, key: bytes) -> tuple[bytes, bool]:
        """Publish ``key`` as the run's pseudonym key unless one is there (design 3.4); return the published key as
        read back and whether this call created it. Only under an exclusive lock on a creator-owned descriptor of the
        run folder: storage without locking gets nothing (``nolock``, before anything is written)."""
        if not isinstance(key, bytes) or len(key) != _PSEUDONYM_KEY_BYTES:
            raise ValueError("pseudonym key must be 32 bytes")
        with self._lock:
            root = self.bind_run(run_dir)  # refuses a folder without a run manifest
            path = self._absolute(run_dir)
            held: list[int] = []
            try:
                lock_fd = self._directory(run_dir)
                held.append(lock_fd)
                if _identity(os.fstat(lock_fd)) != _identity(os.fstat(root)):
                    raise UnsafeRunFileError("run", reason="changed")
                self._lock_run(lock_fd)
                try:
                    os.mkdir(PRIVATE_DIRECTORY, 0o700, dir_fd=lock_fd)
                    created_folder = True
                except FileExistsError:
                    created_folder = False
                folder = os.open(PRIVATE_DIRECTORY, _DIR_FLAGS, dir_fd=lock_fd)
                held.append(folder)
                if created_folder:
                    _sync_directory(lock_fd)
                folder_info = os.fstat(folder)
                if not _safe_directory(folder_info) or folder_info.st_mode & 0o077:
                    raise PseudonymKeyError("permissions")
                try:
                    os.stat(PSEUDONYM_KEY_NAME, dir_fd=folder, follow_symlinks=False)
                    present = True
                except FileNotFoundError:
                    present = False
                if present:
                    # Another creator finished while this one waited: judge it as the reader does.
                    existing = self._read_pseudonym_key(path, folder)
                    if existing is None:
                        raise PseudonymKeyError("unwritable")
                    self._pseudonym_bytes[path] = existing
                    return existing, False
                self._publish_gitignore(folder)
                temporary, identity = self._write_temporary(folder, PSEUDONYM_KEY_NAME, key, private=True)
                try:
                    os.rename(temporary, PSEUDONYM_KEY_NAME, src_dir_fd=folder, dst_dir_fd=folder)
                except BaseException:
                    self._remove_temporary(folder, temporary, identity)
                    raise
                _sync_directory(folder)
                published = self._open_private_key(folder)
                if published is None:
                    raise PseudonymKeyError("unwritable")
                held.append(published)
                info = os.fstat(published)
                if _identity(info) != identity:
                    raise PseudonymKeyError("unwritable")
                self._check_file(info, "private input", _PSEUDONYM_KEY_BYTES, private_verifier=True)
                data = os.pread(published, _PSEUDONYM_KEY_BYTES + 1, 0)
                if len(data) != _PSEUDONYM_KEY_BYTES:
                    raise PseudonymKeyError("unwritable")
                held.remove(published)
                self._fds.append(published)
                self._identities.add(identity)
                self._pseudonym_keys[path] = identity
                self._pseudonym_bytes[path] = data
                return data, True
            except UnsafeRunFileError:
                raise
            except OSError:
                raise PseudonymKeyError("unwritable") from None
            finally:
                for fd in reversed(held):  # closing the creator's run descriptor releases the lock
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def discover_run(self, path: str | Path, *, manifest_max_bytes: int | None = None) -> None:
        """Bind a run containing a selected path when its private directory is identifiable."""
        absolute = Path(self._absolute(path))

        def optional_lstat(candidate: Path) -> os.stat_result | None:
            failed = False
            try:
                return candidate.lstat()
            except FileNotFoundError:
                return None
            except OSError:
                failed = True
            if failed:
                raise UnsafeRunFileError("run") from None
            return None

        def private_pair_present(directory: Path) -> bool:
            failed = False
            descriptor = None
            found = False
            try:
                descriptor = self._directory(directory)
                for name in ("sensitive-users.txt", "sensitive-users.key", "partner-domains.txt", "partner-domains.key",
                             PSEUDONYM_KEY_NAME):
                    try:
                        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        found = True
                    except FileNotFoundError:
                        pass
            except OSError:
                failed = True
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if failed:
                raise UnsafeRunFileError("run") from None
            return found

        nested_manifest = False
        for parent in absolute.parents:
            if not self._eligible_run_root(parent):
                # A pair below an ineligible root cannot be verified as a run.
                # Refuse instead of letting that unregistered pair be read.
                nested_private = parent / "operator-inputs"
                if optional_lstat(nested_private) is not None and private_pair_present(nested_private):
                    raise UnsafeRunFileError("run") from None
                # A marker here is not a root. It only distinguishes an unrelated
                # tree below an empty, unmanifested operator-inputs directory.
                if optional_lstat(parent / "run-manifest.json") is not None:
                    nested_manifest = True
                continue
            private = parent / "operator-inputs"
            manifest = parent / "run-manifest.json"
            private_info = optional_lstat(private)
            if private_info is None:
                if optional_lstat(manifest) is not None:
                    nested_manifest = True
                continue
            if optional_lstat(manifest) is None:
                if private_pair_present(private):
                    raise UnsafeRunFileError("run") from None
                if nested_manifest:
                    continue
                # The filesystem can resolve a case or Unicode variant to the
                # same directory even when the path spellings are unequal.
                for ancestor in absolute.parents:
                    if ancestor == parent:
                        break
                    info = optional_lstat(ancestor)
                    if info is not None and _identity(info) == _identity(private_info):
                        raise UnsafeRunFileError("run") from None
                continue
            limit = manifest_max_bytes if absolute == manifest else None
            self.bind_run(parent, manifest_max_bytes=limit)
            # A nested marker cannot hide an enclosing run's private pair.


@contextmanager
def guard_session() -> Iterator[GuardContext]:
    current = _CURRENT.get()
    if current is not None:
        yield current
    else:
        with GuardContext() as context:
            yield context


def current_context() -> GuardContext | None:
    return _CURRENT.get()


def _text_buffer_is_empty(stream: io.TextIOWrapper) -> bool:
    if (type(stream) is not io.TextIOWrapper or type(stream.buffer) is not io.BufferedReader
            or type(stream.buffer.raw) is not io.FileIO or not gc.is_tracked(stream)):
        return False
    references = gc.get_referents(stream)
    encoding_seen = errors_seen = newline_seen = False
    for item in references:
        if not isinstance(item, str):
            continue
        if item is stream.encoding and not encoding_seen:
            encoding_seen = True
        elif item is stream.errors and not errors_seen:
            errors_seen = True
        elif item in {"\n", "\r", "\r\n"} and not newline_seen:
            newline_seen = True
        else:
            return False
    return encoding_seen and errors_seen and newline_seen


def _stdin_text_buffer_is_empty() -> bool:
    """Prove CPython's standard text wrapper has no decoded characters buffered.

    No interpreter version is trusted by number. A probe wrapper of the same types and configuration as
    stdin must read as empty when fresh and as non-empty with decoded characters pending, after both a
    character read and a line read. An unknown layout that hides pending text, or exposes other strings,
    fails this run-time proof, and admission then refuses stdin rather than guess.
    """
    if (sys.implementation.name != "cpython" or sys.version_info < (3, 11)
            or not _text_buffer_is_empty(sys.stdin)):
        return False
    for payload, by_line in ((b"xy", False), (b"a\nb", True)):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, payload)
            os.close(write_fd)
            write_fd = -1
            with io.TextIOWrapper(io.BufferedReader(io.FileIO(read_fd, "rb", closefd=True)),
                                  encoding=sys.stdin.encoding, errors=sys.stdin.errors, newline="\n",
                                  line_buffering=sys.stdin.line_buffering,
                                  write_through=sys.stdin.write_through) as probe:
                read_fd = -1
                if not _text_buffer_is_empty(probe):
                    return False
                if by_line:
                    probe.readline()
                else:
                    probe.read(1)
                if _text_buffer_is_empty(probe):
                    return False
        except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
            return False
        finally:
            if read_fd >= 0:
                os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
    return True


def _prime_stdin_binary_buffer() -> bool:
    """Detect a prior binary buffer without consuming it; prime only from admitted fd 0."""
    import array
    import fcntl
    import termios

    def pending() -> int:
        count = array.array("I", [0])
        fcntl.ioctl(0, termios.FIONREAD, count, True)
        return count[0]

    before = pending()
    blocking = os.get_blocking(0)
    try:
        os.set_blocking(0, False)
        try:
            peeked = sys.stdin.buffer.peek(1)
        except BlockingIOError:
            peeked = b""
        after = pending()
    finally:
        os.set_blocking(0, blocking)
    return not peeked or after < before


def _descriptor_path(fd: int) -> str | None:
    """The path the platform reports for an open descriptor (``F_GETPATH`` on Darwin, ``/proc`` on Linux), or
    ``None`` where it reports none."""
    try:
        import fcntl

        getpath = getattr(fcntl, "F_GETPATH", None)
        if getpath is not None:
            found = os.fsdecode(fcntl.fcntl(fd, getpath, bytes(1024)).split(b"\0", 1)[0])
        else:
            found = os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError, ImportError):
        return None
    return found if found.startswith("/") else None


def admit_stdin(context: GuardContext) -> None:
    """Admit descriptor zero before reading it, refusing unverifiable regular-file buffers."""
    failed = False
    try:
        with context._lock:
            if sys.stdin is not sys.__stdin__ or sys.stdin.fileno() != 0:
                raise OSError("stdin wrapper provenance unavailable")
            info = os.fstat(0)
            identity = _identity(info)
            if stat.S_ISREG(info.st_mode):
                # The shell opened the file before this process started, so discovery runs now, after that open
                # and before admission (DEC-024): a run's key is refused even when the command bound no run.
                selected = _descriptor_path(0)
                if selected is None:
                    raise OSError("stdin path unavailable")
                context.discover_run(selected)
            context._sync_pseudonym_keys()
            if context._stdin_identity is not None and context._stdin_identity != identity:
                raise OSError("stdin changed")
            if context._stdin_identity is None and not _stdin_text_buffer_is_empty():
                raise OSError("stdin text buffer provenance unavailable")
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1 or identity in context._identities:
                    raise OSError("unsafe stdin")
                if context._stdin_identity is None and sys.stdin.tell() != os.lseek(0, 0, os.SEEK_CUR):
                    raise OSError("stdin has buffered bytes")
            elif not (stat.S_ISFIFO(info.st_mode) or os.isatty(0)):
                raise OSError("stdin type unavailable")
            elif context._stdin_identity is None and not _prime_stdin_binary_buffer():
                raise OSError("stdin binary buffer provenance unavailable")
            context._stdin_identity = identity
    except (OSError, ValueError, AttributeError, ImportError):
        failed = True
    if failed:
        raise UnsafeRunFileError("stdin") from None


def read_guarded_stdin(*, line: bool = False) -> str:
    """Read directly from admitted fd 0 without consuming a text wrapper's buffer."""
    failed = False
    chunks: list[bytes] = []
    with guard_session() as context:
        admit_stdin(context)
        try:
            one_line = line or os.isatty(0)
            while True:
                data = sys.stdin.buffer.read(1 if one_line else 65536)
                if not data:
                    break
                chunks.append(data)
                if one_line and data == b"\n":
                    break
            if _identity(os.fstat(0)) != context._stdin_identity:
                raise OSError("stdin changed")
            if not chunks and stat.S_ISFIFO(os.fstat(0).st_mode):
                raise OSError("stdin provenance unavailable")
            text = b"".join(chunks).decode("utf-8")
        except (OSError, UnicodeError):
            failed = True
    if failed:
        raise UnsafeRunFileError("stdin") from None
    return text


def guarded_operation(function):
    """Share one admission context across a synchronous entry point."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        with guard_session():
            return function(*args, **kwargs)
    return wrapped


def _state(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def open_guarded_file(path: str | Path, *, field: str, context: GuardContext,
                      max_bytes: int | None = None) -> Iterator[int]:
    """Open and admit one read-only descriptor; never reopen the selected path."""
    parent = None
    fd = None
    missing = False
    failed = False
    reason = None
    try:
        with context._lock:
            context.discover_run(path)
            parent, name = context._parent(path)
            fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
            # A run whose private folder appeared after the first discovery is bound now, so a key published
            # between discovery and the open is registered before the comparison and never admitted.
            context.discover_run(path)
            context._check_file(os.fstat(fd), field, max_bytes)
    except FileNotFoundError:
        missing = True
    except UnsafeRunFileError as exc:
        failed = True
        reason = exc.reason
    except (OSError, ValueError, TypeError, UnicodeError):
        failed = True
    if parent is not None:
        try:
            os.close(parent)
        except OSError:
            failed = True
    if missing or failed:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass  # Cleanup cannot replace the primary admission failure or its reason.
        if missing:
            raise FileNotFoundError("Input is absent.") from None
        raise UnsafeRunFileError(field, reason=reason) from None
    try:
        assert fd is not None
        yield fd
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass  # Preserve the consumer's primary failure, including an unsafe-input refusal.
        raise
    else:
        os.close(fd)


def read_guarded_bytes(path: str | Path, *, field: str = "input", max_bytes: int | None = None) -> bytes:
    """Read only the admitted descriptor; an optional bound includes later growth."""
    failed = False
    reason = None
    data = b""
    with guard_session() as context:
        try:
            with open_pinned_binary(path, field=field, context=context, max_bytes=max_bytes) as stream:
                parts: list[bytes] = []
                total = 0
                while True:
                    count = 1024 * 1024 if max_bytes is None else min(1024 * 1024, max_bytes + 1 - total)
                    block = stream.read(count)
                    if not block:
                        break
                    total += len(block)
                    if max_bytes is not None and total > max_bytes:
                        raise UnsafeRunFileError(field, reason="oversize")
                    parts.append(block)
                data = b"".join(parts)
        except FileNotFoundError:
            raise
        except UnsafeRunFileError as exc:
            failed = True
            reason = exc.reason
        except OSError:
            failed = True
    if failed:
        raise UnsafeRunFileError(field, reason=reason) from None
    return data


@contextmanager
def open_pinned_binary(path: str | Path, *, field: str, context: GuardContext,
                       max_bytes: int | None = None):
    """Re-use a previously admitted descriptor when a consumer needs a second pass."""
    with context._lock:
        failed = missing = False
        reason = None
        try:
            key = context._absolute(path)
            if key not in context._pinned:
                with open_guarded_file(path, field=field, context=context, max_bytes=max_bytes) as fd:
                    pinned = os.dup(fd)
                    context._fds.append(pinned)
                    context._pinned[key] = (pinned, _state(os.fstat(pinned)))
            descriptor, expected = context._pinned[key]
            info = os.fstat(descriptor)
            context._check_file(info, field, max_bytes)
            if _state(info) != expected:
                raise UnsafeRunFileError(field, reason="changed")
            os.lseek(descriptor, 0, os.SEEK_SET)
            stream = os.fdopen(os.dup(descriptor), "rb")
        except FileNotFoundError:
            missing = True
        except UnsafeRunFileError as exc:
            failed = True
            reason = exc.reason
        except (OSError, ValueError, TypeError):
            failed = True
        if missing:
            raise FileNotFoundError("Input is absent.") from None
        if failed:
            raise UnsafeRunFileError(field, reason=reason) from None
        try:
            with stream:
                yield stream
            if _state(os.fstat(descriptor)) != expected:
                raise UnsafeRunFileError(field, reason="changed")
        except UnsafeRunFileError as exc:
            failed = True
            reason = exc.reason
        except OSError:
            failed = True
        if failed:
            raise UnsafeRunFileError(field, reason=reason) from None


@contextmanager
def open_private_output(path: str | Path, *, field: str, context: GuardContext,
                        append: bool = False, exclusive: bool = False, existing_only: bool = False) -> Iterator[int]:
    """Admit an existing destination before truncation, or create one exclusively.

    ``existing_only`` serves producer-owned logs: it appends to an existing, admitted file and never creates,
    truncates or changes the mode of it. Every other caller keeps the private 0600 destination.
    """
    parent = None
    fd = None
    failed = False
    reason = None
    try:
        with context._lock:
            context.discover_run(path)
            parent, name = context._parent(path)
            if not _safe_directory(os.fstat(parent)):
                raise UnsafeRunFileError(field, reason="owner")
            flags = (os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_CLOEXEC", 0))
            if existing_only and (not append or exclusive):
                raise ValueError("an existing-only destination is append-only")
            if append:
                flags |= os.O_APPEND
            if exclusive:
                fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
            elif existing_only:
                fd = os.open(name, flags, dir_fd=parent)
            else:
                try:
                    fd = os.open(name, flags, dir_fd=parent)
                except FileNotFoundError:
                    fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
            context.discover_run(path)  # a key published since the first discovery is registered (open_guarded_file)
            context._check_file(os.fstat(fd), field, None)
            if not existing_only:
                os.fchmod(fd, 0o600)
            if not append:
                os.ftruncate(fd, 0)
            context._pinned.pop(context._absolute(path), None)
    except UnsafeRunFileError as exc:
        failed = True
        reason = exc.reason
    except (OSError, ValueError, TypeError):
        failed = True
    if parent is not None:
        os.close(parent)
    if failed:
        if fd is not None:
            os.close(fd)
        raise UnsafeRunFileError(field, reason=reason) from None
    try:
        assert fd is not None
        yield fd
    finally:
        os.close(fd)


def remove_guarded_output(path: str | Path, *, field: str = "output") -> bool:
    """Remove an admitted output entry through its pinned parent, never through a link."""
    parent = None
    fd = None
    missing = False
    failed = False
    with guard_session() as context:
        try:
            with context._lock:
                context.discover_run(path)
                parent, name = context._parent(path)
                if not _safe_directory(os.fstat(parent)):
                    raise UnsafeRunFileError(field)
                fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
                context.discover_run(path)  # a key published since the first discovery is registered (open_guarded_file)
                context._check_file(os.fstat(fd), field, None)
                os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            missing = True
        except (OSError, ValueError, TypeError):
            failed = True
        finally:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)
    if failed:
        raise UnsafeRunFileError(field) from None
    return not missing


def remove_guarded_tree(path: str | Path, *, field: str = "output-dir") -> None:
    """Remove an owned output tree only after admitting each entry without links."""
    failed = False
    parent = None
    root = None
    held: list[int] = []
    with guard_session() as context:
        try:
            with context._lock:
                context.discover_run(path)
                parent, name = context._parent(path)
                if not _safe_directory(os.fstat(parent)):
                    raise UnsafeRunFileError(field)
                root = os.open(name, _DIR_FLAGS, dir_fd=parent)
                held.append(root)
                context.discover_run(path)  # a key published since the first discovery is registered (open_guarded_file)
                removals: list[tuple[int, str, bool]] = []

                def clear(directory: int, below: Path, depth: int) -> None:
                    if depth > 32 or not _safe_directory(os.fstat(directory)):
                        raise UnsafeRunFileError(field)
                    for entry in os.listdir(directory):
                        info = os.stat(entry, dir_fd=directory, follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            child = os.open(entry, _DIR_FLAGS, dir_fd=directory)
                            held.append(child)
                            clear(child, below / entry, depth + 1)
                            removals.append((directory, entry, True))
                        else:
                            child = os.open(entry, _FILE_FLAGS, dir_fd=directory)
                            held.append(child)
                            # Discovery after each open (DEC-024): the upward discovery above never sees a run nested
                            # inside the tree, so each file binds its own run before admission and a key refuses.
                            context.discover_run(below / entry)
                            context._check_file(os.fstat(child), field, None)
                            removals.append((directory, entry, False))

                clear(root, Path(context._absolute(path)), 0)
                for directory, entry, is_directory in removals:
                    if is_directory:
                        os.rmdir(entry, dir_fd=directory)
                    else:
                        os.unlink(entry, dir_fd=directory)
                os.rmdir(name, dir_fd=parent)
        except (OSError, ValueError, TypeError):
            failed = True
        finally:
            for descriptor in reversed(held):
                os.close(descriptor)
            if parent is not None:
                os.close(parent)
    if failed:
        raise UnsafeRunFileError(field) from None
