"""Bounded local operator input. Addresses must never enter evidence or diagnostics."""
from __future__ import annotations

import hmac
import json
import os
import re
import stat
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

MAX_BYTES = 256 * 1024
MAX_ENTRIES = 10_000
BUNDLE_PATH = "operator-inputs/sensitive-users.txt"
KEY_PATH = "operator-inputs/sensitive-users.key"
ENV_VAR = "AUDITEX_SENSITIVE_USERS_FILE"
_LOCAL = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~.-]+", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


class SensitiveUsersError(ValueError):
    """A sanitised usage error, containing neither source text nor a file path."""


def sensitive_users_digest(addresses: tuple[str, ...], key: bytes) -> str:
    """HMAC-SHA256 of the normalised newline-joined list, without a final newline."""
    if len(key) != 32:
        raise SensitiveUsersError("Sensitive-users key must contain 32 bytes.")
    return hmac.new(key, "\n".join(addresses).encode("utf-8"), "sha256").hexdigest()


def read_sensitive_users_key(run_dir: str | Path) -> bytes:
    """Read the private raw key without following links or opening a special file."""
    target = Path(run_dir) / KEY_PATH
    try:
        if target.parent.is_symlink():
            raise OSError
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(target, flags), "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OSError
            key = handle.read(33)
        if len(key) != 32:
            raise OSError
        return key
    except OSError:
        raise SensitiveUsersError("Unable to read the private sensitive-users key.") from None


def verify_sensitive_users(run_dir: str | Path) -> bool:
    """Support check using the private list and key; false for absent or invalid input.

    This proves consistency with the manifest, not authenticity against a holder
    who can replace the manifest and both private files.
    """
    run_dir = Path(run_dir)
    try:
        key = read_sensitive_users_key(run_dir)
        supplied = load_sensitive_users(run_dir / BUNDLE_PATH)
        manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
        metadata = manifest["operator_inputs"]["sensitive_users"]
        digest = metadata["hmac_sha256"]
        if (metadata["supplied"] is not True or type(metadata["count"]) is not int
                or metadata["count"] != len(supplied.addresses)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            return False
        return hmac.compare_digest(sensitive_users_digest(supplied.addresses, key), digest)
    except (OSError, ValueError, KeyError, TypeError):
        return False


@dataclass(frozen=True)
class SensitiveUsers:
    addresses: tuple[str, ...] = field(default=(), repr=False)

    def manifest(self, key: bytes = b"") -> dict[str, object]:
        if not self.addresses:
            return {"supplied": False}
        return {
            "supplied": True,
            "count": len(self.addresses),
            "hmac_sha256": sensitive_users_digest(self.addresses, key),
        }


def _error(line: int, reason: str) -> SensitiveUsersError:
    return SensitiveUsersError(f"Sensitive-users input: line {line}: {reason}.")


def _json_entries(text: str) -> list[tuple[int, str]]:
    """Decode entries separately to retain physical line numbers without echoing JSON errors."""
    decoder = json.JSONDecoder()
    pos = text.index("[") + 1
    newlines = [index for index, char in enumerate(text) if char == "\n"]

    def line_at(index: int) -> int:
        return bisect_right(newlines, index - 1) + 1

    entries: list[tuple[int, str]] = []
    while True:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        line = line_at(pos)
        if pos < len(text) and text[pos] == "]" and not entries:
            pos += 1
            break
        try:
            entry, end = decoder.raw_decode(text, pos)
        except json.JSONDecodeError as exc:
            raise _error(exc.lineno, "invalid JSON array") from None
        except (ValueError, RecursionError):
            raise _error(line, "invalid JSON array") from None
        if not isinstance(entry, str):
            raise _error(line, "expected an e-mail string")
        entries.append((line, entry))
        if len(entries) > MAX_ENTRIES:
            raise _error(line, "too many entries (maximum 10000)")
        pos = end
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if pos < len(text) and text[pos] == "]":
            pos += 1
            break
        if pos >= len(text) or text[pos] != ",":
            raise _error(line_at(pos), "invalid JSON array")
        pos += 1
    while pos < len(text) and text[pos] in " \t\r\n":
        pos += 1
    if pos < len(text):
        raise _error(line_at(pos), "unexpected text after JSON array")
    return entries


def _normalise(entry: str, line: int) -> str:
    if "\x00" in entry:
        raise _error(line, "NUL is not allowed")
    parts = entry.split(";")
    if len(parts) > 2:
        raise _error(line, "ambiguous name and e-mail entry")
    address = parts[-1].strip().lower()
    local, sep, domain = address.rpartition("@")
    if (
        not sep or len(address) > 254 or not 1 <= len(local) <= 64
        or not _LOCAL.fullmatch(local) or local.startswith(".") or local.endswith(".") or ".." in local
        or len(domain) > 253 or "." not in domain
        or not all(_LABEL.fullmatch(label) for label in domain.split("."))
    ):
        raise _error(line, "invalid e-mail address")
    return address


def parse_sensitive_users(data: bytes) -> SensitiveUsers:
    """Validate and normalise captured input bytes without reopening a file."""
    if len(data) > MAX_BYTES:
        raise _error(1, "file exceeds 256 KiB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise _error(exc.object[:exc.start].count(b"\n") + 1, "expected UTF-8") from None
    if "\x00" in text:
        raise _error(text.count("\n", 0, text.index("\x00")) + 1, "NUL is not allowed")
    entries = _json_entries(text) if text.lstrip(" \t\r\n").startswith("[") else [
        (line, entry.rstrip("\r")) for line, entry in enumerate(text.split("\n"), 1) if entry.strip()
    ]
    if not entries:
        raise _error(1, "empty list")
    if len(entries) > MAX_ENTRIES:
        raise _error(entries[MAX_ENTRIES][0], "too many entries (maximum 10000)")
    return SensitiveUsers(tuple(sorted({_normalise(entry, line) for line, entry in entries})))


def load_sensitive_users(path: str | Path | None = None) -> SensitiveUsers:
    """Open once, read only, before collection. An explicit path wins over the environment."""
    selected = path if path is not None else (os.environ.get(ENV_VAR) or None)
    if selected is None:
        return SensitiveUsers()
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(Path(selected).expanduser(), flags)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise _error(1, "expected a regular file")
            if info.st_size > MAX_BYTES:
                raise _error(1, "file exceeds 256 KiB")
            data = handle.read(MAX_BYTES + 1)
    except SensitiveUsersError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise _error(1, "unable to read a regular local file") from None
    return parse_sensitive_users(data)
