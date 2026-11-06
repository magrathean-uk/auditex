"""Bounded customer-confidential domains; private copy and in-memory use only.

SS 2.3 v3.9.1 uses exact trimmed, lower-case strings, without IDNA or wildcard
semantics. Keep the sibling sensitive-users channel behaviour independent.
"""
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
BUNDLE_PATH = "operator-inputs/partner-domains.txt"
KEY_PATH = "operator-inputs/partner-domains.key"
ENV_VAR = "AUDITEX_PARTNER_DOMAINS_FILE"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_HEX_LABEL = re.compile(r"0x[0-9a-f]*", re.ASCII)


class PartnerDomainsError(ValueError):
    """A sanitised usage error, containing neither source text nor a file path."""


def partner_domains_digest(domains: tuple[str, ...], key: bytes) -> str:
    """HMAC-SHA256 of the normalised newline-joined list, without a final newline."""
    if len(key) != 32:
        raise PartnerDomainsError("Partner-domains key must contain 32 bytes.")
    return hmac.new(key, "\n".join(domains).encode("utf-8"), "sha256").hexdigest()


def read_partner_domains_key(run_dir: str | Path) -> bytes:
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
        raise PartnerDomainsError("Unable to read the private partner-domains key.") from None


def verify_partner_domains(run_dir: str | Path) -> bool:
    """Support check using the private list and key; false for absent or invalid input.

    This proves consistency with the manifest, not authenticity against a holder
    who can replace the manifest and both private files.
    """
    run_dir = Path(run_dir)
    try:
        key = read_partner_domains_key(run_dir)
        supplied = load_partner_domains(run_dir / BUNDLE_PATH)
        manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
        metadata = manifest["operator_inputs"]["partner_domains"]
        digest = metadata["hmac_sha256"]
        if (metadata["supplied"] is not True or type(metadata["count"]) is not int
                or metadata["count"] != len(supplied.domains)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            return False
        return hmac.compare_digest(partner_domains_digest(supplied.domains, key), digest)
    except (OSError, ValueError, KeyError, TypeError):
        return False


@dataclass(frozen=True)
class PartnerDomains:
    domains: tuple[str, ...] = field(default=(), repr=False)

    def manifest(self, key: bytes = b"") -> dict[str, object]:
        if not self.domains:
            return {"supplied": False}
        return {
            "supplied": True,
            "count": len(self.domains),
            "hmac_sha256": partner_domains_digest(self.domains, key),
        }


def _error(line: int, reason: str) -> PartnerDomainsError:
    return PartnerDomainsError(f"Partner-domains input: line {line}: {reason}.")


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
            raise _error(line, "expected a domain string")
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
    domain = entry.strip()
    if not domain.isascii():
        raise _error(line, "non-ASCII domain; use an ASCII DNS name")
    domain = domain.lower().removesuffix(".")
    labels = domain.split(".")
    if (
        len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit() or _HEX_LABEL.fullmatch(labels[-1])
        or not all(_LABEL.fullmatch(label) for label in labels)
    ):
        raise _error(line, "invalid DNS domain name")
    return domain


def load_partner_domains(path: str | Path | None = None) -> PartnerDomains:
    """Open once, read only, before collection. An explicit path wins over the environment."""
    selected = path if path is not None else (os.environ.get(ENV_VAR) or None)
    if selected is None:
        return PartnerDomains()
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
    except PartnerDomainsError:
        raise
    except (OSError, ValueError, RuntimeError):
        raise _error(1, "unable to read a regular local file") from None
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
    return PartnerDomains(tuple(sorted({_normalise(entry, line) for line, entry in entries})))
