"""The operator's private tenant key and the keyed pseudonym a Google run records as its tenant id (PRIV-CUSTOMER-ID).

A Google bundle never holds the customer id. Compare and drift still need to tell two customers apart, and a run's own
pseudonym key differs in every run, so the tenant id is an HMAC of the configured customer id under one key the
operator keeps outside every run folder (``AUDITEX_TENANT_KEY_PATH``, else ``tenant-pseudonym.key`` in the user's
auditex config folder; owner-only, 32 random bytes, made on first use). The pseudonym names the key that made it
(``gws-<key id>-<digest>``), so pseudonyms from two different keys are never read as two different tenants.
"""

from __future__ import annotations

import hmac
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

MY_CUSTOMER = "my_customer"
TENANT_KEY_PATH_ENV = "AUDITEX_TENANT_KEY_PATH"
TENANT_KEY_BYTES = 32
TENANT_PSEUDONYM_PREFIX = "gws-"
_TENANT_PSEUDONYM_RE = re.compile(r"gws-([0-9a-f]{8})-([0-9a-f]{16})")


class TenantKeyError(RuntimeError):
    """The operator's tenant key cannot be read or created. The message names the reason, never the key."""


def tenant_key_path() -> Path:
    """``AUDITEX_TENANT_KEY_PATH`` when set, else ``tenant-pseudonym.key`` in the user's auditex config folder."""
    override = os.environ.get(TENANT_KEY_PATH_ENV)
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "auditex" / "tenant-pseudonym.key"


def _read_key(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise TenantKeyError(f"tenant key unreadable ({type(exc).__name__})") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise TenantKeyError("tenant key is not a plain file")
        if os.name != "nt" and info.st_mode & 0o077:
            raise TenantKeyError("tenant key is readable by other accounts")
        data = handle.read(TENANT_KEY_BYTES + 1)
    if len(data) != TENANT_KEY_BYTES:
        raise TenantKeyError("tenant key is damaged")
    return data


def tenant_key(*, create: bool = False) -> bytes | None:
    """The operator's private tenant key; with ``create`` it is made (32 random bytes, owner-only) when missing.
    Without ``create`` a missing key is ``None``."""
    path = tenant_key_path()
    if not os.path.lexists(path):
        if not create:
            return None
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            return _read_key(path)
        except OSError as exc:
            raise TenantKeyError(f"tenant key cannot be created ({type(exc).__name__})") from None
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(TENANT_KEY_BYTES))
            handle.flush()
            os.fsync(handle.fileno())
    return _read_key(path)


def _pseudonym_with(key: bytes, customer_id: str) -> str:
    key_id = hmac.digest(key, b"auditex|tenant-key-id", "sha256").hex()[:8]
    digest = hmac.digest(key, f"auditex|google-customer|{customer_id}".encode(), "sha256").hex()[:16]
    return f"{TENANT_PSEUDONYM_PREFIX}{key_id}-{digest}"


def tenant_pseudonym(customer_id: Any, *, create: bool = True) -> str | None:
    """The configured customer id as the bundle's tenant id: ``gws-<key id>-<keyed digest>``, or ``None`` for the
    ``my_customer`` alias, an empty value or (without ``create``) a machine with no tenant key. The key id says which
    operator key made it, so two pseudonyms from different keys are never read as different tenants."""
    text = customer_id.strip() if isinstance(customer_id, str) else ""
    if not text or text == MY_CUSTOMER:
        return None
    key = tenant_key(create=create)
    return _pseudonym_with(key, text) if key is not None else None


def tenant_pseudonym_parts(value: Any) -> tuple[str, str] | None:
    """``(key id, digest)`` of a bundle's tenant pseudonym, else ``None``."""
    match = _TENANT_PSEUDONYM_RE.fullmatch(value) if isinstance(value, str) else None
    return (match.group(1), match.group(2)) if match else None


def is_tenant_pseudonym(value: Any) -> bool:
    return tenant_pseudonym_parts(value) is not None


def local_pseudonym(customer_id: Any) -> str | None:
    """A legacy bundle's raw customer id as this machine's key pseudonymises it; ``None`` when there is no usable key
    (never creates one)."""
    text = customer_id.strip() if isinstance(customer_id, str) else ""
    if not text or text == MY_CUSTOMER:
        return None
    try:
        key = tenant_key(create=False)
    except TenantKeyError:
        return None
    return _pseudonym_with(key, text) if key is not None else None
