from __future__ import annotations

import json
import os
import re
import shlex
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SENSITIVE_ARG_FLAGS = frozenset(
    {
        "--access-token",
        "--token",
        "--client-secret",
        "--secret",
        "--password",
        "--command-override",
        "--adapter-override",
    }
)

SENSITIVE_KEY_RE = re.compile(
    r"(^|[_-])(access[_-]?token|refresh[_-]?token|token|secret|password|credential|authorization|raw[_-]?claims)([_-]|$)",
    re.IGNORECASE,
)

BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
# ``key=value``, ``key: value`` and the JSON forms ``"key": "value"`` / ``'key':'value'``: the closing quote of the
# key and a quoted value (which may hold spaces) are part of the match, so a JSON-keyed secret is not left behind.
INLINE_SECRET_RE = re.compile(
    r"(?P<prefix>[\"']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|authorization|api[_-]?key)"
    r"[\"']?\s*[=:]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)",
    re.IGNORECASE,
)

_ALLOWED_TOKEN_CLAIMS = (
    "tenant_id",
    "audience",
    "app_id",
    "subject",
    "user_principal_name",
    "delegated_scopes",
    "app_roles",
    "issued_at_utc",
    "not_before_utc",
    "expires_at_utc",
)


def ensure_private_dir(path: str | Path, *, mode: int = 0o700) -> Path:
    """Create a local secret directory and restrict it on POSIX platforms.

    This intentionally degrades gracefully on filesystems or platforms where chmod is not
    meaningful. The caller still gets a usable directory, but POSIX systems get 0700.
    """

    directory = Path(path).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(directory, mode)
        except OSError:
            pass
    return directory


def secure_write_text(path: str | Path, content: str, *, mode: int = 0o600) -> Path:
    """Write text without briefly creating world-readable secret files."""

    target = Path(path).expanduser()
    ensure_private_dir(target.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(target), flags, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
    finally:
        if os.name == "posix":
            try:
                os.chmod(target, mode)
            except OSError:
                pass
    return target


def secure_write_json(path: str | Path, payload: Any, *, mode: int = 0o600) -> Path:
    return secure_write_text(path, json.dumps(payload, indent=2), mode=mode)


def file_mode(path: str | Path) -> int | None:
    try:
        return stat.S_IMODE(Path(path).stat().st_mode)
    except OSError:
        return None


def collect_sensitive_argv_values(
    argv: Sequence[str],
    *,
    sensitive_flags: Iterable[str] = SENSITIVE_ARG_FLAGS,
) -> set[str]:
    flags = set(sensitive_flags)
    values: set[str] = set()
    skip_next = False
    for item in argv:
        if skip_next:
            if item:
                values.add(str(item))
            skip_next = False
            continue
        if item in flags:
            skip_next = True
            continue
        for flag in flags:
            prefix = f"{flag}="
            if item.startswith(prefix):
                value = item[len(prefix) :]
                if value:
                    values.add(value)
                break
    return values


def redact_text(value: str, sensitive_values: Iterable[str] | None = None) -> str:
    redacted = value or ""
    for sensitive in sorted({str(item) for item in sensitive_values or [] if item}, key=len, reverse=True):
        redacted = redacted.replace(sensitive, "***redacted***")
    redacted = BEARER_RE.sub("Bearer ***redacted***", redacted)
    redacted = JWT_RE.sub("***redacted-jwt***", redacted)
    redacted = INLINE_SECRET_RE.sub(lambda match: f"{match.group('prefix')}***redacted***", redacted)
    return redacted


def redact_argv(
    argv: Sequence[str],
    *,
    sensitive_flags: Iterable[str] = SENSITIVE_ARG_FLAGS,
) -> list[str]:
    flags = set(sensitive_flags)
    redacted: list[str] = []
    skip_next = False
    for item in argv:
        if skip_next:
            redacted.append("***redacted***")
            skip_next = False
            continue
        if item in flags:
            redacted.append(str(item))
            skip_next = True
            continue
        replacement = str(item)
        for flag in flags:
            prefix = f"{flag}="
            if replacement.startswith(prefix):
                replacement = f"{flag}=***redacted***"
                break
        redacted.append(redact_text(replacement))
    if skip_next:
        redacted.append("***redacted***")
    return redacted


def redact_command_string(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        return redact_text(command)
    return " ".join(shlex.quote(part) for part in redact_argv(parts))


def _iso_to_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def token_freshness(token_claims: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    expires_at = _iso_to_datetime(token_claims.get("expires_at_utc"))
    if expires_at is None:
        return {"status": "unknown", "expires_at_utc": token_claims.get("expires_at_utc"), "seconds_remaining": None}
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    seconds = int((expires_at - current.astimezone(timezone.utc)).total_seconds())
    if seconds <= 0:
        status = "expired"
    elif seconds <= 3600:
        status = "stale"
    else:
        status = "fresh"
    return {"status": status, "expires_at_utc": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"), "seconds_remaining": seconds}


def sanitize_token_claims(token_claims: Mapping[str, Any] | None) -> dict[str, Any]:
    claims = dict(token_claims or {})
    sanitized: dict[str, Any] = {}
    raw_claims = claims.get("raw_claims") if isinstance(claims.get("raw_claims"), Mapping) else {}

    field_map = {
        "tenant_id": ("tenant_id", "tid"),
        "audience": ("audience", "aud"),
        "app_id": ("app_id", "appid", "azp"),
        "subject": ("subject", "sub"),
        "user_principal_name": ("user_principal_name", "upn", "preferred_username"),
        "delegated_scopes": ("delegated_scopes",),
        "app_roles": ("app_roles", "roles"),
        "issued_at_utc": ("issued_at_utc",),
        "not_before_utc": ("not_before_utc",),
        "expires_at_utc": ("expires_at_utc",),
    }
    for output_key, candidate_keys in field_map.items():
        for key in candidate_keys:
            value = claims.get(key)
            if value is None and isinstance(raw_claims, Mapping):
                value = raw_claims.get(key)
            if value is not None:
                if output_key in {"delegated_scopes", "app_roles"}:
                    if isinstance(value, str):
                        sanitized[output_key] = sorted({item for item in re.split(r"[\s,]+", value) if item})
                    elif isinstance(value, list):
                        sanitized[output_key] = sorted({str(item) for item in value if item})
                    else:
                        sanitized[output_key] = []
                else:
                    sanitized[output_key] = value
                break
    for list_key in ("delegated_scopes", "app_roles"):
        sanitized.setdefault(list_key, [])
    freshness = token_freshness(sanitized)
    sanitized["freshness"] = freshness
    return {key: sanitized[key] for key in (*_ALLOWED_TOKEN_CLAIMS, "freshness") if key in sanitized}


def validate_token_claims(
    token_claims: Mapping[str, Any] | None,
    *,
    expected_audience: str = "https://graph.microsoft.com",
    tenant_id: str | None = None,
) -> dict[str, Any]:
    claims = sanitize_token_claims(token_claims)
    blockers: list[str] = []
    warnings: list[str] = []
    freshness = claims.get("freshness") or {}
    if freshness.get("status") == "expired":
        blockers.append("token_expired")
    elif freshness.get("status") in {"stale", "unknown"}:
        warnings.append(f"token_{freshness.get('status')}")
    audience = claims.get("audience")
    if audience and expected_audience and audience != expected_audience:
        warnings.append("unexpected_audience")
    if tenant_id and claims.get("tenant_id") and str(claims.get("tenant_id")) != str(tenant_id):
        blockers.append("tenant_mismatch")
    if not claims.get("tenant_id"):
        warnings.append("missing_tenant_id")
    if not claims.get("delegated_scopes") and not claims.get("app_roles"):
        warnings.append("missing_scopes_or_roles")
    return {
        "status": "blocked" if blockers else "warning" if warnings else "ok",
        "blockers": blockers,
        "warnings": warnings,
        "token_claims": claims,
    }


def deep_sanitize(value: Any, *, preserve_allowed_token_claims: bool = True) -> Any:
    if isinstance(value, Mapping):
        if preserve_allowed_token_claims and set(value.keys()).issubset(set(_ALLOWED_TOKEN_CLAIMS) | {"freshness"}):
            return {str(key): deep_sanitize(item, preserve_allowed_token_claims=False) for key, item in value.items()}
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text == "token_claims" and isinstance(item, Mapping):
                output[key_text] = sanitize_token_claims(item)
            elif SENSITIVE_KEY_RE.search(key_text):
                output[key_text] = "***redacted***"
            else:
                output[key_text] = deep_sanitize(item)
        return output
    if isinstance(value, list):
        return [deep_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
