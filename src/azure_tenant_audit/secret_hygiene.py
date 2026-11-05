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
        "--sensitive-users",
    }
)

SENSITIVE_KEY_RE = re.compile(
    r"(^|[_-])(access[_-]?token|refresh[_-]?token|token|secret|password|credential|authorization|raw[_-]?claims)([_-]|$)",
    re.IGNORECASE,
)

BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]++\.[A-Za-z0-9_-]++\.[A-Za-z0-9_-]+")
# Include guest UPNs (#EXT#), Unicode local parts and single-label UPN suffixes.
_OUTPUT_EMAIL_RE = re.compile(
    # Keep familiar diagnostic field labels; otherwise mask an ambiguous '=' with
    # the local part, which may legitimately contain it.
    # Apostrophes inside a name are allowed, but surrounding single quotes stay intact.
    # Query/filter separators (? & | + ' and %20/%27) can start another address.
    # Keep these fixed-width starts and the bounded local/domain scans: even a
    # delimiter at every position must take only constant work per input byte.
    # Slash is a URL path separator, not part of a diagnostic local part.
    r"(?:(?<![\w.!#$%*=^`{}~\\-])|(?<=\\[nrtbf])|(?<=%2[07]))"
    r"(?P<field>(?i:SentTo|UserPrincipalName|UPN|EmailAddress|Email|Recipient|From|To)='?)?"
    r"(?P<quote>'?)"
    r'(?P<local>\\?"(?:\\u[0-9a-fA-F]{4}|[^"\\\r\n]){1,64}\\?"|'
    r"(?:\\u[0-9a-fA-F]{4}|[\w.!#$%&*+=?^`{|}~-])"
    r"(?:\\u[0-9a-fA-F]{4}|[\w.!#$%&'*+=?^`{|}~-]){0,63})"
    r"@(?P<domain>[\w](?:[\w.-]{0,251}[\w])?)"
)
_OUTPUT_GUID_RE = re.compile(
    r"(?P<label>(?:Trace ID|Correlation ID):[ \t]*)?"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])",
    re.IGNORECASE,
)
# Public names for the shared output-redaction module (``output_redaction``).
OUTPUT_EMAIL_RE = _OUTPUT_EMAIL_RE
OUTPUT_GUID_RE = _OUTPUT_GUID_RE
# Decode only representations needed for identifier matching; never execute a
# general escape decoder on arbitrary command output. One pass, no recursion.
_OUTPUT_ENCODING_RE = re.compile(r"%40|%7b|%7d|%2d|\\u0040|&#64;|＠", re.IGNORECASE)
_OUTPUT_ENCODINGS = {
    "%40": "@", "%7b": "{", "%7d": "}", "%2d": "-",
    r"\u0040": "@", "&#64;": "@", "＠": "@",
}
# 320 covers a plain 64-character local part plus a 253-character domain.
# JSON can spell each local character as six bytes (\uXXXX); 2048 also covers
# that and percent-encoded GUIDs at the cut, without scanning a whole dump.
_OUTPUT_SAMPLE_MARGIN = 2048
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
        option, separator, value = item.partition("=")
        if _sensitive_option(option, flags):
            if separator:
                if value:
                    values.add(value)
            else:
                skip_next = True
    return values


def _sensitive_option(option: str, flags: set[str]) -> bool:
    """Recognise exact flags and any sensitive long-option prefix, defensively.

    Public parsers reject abbreviations. Retain this protection for synthetic
    command lines and any future parser that accidentally enables them again.
    """
    return option in flags or (
        option.startswith("--")
        and len(option) > 2
        and sum(flag.startswith(option) for flag in flags) >= 1
    )


def redact_text(value: str, sensitive_values: Iterable[str] | None = None) -> str:
    redacted = value or ""
    for sensitive in sorted({str(item) for item in sensitive_values or [] if item}, key=len, reverse=True):
        redacted = redacted.replace(sensitive, "***redacted***")
    redacted = BEARER_RE.sub("Bearer ***redacted***", redacted)
    redacted = JWT_RE.sub("***redacted-jwt***", redacted)
    redacted = INLINE_SECRET_RE.sub(lambda match: f"{match.group('prefix')}***redacted***", redacted)
    return redacted


def redact_output(
    value: Any,
    sensitive_values: Iterable[str] | None = None,
    *,
    limit: int | None = 500,
) -> str:
    """Mask diagnostic output, then bound it; never use on collected evidence rows.

    Domains, punctuation and error wording remain useful. ``limit=None`` is for full
    MCP command responses, which are not log samples and must not be clipped.
    """
    text = "" if value is None else value if isinstance(value, (str, bytes)) else str(value)
    clipped = limit is not None and len(text) > max(0, limit) + _OUTPUT_SAMPLE_MARGIN
    if limit is not None:
        text = text[:max(0, limit) + _OUTPUT_SAMPLE_MARGIN]
    text = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    # Credentials take precedence over decoding, which can change a literal
    # sensitive value. Reuse iterators for the post-decoding pass as well.
    sensitive_values = tuple(sensitive_values) if sensitive_values is not None else None
    text = redact_text(text, sensitive_values)
    text = _OUTPUT_ENCODING_RE.sub(lambda match: _OUTPUT_ENCODINGS[match[0].lower()], text)
    redacted = redact_text(text, sensitive_values)

    def mask_email(match: re.Match[str]) -> str:
        # Package versions and the conventional Git SSH user are diagnostics.
        version = match["domain"].replace(".", "").isdigit()
        git_ssh = match["local"] == "git" and match["domain"].lower().startswith(("git", "ssh."))
        if version or git_ssh:
            return match[0]
        return f"{match['field'] or ''}{match['quote']}***@{match['domain']}"

    redacted = _OUTPUT_EMAIL_RE.sub(mask_email, redacted)
    redacted = _OUTPUT_GUID_RE.sub(lambda match: match[0] if match['label'] else "<redacted-guid>", redacted)
    if clipped:
        # Masking can shrink the window below the requested limit. Discard its
        # last token: the scan boundary may have cut an address before its '@'.
        trailing = re.split(r"[\s,;:\"'<>()\[\]{}]", redacted)[-1]
        if trailing:
            redacted = redacted[:-len(trailing)]
    return redacted if limit is None else redacted[:max(0, limit)]


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
        option, separator, _value = item.partition("=")
        if _sensitive_option(option, flags):
            if separator:
                redacted.append(f"{option}=***redacted***")
                continue
            redacted.append(str(item))
            skip_next = True
            continue
        redacted.append(redact_text(str(item)))
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
