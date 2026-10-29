"""Shared local auth-context reading and token inspection, with no product dependency."""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .secret_hygiene import sanitize_token_claims, validate_token_claims
from .utils import parse_csv_list


AUTH_CONTEXTS_PATH_ENV_VAR = "AUDITEX_AUTH_CONTEXTS_PATH"


def default_auth_contexts_path() -> Path:
    configured = os.environ.get(AUTH_CONTEXTS_PATH_ENV_VAR)
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / ".secrets" / "auditex-auth-contexts.json"


def _safe_context_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value.strip())
    cleaned = cleaned.strip("._") or "context"
    return cleaned[:64]


def _token_dir() -> Path:
    return default_auth_contexts_path().parent / ".tokens"


def default_token_path(name: str, token_file: str | None = None) -> Path:
    """Resolve a context's token path within the shared local token directory."""
    directory = _token_dir()
    directory.mkdir(parents=True, exist_ok=True)
    if token_file:
        safe_token_file = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in token_file.strip())
        safe_token_file = safe_token_file.strip("._") or "token"
        return directory / safe_token_file[:64]
    return directory / f"{_safe_context_name(name)}.token"


def _load_json(path: Path, *, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def auth_context_store() -> dict[str, Any]:
    """Read the shared local context store, normalising absent or invalid data."""
    store = _load_json(default_auth_contexts_path(), default={"active_context": None, "contexts": {}})
    if not isinstance(store, dict):
        return {"active_context": None, "contexts": {}}
    if not isinstance(store.get("contexts"), dict):
        store["contexts"] = {}
    return store


def b64url_json(segment: str) -> dict[str, Any]:
    if not segment:
        return {}
    padding = "=" * ((4 - len(segment) % 4) % 4)
    raw = base64.urlsafe_b64decode(segment + padding)
    decoded = json.loads(raw.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def iso_from_epoch(value: Any) -> str | None:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inspect_token_claims(token: str, *, include_raw_claims: bool = False) -> dict[str, Any]:
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a JWT")
    if not all(parts):
        raise ValueError("token is not a complete JWT")
    payload = b64url_json(parts[1])
    delegated_scopes = sorted(parse_csv_list(str(payload.get("scp", "")).replace(" ", ",")) or [])
    app_roles = sorted(str(item) for item in payload.get("roles", []) if isinstance(item, str))
    result = {
        "tenant_id": payload.get("tid"),
        "audience": payload.get("aud"),
        "app_id": payload.get("appid") or payload.get("azp"),
        "subject": payload.get("sub"),
        "user_principal_name": payload.get("upn") or payload.get("preferred_username"),
        "delegated_scopes": delegated_scopes,
        "app_roles": app_roles,
        "issued_at_utc": iso_from_epoch(payload.get("iat")),
        "not_before_utc": iso_from_epoch(payload.get("nbf")),
        "expires_at_utc": iso_from_epoch(payload.get("exp")),
    }
    if include_raw_claims:
        result["raw_claims"] = payload
    return sanitize_token_claims(result)


def resolve_stored_auth_context(
    store: dict[str, Any],
    name: str | None = None,
    *,
    resolve_token_path: Callable[[str, str | None], Path | None],
    read_token: Callable[[Path], str],
) -> dict[str, Any]:
    selected_name = name or store.get("active_context")
    if not selected_name:
        raise RuntimeError("no saved auth context")
    context = store.get("contexts", {}).get(selected_name)
    if not isinstance(context, dict):
        raise RuntimeError(f"auth context '{selected_name}' not found")

    token = context.get("token")
    if not token:
        token_file = context.get("token_file")
        if isinstance(token_file, str) and token_file:
            token_path = resolve_token_path(selected_name, token_file)
            if token_path is not None:
                token = read_token(token_path)
                if token:
                    context = dict(context)
                    context["token"] = token

    validation = validate_token_claims(context.get("token_claims") or {}, tenant_id=context.get("tenant_id"))
    if validation.get("blockers"):
        raise RuntimeError(
            f"auth context '{selected_name}' is not usable: {', '.join(validation['blockers'])}"
        )
    return context


def resolve_auth_context(name: str | None = None) -> dict[str, Any]:
    """Read a saved context using the same local paths as the product wrapper."""
    return resolve_stored_auth_context(
        auth_context_store(),
        name,
        resolve_token_path=default_token_path,
        read_token=lambda path: path.read_text(encoding="utf-8").strip(),
    )
