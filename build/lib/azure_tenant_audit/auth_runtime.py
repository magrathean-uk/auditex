from __future__ import annotations

import importlib
import json
import subprocess
import time
from typing import Any, Callable, Optional

from .graph import GraphClient
from .secret_hygiene import redact_argv, sanitize_token_claims


SENSITIVE_CLI_ARGS = {"--client-secret", "--access-token"}


def scrub_command_line(command_line: list[str]) -> list[str]:
    return redact_argv(command_line, sensitive_flags=SENSITIVE_CLI_ARGS)


def acquire_azure_cli_access_token(
    tenant_id: str | None,
    log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
) -> str:
    command = [
        "az",
        "account",
        "get-access-token",
        "--resource",
        "https://graph.microsoft.com",
        "--output",
        "json",
    ]
    if tenant_id:
        command.extend(["--tenant", tenant_id])

    start = time.time()
    if log_event:
        log_event(
            "auth.cli.token.requested",
            "Requesting Microsoft Graph token from Azure CLI",
            {"tenant_id": tenant_id or "organizations", "resource": "https://graph.microsoft.com"},
        )
    try:
        completed = subprocess.run(command, check=False, text=True, capture_output=True, timeout=120)
    except FileNotFoundError as exc:
        raise RuntimeError("Azure CLI is not available. Install azure-cli and sign in with 'az login'.") from exc

    duration_ms = round((time.time() - start) * 1000, 2)
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip() or "Azure CLI token command failed."
        if "Please run 'az login'" in message or "Please run: az login" in message:
            if log_event:
                log_event(
                    "auth.cli.token.failed",
                    "Azure CLI token acquisition failed because login is required.",
                    {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
                )
            raise RuntimeError("Azure CLI is not signed in. Run 'az login' in a browser first, then retry.") from None
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token acquisition failed.",
                {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms, "error": message},
            )
        raise RuntimeError(f"Azure CLI token fetch failed: {message}")

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token response was not valid JSON.",
                {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
            )
        raise RuntimeError("Azure CLI returned non-JSON token response.") from exc

    token = payload.get("accessToken") or payload.get("access_token")
    if not token:
        if log_event:
            log_event(
                "auth.cli.token.failed",
                "Azure CLI token response missing access token field.",
                {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
            )
        raise RuntimeError("Azure CLI token response was missing accessToken.")

    if log_event:
        log_event(
            "auth.cli.token.acquired",
            "Azure CLI token acquired.",
            {"tenant_id": tenant_id or "organizations", "duration_ms": duration_ms},
        )
    return token


def capture_signed_in_context(
    client: GraphClient,
    log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
) -> dict[str, Any]:
    try:
        me = client.get_json("/me")
        roles = client.get_all(
            "/me/memberOf/microsoft.graph.directoryRole",
            params={"$select": "id,displayName,roleTemplateId"},
        )
    except Exception as exc:  # noqa: BLE001
        if log_event:
            log_event(
                "auth.session.unavailable",
                "Unable to capture signed-in identity and directory roles.",
                {"error": str(exc)},
            )
        return {}

    role_names = sorted(
        {
            role.get("displayName")
            for role in roles
            if isinstance(role, dict) and role.get("displayName")
        }
    )
    context = {
        "display_name": me.get("displayName"),
        "user_principal_name": me.get("userPrincipalName"),
        "object_id": me.get("id"),
        "roles": role_names,
    }
    if log_event:
        log_event("auth.session.context", "Captured signed-in identity and directory roles.", context)
    return context


def inspect_access_token(token: str) -> dict[str, Any]:
    return importlib.import_module("auditex.auth").inspect_token_claims(token)


def build_auth_context_payload(
    *,
    auth_mode: str,
    tenant_id: str,
    token_claims: dict[str, Any] | None = None,
    session_context: dict[str, Any] | None = None,
    saved_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "auth_mode": auth_mode,
        "tenant_id": tenant_id,
        "token_claims": sanitize_token_claims(token_claims),
        "session_context": session_context or {},
    }
    if saved_context:
        payload["saved_auth_context"] = {
            "name": saved_context.get("name"),
            "auth_type": saved_context.get("auth_type"),
            "tenant_id": saved_context.get("tenant_id"),
        }
        delegated_roles = saved_context.get("delegated_roles") or []
    else:
        delegated_roles = []
    session_roles = (session_context or {}).get("roles") or []
    payload["delegated_roles"] = list(dict.fromkeys([*delegated_roles, *session_roles]))
    return payload
