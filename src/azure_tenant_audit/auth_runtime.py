from __future__ import annotations

from typing import Any

from . import auth_context
from .secret_hygiene import (
    CERTIFICATE_ARG_FLAGS,
    redact_argv,
    sanitize_token_claims,
)

# Every entry stays, removed flags included (DEC-108 D5): an old command line or a mistyped flag is still redacted.
SENSITIVE_CLI_ARGS = {
    "--client-secret", "--access-token", "--sensitive-users", "--partner-domains",
    "--env", "--break-glass-accounts", *CERTIFICATE_ARG_FLAGS,
}

# Engine flags of the removed Microsoft 365 sign-in ways (DEC-107). They are refused by name with the certificate
# way, before argparse could echo a value; the two that carried a secret stay in SENSITIVE_CLI_ARGS for redaction.
REMOVED_AUTH_FLAGS = (
    "--client-secret", "--access-token", "--auth-context", "--use-azure-cli-token",
    "--interactive", "--scopes", "--browser-command",
)


def removed_auth_flag(argv: list[str]) -> str | None:
    """The first removed sign-in flag in ``argv`` (``--flag``, ``--flag=value`` or one malformed token), else None."""
    for item in argv:
        if item == "--":
            break
        parts = item.split(maxsplit=1)
        name = parts[0].partition("=")[0] if parts else ""
        if name in REMOVED_AUTH_FLAGS:
            return name
    return None


def scrub_command_line(command_line: list[str]) -> list[str]:
    return redact_argv(command_line, sensitive_flags=SENSITIVE_CLI_ARGS)


def inspect_access_token(token: str) -> dict[str, Any]:
    return auth_context.inspect_token_claims(token)


def build_auth_context_payload(
    *,
    auth_mode: str,
    tenant_id: str,
    token_claims: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """normalized/auth_context.json for an app-only run: no signed-in user, so no session context or delegated roles."""
    return {
        "auth_mode": auth_mode,
        "tenant_id": tenant_id,
        "token_claims": sanitize_token_claims(token_claims),
        "session_context": {},
        "delegated_roles": [],
    }
