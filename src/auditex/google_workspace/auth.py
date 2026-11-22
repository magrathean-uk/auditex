from __future__ import annotations

import importlib.util
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azure_tenant_audit.secret_hygiene import secure_write_text

DEFAULT_GOOGLE_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/apps.alerts",
    "https://www.googleapis.com/auth/gmail.settings.basic",
)

# Cloud Identity Policy API (org 2-step verification policy). It is requested on its own token, never
# in the shared scope set: with domain-wide delegation one unauthorised scope fails every call that
# shares the token, so a tenant that has not added this scope loses only the policy read.
POLICIES_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
ISOLATED_GOOGLE_SCOPES: frozenset[str] = frozenset({POLICIES_SCOPE})
# The per-user Gmail settings reads need only this scope (every settings get and list the collector makes accepts
# gmail.settings.basic; see the Gmail API users.settings reference). A user-impersonating token is narrowed to
# it, so it never carries the shared set's other scopes (the Directory security scope among them).
GMAIL_SETTINGS_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/gmail.settings.basic",
)

_DEPENDENCIES = {
    "google.auth": "google-auth",
    "google.oauth2.service_account": "google-auth",
    "google.oauth2.credentials": "google-auth",
    "google_auth_oauthlib.flow": "google-auth-oauthlib",
    "googleapiclient.discovery": "google-api-python-client",
}


@dataclass(frozen=True)
class GoogleAuthConfig:
    auth_mode: str
    scopes: tuple[str, ...] = DEFAULT_GOOGLE_SCOPES
    subject: str | None = None
    service_account_key: Path | None = None
    oauth_client: Path | None = None
    token_cache: Path | None = None
    # Scopes in ``scopes`` that domain-wide delegation requests on their own token (see POLICIES_SCOPE).
    isolated_scopes: tuple[str, ...] = ()

    @property
    def supports_user_delegation(self) -> bool:
        """True when the credentials can impersonate each user (domain-wide delegation only)."""
        return self.auth_mode == "domain-delegation"


def google_dependency_status() -> dict[str, Any]:
    missing = [package for module, package in _DEPENDENCIES.items() if not _module_available(module)]
    missing = sorted(dict.fromkeys(missing))
    return {
        "available": not missing,
        "missing": missing,
        "install_hint": "Install Google extras with `python -m pip install -e '.[google]'` "
        "(google-auth, google-auth-oauthlib, google-api-python-client)."
        if missing
        else "",
    }


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False


def ensure_google_dependencies() -> None:
    status = google_dependency_status()
    if not status["available"]:
        raise RuntimeError(status["install_hint"])


def build_google_credentials(config: GoogleAuthConfig) -> Any:
    ensure_google_dependencies()
    if config.auth_mode == "domain-delegation":
        if config.service_account_key is None:
            raise ValueError("--service-account-key is required for domain-delegation auth")
        if not config.subject:
            raise ValueError("--subject is required for domain-delegation auth")
        from google.auth.exceptions import GoogleAuthError
        from google.oauth2 import service_account

        shared_scopes = [scope for scope in config.scopes if scope not in config.isolated_scopes]
        key_path = config.service_account_key.expanduser()
        # Built from the bytes the owner-only check read through one descriptor: the path is never opened again.
        key_info = _parse_service_account_key(_check_private_key_file(key_path))
        try:
            credentials = service_account.Credentials.from_service_account_info(
                key_info,
                scopes=shared_scopes,
            )
        except GoogleAuthError as exc:  # a key file missing fields (MalformedError)
            raise RuntimeError(f"Google sign-in failed ({type(exc).__name__}); check the service-account key file.") from None
        return credentials.with_subject(config.subject)

    if config.auth_mode == "oauth":
        if config.oauth_client is None:
            raise ValueError("--oauth-client is required for oauth auth")
        if config.token_cache is None:
            raise ValueError("--token-cache is required for oauth auth")
        from google.auth.exceptions import GoogleAuthError, RefreshError, TransportError
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow

        token_cache = config.token_cache.expanduser()
        credentials = None
        try:
            if token_cache.exists():
                # Loaded with the scopes it was granted (not this run's), so a run that needs more signs in again
                # rather than reusing a token its new collectors cannot use.
                credentials = Credentials.from_authorized_user_file(str(token_cache))
                if not _has_scopes(credentials, config.scopes) or not credentials.refresh_token:
                    credentials = None
            if credentials is not None:
                # The cache's scopes are what was asked for (an older cache may claim scopes never granted), so it is
                # refreshed every run and trusted only for the scopes Google's token endpoint grants now.
                try:
                    credentials.refresh(Request())
                except (RefreshError, TransportError) as exc:
                    if isinstance(exc, TransportError) or not _is_grant_error(exc):
                        # The token endpoint is down or busy: that says nothing about the grant. A token still in
                        # date is used as it is; an expired one cannot be, and signing in again would not help.
                        if not credentials.valid:
                            raise RuntimeError(
                                "Google sign-in could not be refreshed (temporary error); run again later."
                            ) from None
                    else:
                        # Revoked, expired (Testing-status clients expire refresh tokens after 7 days) or narrower
                        # than asked: sign in again.
                        credentials = None
                    refreshed = False
                else:
                    refreshed = True
                if refreshed and not _granted(credentials, config.scopes):
                    credentials = None
            if not credentials or not credentials.valid:
                flow = InstalledAppFlow.from_client_secrets_file(str(config.oauth_client.expanduser()), list(config.scopes))
                try:
                    credentials = flow.run_local_server(port=0)
                except Exception as exc:  # noqa: BLE001 - oauthlib's denial and scope-change errors are not GoogleAuthError
                    raise RuntimeError(f"Google sign-in failed ({type(exc).__name__}); run again to sign in.") from None
        except GoogleAuthError as exc:
            # A fixed message: the library's text can carry token material.
            raise RuntimeError(f"Google sign-in failed ({type(exc).__name__}); run again to sign in.") from None
        # Creates any missing folder owner-only; an existing folder (the working directory, a shared one) keeps its mode.
        secure_write_text(token_cache, credentials.to_json(), mode=0o600)
        return credentials

    raise ValueError(f"unsupported Google auth mode: {config.auth_mode}")


# A service-account JSON key is a few KB; anything larger is not one.
_SERVICE_ACCOUNT_KEY_LIMIT = 64 * 1024


def _check_private_key_file(path: Path) -> bytes:
    """Refuse a domain-wide delegation key that is not a small, owner-only regular file (no link).

    The key can act as any user in the domain, so it gets the same check as the Microsoft 365 certificate. The
    message is fixed and never repeats the path or the file's content.
    """
    if not os.path.lexists(path):
        raise ValueError("service_account_key_missing: the service-account key file was not found.")
    from azure_tenant_audit.certificate_auth import (
        CertificateAuthError,
        _read_private_file,
    )

    try:
        return _read_private_file(path, _SERVICE_ACCOUNT_KEY_LIMIT, "service_account_key_refused")
    except CertificateAuthError:
        raise ValueError(
            "service_account_key_refused: the service-account key must be an owner-only regular file "
            "(chmod 600, not a link) of at most 64 KB."
        ) from None


def _parse_service_account_key(raw: bytes) -> dict[str, Any]:
    """The key file's JSON object; a fixed message otherwise, never the content."""
    try:
        info = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        info = None
    if not isinstance(info, dict):
        raise ValueError("service_account_key_invalid: the service-account key file is not a JSON key.")
    return info


def _has_scopes(credentials: Any, scopes: tuple[str, ...]) -> bool:
    """Whether cached OAuth credentials were granted every scope this run asks for."""
    has_scopes = getattr(credentials, "has_scopes", None)
    if has_scopes is None:
        return False
    try:
        return bool(has_scopes(list(scopes)))
    except Exception:  # noqa: BLE001 - an unreadable cache is signed in again, never trusted
        return False


# Token endpoint errors that say the grant itself is gone or narrower (RFC 6749 5.2); a fresh consent fixes those.
# Anything else (a 5xx page, a timeout, a busy endpoint) is temporary and says nothing about the grant.
_GRANT_ERRORS = ("invalid_grant", "invalid_scope", "invalid_client", "unauthorized_client", "necessary fields")


def _is_grant_error(exc: Exception) -> bool:
    """Whether a failed refresh means the user must consent again (matched only; the text is never kept)."""
    if getattr(exc, "retryable", False):
        return False
    text = str(exc)
    return any(code in text for code in _GRANT_ERRORS)


def _granted(credentials: Any, scopes: tuple[str, ...]) -> bool:
    """Whether the last refresh granted every scope this run asks for.

    Google reports the grant in the token response's ``scope`` field, which RFC 6749 (5.1) lets it leave out when
    the grant is exactly the scopes the refresh asked for (the cache's own); google-auth then sets no
    ``granted_scopes``, so the scopes asked for are the grant. A refresh asking for a scope never granted fails.
    """
    granted = getattr(credentials, "granted_scopes", None)
    if granted is None:
        granted = getattr(credentials, "scopes", None)
    if not granted:
        return False
    return set(scopes).issubset(set(granted))


def user_delegated_credentials(credentials: Any, subject: str, *, scopes: tuple[str, ...] | None = None) -> Any:
    """Credentials that act as ``subject`` (a user mailbox) under domain-wide delegation.

    ``with_subject`` and ``with_scopes`` return copies, so the admin credentials stay as they are. With
    ``scopes`` the copy is narrowed to just those, which is what keeps a token that can act as any user
    from holding more than the one read it is for. Only a delegated service account can do this; an OAuth
    user token cannot act as anyone else.
    """
    email = str(subject or "").strip()
    if "@" not in email:
        raise ValueError(f"cannot delegate to {subject!r}: not an email address")
    with_subject = getattr(credentials, "with_subject", None)
    if with_subject is None:
        raise ValueError("these credentials cannot act as another user; domain-wide delegation is required")
    delegated = with_subject(email)
    with_scopes = getattr(delegated, "with_scopes", None)
    if scopes and with_scopes is not None:
        delegated = with_scopes(list(scopes))
    return delegated


def safe_auth_summary(config: GoogleAuthConfig) -> dict[str, Any]:
    return {
        "platform": "google_workspace",
        "auth_type": config.auth_mode,
        "subject": config.subject,
        "per_user_delegation": config.supports_user_delegation,
        "scope_count": len(config.scopes),
        "service_account_key_present": config.service_account_key is not None,
        "oauth_client_present": config.oauth_client is not None,
        "token_cache_present": config.token_cache is not None,
    }


def read_service_account_summary(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"present": False}
    try:
        payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"present": path.expanduser().exists(), "error": str(exc)}
    return {
        "present": True,
        "type": payload.get("type"),
        "project_id": payload.get("project_id"),
        "client_email": payload.get("client_email"),
        "client_id": payload.get("client_id"),
    }
