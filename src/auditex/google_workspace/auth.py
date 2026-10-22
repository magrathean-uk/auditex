from __future__ import annotations

import importlib.util
import json
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
    "https://www.googleapis.com/auth/gmail.settings.sharing",
)

# Cloud Identity Policy API (org 2-step verification policy). It is requested on its own token, never
# in the shared scope set: with domain-wide delegation one unauthorised scope fails every call that
# shares the token, so a tenant that has not added this scope loses only the policy read.
POLICIES_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
ISOLATED_GOOGLE_SCOPES: frozenset[str] = frozenset({POLICIES_SCOPE})
# The per-user Gmail settings reads need only these two scopes. A user-impersonating token is narrowed to
# them, so it never carries the shared set's other scopes (the Directory security scope among them).
GMAIL_SETTINGS_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.settings.sharing",
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
        from google.oauth2 import service_account

        shared_scopes = [scope for scope in config.scopes if scope not in config.isolated_scopes]
        credentials = service_account.Credentials.from_service_account_file(
            str(config.service_account_key.expanduser()),
            scopes=shared_scopes,
        )
        return credentials.with_subject(config.subject)

    if config.auth_mode == "oauth":
        if config.oauth_client is None:
            raise ValueError("--oauth-client is required for oauth auth")
        if config.token_cache is None:
            raise ValueError("--token-cache is required for oauth auth")
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow

        token_cache = config.token_cache.expanduser()
        credentials = None
        if token_cache.exists():
            credentials = Credentials.from_authorized_user_file(str(token_cache), list(config.scopes))
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        if not credentials or not credentials.valid:
            flow = InstalledAppFlow.from_client_secrets_file(str(config.oauth_client.expanduser()), list(config.scopes))
            credentials = flow.run_local_server(port=0)
        token_cache.parent.mkdir(parents=True, exist_ok=True)
        secure_write_text(token_cache, credentials.to_json(), mode=0o600)
        return credentials

    raise ValueError(f"unsupported Google auth mode: {config.auth_mode}")


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
