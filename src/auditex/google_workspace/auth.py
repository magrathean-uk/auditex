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

        credentials = service_account.Credentials.from_service_account_file(
            str(config.service_account_key.expanduser()),
            scopes=list(config.scopes),
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


def safe_auth_summary(config: GoogleAuthConfig) -> dict[str, Any]:
    return {
        "platform": "google_workspace",
        "auth_type": config.auth_mode,
        "subject": config.subject,
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
