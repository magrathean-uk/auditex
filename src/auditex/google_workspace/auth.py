from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azure_tenant_audit.logger_hold import LoggerHold
from azure_tenant_audit.secret_hygiene import (
    ownership_enforced,
    secret_file_lock,
    secure_read_text,
    secure_write_text,
)

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
INBOUND_SSO_SCOPE = "https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly"
ISOLATED_GOOGLE_SCOPES: frozenset[str] = frozenset({POLICIES_SCOPE, INBOUND_SSO_SCOPE})
# The per-user Gmail settings reads need only this scope (every settings get and list the collector makes accepts
# gmail.settings.basic; see the Gmail API users.settings reference). A user-impersonating token is narrowed to
# it, so it never carries the shared set's other scopes (the Directory security scope among them).
GMAIL_SETTINGS_SCOPES: tuple[str, ...] = (
    "https://www.googleapis.com/auth/gmail.settings.basic",
)

# The scopes Google's token endpoint actually granted (on the last refresh or consent), kept in the token cache beside
# google-auth's own fields: google-auth serialises only the scopes asked for, which never prove a grant.
VERIFIED_SCOPES_KEY = "auditex_verified_scopes"
# RFC 6749 section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E ). ASCII only; no space, control, DEL, quote or backslash.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")

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
    hint = ""
    if missing:
        from ..bootstrap import extra_install_command, extra_install_note

        note = extra_install_note()
        hint = (f"Install Google extras with `{extra_install_command('google', for_record=True)}` "
                f"({note + '; ' if note else ''}google-auth, google-auth-oauthlib, google-api-python-client).")
    return {"available": not missing, "missing": missing, "install_hint": hint}


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False


def ensure_google_dependencies() -> None:
    status = google_dependency_status()
    if not status["available"]:
        raise RuntimeError(status["install_hint"])


# Dependency loggers that write OAuth request and response details at DEBUG (requests-oauthlib logs the token exchange's
# request body and the token it obtained; oauthlib, google-auth and urllib3 log request material) or the consent
# redirect, which carries the authorisation code, at INFO (google-auth-oauthlib's local server). Children are covered.
_AUTH_DEPENDENCY_LOGGERS: tuple[str, ...] = (
    "requests_oauthlib",
    "oauthlib",
    "google_auth_oauthlib",
    "google.auth",
    "google.oauth2",
    "urllib3",
)
_auth_dependency_hold = LoggerHold(_AUTH_DEPENDENCY_LOGGERS, logging.WARNING)


def _auth_dependency_loggers() -> list[logging.Logger]:
    """Each named dependency logger and every existing child with a level of its own (a host may set one directly)."""
    return _auth_dependency_hold.loggers()


def quiet_auth_dependency_logs() -> Any:
    """Hold the OAuth dependency loggers at WARNING or higher while sign-in, consent, token exchange and refresh run.

    A host (an embedding application, the MCP server, or a user with a DEBUG root logger) would otherwise have codes,
    tokens or refresh tokens written to its logs. Each logger's own level and ``propagate`` setting are put back when
    the last overlapping guard ends, on an exception too. Auditex's own loggers are untouched. Levels are process-wide:
    while any sign-in runs, these logger families drop every message below WARNING, from any thread.
    """
    return _auth_dependency_hold.hold()


@quiet_auth_dependency_logs()  # sign-in, consent, token exchange and refresh all run inside it
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
        cached: Any = None
        recorded: frozenset[str] | None = None
        # Read once, through the same folder and file checks as the write: the grant recorded beside the credentials
        # is then one this account saved, never one planted by another account (a fixed refusal otherwise).
        raw_cache = secure_read_text(token_cache)
        try:
            if raw_cache is not None:
                # A cache lacking a field a refresh needs is found here, on the credentials, so no refresh error text is
                # ever read to decide it. A cache google-auth cannot load at all (Google may leave the refresh token out
                # of a consent, and the cache then has none) signs in again too; google-auth's text is never kept.
                try:
                    cached = json.loads(raw_cache)
                    if not isinstance(cached, dict):
                        raise ValueError("not a token cache")
                    recorded = _recorded_grant(cached)
                    if _cache_covers(cached, recorded, config.scopes):
                        # Narrowed to this run's scopes (all of them inside the grant, as just checked): a scope only an
                        # earlier run needed is never asked for on refresh, nor claimed by the credentials returned.
                        credentials = Credentials.from_authorized_user_info(cached, scopes=list(config.scopes))
                except (ValueError, TypeError, AttributeError):  # a wrong-typed field google-auth cannot parse
                    cached, recorded, credentials = None, None, None
                if credentials is not None and not _can_refresh(credentials):
                    credentials = None
            if credentials is not None:
                # Refreshed every run and trusted only for the scopes Google's token endpoint grants now.
                try:
                    credentials.refresh(Request())
                except (RefreshError, TransportError) as exc:
                    if isinstance(exc, TransportError) or not _is_grant_error(exc):
                        # The token endpoint is down or busy: that says nothing about the grant. A token still in
                        # date whose recorded grant covers this run is used as it is (it claims only this run's
                        # scopes), and the cache is left as it is (another run may have replaced it meanwhile). An
                        # expired token, or a cache that cannot show the grant (an older one records only the scopes
                        # asked for), cannot be used, and signing in again would not help while the endpoint is down.
                        # On a volume that ignores ownership (macOS noowners) another account could have written the
                        # recorded grant, so it is not used there.
                        if (
                            credentials.valid
                            and recorded is not None
                            and set(config.scopes).issubset(recorded)
                            and ownership_enforced(token_cache)
                        ):
                            return credentials
                        raise RuntimeError(
                            "Google sign-in could not be refreshed (temporary error); run again later."
                        ) from None
                    # Revoked, expired (Testing-status clients expire refresh tokens after 7 days) or narrower than
                    # asked: sign in again. The endpoint granted nothing, so the cache's recorded grant is emptied first
                    # (before the consent, which may be declined or abandoned): the refused scope is never sent on a
                    # refresh again, nor claimed by a later outage fallback, until a consent grants it.
                    raw_cache, cached = _narrow_cached_grant(token_cache, raw_cache, cached, frozenset())
                    credentials = None
                else:
                    if not _granted(credentials, config.scopes):
                        # The endpoint granted less than the run needs: the recorded grant keeps only what it granted.
                        raw_cache, cached = _narrow_cached_grant(
                            token_cache, raw_cache, cached, frozenset(_grant(credentials))
                        )
                        credentials = None
            if not credentials or not credentials.valid:
                flow = _oauth_client_flow(InstalledAppFlow, config.oauth_client.expanduser(), config.scopes)
                try:
                    credentials = flow.run_local_server(port=0)
                except Exception as exc:  # noqa: BLE001 - oauthlib's denial and scope-change errors are not GoogleAuthError
                    # oauthlib refuses a narrower grant with its own Warning (unless scope relaxation is on); the
                    # missing scopes are named from this run's list, never the response text or token it carries.
                    missing = _consent_missing_scopes(exc, config.scopes)
                    if missing:
                        # A declined scope: the cache's recorded grant keeps only what this consent granted too.
                        _narrow_cached_grant(token_cache, raw_cache, cached, _consent_grant(exc))
                        raise RuntimeError(_missing_scopes_message(missing)) from None
                    raise RuntimeError(f"Google sign-in failed ({type(exc).__name__}); run again to sign in.") from None
                # With oauthlib's scope relaxation a consent can return a narrower grant; it is neither used nor saved,
                # and the cache's recorded grant keeps only what this consent granted.
                missing = sorted(set(config.scopes) - _grant(credentials))
                if missing:
                    _narrow_cached_grant(token_cache, raw_cache, cached, frozenset(_grant(credentials)))
                    raise RuntimeError(_missing_scopes_message(missing))
        except GoogleAuthError as exc:
            # A fixed message: the library's text can carry token material.
            raise RuntimeError(f"Google sign-in failed ({type(exc).__name__}); run again to sign in.") from None
        # Only a successful refresh or a fresh consent is saved, with the grant Google reported for it. The write holds
        # the cache's lock, so it never lands inside another run's narrowing (between its re-read and its replace). A
        # lock not obtained in time leaves the cache as it is: this run continues with what the endpoint granted now.
        saved = json.loads(credentials.to_json())
        saved[VERIFIED_SCOPES_KEY] = sorted(_grant(credentials))
        with secret_file_lock(token_cache) as locked:
            if locked:
                # Creates any missing folder owner-only; an existing folder (the working directory, a shared one) keeps
                # its mode.
                secure_write_text(token_cache, json.dumps(saved), mode=0o600)
        return credentials

    raise ValueError(f"unsupported Google auth mode: {config.auth_mode}")


def _oauth_client_flow(flow_class: Any, client_file: Path, scopes: tuple[str, ...]) -> Any:
    """The consent flow from the OAuth client file, refused with a fixed message that never repeats the path.

    The library opens the file itself, and its ``OSError`` names the full path, which would reach the probe bundle.
    """
    try:
        return flow_class.from_client_secrets_file(str(client_file), list(scopes))
    except FileNotFoundError:
        raise ValueError("oauth_client_missing: the configured OAuth client file was not found.") from None
    except OSError as exc:
        raise ValueError(
            "oauth_client_unreadable: the configured OAuth client file could not be read "
            f"({exc.strerror or type(exc).__name__})."
        ) from None


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


# Token endpoint errors that say the grant itself is gone or narrower (RFC 6749 5.2); a fresh consent fixes those.
# Anything else (a 5xx page, a timeout, a busy endpoint, another error code) is temporary and says nothing about the grant.
_GRANT_ERRORS = frozenset({"invalid_grant", "invalid_scope", "invalid_client", "unauthorized_client"})
# The fields google-auth needs to refresh a user token; a cache lacking one is signed in again without a refresh.
_REFRESH_FIELDS = ("refresh_token", "token_uri", "client_id", "client_secret")


def _missing_scopes_message(missing: list[str]) -> str:
    return (
        "Google sign-in did not grant every permission this run needs (missing scopes: "
        f"{', '.join(missing)}); run again and approve every requested permission."
    )


def _consent_grant(exc: Exception) -> frozenset[str] | None:
    """The scopes oauthlib's scope-change Warning says the consent granted; ``None`` for any other error."""
    if not isinstance(exc, Warning):
        return None
    granted = getattr(exc, "new_scope", None)
    if isinstance(granted, str):
        granted = granted.split()
    if not isinstance(granted, (list, tuple, set, frozenset)):
        return None
    return frozenset(scope for scope in granted if isinstance(scope, str))


def _consent_missing_scopes(exc: Exception, scopes: tuple[str, ...]) -> list[str]:
    """This run's scopes that oauthlib's scope-change Warning says were not granted; empty for any other error."""
    granted = _consent_grant(exc)
    if granted is None:
        return []
    return sorted(set(scopes) - granted)


def _narrow_cached_grant(
    token_cache: Path, raw: str | None, cached: Any, granted: frozenset[str] | None
) -> tuple[str | None, Any]:
    """Keep in the cache's recorded grant only scopes the token endpoint has just granted (never wider).

    Called after a refresh the endpoint refused or granted narrower, and after a consent that declined a scope, so a
    scope Google refused is neither sent on the next refresh nor claimed by a later outage fallback until a consent
    grants it. An older cache that records no grant proves nothing, so it is recorded as granting nothing. The cache is
    rewritten only while it still holds exactly what this run read (another run may have saved a newer one meanwhile),
    and only when the record changes. The re-read, the comparison and the replace all run under the cache's exclusive
    lock, which every rewrite of the cache takes, so no other run's write can land between them. A lock not obtained in
    time leaves the cache as it is. Returns the cache text and object now on disk.
    """
    if raw is None or granted is None or not isinstance(cached, dict):
        return raw, cached
    narrowed = sorted((_recorded_grant(cached) or frozenset()) & granted)
    if cached.get(VERIFIED_SCOPES_KEY) == narrowed:
        return raw, cached
    with secret_file_lock(token_cache) as locked:
        if not locked or secure_read_text(token_cache) != raw:
            return raw, cached
        updated = {**cached, VERIFIED_SCOPES_KEY: narrowed}
        text = json.dumps(updated)
        secure_write_text(token_cache, text, mode=0o600)
    return text, updated


def _can_refresh(credentials: Any) -> bool:
    """Whether the cached credentials hold every field a refresh needs (decided locally, before any refresh)."""
    return all(getattr(credentials, field, None) for field in _REFRESH_FIELDS)


def _is_grant_error(exc: Exception) -> bool:
    """Whether a failed refresh means the user must consent again (matched only; the text is never kept).

    google-auth raises ``RefreshError(details, response_data)`` for a token endpoint error; only the parsed OAuth
    ``error`` field decides, never a word in the description or an unparsed body. A one-argument error (a plain-text
    endpoint body, or google-auth's own text) is never a grant error: missing local fields are found by
    :func:`_can_refresh` before the refresh.
    """
    if getattr(exc, "retryable", False):
        return False
    args = getattr(exc, "args", ())
    if len(args) > 1 and isinstance(args[1], Mapping):
        code = args[1].get("error")
        return isinstance(code, str) and code in _GRANT_ERRORS
    return False


def _grant(credentials: Any) -> set[str]:
    """The scopes the last refresh or consent granted.

    Google reports the grant in the token response's ``scope`` field, which RFC 6749 (5.1) lets it leave out when
    the grant is exactly the scopes the request asked for; google-auth then sets no ``granted_scopes``, so the scopes
    asked for are the grant. A refresh asking for a scope never granted fails.
    """
    granted = getattr(credentials, "granted_scopes", None)
    if granted is None:
        granted = getattr(credentials, "scopes", None)
    return {str(scope) for scope in granted or ()}


def granted_scopes(credentials: Any) -> frozenset[str]:
    """The scopes the credentials' last refresh or consent granted (see :func:`_grant`); empty when unknown."""
    try:
        return frozenset(_grant(credentials))
    except Exception:  # noqa: BLE001 - an unreadable grant proves no scope
        return frozenset()


def _granted(credentials: Any, scopes: tuple[str, ...]) -> bool:
    """Whether the last refresh granted every scope this run asks for."""
    granted = _grant(credentials)
    return bool(granted) and set(scopes).issubset(granted)


def _recorded_grant(cached: Mapping[str, Any]) -> frozenset[str] | None:
    """The grant recorded in the token cache; ``None`` for an older cache that records none.

    A recorded value that is not a non-empty list of scope tokens (null, a string, a number, a mapping, an empty list, a
    list holding anything else: a non-string, or a string that is not an RFC 6749 section 3.3 scope-token, such as an
    empty string, one with whitespace, a control character, DEL, a double quote, a backslash or a non-ASCII character)
    proves nothing, so it grants nothing: an empty set, whatever else the list holds.
    """
    if VERIFIED_SCOPES_KEY not in cached:
        return None
    recorded = cached.get(VERIFIED_SCOPES_KEY)
    if not isinstance(recorded, list) or not recorded:
        return frozenset()
    if not all(isinstance(scope, str) and _SCOPE_TOKEN.fullmatch(scope) for scope in recorded):
        return frozenset()
    return frozenset(recorded)


def _cache_covers(cached: Mapping[str, Any], recorded: frozenset[str] | None, scopes: tuple[str, ...]) -> bool:
    """Whether the token cache may stand in for this run's sign-in (decided before any refresh).

    A cache that records its grant covers the run when that grant holds every scope the run needs; one that does not
    (or whose record proves nothing) signs in again, so a scope the user declined or an earlier consent never granted
    is not asked for on refresh. An older cache that records no grant keeps the earlier rule: the scopes it asked for
    must include every scope the run needs, and the refresh then proves the grant.
    """
    if recorded is not None:
        return bool(recorded) and set(scopes).issubset(recorded)
    asked = cached.get("scopes")
    if isinstance(asked, str):
        asked = asked.split(" ")
    if not isinstance(asked, list) or not all(isinstance(scope, str) for scope in asked):
        return False
    return set(scopes).issubset(asked)


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
    except OSError as exc:
        # The OS message names the file ("[Errno 2] ...: '/home/...'"); this summary is written into the run bundle,
        # so it keeps only the reason, never the operator's path.
        return {"present": path.expanduser().exists(), "error": exc.strerror or type(exc).__name__}
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError: the message holds a position, not a path
        return {"present": True, "error": str(exc)}
    return {
        "present": True,
        "type": payload.get("type"),
        "project_id": payload.get("project_id"),
        "client_email": payload.get("client_email"),
        "client_id": payload.get("client_id"),
    }
