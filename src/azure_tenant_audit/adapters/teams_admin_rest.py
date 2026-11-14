"""Allowlisted Teams policy GETs; credentials and response diagnostics stay private."""
from __future__ import annotations

import base64
import json
import math
import socket
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from threading import Event, Thread
from urllib.parse import urlsplit

import requests

from .base import Adapter, AdapterMetadata

TEAMS_ADMIN_SCOPE = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
TEAMS_ADMIN_BASE = {
    "commercial": "https://api.interfaces.records.teams.microsoft.com",
    "gcc": "https://api.interfaces.records.teams.microsoft.com",
}
TEAMS_READ_PATHS = {
    "meetingPolicies": "/Skype.Policy/configurations/TeamsMeetingPolicy",
    "tenantFederationConfiguration": "/Skype.Policy/configurations/TenantFederationSettings",
    "clientConfiguration": "/Skype.Policy/configurations/TeamsClientConfiguration",
    "appPermissionPolicies": "/Skype.Policy/configurations/TeamsAppPermissionPolicy",
    "broadcastPolicies": "/Skype.Policy/configurations/TeamsMeetingBroadcastPolicy",
}
# Org-wide unified app settings (the source of Get-M365UnifiedTenantSettings): a separate host and token
# audience, pinned from ScubaGear's API catalogue (Get-TeamsM365UnifiedTenantSettingsRest and
# Get-TeamsUnifiedApiEndpoint). Microsoft serves it to a user sign-in only, so an app-only run never calls it.
TEAMS_UNIFIED_SCOPE = "08ff1ce2-4973-4b08-86a3-ebed13badc7f/.default"
TEAMS_UNIFIED_BASE = {
    "commercial": "https://substrate.office.com",
    "gcc": "https://substrate.office.com",
}
TEAMS_UNIFIED_READ_PATHS = {
    "tenantAppSettings": "/AdminAppCatalog/ps/v2/admin/unifiedApp/settings",
}
_TEAMS_UNIFIED_AUDIENCES = frozenset({TEAMS_UNIFIED_SCOPE.removesuffix("/.default"), "https://substrate.office.com"})


# Bounds apply to each operation, including both attempts and error bodies.
TEAMS_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TEAMS_OPERATION_DEADLINE_SECONDS = 90.0
TEAMS_MAX_JSON_DEPTH = 32

# Explicit REST retention; PowerShell selects are a separate contract. Optional
# federation fields below are consumed by normalisation, not the rule adapters.
TEAMS_REQUIRED_FIELDS = {
    "meetingPolicies": {
        "Identity": str, "AllowCloudRecording": bool,
        "AllowExternalParticipantGiveRequestControl": bool,
        "AllowAnonymousUsersToStartMeeting": bool, "AutoAdmittedUsers": str,
        "AllowPSTNUsersToBypassLobby": bool,
    },
    "tenantFederationConfiguration": {
        "Identity": str, "AllowFederatedUsers": bool, "AllowTeamsConsumer": bool,
        "AllowTeamsConsumerInbound": bool, "AllowedDomains": (str, dict, list),
    },
    "clientConfiguration": {"Identity": (str, type(None)), "AllowEmailIntoChannel": bool},
    "appPermissionPolicies": {
        "Identity": str, "DefaultCatalogAppsType": str,
        "GlobalCatalogAppsType": str, "PrivateCatalogAppsType": str,
    },
    "broadcastPolicies": {"Identity": str, "BroadcastRecordingMode": str},
    "tenantAppSettings": {"SettingName": str},
}
TEAMS_FIELDS = {name: tuple(fields) for name, fields in TEAMS_REQUIRED_FIELDS.items()}
TEAMS_FIELDS["tenantFederationConfiguration"] += ("AllowPublicUsers", "BlockedDomains")
# The rules read SettingValue and judge a missing or non-string one themselves; Users and Groups are never kept.
TEAMS_FIELDS["tenantAppSettings"] += ("SettingValue",)
# Operations whose answer may be a bare JSON array and may be empty (no org-wide setting configured).
_LIST_OPERATIONS = frozenset(TEAMS_UNIFIED_READ_PATHS)


def certificate_token(token):
    """Credential-type gate only; the Teams service validates the token signature.

    Entra v1 appidacr and v2 azpacr identify certificate credentials as '2'.
    Unknown, opaque, delegated and secret-auth tokens fail closed.
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        credential = claims.get("azpacr", claims.get("appidacr"))
        return (credential == "2" and not claims.get("scp")
                and claims.get("aud") == TEAMS_ADMIN_SCOPE.removesuffix("/.default"))
    except (AttributeError, IndexError, ValueError, TypeError, RecursionError):
        return False


def unified_settings_token(token):
    """Audience gate for the unified app-settings host: no Teams admin or Graph token is ever sent there."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return claims.get("aud") in _TEAMS_UNIFIED_AUDIENCES
    except (AttributeError, IndexError, ValueError, TypeError, RecursionError):
        return False


def _rows(parsed, operation):
    if operation in _LIST_OPERATIONS and isinstance(parsed, list):
        rows = parsed
    elif not isinstance(parsed, dict) or "error" in parsed:
        raise ValueError("unexpected_shape")
    elif "value" in parsed:
        rows = parsed["value"]
    elif operation in _LIST_OPERATIONS:
        raise ValueError("unexpected_shape")
    else:
        rows = [parsed]
    # Both configurations are singletons; each policy family includes Global, so none of
    # those five operations can legitimately return no rows. Unified settings may be empty.
    if not isinstance(rows, list) or not rows and operation not in _LIST_OPERATIONS:
        raise ValueError("unexpected_shape")
    for row in rows:
        if not isinstance(row, dict) or "error" in row:
            raise ValueError("unexpected_shape")
        for field, kind in TEAMS_REQUIRED_FIELDS[operation].items():
            if field not in row or not isinstance(row[field], kind):
                raise ValueError("unexpected_shape")
            if kind is str and not row[field].strip():
                raise ValueError("unexpected_shape")
    return rows


def _check_json_depth(body):
    # Scan before json.loads, without recursion, respecting escaped string quotes.
    depth = 0
    quoted = escaped = False
    for char in body:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > TEAMS_MAX_JSON_DEPTH:
                raise ValueError("unexpected_shape")
        elif char in "]}":
            depth -= 1


def _close_response(response):
    try:
        response.close()
    except Exception:
        # Cleanup diagnostics can also contain credentials.
        pass


def _shutdown_response(response):
    # close() can wait on BufferedReader's in-flight read lock. Socket shutdown
    # interrupts recv without taking that lock; the worker owns response.close().
    for path in (("raw", "connection", "sock"), ("raw", "_connection", "sock"),
                 ("raw", "_fp", "fp", "raw", "_sock")):
        try:
            connection_socket = response
            for attribute in path:
                connection_socket = getattr(connection_socket, attribute)
            connection_socket.shutdown(socket.SHUT_RDWR)
            return
        except Exception:
            # Missing, already closed or changed transport internals are private.
            pass


def _read_attempt(url, token, deadline, max_bytes, state):
    """Bound caller latency even while requests is blocked on headers or a chunk.

    requests' socket timeout is an inactivity timeout. A daemon owns the response
    so a blocked call cannot hold the operation open. Cancellation withholds its
    result and shuts down an accessible response socket to interrupt body reads;
    the worker closes even a response returned after expiry. Before headers, or
    if transport internals expose no socket, the worker may remain for as long as
    the peer keeps sending, then up to the 30-second socket inactivity timeout;
    it holds the token in memory only.
    No logging or evidence writes happen in the worker.
    """
    completed, cancelled = Event(), Event()

    def read():
        response = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or cancelled.is_set():
                state["error"] = "timeout"
                return
            response = requests.get(
                url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=min(30.0, remaining), allow_redirects=False, stream=True,
            )
            state["response"] = response
            state["status"] = response.status_code
            body = bytearray()
            if cancelled.is_set() or time.monotonic() >= deadline:
                state["error"] = "timeout"
                return
            # iter_content yields decoded (including gzip/deflate) bytes. Neither
            # Content-Length nor compressed wire size is a trustworthy body cap.
            for chunk in response.iter_content(chunk_size=1024):
                if cancelled.is_set() or time.monotonic() >= deadline:
                    state["error"] = "timeout"
                    return
                if len(body) + len(chunk) > max_bytes:
                    state["error"] = "response_too_large"
                    return
                body.extend(chunk)
            state["body"] = body
            state["headers"] = response.headers
        except requests.Timeout:
            state["error"] = "timeout"
        except requests.RequestException:
            state["error"] = "command_error"
        except Exception:
            state["error"] = "command_error"
        finally:
            try:
                if response is not None:
                    _close_response(response)
            finally:
                completed.set()

    Thread(target=read, name="teams-policy-read", daemon=True).start()
    if not completed.wait(max(0.0, deadline - time.monotonic())) or time.monotonic() >= deadline:
        cancelled.set()
        response = state.get("response")
        if response is not None:
            _shutdown_response(response)
        return "timeout"
    return state.get("error")


def _retry_after(value):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        try:
            seconds = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            seconds = 1.0
    return min(60.0, max(0.0, seconds)) if math.isfinite(seconds) else 1.0


class TeamsAdminRestAdapter(Adapter):
    metadata = AdapterMetadata("teams_admin_rest", ("app",), ())

    def dependency_check(self):
        return True

    def get(self, operation, token, environment, log_event=None):
        if operation in TEAMS_READ_PATHS:
            bases, path, token_ok = TEAMS_ADMIN_BASE, TEAMS_READ_PATHS[operation], certificate_token
        elif operation in TEAMS_UNIFIED_READ_PATHS:
            bases, path, token_ok = TEAMS_UNIFIED_BASE, TEAMS_UNIFIED_READ_PATHS[operation], unified_settings_token
        else:
            raise ValueError("Teams operation is not allowlisted")
        if environment not in bases:
            return {"error": "unsupported_environment", "error_class": "unsupported_environment"}
        if not token_ok(token):
            return {"error": "teams_token_unavailable", "error_class": "command_not_authenticated"}
        base = bases[environment]
        started = time.monotonic()

        def finish(error_class):
            return {"error": error_class, "error_class": error_class,
                    "command": f"GET {path}", "duration_ms": (time.monotonic() - started) * 1000}

        deadline = started + TEAMS_OPERATION_DEADLINE_SECONDS
        remaining_bytes = TEAMS_MAX_RESPONSE_BYTES
        for attempt in range(2):
            if time.monotonic() >= deadline:
                return finish("timeout")
            sent = time.monotonic()
            state = {}
            try:
                error = _read_attempt(base + path, token, deadline, remaining_bytes, state)
            finally:
                if log_event:
                    log_event("teams_admin_rest.request", "Teams policy GET", {
                        "method": "GET", "host": urlsplit(base).hostname, "path": path,
                        "status_code": state.get("status"),
                        "duration_ms": (time.monotonic() - sent) * 1000,
                    })
            if error:
                return finish(error)
            body = state.get("body")
            if body is None:
                return finish("command_error")
            remaining_bytes -= len(body)
            status, headers = state["status"], state["headers"]
            if status == 429 and attempt == 0:
                delay = _retry_after(headers.get("Retry-After"))
                if delay >= deadline - time.monotonic():
                    return finish("timeout")
                time.sleep(delay)
                continue
            if status in (401, 403):
                return finish("command_not_authenticated")
            if status != 200:
                return finish("command_error")
            if headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                return finish("unexpected_shape")
            try:
                # Scan and parse the same UTF-8 text. NUL rejects BOM-less
                # UTF-16/32 that would otherwise decode as UTF-8 ASCII plus NULs.
                text = body.decode("utf-8-sig")
                if "\x00" in text:
                    return finish("unexpected_shape")
                _check_json_depth(text)
                parsed = json.loads(text)
                # One GET is authorised; never follow a page or store partial evidence.
                if isinstance(parsed, dict) and parsed.get("@odata.nextLink"):
                    return finish("command_error")
                rows = _rows(parsed, operation)
                filtered = [{key: value for key, value in row.items() if key in TEAMS_FIELDS[operation]}
                            for row in rows]
                # A credential echoed by a service must never enter raw evidence.
                if token in json.dumps(filtered):
                    return finish("unexpected_shape")
            except (ValueError, UnicodeError, RecursionError):
                return finish("unexpected_shape")
            if time.monotonic() >= deadline:
                return finish("timeout")
            return {"value": filtered, "status": "ok", "command": f"GET {path}",
                    "duration_ms": (time.monotonic() - started) * 1000}
