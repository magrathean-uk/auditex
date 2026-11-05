"""Allowlisted Teams policy GETs; credentials and response diagnostics stay private."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import socket
import time
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
}
TEAMS_FIELDS = {name: tuple(fields) for name, fields in TEAMS_REQUIRED_FIELDS.items()}
TEAMS_FIELDS["tenantFederationConfiguration"] += ("AllowPublicUsers", "BlockedDomains")


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


def _rows(parsed, operation):
    if not isinstance(parsed, dict) or "error" in parsed:
        raise ValueError("unexpected_shape")
    if "value" in parsed:
        rows = parsed["value"]
    else:
        rows = [parsed]
    # Both configurations are singletons; each policy family includes Global.
    # None of these five operations can legitimately return no rows.
    if not isinstance(rows, list) or not rows:
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
    if transport internals expose no socket, the worker may remain until the peer
    stops sending plus the socket inactivity timeout (at most 30 seconds). It
    holds the token in memory only.
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
            seconds = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            seconds = 1.0
    return min(60.0, max(0.0, seconds)) if math.isfinite(seconds) else 1.0


class TeamsAdminRestAdapter(Adapter):
    metadata = AdapterMetadata("teams_admin_rest", ("app",), ())

    def dependency_check(self):
        return True

    def get(self, operation, token, environment, log_event=None):
        if operation not in TEAMS_READ_PATHS:
            raise ValueError("Teams operation is not allowlisted")
        if environment not in TEAMS_ADMIN_BASE:
            return {"error": "unsupported_environment", "error_class": "unsupported_environment"}
        if not certificate_token(token):
            return {"error": "teams_token_unavailable", "error_class": "command_not_authenticated"}
        path = TEAMS_READ_PATHS[operation]
        base = TEAMS_ADMIN_BASE[environment]
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
