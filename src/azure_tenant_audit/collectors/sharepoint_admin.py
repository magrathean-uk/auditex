"""Opt-in SharePoint admin tenant settings for MS.SHAREPOINT 1.2, 2.1, 2.2 and 3.1-3.3.

Graph's ``/admin/sharepoint/settings`` does not carry the OneDrive sharing level, the default link type and
permission, the anonymous link expiry and types or the email attestation settings. SharePoint's admin API does:
one ``GET https://<tenant>-admin.sharepoint.com/_api/SPO.Tenant`` (pinned from ScubaGear's API catalogue,
``Get-SharePointAdminApiEndpoint`` and ``Get-SPOTenantRest``). ``<tenant>`` is the prefix of the tenant's current
SharePoint host, ``siteCollection.hostname`` of its root site in the tenant's own Graph answer (``GET /sites/root``),
never guessed. The initial ``onmicrosoft.com`` domain is never used: it does not change when SharePoint is renamed.

Tokens (Microsoft Learn, "SharePoint admin APIs authentication and authorization"): app-only needs the SharePoint
application permission Sites.FullControl.All and a certificate; the reader app's certificate mints the token
(DEC-107), and a client without one records a named skip and requests nothing. The permission is write-capable;
this collector makes only the one pinned GET, checked by the read guard before it is sent.

The collector is in no profile or preset: only an explicit ``--collectors sharepoint_admin`` selects it.
"""
from __future__ import annotations

import base64
import json
import math
import time
from collections.abc import Callable
from typing import Any

import requests

from ..adapters.read_guard import (
    SHAREPOINT_ADMIN_ACCEPT,
    SHAREPOINT_ADMIN_HOST_SUFFIX,
    SHAREPOINT_ADMIN_METHOD,
    RequestRefused,
    check_sharepoint_admin_request,
    sharepoint_admin_host,
)
from ..collection_gaps import SECTION_SCOPED
from ..graph import GraphError
from ..versioning import package_user_agent
from .base import (
    Collector,
    CollectorResult,
    _classify_graph_error,
)

OPERATION = "tenantSettings"
ROOT_SITE_OPERATION = "rootSite"
ROOT_SITE_ENDPOINT = "/sites/root"
# Read-only Graph permission for the root site read; already in the default set.
ROOT_SITE_SCOPE = "Sites.Read.All"
TENANT_PATH = "/_api/SPO.Tenant"
# The ledger and coverage name the host by its template: the real host carries the tenant's name.
HOST_TEMPLATE = "{tenant}" + SHAREPOINT_ADMIN_HOST_SUFFIX
ENDPOINT_TEMPLATE = f"https://{HOST_TEMPLATE}{TENANT_PATH}"
# Only the commercial and GCC clouds reach discovery (other environments are a named skip first); both host
# SharePoint under sharepoint.com.
SHAREPOINT_HOST_SUFFIX = ".sharepoint.com"
# Hosts that are SharePoint but never a tenant's root site collection.
_NON_ROOT_PREFIX_SUFFIXES = ("-admin", "-my")
SHAREPOINT_RESOURCE_APP_ID = "00000003-0000-0ff1-ce00-000000000000"
# App-only (client credentials) asks for the resource's .default.
APP_SCOPE_SUFFIX = "/.default"
SHAREPOINT_ADMIN_FIELDS = (
    "ODBSharingCapability",
    "DefaultSharingLinkType",
    "DefaultLinkPermission",
    "RequireAnonymousLinksExpireInDays",
    "FileAnonymousLinkType",
    "FolderAnonymousLinkType",
    "EmailAttestationRequired",
    "EmailAttestationReAuthDays",
)

MAX_RESPONSE_BYTES = 1024 * 1024
OPERATION_DEADLINE_SECONDS = 60.0
CONNECT_TIMEOUT_SECONDS = 10.0
READ_TIMEOUT_SECONDS = 30.0
MAX_RETRY_AFTER_SECONDS = 30.0
_RETRY_STATUSES = frozenset({429, 503})

# Named skips: nothing is requested from SharePoint. The second-sign-in and token-unavailable reasons are written
# only by older bundles from the removed sign-in ways; they stay so those bundles still render.
REASON_CERTIFICATE_REQUIRED = "sharepoint_admin_certificate_required"
REASON_SECOND_SIGN_IN_REQUIRED = "sharepoint_admin_second_sign_in_required"
REASON_TOKEN_UNAVAILABLE = "sharepoint_admin_token_unavailable"
REASON_HOST_UNRESOLVED = "sharepoint_admin_host_unresolved"
REASON_UNSUPPORTED_ENVIRONMENT = "sharepoint_admin_unsupported_environment"
SKIP_TEXT = {
    REASON_CERTIFICATE_REQUIRED: (
        "not collected: the SharePoint admin settings need an app token from the reader app's certificate; "
        "no SharePoint token was requested"
    ),
    REASON_SECOND_SIGN_IN_REQUIRED: (
        "not collected: the run's one sign-in cannot give a SharePoint admin token without a second prompt "
        "(AllSites.FullControl not consented, or conditional access asks again); Auditex signs in once per run, "
        "so no second sign-in was opened"
    ),
    REASON_TOKEN_UNAVAILABLE: (
        "not collected: this authentication mode cannot mint a SharePoint admin token; use app-only certificate "
        "authentication or a delegated sign-in"
    ),
    REASON_HOST_UNRESOLVED: (
        "not collected: the tenant's Graph root site answer names no usable SharePoint host (siteCollection.hostname "
        "under sharepoint.com), so the SharePoint admin host is not known and was not guessed; the initial "
        "onmicrosoft.com domain is not used because it does not follow a SharePoint rename"
    ),
    REASON_UNSUPPORTED_ENVIRONMENT: (
        "not collected: the SharePoint admin read is pinned to the commercial and GCC admin host "
        "(<tenant>-admin.sharepoint.com)"
    ),
}
# Failures carry a fixed text: never a response body, header, token or vendor diagnostic. ``reason`` keeps the precise
# code; ``error_class`` is its class from the engine's collector error vocabulary (scuba_assessment.COLLECTOR_ERROR_CLASSES).
ERROR_CLASS_BY_REASON = {
    "sharepoint_admin_token_failed": "unauthenticated",
    "sharepoint_admin_token_refused": "unauthenticated",
    "sharepoint_admin_unauthenticated": "unauthenticated",
    "sharepoint_admin_access_denied": "insufficient_permissions",
    "sharepoint_admin_throttled": "service_not_available",
    "redirect_refused": "client_error",
    "resource_not_found": "resource_not_found",
    "sharepoint_admin_http_error": "client_error",
    "unexpected_shape": "incomplete_evidence",
    "response_too_large": "incomplete_evidence",
    "timeout": "service_not_available",
    "transport_error": "service_not_available",
    "request_refused": "command_refused",
}
FAILURE_TEXT = {
    "sharepoint_admin_token_failed": "SharePoint admin token could not be acquired from the certificate credential.",
    "sharepoint_admin_token_refused": "The token is not a SharePoint admin token of the expected kind; it was not sent.",
    "sharepoint_admin_unauthenticated": "SharePoint did not accept the token for the admin read (HTTP 401).",
    "sharepoint_admin_access_denied": "SharePoint refused the admin read (HTTP 403).",
    "sharepoint_admin_throttled": "SharePoint throttled the admin read and the retry did not succeed.",
    "redirect_refused": "SharePoint answered with a redirect; redirects are not followed.",
    "resource_not_found": "SharePoint answered HTTP 404 for the admin read.",
    "sharepoint_admin_http_error": "SharePoint answered the admin read with an unexpected HTTP status.",
    "unexpected_shape": "SharePoint's admin answer was not the expected tenant settings object.",
    "response_too_large": "SharePoint's admin answer exceeded the size limit.",
    "timeout": "The SharePoint admin read did not finish in time.",
    "transport_error": "The SharePoint admin read failed in transport.",
    "request_refused": "The read guard refused the SharePoint admin request; nothing was sent.",
}


HOST_UNKNOWN_TEXT = "The SharePoint admin read did not run: the Graph root site read failed."


def root_site_prefix(site: Any) -> str | None:
    """The tenant prefix of ``siteCollection.hostname`` in a Graph ``/sites/root`` answer, else None.

    The hostname must be ``<prefix>.sharepoint.com`` with a plain prefix (one DNS label, no port, path or trailing
    dot) that is not itself an admin or OneDrive host; anything else is inconclusive and nothing is derived.
    """
    collection = site.get("siteCollection") if isinstance(site, dict) else None
    hostname = collection.get("hostname") if isinstance(collection, dict) else None
    if not isinstance(hostname, str):
        return None
    name = hostname.lower()
    if not name.endswith(SHAREPOINT_HOST_SUFFIX):
        return None
    prefix = name[: -len(SHAREPOINT_HOST_SUFFIX)]
    if prefix.endswith(_NON_ROOT_PREFIX_SUFFIXES):
        return None
    return prefix if sharepoint_admin_host(prefix) else None


def _claims(token: Any) -> dict[str, Any]:
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (AttributeError, IndexError, ValueError, TypeError, RecursionError):
        return {}
    return claims if isinstance(claims, dict) else {}


def token_fits(token: Any, origin: str) -> bool:
    """Audience and credential gate before a token goes to the admin host; the service validates the signature.

    The audience must be the admin origin or the SharePoint resource, so a Graph token is never sent there. The token
    must come from a certificate (v1 ``appidacr`` or v2 ``azpacr`` ``"2"``) with no ``scp``.
    """
    claims = _claims(token)
    if claims.get("aud") not in {origin, origin + "/", SHAREPOINT_RESOURCE_APP_ID}:
        return False
    return claims.get("azpacr", claims.get("appidacr")) == "2" and not claims.get("scp")


def _read_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": SHAREPOINT_ADMIN_ACCEPT, "User-Agent": package_user_agent()}


def _send(session: Any, url: str, headers: dict[str, str], timeout: tuple[float, float]) -> Any:
    """The module's only network call: the read guard first, then the pinned body-free GET without redirects."""
    check_sharepoint_admin_request(SHAREPOINT_ADMIN_METHOD, url, headers=headers)
    return session.get(url, headers=headers, timeout=timeout, allow_redirects=False, stream=True)


def _retry_after(value: Any) -> float | None:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return min(MAX_RETRY_AFTER_SECONDS, max(0.0, seconds)) if math.isfinite(seconds) else None


def _body(response: Any, deadline: float, monotonic: Callable[[], float]) -> tuple[bytes | None, str | None]:
    body = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if monotonic() >= deadline:
                return None, "timeout"
            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                return None, "response_too_large"
            body.extend(chunk)
    except requests.Timeout:
        return None, "timeout"
    except Exception:  # noqa: BLE001 - transport messages can carry request material
        return None, "transport_error"
    return bytes(body), None


def parse_tenant_settings(body: bytes, content_type: Any, token: str) -> dict[str, Any]:
    """The eight settings from an ``odata=verbose`` SPO.Tenant answer (``{"d": {...}}``); ValueError otherwise."""
    if str(content_type or "").split(";", 1)[0].strip().lower() != "application/json":
        raise ValueError("unexpected_shape")
    text = body.decode("utf-8-sig")
    if "\x00" in text:
        raise ValueError("unexpected_shape")
    parsed = json.loads(text)
    tenant = parsed.get("d") if isinstance(parsed, dict) else None
    if not isinstance(tenant, dict) or "error" in parsed or "error" in tenant or "odata.error" in parsed:
        raise ValueError("unexpected_shape")
    row: dict[str, Any] = {}
    for name in SHAREPOINT_ADMIN_FIELDS:
        if name not in tenant:
            continue
        value = tenant[name]
        if value is not None and type(value) not in (bool, int, str):
            raise ValueError("unexpected_shape")
        row[name] = value
    if not row:
        raise ValueError("unexpected_shape")
    # A credential echoed by a service must never enter raw evidence.
    if token and token in json.dumps(row):
        raise ValueError("unexpected_shape")
    return row


def read_tenant_settings(
    session: Any,
    url: str,
    token: str,
    *,
    log_event: Callable[[str, str, dict[str, Any] | None], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """One guarded GET of SPO.Tenant, retried once on 429 or 503; ``{"row": ...}`` or ``{"reason": ...}``."""
    monotonic = monotonic or time.monotonic
    sleep = sleep or time.sleep
    started = monotonic()
    deadline = started + OPERATION_DEADLINE_SECONDS
    headers = _read_headers(token)
    for attempt in range(2):
        remaining = deadline - monotonic()
        if remaining <= 0:
            return {"reason": "timeout"}
        sent = monotonic()
        status: int | None = None
        response = None
        refused = False
        try:
            response = _send(session, url, headers, (CONNECT_TIMEOUT_SECONDS, min(READ_TIMEOUT_SECONDS, remaining)))
            status = response.status_code
            body, error = _body(response, deadline, monotonic) if status == 200 else (b"", None)
            response_headers = response.headers
        except RequestRefused as exc:
            refused = True
            if log_event:
                log_event("sharepoint_admin_rest.refused", "Refused a SharePoint admin request that is not the pinned read",
                          {"method": SHAREPOINT_ADMIN_METHOD, "host": HOST_TEMPLATE, "path": TENANT_PATH, "reason": exc.reason})
            return {"reason": "request_refused"}
        except requests.Timeout:
            body, error, response_headers = None, "timeout", {}
        except Exception:  # noqa: BLE001 - transport messages can carry request material
            body, error, response_headers = None, "transport_error", {}
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:  # noqa: BLE001,S110 - cleanup diagnostics can carry request material
                    pass
            if log_event and not refused:
                log_event("sharepoint_admin_rest.request", "SharePoint admin tenant settings GET", {
                    "method": SHAREPOINT_ADMIN_METHOD, "host": HOST_TEMPLATE, "path": TENANT_PATH,
                    "status_code": status, "attempt": attempt + 1,
                    "duration_ms": round((monotonic() - sent) * 1000, 2),
                })
        if error:
            return {"reason": error}
        if status in _RETRY_STATUSES and attempt == 0:
            delay = _retry_after(response_headers.get("Retry-After"))
            delay = 1.0 if delay is None else delay
            if delay >= deadline - monotonic():
                return {"reason": "sharepoint_admin_throttled"}
            sleep(delay)
            continue
        if status in _RETRY_STATUSES:
            return {"reason": "sharepoint_admin_throttled"}
        if status == 401:
            return {"reason": "sharepoint_admin_unauthenticated"}
        if status == 403:
            return {"reason": "sharepoint_admin_access_denied"}
        if status is not None and 300 <= status < 400:
            return {"reason": "redirect_refused"}
        if status == 404:
            return {"reason": "resource_not_found"}
        if status != 200:
            return {"reason": "sharepoint_admin_http_error"}
        try:
            return {"row": parse_tenant_settings(body or b"", response_headers.get("Content-Type"), token)}
        except (ValueError, UnicodeError, RecursionError):
            return {"reason": "unexpected_shape"}
    return {"reason": "sharepoint_admin_throttled"}


def _environment(context: dict[str, Any]) -> str | None:
    manifest = context.get("manifest") or {}
    value = context.get("environment") or context.get("m365_environment") or manifest.get("environment")
    return str(value) if value else None


class SharePointAdminCollector(Collector):
    name = "sharepoint_admin"
    description = (
        "Opt-in SharePoint admin tenant settings (SPO.Tenant): OneDrive sharing, default link type and permission, "
        "anonymous link expiry and types, email attestation."
    )
    # The Graph scope is the read-only root site read that names the SharePoint host. The SharePoint permission
    # (Sites.FullControl.All, app-only) is on the SharePoint resource, not Microsoft Graph.
    required_permissions: list[str] = [ROOT_SITE_SCOPE]
    session_factory: Callable[[], Any] = requests.Session

    def _token_plan(self, client: Any) -> tuple[str | None, str | None]:
        """("app", None) when the client has the certificate, else (None, skip reason); decided before any call."""
        auth = getattr(client, "auth", None)
        if getattr(auth, "certificate", None) is not None:
            return "app", None
        return None, REASON_CERTIFICATE_REQUIRED

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        log_event = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        started = time.monotonic()

        def finish(section: dict[str, Any]) -> CollectorResult:
            row: dict[str, Any] = {
                "collector": self.name,
                "type": "sharepoint_admin_rest",
                "method": SHAREPOINT_ADMIN_METHOD,
                "endpoint": ENDPOINT_TEMPLATE,
                "name": OPERATION,
                "status": section["status"],
                "item_count": len(section["value"]),
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
                "error_class": section.get("error_class"),
                "error": section.get("error"),
            }
            if section.get("reason"):
                row["reason"] = section["reason"]
            if section["status"] == "skipped":
                row[SECTION_SCOPED] = True
            coverage.append(row)
            failed = any(item["status"] == "failed" for item in coverage)
            message = SKIP_TEXT[section["reason"]] if section["status"] == "skipped" else (
                "SharePoint admin collection partially completed" if failed else "")
            return CollectorResult(name=self.name, status="partial" if failed else "ok", payload={OPERATION: section},
                                   item_count=len(section["value"]), message=message, coverage=coverage)

        def skipped(reason: str) -> CollectorResult:
            # A named skip, not an error: the reason names it and no error class is claimed.
            return finish({"value": [], "status": "skipped", "reason": reason, SECTION_SCOPED: True,
                           "error": SKIP_TEXT[reason]})

        def failed(reason: str, error_class: str | None = None) -> CollectorResult:
            return finish({"value": [], "status": "failed", "reason": reason,
                           "error_class": error_class or ERROR_CLASS_BY_REASON[reason],
                           "error": FAILURE_TEXT.get(reason, HOST_UNKNOWN_TEXT)})

        environment = _environment(context)
        if environment and environment not in {"commercial", "gcc"}:
            return skipped(REASON_UNSUPPORTED_ENVIRONMENT)
        mode, reason = self._token_plan(client)
        if mode is None:
            return skipped(reason or REASON_TOKEN_UNAVAILABLE)

        read_started = time.monotonic()
        root_site_row: dict[str, Any] = {
            "collector": self.name, "type": "graph", "name": ROOT_SITE_OPERATION, "endpoint": ROOT_SITE_ENDPOINT,
            "api_version": "v1.0", "status": "ok", "item_count": 0,
        }
        coverage.append(root_site_row)
        try:
            # The root site names the tenant's current SharePoint host, so a renamed tenant resolves to its new name.
            site = client.get_json("/sites/root", params={"$select": "siteCollection"})
        except (GraphError, ValueError) as exc:
            error_class, _ = _classify_graph_error(exc)
            root_site_row.update(status="failed", error_class=error_class,
                                 error="The Graph root site read failed; the SharePoint admin host is unknown.",
                                 duration_ms=round((time.monotonic() - read_started) * 1000, 2))
            # The admin read inherits the root site read's class; its own reason says it never ran.
            return failed("sharepoint_admin_host_unknown", error_class)
        prefix = root_site_prefix(site)
        root_site_row.update(item_count=1 if prefix else 0,
                             duration_ms=round((time.monotonic() - read_started) * 1000, 2))
        if prefix is None:
            return skipped(REASON_HOST_UNRESOLVED)
        origin = f"https://{sharepoint_admin_host(prefix)}"

        try:
            token = client.app_token_for(origin + APP_SCOPE_SUFFIX)
        except Exception:  # noqa: BLE001 - token errors can carry credential material
            token = None
        if not token:
            return failed("sharepoint_admin_token_failed")
        if not token_fits(token, origin):
            return failed("sharepoint_admin_token_refused")

        session = self.session_factory()
        try:
            result = read_tenant_settings(session, origin + TENANT_PATH, token, log_event=log_event)
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001,S110 - cleanup diagnostics can carry request material
                pass
        if "row" not in result:
            return failed(result["reason"])
        return finish({"value": [result["row"]], "status": "ok", "item_count": 1})
