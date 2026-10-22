from __future__ import annotations

import logging
import random
import time
import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, Optional
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests.exceptions import RequestException

from .config import AuthConfig
from .versioning import package_user_agent


LOG = logging.getLogger(__name__)
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
# Beta is opt-in per endpoint: only surfaces without a v1.0 equivalent use it, and
# every beta call is recorded with api_version="beta" in coverage and the API ledger.
GRAPH_BETA_ROOT = "https://graph.microsoft.com/beta"
GRAPH_API_ROOTS = {"v1.0": GRAPH_ROOT, "beta": GRAPH_BETA_ROOT}
# Error code of a refused @odata.nextLink; the paging that stopped is recorded as a coverage gap.
NEXT_LINK_REFUSED = "NextLinkRefused"
# Error code of a request the client refused because it is not a read (see read_only_violation).
READ_ONLY_VIOLATION = "ReadOnlyViolation"
# Error code of a redirect the client refused to follow (a host that is not Microsoft, a loop, a downgrade).
REDIRECT_REFUSED = "RedirectRefused"
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 3
# The usage-report functions answer 302 to a short-lived pre-authenticated download URL. Only Microsoft-owned
# download hosts are followed, over HTTPS, and never with the bearer token.
_DOWNLOAD_HOST_SUFFIXES = (
    ".office.com",
    ".office.net",
    ".office365.com",
    ".microsoft.com",
    ".microsoftonline.com",
    ".sharepoint.com",
    ".azureedge.net",
    ".windows.net",
)
# The only methods the audit plane may send: GET, and POST solely to /$batch with GET-only inner requests.
READ_ONLY_METHODS = frozenset({"GET"})
_BATCH_ENVELOPE_KEYS = frozenset({"requests"})
_BATCH_INNER_KEYS = frozenset({"id", "method", "url", "headers", "dependsOn"})
_BODY_KWARGS = frozenset({"json", "data", "files"})
# Headers that make a server treat a GET or POST as another method; a read never needs them.
_METHOD_OVERRIDE_HEADERS = frozenset({"x-http-method-override", "x-http-method", "x-method-override"})


def graph_url(path: str, api_version: str = "v1.0") -> str:
    """Return the full Graph URL for ``path`` under the requested API version."""
    if path.startswith("http"):
        return path
    try:
        root = GRAPH_API_ROOTS[api_version]
    except KeyError as exc:
        raise ValueError(f"Unsupported Graph api_version: {api_version!r}") from exc
    return f"{root}{path}"


def graph_host_url(url: str) -> bool:
    """Whether url is an HTTPS URL on the Microsoft Graph host the client talks to."""
    if not isinstance(url, str):
        return False
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname == urlparse(GRAPH_ROOT).hostname


def redacted_url(url: str) -> str:
    """``scheme://host/path`` of a URL: the query of a pre-authenticated download URL is a credential."""
    parsed = urlparse(str(url))
    return f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}" if parsed.scheme else str(url).split("?", 1)[0]


def download_host_allowed(url: str) -> bool:
    """Whether a redirect target is an HTTPS URL on a Microsoft-owned download host."""
    parsed = urlparse(str(url))
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and any(host.endswith(suffix) for suffix in _DOWNLOAD_HOST_SUFFIXES)


def graph_api_version(url: str) -> str:
    """Infer the Graph API version from a path or full URL (relative paths are v1.0)."""
    if url.startswith(GRAPH_BETA_ROOT):
        return "beta"
    return "v1.0"
GRAPH_BATCH_CHUNK_SIZE = 20
TOKEN_URL_TEMPLATE = "{authority}{tenant_id}/oauth2/v2.0/token"


def graph_batch_url(url: Any) -> bool:
    """Whether url is exactly the Microsoft Graph ``/$batch`` endpoint (v1.0 or beta), with no query."""
    if not isinstance(url, str) or not graph_host_url(url):
        return False
    parsed = urlparse(url)
    return parsed.path in {"/v1.0/$batch", "/beta/$batch"} and not parsed.query and not parsed.params


def batch_inner_requests(kwargs: dict[str, Any]) -> list[dict[str, Any]] | None:
    """The inner requests of a ``$batch`` call, or None when the body is not a plain ``{"requests": [...]}``."""
    if set(kwargs) != {"json"}:
        return None
    body = kwargs.get("json")
    if not isinstance(body, dict) or set(body) != _BATCH_ENVELOPE_KEYS:
        return None
    inner = body.get("requests")
    if not isinstance(inner, list) or not all(isinstance(item, dict) for item in inner):
        return None
    return inner


def _override_header(headers: Any) -> str | None:
    if isinstance(headers, dict):
        for name in headers:
            if str(name).strip().lower() in _METHOD_OVERRIDE_HEADERS:
                return str(name)
    return None


def read_only_violation(method: Any, url: Any, kwargs: dict[str, Any]) -> str | None:
    """Why a request is not a read, or None when it may be sent.

    Allowed: ``GET`` without a body, and ``POST`` to ``/$batch`` whose inner requests are all
    relative ``GET`` calls without a body. Requests go only to https://graph.microsoft.com, so the
    bearer token never leaves it, and no method-override header may be set. Everything else is
    refused before any network call.
    """
    if not graph_host_url(url):
        return "requests may only go to https://graph.microsoft.com"
    override = _override_header(kwargs.get("headers"))
    if override:
        return f"the {override} header could turn a read into a write"
    verb = method.upper() if isinstance(method, str) else ""
    if verb in READ_ONLY_METHODS:
        if _BODY_KWARGS & set(kwargs):
            return "a GET request must not carry a body"
        return None
    if verb == "POST":
        if not graph_batch_url(url):
            return "POST is only allowed to the Microsoft Graph /$batch endpoint"
        inner = batch_inner_requests(kwargs)
        if inner is None:
            return "a $batch request must be a plain JSON body with a requests list"
        for item in inner:
            inner_method = item.get("method")
            if not isinstance(inner_method, str) or inner_method.upper() not in READ_ONLY_METHODS:
                return f"a $batch request contains a non-GET inner request ({inner_method!r})"
            inner_url = item.get("url")
            if not isinstance(inner_url, str) or not inner_url.startswith("/") or inner_url.startswith("//"):
                return "a $batch inner request must use a relative Graph path"
            if "body" in item or set(item) - _BATCH_INNER_KEYS:
                return "a $batch inner request must not carry a body"
            if _override_header(item.get("headers")):
                return "a $batch inner request must not set a method-override header"
        return None
    return f"{verb or repr(method)} is not a read method"


def _batch_summary(kwargs: dict[str, Any]) -> dict[str, Any]:
    inner = batch_inner_requests(kwargs) or []
    return {
        "size": len(inner),
        "methods": sorted({str(item.get("method", "")).upper() for item in inner}),
        "urls": [str(item.get("url", "")) for item in inner],
    }


@dataclass(frozen=True)
class ThrottlePolicy:
    min_delay_seconds: float
    jitter_seconds: float
    rate_limit_retries: int
    server_error_retries: int
    permission_stop_after: int
    base_backoff_seconds: float


THROTTLE_POLICIES: dict[str, ThrottlePolicy] = {
    "fast": ThrottlePolicy(
        min_delay_seconds=0.0,
        jitter_seconds=0.0,
        rate_limit_retries=3,
        server_error_retries=2,
        permission_stop_after=0,
        base_backoff_seconds=1.0,
    ),
    "safe": ThrottlePolicy(
        min_delay_seconds=0.2,
        jitter_seconds=0.1,
        rate_limit_retries=4,
        server_error_retries=3,
        permission_stop_after=2,
        base_backoff_seconds=1.5,
    ),
    "ultra-safe": ThrottlePolicy(
        min_delay_seconds=0.75,
        jitter_seconds=0.25,
        rate_limit_retries=5,
        server_error_retries=4,
        permission_stop_after=1,
        base_backoff_seconds=2.0,
    ),
}


class GraphError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        request: str | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.request = request
        self.error_code = error_code


@dataclass
class GraphClient:
    auth: AuthConfig
    session: requests.Session = field(default_factory=requests.Session)
    _token: Optional[str] = None
    audit_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None
    _next_request_not_before: float = field(default=0.0, init=False)
    _permission_failures: dict[str, int] = field(default_factory=dict, init=False)
    _token_claims: Optional[dict[str, Any]] = field(default=None, init=False)

    def _emit(self, event: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
        if self.audit_event is None:
            return
        try:
            self.audit_event(event, message, details)
        except Exception:  # noqa: BLE001
            LOG.exception("Failed to emit audit event.")

    @staticmethod
    def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
        copy = dict(payload)
        if "client_secret" in copy:
            copy["client_secret"] = "***redacted***"
        return copy

    @staticmethod
    def _params_overview(params: Optional[Dict[str, Any]]) -> dict[str, Any]:
        if not params:
            return {}
        return {key: params[key] for key in params.keys()}

    def _token_url(self) -> str:
        return TOKEN_URL_TEMPLATE.format(
            authority=self.auth.authority.rstrip("/") + "/",
            tenant_id=self.auth.tenant_id,
        )

    def _throttle_policy(self) -> ThrottlePolicy:
        return THROTTLE_POLICIES.get(self.auth.throttle_mode, THROTTLE_POLICIES["safe"])

    def _request_family(self, url: str) -> str:
        path = urlparse(url).path
        parts = [item for item in path.split("/") if item]
        if parts and parts[0] in {"v1.0", "beta"}:
            parts = parts[1:]
        # Two segments: /security/alerts_v2 and /security/secureScores need different permissions,
        # so a 403 on one must not stop the other.
        return "/".join(part.split("(", 1)[0] for part in parts[:2]) if parts else "root"

    def _apply_pacing(self, *, method: str, url: str, attempt: int) -> None:
        now = time.monotonic()
        if self._next_request_not_before <= now:
            return
        wait_seconds = round(self._next_request_not_before - now, 3)
        if wait_seconds <= 0:
            return
        self._emit(
            "graph.request.pacing",
            "Waiting before next Graph request",
            {
                "method": method,
                "url": url,
                "attempt": attempt,
                "delay_seconds": wait_seconds,
                "mode": self.auth.throttle_mode,
            },
        )
        time.sleep(wait_seconds)
        self._next_request_not_before = 0.0

    def _arm_next_request_delay(self) -> None:
        policy = self._throttle_policy()
        delay_seconds = policy.min_delay_seconds
        if policy.jitter_seconds > 0:
            delay_seconds += random.uniform(0.0, policy.jitter_seconds)
        self._next_request_not_before = time.monotonic() + delay_seconds

    def _retry_delay(self, attempt: int, *, retry_after: str | None = None) -> float:
        policy = self._throttle_policy()
        if retry_after:
            try:
                return max(float(retry_after), policy.base_backoff_seconds)
            except ValueError:
                pass
        return round(policy.base_backoff_seconds * (2 ** max(0, attempt - 1)), 2)

    def _authority(self) -> str:
        tenant_id = self.auth.tenant_id or "organizations"
        return f"{self.auth.authority.rstrip('/')}/{tenant_id}"

    def ensure_token(self) -> str:
        if self._token:
            return self._token
        if self.auth.access_token:
            self._token = self.auth.access_token
            return self._token
        if self.auth.auth_mode == "interactive":
            return self._interactive_token()
        return self._app_token()

    def app_token_for(self, scope: str) -> str | None:
        """Client-credentials token for another resource (e.g. Exchange Online), or None outside app mode."""
        if self.auth.access_token or self.auth.auth_mode == "interactive" or not self.auth.client_secret or not self.auth.client_id:
            return None
        cache = self.__dict__.setdefault("_resource_tokens", {})
        if scope in cache:
            return cache[scope]
        # Counted like the Graph token request, so token_requests matches token_succeeded and the ledger names the resource.
        self._emit(
            "graph.token.requested",
            "Requesting resource token",
            {"mode": "client_credentials", "token_url": self._token_url(), "scope": scope},
        )
        try:
            response = self.session.post(
                self._token_url(),
                data={
                    "client_id": self.auth.client_id,
                    "client_secret": self.auth.client_secret,
                    "scope": scope,
                    "grant_type": "client_credentials",
                },
                timeout=self.auth.timeout_seconds,
            )
        except RequestException as exc:  # noqa: BLE001
            self._emit("graph.token.failed", "Resource token request raised transport exception", {"scope": scope, "error": str(exc)})
            return None
        if response.status_code >= 400:
            self._emit("graph.token.failed", "Resource token request returned an error response", {"scope": scope, "status": response.status_code})
            return None
        token = response.json().get("access_token")
        cache[scope] = token
        self._emit("graph.token.succeeded", "Resource token acquired", {"scope": scope, "status": response.status_code})
        return token

    def _app_token(self) -> str:
        if not self.auth.client_secret:
            raise GraphError("No client secret or access token provided.")

        payload = {
            "client_id": self.auth.client_id,
            "client_secret": self.auth.client_secret,
            "scope": self.auth.graph_scope,
            "grant_type": "client_credentials",
        }
        start = time.time()
        self._emit(
            "graph.token.requested",
            "Requesting app token",
            {
                "mode": "client_credentials",
                "token_url": self._token_url(),
                "payload": self._safe_payload(payload),
            },
        )
        try:
            response = self.session.post(
                self._token_url(),
                data=payload,
                timeout=self.auth.timeout_seconds,
            )
        except RequestException as exc:  # noqa: BLE001
            self._emit("graph.token.failed", "Token request raised transport exception", {"error": str(exc)})
            raise GraphError(f"Token request failed: {exc}") from exc
        duration_ms = round((time.time() - start) * 1000, 2)
        if response.status_code >= 400:
            self._emit(
                "graph.token.failed",
                "Token request returned an error response",
                {"status": response.status_code, "duration_ms": duration_ms},
            )
            raise GraphError(f"Token request failed ({response.status_code}): {response.text}")
        self._token = response.json()["access_token"]
        self._emit(
            "graph.token.succeeded",
            "App token acquired",
            {"status": response.status_code, "duration_ms": duration_ms},
        )
        return self._token

    def _interactive_token(self) -> str:
        try:
            import msal
        except Exception as exc:  # noqa: BLE001
            raise GraphError(f"Interactive auth requires msal dependency: {exc}")

        requested_scopes = self.auth.interactive_scopes or [self.auth.graph_scope]
        scopes = list(dict.fromkeys(requested_scopes)) or ["User.Read"]
        if self.auth.graph_scope.endswith("/.default") and self.auth.graph_scope in scopes:
            scopes = [scope for scope in scopes if scope != self.auth.graph_scope]
            if not scopes:
                scopes = ["User.Read"]

        self._emit(
            "graph.token.interactive",
            "Starting interactive token acquisition",
            {"scopes": scopes, "authority": self._authority()},
        )
        app = msal.PublicClientApplication(
            client_id=self.auth.client_id,
            authority=self._authority(),
            token_cache=None,
        )
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(scopes=scopes, account=accounts[0])
            if result and "access_token" in result:
                self._token = result["access_token"]
                self._emit("graph.token.succeeded", "Interactive token loaded from cache", {"source": "cache"})
                return self._token

        result = app.acquire_token_interactive(scopes=scopes)
        if not result:
            self._emit("graph.token.failed", "Interactive auth returned no token", {"scopes": scopes})
            raise GraphError("Interactive auth was canceled or did not return a token.")
        if "access_token" not in result:
            error = result.get("error_description") or result.get("error") or "interactive login failed"
            self._emit("graph.token.failed", "Interactive auth returned error response", {"error": error})
            raise GraphError(error)
        self._token = result["access_token"]
        self._emit("graph.token.succeeded", "Interactive token acquired", {"source": "interactive"})
        return self._token

    def token_claims(self) -> dict[str, Any]:
        if self._token_claims is not None:
            return dict(self._token_claims)
        try:
            token = self.ensure_token()
            inspect_token_claims = importlib.import_module("auditex.auth").inspect_token_claims
            self._token_claims = dict(inspect_token_claims(token))
        except Exception:  # noqa: BLE001
            self._token_claims = {}
        return dict(self._token_claims)

    def _enforce_read_only(self, method: str, url: str, kwargs: dict[str, Any]) -> None:
        """Refuse any request that is not a read, before a token is acquired or the network is touched."""
        reason = read_only_violation(method, url, kwargs)
        if reason is None:
            return
        self._emit(
            "graph.request.refused",
            "Refused a Graph request that is not a read",
            {"method": str(method), "url": str(url), "reason": reason},
        )
        raise GraphError(
            f"Refusing {method} {url}: {reason}.",
            request=str(url),
            error_code=READ_ONLY_VIOLATION,
        )

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self._enforce_read_only(method, url, kwargs)
        token = self.ensure_token()
        headers = kwargs.pop("headers", {})
        headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": package_user_agent(),
            }
        )
        attempt = 0
        family = self._request_family(url)
        permission_stop_after = self._throttle_policy().permission_stop_after
        while True:
            attempt += 1
            if permission_stop_after and self._permission_failures.get(family, 0) >= permission_stop_after:
                self._emit(
                    "graph.request.permission_stop",
                    "Skipping request after repeated permission failures",
                    {"method": method, "url": url, "family": family, "attempt": attempt},
                )
                raise GraphError(
                    f"Permission stop triggered for Graph family '{family}'.",
                    status=403,
                    request=url,
                    error_code="PermissionStop",
                )
            self._apply_pacing(method=method, url=url, attempt=attempt)
            request_start = time.time()
            started: dict[str, Any] = {
                "method": method,
                "url": url,
                "attempt": attempt,
                "params": self._params_overview(kwargs.get("params")),
            }
            if graph_batch_url(url):
                # The inner calls are what the API ledger reports, so they are recorded here (paths only, no bodies).
                started["batch"] = _batch_summary(kwargs)
            self._emit("graph.request.started", "Graph request started", started)
            try:
                # Redirects are followed by hand (see _follow_redirects): the host check and the audit log must
                # see every hop, and the bearer token must never be sent to a host that is not Graph.
                response = self.session.request(
                    method, url, headers=headers, timeout=self.auth.timeout_seconds, allow_redirects=False, **kwargs
                )
            except RequestException as exc:  # noqa: BLE001
                self._emit(
                    "graph.request.exception",
                    "Graph request raised exception",
                    {"method": method, "url": url, "error": str(exc), "attempt": attempt},
                )
                raise
            duration_ms = round((time.time() - request_start) * 1000, 2)
            self._emit(
                "graph.request.completed",
                "Graph request finished",
                {
                    "method": method,
                    "url": url,
                    "status": response.status_code,
                    "attempt": attempt,
                    "duration_ms": duration_ms,
                    "response_length": len(response.text),
                },
            )
            if response.status_code in _REDIRECT_STATUSES:
                response = self._follow_redirects(response, method, url, headers)
            if response.status_code == 403 and permission_stop_after:
                self._permission_failures[family] = self._permission_failures.get(family, 0) + 1
            elif response.status_code < 400:
                self._permission_failures.pop(family, None)

            if response.status_code == 429 and attempt <= self._throttle_policy().rate_limit_retries:
                retry_after = self._retry_delay(attempt, retry_after=response.headers.get("Retry-After"))
                LOG.warning("Graph rate limit. Retry in %s seconds.", retry_after)
                self._emit(
                    "graph.request.retry",
                    "Rate limited, retrying request",
                    {
                        "method": method,
                        "url": url,
                        "retry_after_sec": retry_after,
                        "backoff_seconds": retry_after,
                        "attempt": attempt,
                        "reason": "rate_limit",
                    },
                )
                time.sleep(retry_after)
                continue
            if response.status_code >= 500 and attempt <= self._throttle_policy().server_error_retries:
                backoff_seconds = self._retry_delay(attempt)
                LOG.warning(
                    "Graph server error (%s). Retrying (%s/%s).",
                    response.status_code,
                    attempt,
                    self._throttle_policy().server_error_retries,
                )
                self._emit(
                    "graph.request.retry",
                    "Server error, retrying request",
                    {
                        "method": method,
                        "url": url,
                        "status": response.status_code,
                        "attempt": attempt,
                        "backoff_seconds": backoff_seconds,
                        "reason": "server_error",
                    },
                )
                time.sleep(backoff_seconds)
                continue
            self._arm_next_request_delay()
            return response

    def _follow_redirects(
        self, response: requests.Response, method: str, url: str, headers: dict[str, str]
    ) -> requests.Response:
        """Follow a redirect a read was answered with, hop by hop, and record each hop without its query.

        A hop on Graph keeps the bearer token. Any other hop must be an HTTPS URL on a Microsoft download host
        and is fetched without the token. Anything else is refused, and the hop is logged as host and path only
        because the query of a pre-authenticated download URL is a credential.
        """
        hops = 0
        current_url = url
        while response.status_code in _REDIRECT_STATUSES:
            location = response.headers.get("Location")
            if not location or method.upper() != "GET":
                return response
            hops += 1
            target = urljoin(current_url, location)
            parsed = urlparse(target)
            event = {
                "method": method,
                "status": response.status_code,
                "hop": hops,
                "from_path": urlparse(current_url).path,
                "host": parsed.hostname or "unknown",
                "path": parsed.path,
            }
            graph_hop = graph_host_url(target)
            if hops > _MAX_REDIRECTS or not (graph_hop or download_host_allowed(target)):
                self._emit("graph.request.redirect_refused", "Refused a redirect", event)
                raise GraphError(
                    f"Refusing to follow a redirect to {event['host']}; it is not a Microsoft download host.",
                    request=redacted_url(target),
                    error_code=REDIRECT_REFUSED,
                )
            self._emit("graph.request.redirect", "Following a redirect", event)
            hop_headers = (
                headers
                if graph_hop
                else {name: value for name, value in headers.items() if name.lower() != "authorization"}
            )
            try:
                response = self.session.request(
                    "GET", target, headers=hop_headers, timeout=self.auth.timeout_seconds, allow_redirects=False
                )
            except RequestException as exc:  # noqa: BLE001
                self._emit(
                    "graph.request.exception",
                    "Graph redirect hop raised exception",
                    {"method": "GET", "url": redacted_url(target), "error": type(exc).__name__, "hop": hops},
                )
                raise
            current_url = target
        return response

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None, full_url: bool = False) -> Dict[str, Any]:
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        if full_url:
            self._require_graph_url(url)
        response = self._request("GET", url, params=params)
        if response.status_code >= 400:
            payload: dict[str, Any]
            error_code: str | None = None
            reason = response.text
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict):
                error = payload.get("error")
                if isinstance(error, dict):
                    error_code = error.get("code")
                    reason = str(error.get("message") or reason)
                elif isinstance(error, str):
                    reason = error
            error_url = response.url if graph_host_url(response.url) else redacted_url(response.url)
            self._emit(
                "graph.response.error",
                "Graph endpoint returned error response",
                {
                    "url": error_url,
                    "status": response.status_code,
                    "error_code": error_code,
                },
            )
            raise GraphError(reason, status=response.status_code, request=error_url, error_code=error_code)
        return response.json()

    def get_content(self, path: str, params: Optional[Dict[str, Any]] = None, full_url: bool = False) -> str:
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        if full_url:
            self._require_graph_url(url)
        response = self._request("GET", url, params=params)
        if response.status_code >= 400:
            error_url = response.url if graph_host_url(response.url) else redacted_url(response.url)
            raise GraphError(response.text, status=response.status_code, request=error_url)
        return response.text

    def _require_graph_url(self, url: Any) -> None:
        """Refuse to send the bearer token anywhere but Microsoft Graph, and never read a stopped list as complete."""
        if isinstance(url, str) and graph_host_url(url):
            return
        host = urlparse(str(url)).hostname or "unknown"
        self._emit(
            "graph.request.next_link_refused",
            "Refused a URL outside Microsoft Graph",
            {"host": host},
        )
        raise GraphError(
            f"Refusing to request {host}, which is not Microsoft Graph; the list is incomplete.",
            request=host,
            error_code=NEXT_LINK_REFUSED,
        )

    def iter_pages(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        if path.startswith("http"):
            # An absolute first URL (a batch body's nextLink, a beta endpoint) gets the same host check as every later page.
            self._require_graph_url(path)
        page_url: Optional[str] = path if path.startswith("http") else f"{GRAPH_ROOT}{path}"
        current_params = params
        while page_url:
            payload = self.get_json(page_url, params=current_params, full_url=page_url.startswith("http"))
            if not isinstance(payload, dict):
                raise GraphError(f"Non-dict response from {page_url}", request=page_url)
            yield payload
            page_url = payload.get("@odata.nextLink")
            if page_url:
                self._require_graph_url(page_url)
            current_params = None

    def iter_items(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        result_limit: int | None = None,
    ) -> Iterator[Dict[str, Any]]:
        yielded = 0
        for payload in self.iter_pages(path, params=params):
            values = payload.get("value", [])
            if not isinstance(values, list):
                raise GraphError(f"Non-list page payload from {path}", request=path)
            for row in values:
                if result_limit is not None and yielded >= result_limit:
                    return
                yield row
                yielded += 1

    def get_all(self, path: str, params: Optional[Dict[str, Any]] = None) -> list[Dict[str, Any]]:
        return list(self.iter_items(path, params=params))

    @staticmethod
    def _batch_request_url(path: str, params: Optional[Dict[str, Any]] = None, *, full_url: bool = False) -> str:
        parsed = urlparse(path)
        batch_path = parsed.path or "/"
        parts = [item for item in batch_path.split("/") if item]
        if parts and parts[0] in {"v1.0", "beta"}:
            batch_path = "/" + "/".join(parts[1:])
        query_parts: list[str] = []
        if parsed.query:
            query_parts.append(parsed.query)
        if params:
            query_parts.append(urlencode(params, doseq=True))
        if query_parts:
            return f"{batch_path}?{'&'.join(part for part in query_parts if part)}"
        return batch_path

    def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not requests:
            return []

        results: list[dict[str, Any]] = []
        for offset in range(0, len(requests), GRAPH_BATCH_CHUNK_SIZE):
            chunk = requests[offset : offset + GRAPH_BATCH_CHUNK_SIZE]
            batch_requests: list[dict[str, Any]] = []
            for index, request_spec in enumerate(chunk):
                method = str(request_spec.get("method", "GET")).upper()
                if method != "GET":
                    raise GraphError("Graph batch helper only supports GET requests.")
                path = request_spec.get("path")
                if not isinstance(path, str) or not path:
                    raise GraphError("Graph batch request requires a path.")
                batch_requests.append(
                    {
                        "id": str(index),
                        "method": "GET",
                        "url": self._batch_request_url(
                            path,
                            request_spec.get("params"),
                            full_url=bool(request_spec.get("full_url", False)),
                        ),
                    }
                )

            response = self._request("POST", f"{GRAPH_ROOT}/$batch", json={"requests": batch_requests})
            if response.status_code >= 400:
                payload: dict[str, Any]
                error_code: str | None = None
                reason = response.text
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                if isinstance(payload, dict):
                    error = payload.get("error")
                    if isinstance(error, dict):
                        error_code = error.get("code")
                        reason = str(error.get("message") or reason)
                    elif isinstance(error, str):
                        reason = error
                raise GraphError(reason, status=response.status_code, request=response.url, error_code=error_code)

            payload = response.json()
            if not isinstance(payload, dict):
                raise GraphError("Graph batch returned a non-dict payload.", request=response.url)
            responses = payload.get("responses")
            if not isinstance(responses, list):
                raise GraphError("Graph batch returned no responses array.", request=response.url)

            responses_by_id: dict[str, dict[str, Any]] = {}
            for response_item in responses:
                if isinstance(response_item, dict):
                    response_id = response_item.get("id")
                    if response_id is not None:
                        responses_by_id[str(response_id)] = response_item

            for index, request_spec in enumerate(chunk):
                response_item = responses_by_id.get(str(index))
                if not isinstance(response_item, dict):
                    results.append(
                        {
                            "request": request_spec,
                            "status": 502,
                            "body": {},
                            "error_code": "BatchMissingResponse",
                            "error": "Graph batch response was missing an entry.",
                        }
                    )
                    continue

                status = response_item.get("status")
                body = response_item.get("body")
                entry: dict[str, Any] = {
                    "request": request_spec,
                    "status": status if isinstance(status, int) else 0,
                    "body": body if isinstance(body, dict) else body,
                }
                if isinstance(body, dict):
                    error = body.get("error")
                    if isinstance(error, dict):
                        error_code = error.get("code")
                        error_message = error.get("message")
                        if error_code is not None:
                            entry["error_code"] = error_code
                        if error_message is not None:
                            entry["error"] = str(error_message)
                    elif isinstance(error, str):
                        entry["error"] = error
                results.append(entry)

        return results
