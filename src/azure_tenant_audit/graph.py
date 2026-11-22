from __future__ import annotations

import copy
import logging
import math
import random
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException, Timeout

from . import auth_context, certificate_auth
from .certificate_auth import CERTIFICATE_ERRORS, CertificateAuthError
from .config import CERTIFICATE_WAY, AuthConfig, check_single_credential
from .versioning import package_user_agent

LOG = logging.getLogger(__name__)
# A certificate token is refreshed this many seconds before msal says it expires.
_CERTIFICATE_REFRESH_MARGIN_SECONDS = 300.0


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
# Beta is opt-in per endpoint: only surfaces without a v1.0 equivalent use it, and
# every beta call is recorded with api_version="beta" in coverage and the API ledger.
GRAPH_BETA_ROOT = "https://graph.microsoft.com/beta"
GRAPH_API_ROOTS = {"v1.0": GRAPH_ROOT, "beta": GRAPH_BETA_ROOT}
# Error code of a refused @odata.nextLink; the paging that stopped is recorded as a coverage gap.
NEXT_LINK_REFUSED = "NextLinkRefused"
# A paging safety stop cannot establish a complete collection.
INCOMPLETE_EVIDENCE = "IncompleteEvidence"
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
# The Graph read guard (read_only_violation, via _enforce_read_only first in _request) allows only:
#   GET, body-free, to https://graph.microsoft.com (class 1 tenant read); redirect hops are GET-only
#   to the allowed download hosts (_follow_redirects);
#   POST only to /v1.0/$batch or /beta/$batch, every sub-request a body-free, relative GET
#   (class 3 Graph $batch).
# The only other non-GET calls in this module are token POSTs to the Entra authority (class 2: msal in
# _certificate_exchange for the reader app's certificate credential), which never pass through _request.
# tests/test_http_verb_allowlist.py holds the frozen allow-list; a new non-GET site fails it.
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
# Per-item answers inside a $batch response that are re-sent (only those items) after the item's Retry-After.
BATCH_RETRY_STATUSES = frozenset({429, 503, 504})
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
    # Total time a $batch call may spend waiting to re-send its throttled or unavailable items.
    max_retry_wait_seconds: float = 120.0


THROTTLE_POLICIES: dict[str, ThrottlePolicy] = {
    "fast": ThrottlePolicy(
        min_delay_seconds=0.0,
        jitter_seconds=0.0,
        rate_limit_retries=3,
        server_error_retries=2,
        permission_stop_after=0,
        base_backoff_seconds=1.0,
        max_retry_wait_seconds=30.0,
    ),
    "safe": ThrottlePolicy(
        min_delay_seconds=0.2,
        jitter_seconds=0.1,
        rate_limit_retries=4,
        server_error_retries=3,
        permission_stop_after=2,
        base_backoff_seconds=1.5,
        max_retry_wait_seconds=120.0,
    ),
    "ultra-safe": ThrottlePolicy(
        min_delay_seconds=0.75,
        jitter_seconds=0.25,
        rate_limit_retries=5,
        server_error_retries=4,
        permission_stop_after=1,
        base_backoff_seconds=2.0,
        max_retry_wait_seconds=300.0,
    ),
}


@dataclass
class _WaitBudget:
    """The seconds one ``$batch`` chunk or one request may still spend waiting to retry, shared by all its retries."""

    remaining: float
    spent: float = 0.0

    def allows(self, seconds: float) -> bool:
        return math.isfinite(seconds) and seconds <= self.remaining

    def take(self, seconds: float) -> None:
        self.remaining -= seconds
        self.spent += seconds


# Phrases and error codes of a Graph answer that refuses a read for a missing licence, not a missing permission. The
# phrases match those collectors.base._classify_graph_error maps to license_required.
_LICENCE_PHRASES = (
    "premium license",
    "spo license",
    "not licensed",
    "does not have a license",
    "license is required",
    "needs to have microsoft entra id p2",
    "governance license",
)


def _licence_refusal(response: Any) -> bool:
    """Whether a 403 answer names a missing licence rather than a missing permission."""
    try:
        payload = response.json()
    except ValueError:
        payload = None
    code, message = "", str(getattr(response, "text", "") or "")
    if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
        code = str(payload["error"].get("code") or "")
        message = str(payload["error"].get("message") or message)
    if "license" in code.lower() or "licence" in code.lower():
        return True
    lower = message.lower()
    return any(phrase in lower for phrase in _LICENCE_PHRASES)


def _off_graph_reason(response: Any) -> str:
    """An error from the download host after a redirect: its body can echo the signed URL (a credential), so only the
    host and status are kept (R158)."""
    host = urlparse(str(getattr(response, "url", "") or "")).hostname or "unknown"
    return f"HTTP {response.status_code} from download host {host}"


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
    _token: str | None = None
    audit_event: Callable[[str, str, dict[str, Any] | None], None] | None = None
    # Explicit caller backstop only; ordinary inventories have no page-count ceiling.
    max_pages: int | None = None
    _next_request_not_before: float = field(default=0.0, init=False)
    _permission_failures: dict[str, int] = field(default_factory=dict, init=False)
    _token_claims: dict[str, Any] | None = field(default=None, init=False)
    # Certificate credential runtime, process memory only: one msal app and scope -> (token, refresh deadline).
    _certificate_app: Any = field(default=None, init=False, repr=False, compare=False)
    _certificate_tokens: dict[str, tuple[str, float]] = field(default_factory=dict, init=False, repr=False, compare=False)
    _certificate_lock: Any = field(default_factory=threading.Lock, init=False, repr=False, compare=False)
    # Injected clock for tests: a monotonic reading and a wait; None uses time.monotonic and time.sleep.
    clock: Callable[[], float] | None = field(default=None, repr=False, compare=False)
    sleep: Callable[[float], None] | None = field(default=None, repr=False, compare=False)

    def _sleep(self, seconds: float) -> None:
        (self.sleep or time.sleep)(seconds)

    def _monotonic(self) -> float:
        return (self.clock or time.monotonic)()

    def _emit(self, event: str, message: str, details: dict[str, Any] | None = None) -> None:
        if self.audit_event is None:
            return
        try:
            self.audit_event(event, message, details)
        except Exception:  # noqa: BLE001
            LOG.exception("Failed to emit audit event.")

    @staticmethod
    def _params_overview(params: dict[str, Any] | None) -> dict[str, Any]:
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
        now = self._monotonic()
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
        self._sleep(wait_seconds)
        self._next_request_not_before = 0.0

    def _arm_next_request_delay(self) -> None:
        policy = self._throttle_policy()
        delay_seconds = policy.min_delay_seconds
        if policy.jitter_seconds > 0:
            delay_seconds += random.uniform(0.0, policy.jitter_seconds)
        self._next_request_not_before = self._monotonic() + delay_seconds

    def _retry_delay(self, attempt: int, *, retry_after: str | None = None) -> float:
        policy = self._throttle_policy()
        if retry_after:
            try:
                seconds = float(retry_after)
            except ValueError:
                seconds = math.nan
            # An HTTP date, NaN or infinity is not a usable delay: the policy back-off applies instead.
            if math.isfinite(seconds):
                return max(seconds, policy.base_backoff_seconds)
        return round(policy.base_backoff_seconds * (2 ** max(0, attempt - 1)), 2)

    def ensure_token(self) -> str:
        """The Graph token, minted from the reader app's certificate (DEC-107); there is no other credential."""
        if self.auth.certificate is not None:
            # Certificate tokens carry a refresh deadline, so the cached _token is not trusted alone.
            return self._certificate_token(self.auth.graph_scope)
        if self._token:
            # Offline tests inject a constructed token here; no product path sets it.
            return self._token
        raise GraphError(f"No certificate credential. {CERTIFICATE_WAY}.", error_code="certificate_required")

    def app_token_for(self, scope: str) -> str | None:
        """App token for another resource (e.g. Exchange Online), minted from the certificate, or None.

        A token that cannot be acquired is None (the collector records a named gap); without a certificate
        there is no token for any other resource.
        """
        if self.auth.certificate is None:
            return None
        try:
            return self._certificate_token(scope)
        except GraphError:
            if scope == self.auth.graph_scope:
                raise
            return None

    def _certificate_token(self, scope: str) -> str:
        """An app token from the certificate credential, cached in memory until its refresh deadline."""
        with self._certificate_lock:
            cached = self._certificate_tokens.get(scope)
            if cached is not None and time.monotonic() < cached[1]:
                return cached[0]
            self._certificate_tokens.pop(scope, None)
            check_single_credential(self.auth)
            started = time.monotonic()
            # Events name the mode, endpoint and scope only: no assertion, key, token or vendor diagnostic.
            self._emit(
                "graph.token.requested",
                "Requesting certificate app token",
                {"mode": "certificate", "token_url": self._token_url(), "scope": scope},
            )
            token, lifetime, failure = self._certificate_exchange(scope)
            duration_ms = round((time.monotonic() - started) * 1000, 2)
            if failure is not None or token is None:
                self._emit(
                    "graph.token.failed",
                    "Certificate token request failed",
                    {"mode": "certificate", "scope": scope, "error_code": failure, "duration_ms": duration_ms},
                )
                # A GraphError, so each Graph read fails as it does for a refused secret, with a fixed message.
                code = failure if failure == "certificate_authority_refused" else "certificate_token_failed"
                raise GraphError(CERTIFICATE_ERRORS[code], error_code=code)
            self._certificate_tokens[scope] = (token, started + max(0.0, lifetime - _CERTIFICATE_REFRESH_MARGIN_SECONDS))
            if scope == self.auth.graph_scope:
                self._token = token
            self._emit(
                "graph.token.succeeded",
                "Certificate app token acquired",
                {"mode": "certificate", "scope": scope, "duration_ms": duration_ms},
            )
            return token

    def _certificate_exchange(self, scope: str) -> tuple[str | None, float, str | None]:
        """Run msal inside one frame; every failure comes back as a fixed code, never an exception or body."""
        try:
            app = self._certificate_app
            if app is None:
                authority = certificate_auth.certificate_authority(self.auth.authority, self.auth.tenant_id)
                app = certificate_auth.build_confidential_client(
                    self.auth.certificate,
                    client_id=self.auth.client_id,
                    authority=authority,
                    timeout=self.auth.timeout_seconds,
                )
                self._certificate_app = app
            result = app.acquire_token_for_client(scopes=[scope])
        except CertificateAuthError as exc:
            return None, 0.0, exc.error_code
        except Exception:  # noqa: BLE001 - msal and transport messages can carry request material
            return None, 0.0, "certificate_token_failed"
        token = result.get("access_token") if isinstance(result, dict) else None
        if not isinstance(token, str) or not token:
            return None, 0.0, certificate_auth.safe_oauth_error(result)
        lifetime = result.get("expires_in")
        if isinstance(lifetime, bool) or not isinstance(lifetime, (int, float)) or not math.isfinite(lifetime) or lifetime <= 0:
            return None, 0.0, "certificate_token_failed"
        return token, float(lifetime), None

    def token_claims(self) -> dict[str, Any]:
        if self._token_claims is not None:
            return dict(self._token_claims)
        try:
            token = self.ensure_token()
            self._token_claims = dict(auth_context.inspect_token_claims(token))
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

    def _request(self, method: str, url: str, *, wait_budget: _WaitBudget | None = None, **kwargs: Any) -> requests.Response:
        self._enforce_read_only(method, url, kwargs)
        # Send one Graph request, retrying 429 and 5xx answers within the throttle policy. The read guard above stays
        # the first statement (tests/test_http_verb_allowlist.py). ``wait_budget`` is the shared retry-wait allowance
        # of a ``$batch`` chunk, or of this one request when None: a retry whose wait would pass it is not slept and the
        # last answer is returned instead.
        token = self.ensure_token()
        headers = kwargs.pop("headers", {})
        headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": package_user_agent(),
            }
        )
        if wait_budget is None:
            # Every read has a retry-wait bound, not only a $batch chunk (R104): a Retry-After past it is not slept, and
            # the throttled answer is returned so the read becomes a recorded gap instead of a run that looks hung.
            wait_budget = _WaitBudget(self._throttle_policy().max_retry_wait_seconds)
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
                self._retry_transport_error(exc, method=method, url=url, attempt=attempt, wait_budget=wait_budget)
                continue
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
                try:
                    response = self._follow_redirects(response, method, url, headers)
                except (Timeout, RequestsConnectionError) as exc:
                    # A blip on an allowed download hop is retried from the Graph URL, which mints a fresh signed
                    # link, within the same bound as a blip on Graph itself (R033). The error is already redacted.
                    self._retry_transport_error(exc, method=method, url=url, attempt=attempt, wait_budget=wait_budget)
                    continue
            if response.status_code == 403 and permission_stop_after:
                # A licence answer is not a permission refusal: sibling reads of the family may still be licensed or
                # take another path (R004), so only genuine authorisation refusals count toward the stop.
                if not _licence_refusal(response):
                    self._permission_failures[family] = self._permission_failures.get(family, 0) + 1
            elif response.status_code < 400:
                self._permission_failures.pop(family, None)

            if response.status_code == 429 and attempt <= self._throttle_policy().rate_limit_retries:
                retry_after = self._retry_delay(attempt, retry_after=response.headers.get("Retry-After"))
                if self._over_wait_budget(wait_budget, retry_after, method=method, url=url, attempt=attempt):
                    self._arm_next_request_delay()
                    return response
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
                self._take_wait(wait_budget, retry_after)
                continue
            if response.status_code >= 500 and attempt <= self._throttle_policy().server_error_retries:
                backoff_seconds = self._retry_delay(attempt)
                if self._over_wait_budget(wait_budget, backoff_seconds, method=method, url=url, attempt=attempt):
                    self._arm_next_request_delay()
                    return response
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
                self._take_wait(wait_budget, backoff_seconds)
                continue
            self._arm_next_request_delay()
            return response

    def _retry_transport_error(
        self, exc: RequestException, *, method: str, url: str, attempt: int, wait_budget: _WaitBudget | None
    ) -> None:
        """Wait before retrying a read timeout or dropped connection, or re-raise ``exc`` when it may not be retried.

        A transport blip is retried like a 5xx (R033): one network blip must not fail an endpoint or cut a long paged
        list. Other request errors (a bad URL, a refused redirect) are not retried.
        """
        if not isinstance(exc, (Timeout, RequestsConnectionError)):
            raise exc
        if attempt > self._throttle_policy().server_error_retries:
            raise exc
        backoff_seconds = self._retry_delay(attempt)
        if wait_budget is not None and not wait_budget.allows(backoff_seconds):
            raise exc
        self._emit(
            "graph.request.retry",
            "Transport error, retrying request",
            {
                "method": method,
                "url": url,
                "error": type(exc).__name__,
                "attempt": attempt,
                "backoff_seconds": backoff_seconds,
                "reason": "transport_error",
            },
        )
        self._take_wait(wait_budget, backoff_seconds)

    def _over_wait_budget(
        self, wait_budget: _WaitBudget | None, seconds: float, *, method: str, url: str, attempt: int
    ) -> bool:
        if wait_budget is None or wait_budget.allows(seconds):
            return False
        self._emit(
            "graph.request.retry_budget_exhausted",
            "Retry wait would pass the retry-wait bound; not retrying",
            {
                "method": method,
                "url": url,
                "attempt": attempt,
                "backoff_seconds": seconds,
                "remaining_seconds": wait_budget.remaining,
                "mode": self.auth.throttle_mode,
            },
        )
        return True

    def _take_wait(self, wait_budget: _WaitBudget | None, seconds: float) -> None:
        self._sleep(seconds)
        if wait_budget is not None:
            wait_budget.take(seconds)

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
                # R158: the original text names the signed download URL (its query is a credential) and collectors
                # store str(exc). Re-raise a copy of the same exception type, so retries and classification are
                # unchanged, naming only the host and path and holding no request or response.
                safe = copy.copy(exc)
                safe.args = (f"Redirect hop to {event['host']}{event['path']} failed ({type(exc).__name__})",)
                safe.request = safe.response = None
                raise safe from None
            current_url = target
        return response

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
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
            if not graph_host_url(response.url):
                reason, error_code = _off_graph_reason(response), None
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

    def get_content(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> str:
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        if full_url:
            self._require_graph_url(url)
        response = self._request("GET", url, params=params)
        if response.status_code >= 400:
            if graph_host_url(response.url):
                raise GraphError(response.text, status=response.status_code, request=response.url)
            raise GraphError(_off_graph_reason(response), status=response.status_code, request=redacted_url(response.url))
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

    def iter_pages(self, path: str, params: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
        if self.max_pages is not None and (
            isinstance(self.max_pages, bool) or not isinstance(self.max_pages, int) or self.max_pages < 1
        ):
            raise ValueError("max_pages must be None or a positive integer")
        if path.startswith("http"):
            # An absolute first URL (a batch body's nextLink, a beta endpoint) gets the same host check as every later page.
            self._require_graph_url(path)
        page_url: str | None = path if path.startswith("http") else f"{GRAPH_ROOT}{path}"
        current_params = params
        visited: set[str] = set()
        page_count = 0
        while page_url:
            request_url = page_url
            if current_params:
                request_url += ("&" if "?" in request_url else "?") + urlencode(current_params, doseq=True)
            if request_url in visited or (self.max_pages is not None and page_count >= self.max_pages):
                reason = "Repeated Graph page link" if request_url in visited else "Graph page-count limit reached"
                raise GraphError(f"{reason}; evidence withheld because the list is incomplete.",
                                 error_code=INCOMPLETE_EVIDENCE)
            visited.add(request_url)
            page_count += 1
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
        params: dict[str, Any] | None = None,
        *,
        result_limit: int | None = None,
    ) -> Iterator[dict[str, Any]]:
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

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return list(self.iter_items(path, params=params))

    @staticmethod
    def _batch_request_url(path: str, params: dict[str, Any] | None = None, *, full_url: bool = False) -> str:
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
        """GET each request through ``$batch``, in chunks of ``GRAPH_BATCH_CHUNK_SIZE``; one result per request, in order.

        An item answered 429, 503 or 504 is re-sent alone (with the other failed items of its chunk) after its
        ``Retry-After``, or the throttle policy's back-off when it has none. The attempts are bounded like a single
        request (``rate_limit_retries`` for 429, ``server_error_retries`` for 503 and 504) and the total wait by
        ``max_retry_wait_seconds``, which the transport retries of the chunk's POSTs share. An item whose delay would
        pass the remaining wait, or whose re-send fails, is returned with ``retry_exhausted`` set; settled answers stay.
        """
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
            results.extend(self._run_batch_chunk(chunk, batch_requests))
        return results

    def _run_batch_chunk(self, chunk: list[dict[str, Any]], batch_requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        policy = self._throttle_policy()
        budget = _WaitBudget(policy.max_retry_wait_seconds)
        entries: list[dict[str, Any]] = [{} for _ in chunk]
        pending = list(range(len(chunk)))
        attempt = 0
        while True:
            attempt += 1
            try:
                responses_by_id = self._post_batch([batch_requests[index] for index in pending], wait_budget=budget)
            except Exception as exc:  # noqa: BLE001
                if attempt == 1:
                    raise  # nothing settled yet: the caller decides how to read the chunk
                # The re-send failed: the settled answers stay, and only the pending items become named gaps.
                for index in pending:
                    entries[index]["error"] = f"{entries[index].get('error') or ''} Retry request failed: {exc}".strip()
                self._emit(
                    "graph.batch.retry_failed",
                    "The re-sent $batch request failed; its items were not read",
                    {"attempt": attempt, "urls": [batch_requests[index]["url"] for index in pending], "error": str(exc)},
                )
                break
            retry: list[int] = []
            for index in pending:
                entry = self._batch_entry(chunk[index], responses_by_id.get(str(index)))
                if attempt > 1:
                    entry["attempts"] = attempt
                entries[index] = entry
                if self._batch_item_retryable(entry["status"], attempt, policy):
                    retry.append(index)
            # Each item waits its own delay: one whose delay passes the remaining budget is left as a gap and does
            # not hold back the others, which are re-sent after the longest delay among them.
            delays = {
                index: self._retry_delay(attempt, retry_after=_header(entries[index].get("headers"), "Retry-After"))
                for index in retry
            }
            retry = [index for index in retry if budget.allows(delays[index])]
            if not retry:
                break
            wait = max(delays[index] for index in retry)
            self._emit(
                "graph.batch.retry",
                "Retrying throttled or unavailable $batch items",
                {
                    "attempt": attempt,
                    "item_count": len(retry),
                    "urls": [batch_requests[index]["url"] for index in retry],
                    "statuses": sorted({entries[index]["status"] for index in retry}),
                    "wait_seconds": wait,
                    "waited_seconds": budget.spent,
                    "mode": self.auth.throttle_mode,
                },
            )
            LOG.warning("Graph batch: %s items throttled or unavailable. Retry in %s seconds.", len(retry), wait)
            self._take_wait(budget, wait)
            pending = retry
        exhausted = [index for index, entry in enumerate(entries) if entry.get("status") in BATCH_RETRY_STATUSES]
        for index in exhausted:
            entry = entries[index]
            entry["retry_exhausted"] = True
            entry["error"] = (
                f"Graph batch item still answered HTTP {entry['status']} after {entry.get('attempts', 1)} attempts"
                f" (retry bound of throttle mode '{self.auth.throttle_mode}'); not read. "
                + str(entry.get("error") or "")
            ).strip()
        if exhausted:
            self._emit(
                "graph.batch.retry_exhausted",
                "Throttled or unavailable $batch items were not read within the retry bound",
                {
                    "item_count": len(exhausted),
                    "urls": [batch_requests[index]["url"] for index in exhausted],
                    "statuses": sorted({entries[index]["status"] for index in exhausted}),
                    "attempts": attempt,
                    "waited_seconds": budget.spent,
                    "mode": self.auth.throttle_mode,
                },
            )
        return entries

    @staticmethod
    def _batch_item_retryable(status: Any, attempt: int, policy: ThrottlePolicy) -> bool:
        if status == 429:
            return attempt <= policy.rate_limit_retries
        if status in BATCH_RETRY_STATUSES:
            return attempt <= policy.server_error_retries
        return False

    def _post_batch(
        self, batch_requests: list[dict[str, Any]], *, wait_budget: _WaitBudget | None = None
    ) -> dict[str, dict[str, Any]]:
        response = self._request("POST", f"{GRAPH_ROOT}/$batch", wait_budget=wait_budget, json={"requests": batch_requests})
        if response.status_code >= 400:
            payload: Any
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
        return responses_by_id

    @staticmethod
    def _batch_entry(request_spec: dict[str, Any], response_item: Any) -> dict[str, Any]:
        if not isinstance(response_item, dict):
            return {
                "request": request_spec,
                "status": 502,
                "body": {},
                "error_code": "BatchMissingResponse",
                "error": "Graph batch response was missing an entry.",
            }
        status = response_item.get("status")
        body = response_item.get("body")
        entry: dict[str, Any] = {
            "request": request_spec,
            "status": status if isinstance(status, int) else 0,
            "body": body,
        }
        headers = response_item.get("headers")
        if isinstance(headers, dict) and headers:
            entry["headers"] = headers
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
        return entry


def _header(headers: Any, name: str) -> str | None:
    """A header of a ``$batch`` item, matched without regard to case."""
    if not isinstance(headers, dict):
        return None
    for key, value in headers.items():
        if str(key).casefold() == name.casefold():
            return str(value)
    return None
