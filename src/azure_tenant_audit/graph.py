from __future__ import annotations

import logging
import random
import time
import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, Optional
from urllib.parse import urlencode, urlparse

import requests
from requests.exceptions import RequestException

from .config import AuthConfig
from .versioning import package_user_agent


LOG = logging.getLogger(__name__)
GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_BATCH_CHUNK_SIZE = 20
TOKEN_URL_TEMPLATE = "{authority}{tenant_id}/oauth2/v2.0/token"


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
        return parts[0] if parts else "root"

    def _apply_pacing(self, *, method: str, url: str, attempt: int) -> None:
        policy = self._throttle_policy()
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

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
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
            self._emit(
                "graph.request.started",
                "Graph request started",
                {
                    "method": method,
                    "url": url,
                    "attempt": attempt,
                    "params": self._params_overview(kwargs.get("params")),
                },
            )
            try:
                response = self.session.request(method, url, headers=headers, timeout=self.auth.timeout_seconds, **kwargs)
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

    def get_json(self, path: str, params: Optional[Dict[str, Any]] = None, full_url: bool = False) -> Dict[str, Any]:
        url = path if full_url else f"{GRAPH_ROOT}{path}"
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
            self._emit(
                "graph.response.error",
                "Graph endpoint returned error response",
                {
                    "url": response.url,
                    "status": response.status_code,
                    "error_code": error_code,
                },
            )
            raise GraphError(reason, status=response.status_code, request=response.url, error_code=error_code)
        return response.json()

    def get_content(self, path: str, params: Optional[Dict[str, Any]] = None, full_url: bool = False) -> str:
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        response = self._request("GET", url, params=params)
        if response.status_code >= 400:
            raise GraphError(response.text, status=response.status_code, request=response.url)
        return response.text

    def iter_pages(self, path: str, params: Optional[Dict[str, Any]] = None) -> Iterator[Dict[str, Any]]:
        page_url: Optional[str] = path if path.startswith("http") else f"{GRAPH_ROOT}{path}"
        current_params = params
        while page_url:
            payload = self.get_json(page_url, params=current_params, full_url=page_url.startswith("http"))
            if not isinstance(payload, dict):
                raise GraphError(f"Non-dict response from {page_url}", request=page_url)
            yield payload
            page_url = payload.get("@odata.nextLink")
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
