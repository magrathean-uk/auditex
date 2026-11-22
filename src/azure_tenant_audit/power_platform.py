"""Thin, commercial-cloud client for Power Platform admin metadata reads: GET, plus the one body-free POST read."""
from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

POWER_PLATFORM_ROOT = "https://api.bap.microsoft.com"
POWER_PLATFORM_DEFAULT_API_VERSION = "2020-10-01"
POWER_PLATFORM_DEFAULT_TIMEOUT = 15.0
# A throttled (429) or unavailable (503) answer is re-sent at most twice after its Retry-After, capped like the
# SharePoint admin client's, or a short back-off when it has none (R110).
RETRY_STATUSES = frozenset({429, 503})
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER_SECONDS = 30.0
DEFAULT_BACKOFF_SECONDS = 2.0
BAP_SCOPE = "https://service.powerapps.com//.default"
ALLOWED_METHODS = frozenset({"GET"})
# The one documented body-free POST read: Power Platform "List tenant settings" (Microsoft Learn, Power Platform API
# 2020-10-01: "POST .../listtenantsettings", "Don't supply a request body for this method"). post_read sends it; any
# other path is refused before the session is touched (DEC-061).
POST_READ_PATHS = frozenset({"/providers/Microsoft.BusinessAppPlatform/listTenantSettings"})


class PowerPlatformError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, request: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.request = request


def same_origin(path: str, root: str = POWER_PLATFORM_ROOT) -> bool:
    """Never forward a bearer token to another origin, including a redirect."""
    try:
        target = urlsplit(urljoin(root + "/", path))
        origin = urlsplit(root)
        return (target.scheme, target.hostname, target.port) == (origin.scheme, origin.hostname, origin.port) and not (
            target.username or target.password or target.fragment
        )
    except ValueError:
        return False


def power_platform_client_from(context: dict[str, Any]) -> PowerPlatformClient | None:
    if "power_platform_client" in context:
        return context["power_platform_client"]
    graph = context.get("client")
    token = graph.app_token_for(BAP_SCOPE) if hasattr(graph, "app_token_for") else None
    return PowerPlatformClient(token=token) if token else None


@dataclass
class PowerPlatformClient:
    token: str | None = field(default=None, repr=False)
    api_version: str = POWER_PLATFORM_DEFAULT_API_VERSION
    session: Any = field(default_factory=requests.Session, repr=False)
    timeout: float = POWER_PLATFORM_DEFAULT_TIMEOUT
    root: str = POWER_PLATFORM_ROOT
    sleep: Callable[[float], None] = field(default=time.sleep, repr=False)

    def get(self, path: str, *, api_version: str | None = None) -> Any:
        return self.request("GET", path, api_version=api_version)

    def request(self, method: str, path: str, *, api_version: str | None = None) -> Any:
        if method not in ALLOWED_METHODS:
            raise PowerPlatformError("method refused")
        url, params = self._target(path, api_version)
        return self._decode(self._send(lambda: self.session.request(
            method, url, params=params, headers=self._headers(), timeout=self.timeout, allow_redirects=False,
        )))

    def post_read(self, path: str, *, api_version: str | None = None) -> Any:
        """Send the one documented body-free POST read (List tenant settings); refuse every other path."""
        if not isinstance(path, str) or urlsplit(path).path not in POST_READ_PATHS:
            raise PowerPlatformError("POST read refused")
        url, params = self._target(path, api_version)
        return self._decode(self._send(lambda: self.session.post(
            url, params=params, headers=self._headers(), timeout=self.timeout, allow_redirects=False,
        )))

    def _send(self, send: Callable[[], Any]) -> Any:
        """Send once, re-sending a 429 or 503 answer within MAX_ATTEMPTS; the last answer is returned."""
        attempt = 0
        while True:
            attempt += 1
            try:
                response = send()
            except Exception:  # Transport exceptions can contain headers; never retain their text.
                raise PowerPlatformError("Power Platform transport error") from None
            if response.status_code not in RETRY_STATUSES or attempt >= MAX_ATTEMPTS:
                return response
            self.sleep(_retry_after(response, attempt))

    def _target(self, path: str, api_version: str | None) -> tuple[str, dict[str, str] | None]:
        if not self.token:
            raise PowerPlatformError("missing Power Platform admin token", status=401)
        if self.root != POWER_PLATFORM_ROOT or not same_origin(path, self.root) or self.token in path:
            raise PowerPlatformError("Power Platform request URL refused")
        url = urljoin(self.root + "/", path)
        params = None if "api-version" in parse_qs(urlsplit(url).query) else {
            "api-version": api_version or self.api_version,
        }
        return url, params

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "accept": "application/json"}

    @staticmethod
    def _decode(response: Any) -> Any:
        if not 200 <= response.status_code < 300:
            raise PowerPlatformError("Power Platform HTTP request failed", status=response.status_code)
        if not response.content or not response.content.strip():
            return None
        try:
            return response.json()
        except ValueError:
            raise PowerPlatformError("invalid JSON from Power Platform") from None

def _retry_after(response: Any, attempt: int) -> float:
    headers = getattr(response, "headers", None) or {}
    value = next((str(v) for k, v in headers.items() if str(k).lower() == "retry-after"), None)
    try:
        seconds = float(value) if value is not None else math.nan
    except ValueError:
        seconds = math.nan  # an HTTP date is not used; the back-off applies
    if not math.isfinite(seconds):
        seconds = DEFAULT_BACKOFF_SECONDS * attempt
    return min(MAX_RETRY_AFTER_SECONDS, max(0.0, seconds))


def http_error_class(status: int | None) -> str:
    if status in (401, 403):
        return "insufficient_permissions"
    if status in (404, 410, 429) or (isinstance(status, int) and 500 <= status <= 599):
        return "service_not_available"
    return "client_error"
