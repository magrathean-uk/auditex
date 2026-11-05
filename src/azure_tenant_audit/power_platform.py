"""Thin, commercial-cloud client for Power Platform admin metadata reads."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import requests

POWER_PLATFORM_ROOT = "https://api.bap.microsoft.com"
POWER_PLATFORM_DEFAULT_API_VERSION = "2020-10-01"
POWER_PLATFORM_DEFAULT_TIMEOUT = 15.0
BAP_SCOPE = "https://service.powerapps.com//.default"
ALLOWED_METHODS = frozenset({"GET"})


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

    def get(self, path: str, *, api_version: str | None = None) -> Any:
        return self.request("GET", path, api_version=api_version)

    def request(self, method: str, path: str, *, api_version: str | None = None) -> Any:
        if method not in ALLOWED_METHODS:
            raise PowerPlatformError("method refused")
        if not self.token:
            raise PowerPlatformError("missing Power Platform admin token", status=401)
        if self.root != POWER_PLATFORM_ROOT or not same_origin(path, self.root) or self.token in path:
            raise PowerPlatformError("Power Platform request URL refused")
        url = urljoin(self.root + "/", path)
        params = None if "api-version" in parse_qs(urlsplit(url).query) else {
            "api-version": api_version or self.api_version,
        }
        try:
            response = self.session.request(
                method, url, params=params,
                headers={"Authorization": f"Bearer {self.token}", "accept": "application/json"},
                timeout=self.timeout, allow_redirects=False,
            )
        except Exception:  # Transport exceptions can contain headers; never retain their text.
            raise PowerPlatformError("Power Platform transport error") from None
        if not 200 <= response.status_code < 300:
            raise PowerPlatformError("Power Platform HTTP request failed", status=response.status_code)
        if not response.content or not response.content.strip():
            return None
        try:
            return response.json()
        except ValueError:
            raise PowerPlatformError("invalid JSON from Power Platform") from None


def http_error_class(status: int | None) -> str:
    if status in (401, 403):
        return "insufficient_permissions"
    if status in (404, 410, 429) or (isinstance(status, int) and 500 <= status <= 599):
        return "service_not_available"
    return "client_error"
