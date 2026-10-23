"""Minimal client for the Power Platform admin (BAP) API.

This client is intentionally thin: it only knows how to authenticate against
the Power Platform admin endpoint, fetch JSON, and surface transport errors.
The collector is responsible for shaping the data, applying capability gating,
and translating authentication or licensing failures into structured
diagnostics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import requests


POWER_PLATFORM_ROOT = "https://api.bap.microsoft.com"
POWER_PLATFORM_DEFAULT_API_VERSION = "2020-10-01"
POWER_PLATFORM_DEFAULT_TIMEOUT = 15.0


class PowerPlatformError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, request: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.request = request


@dataclass
class PowerPlatformClient:
    token: Optional[str] = None
    api_version: str = POWER_PLATFORM_DEFAULT_API_VERSION
    session: Any = field(default_factory=requests.Session)
    timeout: float = POWER_PLATFORM_DEFAULT_TIMEOUT
    root: str = POWER_PLATFORM_ROOT

    def get(self, path: str) -> Any:
        if not self.token:
            raise PowerPlatformError("missing power platform admin token", status=401, request=path)
        url = path if path.startswith("http") else f"{self.root}{path}"
        params = {"api-version": self.api_version} if "api-version" not in url else None
        try:
            response = self.session.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {self.token}", "accept": "application/json"},
                timeout=self.timeout,
            )
        except Exception as exc:  # noqa: BLE001
            raise PowerPlatformError(f"transport error: {exc}", request=path) from exc
        if response.status_code in (401, 403):
            raise PowerPlatformError(
                f"power platform request denied: {response.status_code}",
                status=response.status_code,
                request=path,
            )
        if response.status_code == 404:
            raise PowerPlatformError(
                f"power platform endpoint not found: {response.status_code}",
                status=response.status_code,
                request=path,
            )
        if response.status_code >= 400:
            raise PowerPlatformError(
                f"power platform request failed: {response.status_code}",
                status=response.status_code,
                request=path,
            )
        try:
            return response.json()
        except ValueError as exc:
            raise PowerPlatformError(f"invalid JSON from power platform: {exc}", request=path) from exc
