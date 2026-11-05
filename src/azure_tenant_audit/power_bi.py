"""GET-only commercial Power BI admin metadata client."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import requests

from .power_platform import same_origin

POWERBI_ROOT = "https://api.powerbi.com"
POWERBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"


class PowerBIError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def power_bi_client_from(context: dict[str, Any]) -> PowerBIClient | None:
    if "power_bi_client" in context:
        return context["power_bi_client"]
    graph = context.get("client")
    token = graph.app_token_for(POWERBI_SCOPE) if hasattr(graph, "app_token_for") else None
    return PowerBIClient(token=token) if token else None


@dataclass
class PowerBIClient:
    token: str | None = field(default=None, repr=False)
    session: Any = field(default_factory=requests.Session, repr=False)
    timeout: float = 15.0
    root: str = POWERBI_ROOT
    last_status: int | None = field(default=None, init=False)

    def get(self, path: str) -> Any:
        self.last_status = None
        if not self.token:
            raise PowerBIError("missing Power BI admin token", status=401)
        if self.root != POWERBI_ROOT or not same_origin(path, self.root) or self.token in path:
            raise PowerBIError("Power BI request URL refused")
        try:
            response = self.session.get(
                urljoin(self.root + "/", path),
                headers={"Authorization": f"Bearer {self.token}", "accept": "application/json"},
                timeout=self.timeout, allow_redirects=False,
            )
        except Exception:
            raise PowerBIError("Power BI transport error") from None
        self.last_status = response.status_code
        if not 200 <= response.status_code < 300:
            raise PowerBIError("Power BI HTTP request failed", status=response.status_code)
        try:
            return response.json()
        except ValueError:
            raise PowerBIError("invalid JSON from Power BI", status=response.status_code) from None
