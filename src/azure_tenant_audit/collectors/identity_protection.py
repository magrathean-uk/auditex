"""Capability-gated collector: is Microsoft Entra ID Protection risk detection available?

Reads one page of ``GET /identityProtection/riskyUsers`` (Graph v1.0, read-only,
``IdentityRiskyUser.Read.All``, Microsoft Entra ID P2) and keeps only aggregate
counts. User names, UPNs, and object ids are never written to the bundle.
https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0
"""
from __future__ import annotations

import time
from collections import Counter
from typing import Any

from .base import Collector, CollectorResult, _classify_graph_error

RISKY_USERS_ENDPOINT = "/identityProtection/riskyUsers"
RISKY_USERS_PAGE_SIZE = 500


class IdentityProtectionCollector(Collector):
    name = "identity_protection"
    description = (
        "Microsoft Entra ID Protection availability: aggregate risky-user counts only "
        "(capability-gated; Entra ID P2 required)."
    )
    required_permissions = ["IdentityRiskyUser.Read.All"]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        log_event = context.get("audit_logger")
        params = {"$select": "id,riskLevel,riskState", "$top": str(RISKY_USERS_PAGE_SIZE)}
        start = time.perf_counter()
        status = "ok"
        error_class: str | None = None
        error: str | None = None
        rows: list[dict[str, Any]] = []
        if client is None or not hasattr(client, "get_json"):
            status = "skipped"
            error_class = "service_not_available"
            error = "no Graph client available"
        else:
            try:
                response = client.get_json(RISKY_USERS_ENDPOINT, params=params)
                values = response.get("value") if isinstance(response, dict) else None
                rows = [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []
            except Exception as exc:  # noqa: BLE001
                status = "failed"
                error_class, error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        payload: dict[str, Any] = {}
        if status == "ok":
            payload["riskyUserSummary"] = {"value": [summarize_risky_users(rows)]}
        else:
            payload["riskyUserSummary"] = {"error": error, "error_class": error_class, "value": []}
        coverage = [
            {
                "collector": self.name,
                "type": "graph",
                "name": "riskyUserSummary",
                "endpoint": RISKY_USERS_ENDPOINT,
                "status": status,
                "item_count": 1 if status == "ok" else 0,
                "duration_ms": duration_ms,
                "error_class": error_class,
                "error": error,
            }
        ]
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": self.name,
                    "endpoint_name": "riskyUserSummary",
                    "status": status,
                    "item_count": coverage[0]["item_count"],
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )
        return CollectorResult(
            name=self.name,
            status="ok" if status == "ok" else "partial",
            payload=payload,
            item_count=coverage[0]["item_count"],
            message="" if status == "ok" else "Identity Protection not readable; check licensing and permission",
            coverage=coverage,
        )


def summarize_risky_users(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate a page of riskyUser rows into counts without identities."""
    states = Counter(str(item.get("riskState") or "unknown") for item in rows)
    levels = Counter(str(item.get("riskLevel") or "unknown") for item in rows)
    return {
        "id": "summary",
        "available": True,
        "sampled_count": len(rows),
        "sample_limit": RISKY_USERS_PAGE_SIZE,
        "at_risk_count": states.get("atRisk", 0) + states.get("confirmedCompromised", 0),
        "risk_state_counts": dict(sorted(states.items())),
        "risk_level_counts": dict(sorted(levels.items())),
    }
