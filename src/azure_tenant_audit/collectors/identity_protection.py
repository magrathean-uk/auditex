"""Capability-gated collector: is Microsoft Entra ID Protection risk detection available?

Reads ``GET /identityProtection/riskyUsers`` (Graph v1.0, read-only,
``IdentityRiskyUser.Read.All``, Microsoft Entra ID P2), following the next-page link to
the last row, and keeps only aggregate counts. User names, UPNs, and object ids are never
written to the bundle. A page that cannot be read leaves the summary cut and marked so.
https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0
"""
from __future__ import annotations

import time
from collections import Counter
from typing import Any

from ..collection_gaps import REASON_PAGINATION_FAILED, REASON_PAGINATION_NOT_FOLLOWED
from .base import Collector, CollectorResult, _classify_graph_error, record_truncation

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
        cut_reason: str | None = None
        if client is None or not hasattr(client, "get_json"):
            status = "skipped"
            error_class = "service_not_available"
            error = "no Graph client available"
        else:
            try:
                response = client.get_json(RISKY_USERS_ENDPOINT, params=params)
                values = response.get("value") if isinstance(response, dict) else None
                rows = [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []
                next_link = response.get("@odata.nextLink") if isinstance(response, dict) else None
                if isinstance(next_link, str) and next_link:
                    if hasattr(client, "iter_items"):
                        try:
                            rows.extend(item for item in client.iter_items(next_link) if isinstance(item, dict))
                        except Exception as exc:  # noqa: BLE001
                            # A later page failed: the rows read so far are a cut summary, never the whole list.
                            cut_reason = REASON_PAGINATION_FAILED
                            error_class, error = _classify_graph_error(exc)
                    else:
                        cut_reason = REASON_PAGINATION_NOT_FOLLOWED
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
                "error_class": error_class if status != "ok" else None,
                "error": error if status != "ok" else None,
            }
        ]
        if status == "ok" and cut_reason:
            row = coverage[0]
            if cut_reason == REASON_PAGINATION_FAILED:
                # Keep the failure the page read carries; record_truncation only marks the cut.
                row.update(status="failed", error_class=error_class, error=error)
            record_truncation(row, list_name="riskyUserSummary", rows=len(rows), limit=None, reason=cut_reason)
            payload["riskyUserSummary"].update({"collection_truncated": True, "truncation_reason": cut_reason})
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
            status="ok" if coverage[0]["status"] == "ok" else "partial",
            payload=payload,
            item_count=coverage[0]["item_count"],
            message="" if coverage[0]["status"] == "ok" else "Identity Protection not readable in full; check licensing and permission",
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
