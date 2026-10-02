from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class DefenderCollector(Collector):
    name = "defender"
    description = "Defender alerts, incidents, and security score posture from Microsoft Graph."
    required_permissions = [
        "SecurityAlert.Read.All",
        "SecurityEvents.Read.All",
        "SecurityIncident.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        page_size = context.get("page_size")
        since = context.get("since")
        until = context.get("until")

        time_filter_clauses: list[str] = []
        if since:
            time_filter_clauses.append(f"createdDateTime ge {since}")
        if until:
            time_filter_clauses.append(f"createdDateTime le {until}")
        query_params = {"$filter": " and ".join(time_filter_clauses)} if time_filter_clauses else {}

        queries = {
            "securityAlerts": {
                "endpoint": "/security/alerts_v2",
                "params": query_params,
                "min_top": 1,
            },
            "defenderIncidents": {
                "endpoint": "/security/incidents",
                "params": query_params,
            },
            "secureScores": {
                "endpoint": "/security/secureScores",
                "params": {},
                "page": False,
            },
            "secureScoreControlProfiles": {
                "endpoint": "/security/secureScoreControlProfiles",
                "params": {},
                "page": False,
            },
        }

        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            queries,
            top=top,
            page_size=page_size,
            chunk_writer=context.get("chunk_writer"),
            log_event=context.get("audit_logger"),
        )

        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="defender collector completed with partial errors" if partial else "",
            coverage=coverage,
        )
