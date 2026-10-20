from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class ServiceHealthCollector(Collector):
    name = "service_health"
    description = "Microsoft 365 service health, issues, and message center posture."
    required_permissions = [
        "ServiceHealth.Read.All",
        "ServiceMessage.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "healthOverviews": {"endpoint": "/admin/serviceAnnouncement/healthOverviews", "params": {}},
                "serviceIssues": {"endpoint": "/admin/serviceAnnouncement/issues", "params": {}},
                "messages": {"endpoint": "/admin/serviceAnnouncement/messages", "params": {}},
            },
            top=context.get("top"),
            page_size=context.get("page_size"),
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
            message="Service health collector partially completed" if partial else "",
            coverage=coverage,
        )
