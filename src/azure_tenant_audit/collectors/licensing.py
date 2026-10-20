from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class LicensingCollector(Collector):
    name = "licensing"
    description = "Subscribed SKUs plus sampled direct and group-based licensing posture."
    required_permissions = [
        "Organization.Read.All",
        "Directory.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "subscribedSkus": {
                    "endpoint": "/subscribedSkus",
                    "params": {},
                    "page": False,
                    "apply_top": False,
                },
                "licensedUsers": {
                    "endpoint": "/users",
                    "params": {
                        "$select": "id,displayName,userPrincipalName,assignedLicenses,licenseAssignmentStates",
                    },
                },
                "licensedGroups": {
                    "endpoint": "/groups",
                    "params": {
                        "$select": "id,displayName,assignedLicenses",
                    },
                },
            },
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
            message="Licensing collector partially completed" if partial else "",
            coverage=coverage,
        )
