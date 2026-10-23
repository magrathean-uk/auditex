from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class SharePointCollector(Collector):
    name = "sharepoint"
    description = "SharePoint and OneDrive tenant posture."
    required_permissions = [
        "Sites.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        endpoints = {
            "sharePointSettings": {
                "endpoint": "/admin/sharepoint/settings",
                "page": False,
                "params": {},
            },
            "sites": {
                "endpoint": "/sites",
                "params": {
                    "$select": "id,name,webUrl,createdDateTime",
                },
            },
        }
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            endpoints,
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
            message="SharePoint collection partially completed" if partial else "",
            coverage=coverage,
        )
