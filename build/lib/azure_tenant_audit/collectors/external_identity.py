from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class ExternalIdentityCollector(Collector):
    name = "external_identity"
    description = "Cross-tenant access, invitation policy, and authentication flow posture."
    required_permissions = [
        "Policy.Read.All",
        "Directory.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "crossTenantAccessPolicy": {"endpoint": "/policies/crossTenantAccessPolicy", "page": False, "params": {}},
                "authorizationPolicy": {"endpoint": "/policies/authorizationPolicy", "page": False, "params": {}},
                "authenticationFlowsPolicy": {"endpoint": "/policies/authenticationFlowsPolicy", "page": False, "params": {}},
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
            message="External identity collector partially completed" if partial else "",
            coverage=coverage,
        )
