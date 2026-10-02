from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class ConditionalAccessCollector(Collector):
    name = "conditional_access"
    description = "Conditional Access policies, named locations, and advanced policy dependencies."
    required_permissions = [
        "Policy.Read.All",
        "Directory.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top", 500)
        page_size = context.get("page_size")

        queries = {
            "conditionalAccessPolicies": {
                "endpoint": "/identity/conditionalAccess/policies",
                "params": {},
            },
            "namedLocations": {
                "endpoint": "/identity/conditionalAccess/namedLocations",
                "params": {},
            },
            "authenticationStrengthPolicies": {
                "endpoint": "/policies/authenticationStrengthPolicies",
                "params": {},
                # Live tenants reject $top here ("Query option 'Top' is not allowed").
                "apply_top": False,
            },
            "authenticationContextClassReferences": {
                "endpoint": "/identity/conditionalAccess/authenticationContextClassReferences",
                "params": {},
                # Live tenants reject $top here ("Query option 'Top' is not allowed").
                "apply_top": False,
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
            message="conditional access collector completed with partial errors" if partial else "",
            coverage=coverage,
        )
