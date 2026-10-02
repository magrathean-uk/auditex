from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class ConsentPolicyCollector(Collector):
    name = "consent_policy"
    description = "Admin consent workflow, user consent, and permission grant policy posture."
    required_permissions = [
        "Policy.Read.All",
        "Directory.Read.All",
        "Policy.Read.PermissionGrant",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        payload, coverage = run_graph_endpoints(
            self.name,
            client,
            {
                "adminConsentRequestPolicy": {"endpoint": "/policies/adminConsentRequestPolicy", "page": False, "params": {}},
                "permissionGrantPolicies": {"endpoint": "/policies/permissionGrantPolicies", "params": {}},
                "authorizationPolicy": {"endpoint": "/policies/authorizationPolicy", "page": False, "params": {}},
            },
            top=context.get("top", 100),
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
            message="Consent policy collector partially completed" if partial else "",
            coverage=coverage,
        )
