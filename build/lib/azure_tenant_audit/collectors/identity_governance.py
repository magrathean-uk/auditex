from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class IdentityGovernanceCollector(Collector):
    name = "identity_governance"
    description = "Identity governance, entitlement management, and privileged schedule inventory."
    required_permissions = [
        "AccessReview.Read.All",
        "EntitlementManagement.Read.All",
        "RoleManagement.Read.Directory",
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
                "accessReviews": {
                    "endpoint": "/identityGovernance/accessReviews/definitions",
                    "params": {},
                },
                "entitlementCatalogs": {
                    "endpoint": "/identityGovernance/entitlementManagement/catalogs",
                    "params": {},
                },
                "accessPackages": {
                    "endpoint": "/identityGovernance/entitlementManagement/accessPackages",
                    "params": {},
                },
                "roleAssignmentSchedules": {
                    "endpoint": "/roleManagement/directory/roleAssignmentSchedules",
                    "params": {},
                },
                "roleEligibilitySchedules": {
                    "endpoint": "/roleManagement/directory/roleEligibilitySchedules",
                    "params": {},
                },
                "administrativeUnits": {
                    "endpoint": "/directory/administrativeUnits",
                    "params": {
                        "$select": "id,displayName,description",
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
            message="Identity governance collector partially completed" if partial else "",
            coverage=coverage,
        )
