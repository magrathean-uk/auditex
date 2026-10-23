from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints


class AuthMethodsCollector(Collector):
    name = "auth_methods"
    description = "Authentication methods policy and registration posture."
    required_permissions = [
        "Policy.Read.All",
        "Reports.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        endpoints = {
            "authenticationMethodsPolicy": {
                "endpoint": "/policies/authenticationMethodsPolicy",
                "page": False,
                "params": {},
            },
            "userRegistrationDetails": {
                "endpoint": "/reports/authenticationMethods/userRegistrationDetails",
                "params": {
                    "$select": (
                        "id,userPrincipalName,userType,isAdmin,isMfaCapable,isMfaRegistered,"
                        "isPasswordlessCapable,isSsprEnabled"
                    ),
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
            message="Authentication methods collection partially completed" if partial else "",
            coverage=coverage,
        )
