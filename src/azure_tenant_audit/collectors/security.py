from __future__ import annotations

from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, run_graph_endpoints

# Most recent events kept per Entra log when the operator sets no row limit.
LOG_SAMPLE_LIMIT = 500


class SecurityCollector(Collector):
    name = "security"
    description = "Sign-in and directory audit signals from Microsoft Graph."
    required_permissions = [
        "AuditLog.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        top = context.get("top")
        page_size = context.get("page_size")
        since = context.get("since")
        until = context.get("until")
        filter_clauses: list[str] = []
        if since:
            filter_clauses.append(f"createdDateTime ge {since}")
        if until:
            filter_clauses.append(f"createdDateTime le {until}")
        sign_in_params = {"$filter": " and ".join(filter_clauses)} if filter_clauses else {}
        directory_filter_clauses: list[str] = []
        if since:
            directory_filter_clauses.append(f"activityDateTime ge {since}")
        if until:
            directory_filter_clauses.append(f"activityDateTime le {until}")
        directory_audit_params = {"$filter": " and ".join(directory_filter_clauses)} if directory_filter_clauses else {}
        queries = {
            # Event logs are the most recent events, a sample by design: without --since/--until an
            # unbounded read of a large tenant's logs is not practical. An explicit --top below the
            # sample size is still recorded as a coverage gap.
            "signIns": {
                "endpoint": "/auditLogs/signIns",
                "params": sign_in_params,
                "sample_limit": LOG_SAMPLE_LIMIT,
            },
            "directoryAudits": {
                "endpoint": "/auditLogs/directoryAudits",
                "params": directory_audit_params,
                "sample_limit": LOG_SAMPLE_LIMIT,
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
            message="security collector completed with partial errors" if partial else "",
            coverage=coverage,
        )

    @staticmethod
    def _safe_count(payload: dict[str, Any]) -> int:
        if not payload or "value" not in payload:
            return 0
        return len(payload["value"]) if isinstance(payload["value"], list) else 0
