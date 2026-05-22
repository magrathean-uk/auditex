from __future__ import annotations

import csv
from io import StringIO
import time
from typing import Any

from ..graph import GraphClient
from .base import Collector, CollectorResult, _classify_graph_error, apply_collection_limit, normalize_collection_limit


def _parse_csv_rows(content: str) -> list[dict[str, str]]:
    if not content.strip():
        return []
    reader = csv.DictReader(StringIO(content))
    return [dict(row) for row in reader]


class ReportsUsageCollector(Collector):
    name = "reports_usage"
    description = "Microsoft 365 usage report samples for Exchange, SharePoint, and OneDrive."
    required_permissions = [
        "Reports.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {}
        report_endpoints = {
            "office365ActiveUserCounts": "/reports/getOffice365ActiveUserCounts(period='D30')",
            "sharePointSiteUsageDetail": "/reports/getSharePointSiteUsageDetail(period='D30')",
            "oneDriveUsageAccountDetail": "/reports/getOneDriveUsageAccountDetail(period='D30')",
            "mailboxUsageDetail": "/reports/getMailboxUsageDetail(period='D30')",
        }
        for name, endpoint in report_endpoints.items():
            start = time.perf_counter()
            try:
                content = client.get_content(endpoint)
                rows = apply_collection_limit(
                    _parse_csv_rows(content),
                    normalize_collection_limit(context.get("top"), default=100),
                )
                payload[name] = {"value": rows}
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": name,
                        "endpoint": endpoint,
                        "status": "ok",
                        "item_count": len(rows),
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": None,
                        "error": None,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                error_class, error = _classify_graph_error(exc)
                payload[name] = {"error": error, "error_class": error_class}
                coverage.append(
                    {
                        "collector": self.name,
                        "type": "graph",
                        "name": name,
                        "endpoint": endpoint,
                        "status": "failed",
                        "item_count": 0,
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        "error_class": error_class,
                        "error": error,
                    }
                )
        total = sum(item.get("item_count", 0) for item in coverage)
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Reports usage collector partially completed" if partial else "",
            coverage=coverage,
        )
