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
        "ReportSettings.Read.All",
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client: GraphClient = context["client"]
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {}
        payload["concealed_names"] = self._read_report_settings(client, payload, coverage)
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
        if payload.get("concealed_names") is True:
            for name in report_endpoints:
                section = payload.get(name)
                if isinstance(section, dict) and "value" in section:
                    section["concealed_names"] = True
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

    def _read_report_settings(
        self,
        client: GraphClient,
        payload: dict[str, Any],
        coverage: list[dict[str, Any]],
    ) -> bool | None:
        """Read /admin/reportSettings before the reports.

        When displayConcealedNames is true, Microsoft 365 usage reports replace user,
        group, and site names with hashes, so per-user report rows cannot be tied to
        identities. Returns None when the setting could not be read.
        """
        endpoint = "/admin/reportSettings"
        start = time.perf_counter()
        try:
            response = client.get_json(endpoint)
            settings = response if isinstance(response, dict) else {}
            concealed = settings.get("displayConcealedNames")
            concealed_names = concealed if isinstance(concealed, bool) else None
            payload["reportSettings"] = {
                "value": [{"id": "reportSettings", "displayConcealedNames": concealed_names}]
            }
            coverage.append(
                {
                    "collector": self.name,
                    "type": "graph",
                    "name": "reportSettings",
                    "endpoint": endpoint,
                    "api_version": "v1.0",
                    "status": "ok",
                    "item_count": 1,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                    "error_class": None,
                    "error": None,
                }
            )
            return concealed_names
        except Exception as exc:  # noqa: BLE001
            error_class, error = _classify_graph_error(exc)
            payload["reportSettings"] = {"error": error, "error_class": error_class}
            coverage.append(
                {
                    "collector": self.name,
                    "type": "graph",
                    "name": "reportSettings",
                    "endpoint": endpoint,
                    "api_version": "v1.0",
                    "status": "failed",
                    "item_count": 0,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                    "error_class": error_class,
                    "error": error,
                    "coverage_note": "Report privacy setting unknown; usage report names may be hashed.",
                }
            )
            return None
