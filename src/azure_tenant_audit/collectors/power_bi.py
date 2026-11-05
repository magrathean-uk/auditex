"""Optional Power BI tenant settings, with explicit access-state evidence."""
from __future__ import annotations

import time
from typing import Any

from ..power_bi import power_bi_client_from
from ..power_platform import http_error_class
from .base import Collector, CollectorResult

TENANT_SETTINGS = "/v1/admin/tenantsettings"


class PowerBICollector(Collector):
    name = "power_bi"
    description = "Optional Power BI admin tenant settings and access state."
    required_permissions: list[str] = []

    def run(self, context: dict[str, Any]) -> CollectorResult:
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []

        def put(name: str, rows: list[Any], status: str, error_class: str | None = None,
                error: str | None = None, duration_ms: float = 0.0) -> None:
            payload[name] = {"value": rows, "status": status}
            coverage.append({
                "collector": self.name, "type": "powerbi", "name": name, "endpoint": TENANT_SETTINGS,
                "status": status, "item_count": len(rows), "duration_ms": duration_ms,
                "error_class": error_class, "error": error,
            })
            logger = context.get("audit_logger")
            if logger:
                logger("collector.endpoint.finished", "Collector endpoint request completed", {
                    "collector": self.name, "endpoint_name": name, "status": status,
                    "item_count": len(rows), "duration_ms": duration_ms, "error_class": error_class,
                })

        try:
            client = power_bi_client_from(context)
        except Exception:
            client = None
        if client is None or (hasattr(client, "token") and not client.token):
            for name in ("tenantSettings", "accessState"):
                put(name, [], "skipped", "service_not_available", "no Power BI admin token available")
        else:
            start = time.perf_counter()
            status = "ok"
            error_class = error = None
            http_status = None
            rows = []
            try:
                raw = client.get(TENANT_SETTINGS)
                http_status = getattr(client, "last_status", None)
                settings = raw.get("tenantSettings") if isinstance(raw, dict) else None
                if not isinstance(settings, list) or not settings or any(not isinstance(item, dict) for item in settings):
                    status, error_class, error = "failed", "incomplete_evidence", "Power BI tenant settings list missing or unusable"
                else:
                    rows = [self._setting(item) for item in settings]
            except Exception as exc:
                http_status = getattr(exc, "status", None) or getattr(client, "last_status", None)
                status, error_class, error = "failed", http_error_class(http_status), "Power BI read failed"
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            if type(http_status) is not int:
                http_status = None
            put("tenantSettings", rows, status, error_class, error, duration_ms)
            put("accessState", [{"denied": http_status in (401, 403), "http_status": http_status}], "ok", duration_ms=duration_ms)
        partial = any(row["status"] != "ok" for row in coverage)
        return CollectorResult(
            name=self.name, status="partial" if partial else "ok", payload=payload,
            item_count=sum(row["item_count"] for row in coverage), coverage=coverage,
            message="Power BI collection incomplete" if partial else "",
        )

    @staticmethod
    def _setting(item: dict[str, Any]) -> dict[str, Any]:
        row = {key: item[key] for key in ("settingName", "enabled", "enabledSecurityGroups") if key in item}
        groups = row.get("enabledSecurityGroups")
        if isinstance(groups, list):
            row["enabledSecurityGroups"] = [
                ({"graphId": group["graphId"]} if "graphId" in group else {}) if isinstance(group, dict) else group
                for group in groups
            ]
        return row
