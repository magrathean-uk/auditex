"""Inert, capability-gated Power Platform admin metadata collection."""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..collection_gaps import REASON_PAGINATION_FAILED, REASON_PAGINATION_NOT_FOLLOWED
from ..power_platform import (
    POWER_PLATFORM_ROOT, PowerPlatformClient, http_error_class, power_platform_client_from, same_origin,
)
from .base import Collector, CollectorResult, record_truncation

MAX_LIST_PAGES = 50
TENANT_SETTINGS_METHOD = "GET"
ENVIRONMENTS = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2023-06-01"
DLP_POLICIES = "/providers/PowerPlatform.Governance/v2/policies?api-version=2020-10-01"
DLP_SCOPES = "/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01"
TENANT_SETTINGS = "/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2023-06-01"
TENANT_ISOLATION = "/providers/PowerPlatform.Governance/v1/tenants/{TenantId}/tenantIsolationPolicy?api-version=2020-06-01"
OPERATIONS = {
    "environments": ENVIRONMENTS, "dlpPolicies": DLP_POLICIES, "dlpPolicyScopes": DLP_SCOPES,
    "tenantSettings": TENANT_SETTINGS, "environmentCreation": TENANT_SETTINGS, "tenantIsolation": TENANT_ISOLATION,
}
_GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")


def _status(status: str = "ok", error_class: str | None = None, error: str | None = None) -> dict[str, Any]:
    return {"status": status, "duration_ms": 0.0, "error_class": error_class, "error": error}


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class PowerPlatformCollector(Collector):
    name = "power_platform"
    description = "Optional Power Platform environments, DLP policy scopes and tenant settings."
    required_permissions: list[str] = []

    def run(self, context: dict[str, Any]) -> CollectorResult:
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {}

        def put(name: str, rows: list[Any], status: dict[str, Any], cut: str | None = None,
                endpoint: str | None = None) -> None:
            row = self._coverage_row(name, endpoint or OPERATIONS[name], status, len(rows))
            envelope = {"value": rows, "status": row["status"]}
            if cut:
                record_truncation(row, list_name=name, rows=len(rows), limit=None, reason=cut)
                envelope.update(status=row["status"], collection_truncated=True, truncation_reason=cut)
            coverage.append(row)
            payload[name] = envelope
            logger = context.get("audit_logger")
            if logger:
                logger("collector.endpoint.finished", "Collector endpoint request completed", {
                    "collector": self.name, "endpoint_name": name, "status": row["status"],
                    "item_count": len(rows), "duration_ms": row["duration_ms"], "error_class": row["error_class"],
                })

        try:
            client = power_platform_client_from(context)
        except Exception:
            client = None
        if client is None or (hasattr(client, "token") and not client.token):
            for name in OPERATIONS:
                put(name, [], _status("skipped", "service_not_available", "no Power Platform admin token available"))
        else:
            for name, shape in (("environments", self._environment), ("dlpPolicies", self._dlp_policy),
                                ("dlpPolicyScopes", self._dlp_scope)):
                path = OPERATIONS[name]
                api_version = parse_qs(urlsplit(path).query)["api-version"][0]
                items, status, cut = self._safe_get_all(client, path, api_version=api_version)
                try:
                    rows = [shape(item) for item in items or [] if isinstance(item, dict)]
                except (TypeError, ValueError):
                    rows = []
                    status.update(status="failed", error_class="incomplete_evidence", error="list item structure unusable")
                put(name, rows, status, cut)

            raw, status = self._safe_get(client, TENANT_SETTINGS, method=TENANT_SETTINGS_METHOD)
            if status["status"] == "ok" and not isinstance(raw, dict):
                status.update(status="failed", error_class="incomplete_evidence", error="tenant settings object missing")
            settings = []
            creation = []
            if status["status"] == "ok":
                settings = [{
                    "is_power_apps_enabled": raw.get("isPowerAppsEnabled"),
                    "is_power_automate_enabled": raw.get("isPowerAutomateEnabled"),
                    "is_dataverse_enabled": raw.get("isDataverseEnabled"),
                }]
                creation = [self._environment_creation(raw)]
            put("tenantSettings", settings, status)
            put("environmentCreation", creation, status)

            tenant_id = None
            graph = context.get("client")
            if hasattr(graph, "get_all"):
                try:
                    organisations = graph.get_all("/organization", params={"$select": "id"})
                    if isinstance(organisations, list) and len(organisations) == 1:
                        candidate = _object(organisations[0]).get("id")
                        if isinstance(candidate, str) and _GUID.fullmatch(candidate):
                            tenant_id = candidate
                except Exception:
                    pass  # Never retain Graph errors or credentials in this collector's diagnostics.
            if tenant_id is None:
                put("tenantIsolation", [], _status("failed", "missing_argument", "canonical tenant GUID unavailable"))
            else:
                endpoint = TENANT_ISOLATION.replace("{TenantId}", tenant_id)
                raw, status = self._safe_get(client, endpoint)
                rows = []
                if status["status"] == "ok":
                    if raw is None:
                        rows = [{"never_configured": True}]
                    elif isinstance(raw, dict):
                        properties = _object(raw.get("properties"))
                        rows = [{"properties": {"isDisabled": properties["isDisabled"]} if "isDisabled" in properties else {}}]
                    else:
                        status.update(status="failed", error_class="incomplete_evidence", error="tenant isolation object missing")
                put("tenantIsolation", rows, status)

        partial = any(row["status"] != "ok" for row in coverage)
        return CollectorResult(
            name=self.name, status="partial" if partial else "ok", payload=payload,
            item_count=sum(row["item_count"] for row in coverage), coverage=coverage,
            message="Power Platform collection incomplete" if partial else "",
        )

    @staticmethod
    def _environment(env: dict[str, Any]) -> dict[str, Any]:
        properties = _object(env.get("properties"))
        return {
            "id": env.get("id") or env.get("name"), "name": env.get("name"),
            "environment_sku": properties.get("environmentSku"),
            "is_default": properties.get("isDefault"), "created_time": properties.get("createdTime"),
        }

    @staticmethod
    def _dlp_policy(policy: dict[str, Any]) -> dict[str, Any]:
        counts = {"business": 0, "nonbusiness": 0, "blocked": 0}
        for group in policy.get("connectorGroups", []) or []:
            if isinstance(group, dict):
                classification = str(group.get("classification") or "").lower()
                if classification in counts:
                    counts[classification] += len(group.get("connectors") or [])
        return {
            "id": policy.get("name") or policy.get("id"), "display_name": policy.get("displayName"),
            "environment_type": policy.get("environmentType"), "business_connector_count": counts["business"],
            "non_business_connector_count": counts["nonbusiness"], "blocked_connector_count": counts["blocked"],
        }

    @staticmethod
    def _dlp_scope(policy: dict[str, Any]) -> dict[str, Any]:
        properties = _object(policy.get("properties"))
        constraint = _object(_object(properties.get("definition")).get("constraints")).get("environmentFilter1")
        row = {}
        if "name" in policy:
            row["name"] = policy["name"]
        if "displayName" in properties:
            row["displayName"] = properties["displayName"]
        if constraint is None:
            row.update(environmentType="AllEnvironments", environments=[])
        else:
            parameters = _object(_object(constraint).get("parameters"))
            filter_type = parameters.get("filterType")
            row["environmentType"] = {"include": "OnlyEnvironments", "exclude": "ExceptEnvironments"}.get(
                filter_type.lower() if isinstance(filter_type, str) else None
            )
            if "environments" in parameters:
                environments = parameters["environments"]
                if not isinstance(environments, list):
                    raise ValueError("DLP scope environments must be a list")
                row["environments"] = [
                    ({"name": env["name"]} if "name" in env else {}) if isinstance(env, dict) else env
                    for env in environments
                ]
        return row

    @staticmethod
    def _environment_creation(raw: dict[str, Any]) -> dict[str, Any]:
        row = {key: raw[key] for key in (
            "disableEnvironmentCreationByNonAdminUsers", "disableTrialEnvironmentCreationByNonAdminUsers",
            "disablePortalsCreationByNonAdminUsers",
        ) if key in raw}
        platform = _object(raw.get("powerPlatform"))
        apps = _object(platform.get("powerApps"))
        if "disableShareWithEveryone" in apps:
            row["powerPlatform"] = {"powerApps": {"disableShareWithEveryone": apps["disableShareWithEveryone"]}}
        return row

    @staticmethod
    def _safe_get(client: PowerPlatformClient, path: str, *, method: str | None = None,
                  api_version: str | None = None) -> tuple[Any, dict[str, Any]]:
        start = time.perf_counter()
        try:
            kwargs = {"api_version": api_version} if api_version is not None else {}
            raw = client.get(path, **kwargs) if method is None else client.request(method, path, **kwargs)
            status = _status()
        except Exception as exc:
            raw = None
            status = _status("failed", http_error_class(getattr(exc, "status", None)), "Power Platform read failed")
        status["duration_ms"] = round((time.perf_counter() - start) * 1000, 2)
        return raw, status

    @classmethod
    def _safe_get_all(cls, client: PowerPlatformClient, path: str, *,
                      api_version: str) -> tuple[list[Any] | None, dict[str, Any], str | None]:
        raw, status = cls._safe_get(client, path, api_version=api_version)
        if status["status"] != "ok":
            return None, status, None
        items: list[Any] = []
        pages = 0
        while True:
            if not isinstance(raw, dict) or not isinstance(raw.get("value"), list):
                status.update(status="failed", error_class="incomplete_evidence", error="list response missing")
                return items, status, REASON_PAGINATION_FAILED if pages else None
            items.extend(raw["value"])
            pages += 1
            next_link = raw.get("nextLink") or raw.get("@odata.nextLink")
            if not next_link:
                return items, status, None
            if not isinstance(next_link, str) or not same_origin(next_link, POWER_PLATFORM_ROOT):
                status.update(status="failed", error_class="client_error", error="pagination URL refused")
                return items, status, REASON_PAGINATION_FAILED
            if pages >= MAX_LIST_PAGES:
                return items, status, REASON_PAGINATION_NOT_FOLLOWED
            raw, page_status = cls._safe_get(client, next_link, api_version=api_version)
            status["duration_ms"] += page_status["duration_ms"]
            if page_status["status"] != "ok":
                status.update(status="failed", error_class=page_status["error_class"], error=page_status["error"])
                return items, status, REASON_PAGINATION_FAILED

    def _coverage_row(self, name: str, endpoint: str, status: dict[str, Any], item_count: int) -> dict[str, Any]:
        return {"collector": self.name, "type": "bap", "name": name, "endpoint": endpoint,
                "item_count": item_count, **status}
