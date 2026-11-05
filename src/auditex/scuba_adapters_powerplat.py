"""Read-only C1 bundle adapters for Power Platform and Power BI rule evidence.

Values remain type-faithful so the rules can distinguish unusable settings from
failed collection. Bundle scans must finish before any derived flag is trusted.
"""
from __future__ import annotations

import re
from typing import Any

from .scuba_projection import Bundle, Unavailable, _plans, _require


POWERBI_PLAN = re.compile(r"(POWER_BI|BI_AZURE_P_?[0-9]|PBI_PREMIUM|FABRIC)", re.I)
# ScubaGear's sentinel has not been confirmed against a never-configured tenant.
NEVER_CONFIRMED_NULL_SENTINEL = False
_CREATION_FIELDS = {
    "disableEnvironmentCreationByNonAdminUsers",
    "disableTrialEnvironmentCreationByNonAdminUsers",
    "disablePortalsCreationByNonAdminUsers",
    "powerPlatform",
}


def _environment_creation(bundle: Bundle) -> list[dict[str, Any]]:
    rows = list(bundle.scan("power_platform", "environmentCreation"))
    _require(bool(rows), "environmentCreation", "missing_field")
    result = []
    for row in rows:
        bundle.known_fields(row, _CREATION_FIELDS)
        _require(bool(row.keys() & _CREATION_FIELDS), "environmentCreation", "missing_field")
        result.append({key: value for key, value in row.items() if key in _CREATION_FIELDS})
    return result


def _tenant_isolation(bundle: Bundle) -> list[Any]:
    rows = list(bundle.scan("power_platform", "tenantIsolation"))
    result = []
    for row in rows:
        bundle.known_fields(row, {"properties", "never_configured"})
        if row.get("never_configured") is True:
            if not NEVER_CONFIRMED_NULL_SENTINEL:
                raise Unavailable("tenant_isolation_unconfirmed")
            result.append("null")
            continue
        _require("properties" in row, "properties", "missing_field")
        props = row["properties"]
        bundle.known_fields(props, {"isDisabled"}, "properties")
        _require("isDisabled" in props, "properties.isDisabled", "missing_field")
        result.append({"properties": {"isDisabled": props["isDisabled"]}})
    return result


def _dlp_policies(bundle: Bundle) -> list[dict[str, Any]]:
    return [{"value": list(bundle.scan("power_platform", "dlpPolicyScopes"))}]


def _environment_list(bundle: Bundle) -> list[dict[str, Any]]:
    return [{"EnvironmentName": row.get("name"), "IsDefault": row.get("is_default")}
            for row in bundle.scan("power_platform", "environments")]


def _powerbi_tenant_settings(bundle: Bundle) -> list[dict[str, Any]]:
    return list(bundle.scan("power_bi", "tenantSettings"))


def _powerbi_license_found(bundle: Bundle) -> bool:
    # _plans consumes the complete scan, including late errors, before any().
    return any(POWERBI_PLAN.search(plan["ServicePlanName"]) for plan in _plans(bundle))


def _powerbi_access_denied_reason(bundle: Bundle) -> str:
    rows = list(bundle.scan("power_bi", "accessState"))
    _require(bool(rows), "accessState", "missing_field")
    _require(len(rows) == 1, "accessState")
    row = rows[0]
    bundle.known_fields(row, {"denied", "http_status"})
    _require("denied" in row, "denied", "missing_field")
    _require(type(row["denied"]) is bool, "denied", "invalid_type")
    if not row["denied"]:
        return ""
    status = row.get("http_status")
    _require(type(status) is int and status in {401, 403}, "http_status", "invalid_type")
    return f"Power BI Admin API denied access (HTTP {status})"


ADAPTERS = {
    "environment_creation": _environment_creation,
    "tenant_isolation": _tenant_isolation,
    "dlp_policies": _dlp_policies,
    "environment_list": _environment_list,
    "powerbi_tenant_settings": _powerbi_tenant_settings,
    "powerbi_license_found": _powerbi_license_found,
    "powerbi_access_denied_reason": _powerbi_access_denied_reason,
}
