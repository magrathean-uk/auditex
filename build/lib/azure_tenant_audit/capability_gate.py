from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any


BLOCKER_KINDS = (
    "none",
    "auth_scope",
    "admin_role",
    "license",
    "service_absent",
    "local_tool",
    "tenant_policy",
    "runtime",
    "unverified",
)


_TRUSTED_STATUSES = {
    "supported",
    "supported_exact_scope",
    "supported_effective_role",
    "supported_equivalent_scope",
    "offline_sample",
    "not_applicable",
}


# Intune answers 401/403 {"ErrorCode":"Forbidden"} both when the token lacks
# DeviceManagement scopes and when the tenant has no Intune licence. Licensing data
# (subscribedSkus) disambiguates the two.
INTUNE_COLLECTORS = frozenset({"intune", "intune_depth"})
_INTUNE_SERVICE_PLAN_PREFIXES = ("INTUNE",)
_INTUNE_SKU_PART_NUMBERS = frozenset(
    {
        "EMS",
        "EMSPREMIUM",
        "EMS_EDU",
        "SPE_E3",
        "SPE_E5",
        "SPE_F1",
        "SPE_E3_USGOV_DOD",
        "SPE_E3_USGOV_GCCHIGH",
        "SPB",
        "M365EDU_A3_FACULTY",
        "M365EDU_A3_STUDENT",
        "M365EDU_A5_FACULTY",
        "M365EDU_A5_STUDENT",
        "INTUNE_A",
        "INTUNE_A_D",
        "INTUNE_A_VL",
        "INTUNE_EDU",
        "INTUNE_SMB",
    }
)
_FORBIDDEN_CLASSES = frozenset({"insufficient_permissions", "unauthenticated"})


def _sku_is_active(sku: Mapping[str, Any]) -> bool:
    status = _text(sku.get("capabilityStatus") or sku.get("capability_status")).lower()
    return status in {"", "enabled", "warning"}


def _sku_has_intune(sku: Mapping[str, Any]) -> bool:
    part = _text(sku.get("skuPartNumber") or sku.get("sku_part_number")).upper()
    if part in _INTUNE_SKU_PART_NUMBERS or "INTUNE" in part:
        return True
    plans = sku.get("servicePlans") or sku.get("service_plans") or []
    if not isinstance(plans, list):
        return False
    for plan in plans:
        if not isinstance(plan, Mapping):
            continue
        name = _text(plan.get("servicePlanName") or plan.get("service_plan_name")).upper()
        provisioning = _text(plan.get("provisioningStatus") or plan.get("provisioning_status")).lower()
        if name.startswith(_INTUNE_SERVICE_PLAN_PREFIXES) and provisioning != "disabled":
            return True
    return False


def intune_license_state(collector_payloads: Mapping[str, Any] | None) -> str:
    """Return "present", "absent", or "unknown" for Intune-capable licensing.

    "unknown" means licensing was not collected or the subscribedSkus read failed,
    in which case callers must not infer a licence gap.
    """
    licensing = (collector_payloads or {}).get("licensing")
    if not isinstance(licensing, Mapping):
        return "unknown"
    section = licensing.get("subscribedSkus")
    if not isinstance(section, Mapping) or "error" in section or not isinstance(section.get("value"), list):
        return "unknown"
    skus = [item for item in section["value"] if isinstance(item, Mapping)]
    if any(_sku_is_active(sku) and _sku_has_intune(sku) for sku in skus):
        return "present"
    return "absent"


def _is_intune_forbidden(row: Mapping[str, Any]) -> bool:
    if _text(row.get("collector")) not in INTUNE_COLLECTORS or _text(row.get("status")) == "ok":
        return False
    error_class = _text(row.get("error_class"))
    if error_class in _FORBIDDEN_CLASSES:
        return True
    lowered = _text(row.get("error")).lower().replace(" ", "")
    return '"errorcode":"forbidden"' in lowered


def relabel_intune_license_blockers(
    coverage_rows: list[dict[str, Any]],
    collector_payloads: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    """Relabel Intune Forbidden failures as license_required when licensing shows no Intune SKU.

    Rows keep their original class in ``original_error_class``. When licensing is
    present or unknown, rows are returned unchanged (auth_scope stays the label).
    """
    if intune_license_state(collector_payloads) != "absent":
        return coverage_rows
    relabelled: list[dict[str, Any]] = []
    for row in coverage_rows:
        if isinstance(row, Mapping) and _is_intune_forbidden(row):
            item = dict(row)
            item["original_error_class"] = item.get("error_class")
            item["error_class"] = "license_required"
            item["blocker_hint"] = (
                "Intune returned Forbidden and subscribedSkus shows no Intune-capable licence; "
                "treat as a licence gap rather than a missing scope."
            )
            relabelled.append(item)
        else:
            relabelled.append(row)
    return relabelled


def _text(value: Any) -> str:
    return str(value or "").strip()


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _haystack(row: Mapping[str, Any]) -> str:
    values: list[str] = []
    for key in ("status", "reason", "notes", "error_class", "error", "message"):
        value = row.get(key)
        if value:
            values.append(str(value))
    endpoint_statuses = row.get("endpoint_statuses")
    if isinstance(endpoint_statuses, list):
        for item in endpoint_statuses:
            if not isinstance(item, Mapping):
                continue
            values.extend(str(item.get(key) or "") for key in ("name", "status", "error_class", "error"))
    return " ".join(values).lower()


def _endpoint_classes(row: Mapping[str, Any]) -> set[str]:
    classes: set[str] = set()
    endpoint_statuses = row.get("endpoint_statuses")
    if isinstance(endpoint_statuses, list):
        for item in endpoint_statuses:
            if isinstance(item, Mapping) and item.get("error_class"):
                classes.add(_text(item.get("error_class")))
    return classes


def classify_capability_blocker(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {
            "blocker_kind": "unverified",
            "blocker_reason": "collector was not live-verified",
            "next_step": "Run a probe or live audit for this collector.",
        }

    status = _text(row.get("status"))
    reason = _text(row.get("reason"))
    missing = _strings(row.get("missing_permissions"))
    text = _haystack(row)

    if status in _TRUSTED_STATUSES and not missing:
        return {"blocker_kind": "none", "blocker_reason": "", "next_step": ""}
    if not missing and _text(row.get("license_state")) == "absent" and _endpoint_classes(row) & {"license_required"}:
        return {
            "blocker_kind": "license",
            "blocker_reason": reason if reason and reason != "missing_required_permissions" else "tenant has no licence for this service",
            "next_step": "Confirm service licensing (no matching SKU in subscribedSkus) and mark the surface out of scope if unavailable.",
        }
    if any(token in text for token in ("unauthorized_client", "conditional access", "ca policy", "tenant policy", "client not authorized")):
        return {
            "blocker_kind": "tenant_policy",
            "blocker_reason": reason or "tenant policy blocks this audit client",
            "next_step": "Review tenant app consent, DWD, or Conditional Access policy for the audit client.",
        }
    if missing or status == "blocked_by_scope" or "invalid_scope" in text or "insufficient_permissions" in text:
        return {
            "blocker_kind": "auth_scope",
            "blocker_reason": reason or "missing or insufficient OAuth/API permissions",
            "next_step": "Grant the listed read permissions or scopes, then rerun doctor/probe.",
        }
    if status == "blocked_by_role" or "global_reader_limit" in text or "role" in text and "blocked" in text:
        return {
            "blocker_kind": "admin_role",
            "blocker_reason": reason or "admin role cannot read this surface",
            "next_step": "Use a role with read access to this surface or document the role limitation.",
        }
    if any(token in text for token in ("license", "licensed", "e5", "premium", "copilot", "windows365")):
        return {
            "blocker_kind": "license",
            "blocker_reason": reason or "tenant license does not expose this surface",
            "next_step": "Confirm service licensing and mark the surface out of scope if unavailable.",
        }
    if any(token in text for token in ("service_not_available", "not provisioned", "not found", "404", "disabled")):
        return {
            "blocker_kind": "service_absent",
            "blocker_reason": reason or "service or API surface is absent in this tenant",
            "next_step": "Confirm the workload is enabled before treating this as a security gap.",
        }
    if "session_not_connected" in text or "command_not_authenticated" in text:
        return {
            "blocker_kind": "local_tool",
            "blocker_reason": reason or "no authorised Exchange Online, Teams, or m365 CLI session was available",
            "next_step": "Grant the audit app Exchange.ManageAsApp plus a read role (e.g. Global Reader) for app-only Exchange, or run from a connected session.",
        }
    if any(token in text for token in ("missing_google_dependencies", "command_not_found", "module_not_found", "toolchain", "dependency")):
        return {
            "blocker_kind": "local_tool",
            "blocker_reason": reason or "local dependency or toolchain is missing",
            "next_step": "Install or authenticate the local toolchain, then rerun probe.",
        }
    if status in {"", "unknown"}:
        return {
            "blocker_kind": "unverified",
            "blocker_reason": reason or "collector has not been verified",
            "next_step": "Run a probe or live audit for this collector.",
        }
    return {
        "blocker_kind": "runtime" if status in {"partial", "failed", "blocked"} or status.startswith("blocked") else "unverified",
        "blocker_reason": reason or status,
        "next_step": "Inspect endpoint errors and rerun the affected collector after the runtime issue is fixed.",
    }


def enrich_capability_row(row: Mapping[str, Any] | None) -> dict[str, Any]:
    enriched = dict(row or {})
    classification = classify_capability_blocker(enriched)
    enriched.update(classification)
    return enriched


def capability_blocker_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    blockers = [
        {
            "collector": _text(row.get("collector") or row.get("name")),
            "status": _text(row.get("status")),
            "reason": _text(row.get("reason")),
            "blocker_kind": _text(row.get("blocker_kind")) or classify_capability_blocker(row)["blocker_kind"],
            "blocker_reason": _text(row.get("blocker_reason")) or classify_capability_blocker(row)["blocker_reason"],
            "next_step": _text(row.get("next_step")) or classify_capability_blocker(row)["next_step"],
            "missing_permissions": _strings(row.get("missing_permissions")),
        }
        for row in rows
        if (_text(row.get("blocker_kind")) or classify_capability_blocker(row)["blocker_kind"]) != "none"
    ]
    counts = Counter(item["blocker_kind"] for item in blockers)
    return {"counts": dict(sorted(counts.items())), "blockers": blockers}
