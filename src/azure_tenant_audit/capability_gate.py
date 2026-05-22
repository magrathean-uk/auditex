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
