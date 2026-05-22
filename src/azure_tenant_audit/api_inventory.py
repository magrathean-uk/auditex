from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any


SCHEMA_VERSION = "2026-04-21"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _text(value: Any, fallback: str = "") -> str:
    rendered = str(value or "").strip()
    return rendered if rendered else fallback


def _method(row: Mapping[str, Any]) -> str:
    explicit = _text(row.get("method") or row.get("http_method")).upper()
    if explicit:
        return explicit
    row_type = _text(row.get("type")).lower()
    endpoint = _text(row.get("endpoint") or row.get("path") or row.get("name"))
    if row_type in {"command", "adapter", "powershell", "m365_cli"}:
        return "COMMAND"
    if endpoint.startswith(("Get-", "Export-", "Search-")):
        return "COMMAND"
    return "GET"


def _access_mode(method: str) -> str:
    if method in _MUTATING_METHODS:
        return "write"
    if method == "COMMAND":
        return "read_command"
    return "read"


def _data_class(*, platform: str, collector: str, endpoint: str, name: str) -> str:
    haystack = f"{platform} {collector} {endpoint} {name}".lower()
    if any(token in haystack for token in ("gmail", "mailbox", "message", "exchange")):
        return "mail_metadata_and_settings"
    if any(token in haystack for token in ("drive", "onedrive", "sharepoint", "site")):
        return "file_metadata_and_sharing"
    if any(token in haystack for token in ("audit", "signin", "signins", "reports", "activities", "alert")):
        return "audit_and_security_events"
    if any(token in haystack for token in ("device", "intune", "chrome", "mobile")):
        return "device_inventory_and_policy"
    if any(token in haystack for token in ("policy", "settings", "conditionalaccess", "authmethods")):
        return "configuration_policy"
    if any(token in haystack for token in ("user", "group", "directory", "role", "domain")):
        return "directory_identity"
    return "tenant_metadata"


def _capability_index(capability_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in capability_rows:
        collector = _text(row.get("collector"))
        if collector:
            indexed[collector] = row
    return indexed


def _collector_plan(
    *,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    collector_descriptions: Mapping[str, str] | None,
    observed_counts: Counter[str],
) -> list[dict[str, Any]]:
    capabilities = _capability_index(capability_rows)
    descriptions = dict(collector_descriptions or {})
    rows: list[dict[str, Any]] = []
    for collector in selected_collectors:
        capability = capabilities.get(collector, {})
        rows.append(
            {
                "collector": collector,
                "description": descriptions.get(collector, ""),
                "status": capability.get("status"),
                "reason": capability.get("reason"),
                "required_permissions": list(capability.get("required_permissions") or []),
                "observed_permissions": list(capability.get("observed_permissions") or []),
                "missing_permissions": list(capability.get("missing_permissions") or []),
                "observed_call_count": observed_counts.get(collector, 0),
            }
        )
    return rows


def build_api_call_inventory(
    *,
    platform: str,
    selected_collectors: list[str],
    capability_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    data_handling: Mapping[str, Any] | None,
    collector_descriptions: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    provider = platform or "m365"
    data_handling_payload = dict(data_handling or {})
    capabilities = _capability_index(capability_rows)
    observed_calls: list[dict[str, Any]] = []
    observed_counts: Counter[str] = Counter()
    mutating_calls: list[dict[str, Any]] = []
    content_calls: list[dict[str, Any]] = []

    for index, row in enumerate(_rows(coverage_rows), start=1):
        collector = _text(row.get("collector"), "unknown")
        name = _text(row.get("name") or row.get("operation"), f"call-{index}")
        endpoint = _text(row.get("endpoint") or row.get("path") or name, name)
        method = _method(row)
        access_mode = _access_mode(method)
        content_reads = bool(row.get("content_reads") or row.get("body_reads") or row.get("file_content_reads"))
        write_actions = bool(row.get("write_actions") or access_mode == "write")
        capability = capabilities.get(collector, {})
        call = {
            "id": f"{collector}:{name}:{index}",
            "source": "observed",
            "platform": provider,
            "collector": collector,
            "name": name,
            "endpoint": endpoint,
            "method": method,
            "access_mode": access_mode,
            "status": row.get("status"),
            "item_count": int(row.get("item_count") or 0),
            "duration_ms": row.get("duration_ms"),
            "data_class": _data_class(platform=provider, collector=collector, endpoint=endpoint, name=name),
            "content_reads": content_reads,
            "write_actions": write_actions,
            "required_permissions": list(capability.get("required_permissions") or []),
            "missing_permissions": list(capability.get("missing_permissions") or []),
            "error_class": row.get("error_class"),
        }
        observed_calls.append(call)
        observed_counts[collector] += 1
        if write_actions:
            mutating_calls.append({"id": call["id"], "method": method, "endpoint": endpoint})
        if content_reads:
            content_calls.append({"id": call["id"], "endpoint": endpoint})

    data_content = bool(data_handling_payload.get("content_reads"))
    data_write = bool(data_handling_payload.get("write_actions"))
    read_only = bool(data_handling_payload.get("read_only", True)) and not data_write and not mutating_calls
    no_content_reads = not data_content and not content_calls
    return {
        "schema_version": SCHEMA_VERSION,
        "platform": provider,
        "plane": data_handling_payload.get("plane"),
        "declared_collectors": _collector_plan(
            selected_collectors=selected_collectors,
            capability_rows=capability_rows,
            collector_descriptions=collector_descriptions,
            observed_counts=observed_counts,
        ),
        "observed_calls": observed_calls,
        "counts": {
            "declared_collectors": len(selected_collectors),
            "observed_calls": len(observed_calls),
            "mutating_calls": len(mutating_calls),
            "content_read_calls": len(content_calls),
        },
        "safety": {
            "read_only": read_only,
            "no_content_reads": no_content_reads,
            "write_actions": data_write or bool(mutating_calls),
            "content_reads": data_content or bool(content_calls),
            "mutating_calls": mutating_calls,
            "content_read_calls": content_calls,
            "scope_risk": data_handling_payload.get("scope_risk"),
            "write_capable_scopes": list(data_handling_payload.get("write_capable_scopes") or []),
        },
    }
