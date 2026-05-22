from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _event_rows(events: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in events or [] if isinstance(item, Mapping)]


def classify_auth_scope(scope: str) -> str:
    value = str(scope or "").strip()
    lower = value.lower()
    if not value:
        return "unknown"
    if lower.endswith("/.default"):
        return "tenant_configured"
    if "readwrite" in lower or ".write" in lower or lower.endswith(".write"):
        return "write_capable"
    if "readonly" in lower or ".read." in lower or lower.endswith(".read") or lower.endswith(".read.all"):
        return "read_only"
    if lower.endswith(".readbasic.all"):
        return "read_only"
    return "write_capable"


def _scope_summary(auth_scopes: list[str] | None) -> dict[str, Any]:
    scopes = sorted({str(item) for item in auth_scopes or [] if str(item)})
    by_class: dict[str, list[str]] = {"read_only": [], "write_capable": [], "tenant_configured": [], "unknown": []}
    for scope in scopes:
        by_class.setdefault(classify_auth_scope(scope), []).append(scope)
    return {
        "total": len(scopes),
        "read_only": by_class["read_only"],
        "write_capable": by_class["write_capable"],
        "tenant_configured": by_class["tenant_configured"],
        "unknown": by_class["unknown"],
    }


def build_data_handling_summary(
    *,
    platform: str,
    mode: str,
    plane: str,
    collectors: list[str],
    auth_scopes: list[str] | None = None,
    events: list[dict[str, Any]] | None = None,
    response_execute: bool = False,
    response_allow_write: bool = False,
) -> dict[str, Any]:
    event_rows = _event_rows(events)
    scope_summary = _scope_summary(auth_scopes)
    write_capable_scopes = scope_summary["write_capable"]
    write_actions = bool(plane == "response" and response_execute and response_allow_write)
    read_only = not write_actions
    provider_assertions: dict[str, Any] = {
        "api_methods": "read_only" if read_only else "guarded_response",
        "body_or_file_content_reads": False,
        "raw_secret_capture": False,
        "write_capable_scopes_used_for_read_only_methods": bool(write_capable_scopes and read_only),
    }
    if platform == "google_workspace":
        provider_assertions.update(
            {
                "gmail_body_reads": False,
                "drive_file_content_reads": False,
                "drive_metadata_only": True,
                "gmail_settings_only": True,
            }
        )
    else:
        provider_assertions.update(
            {
                "mailbox_body_reads": False,
                "drive_file_content_reads": False,
                "graph_metadata_and_settings_only": plane != "response",
            }
        )

    return {
        "schema_version": "2026-04-21",
        "platform": platform or "m365",
        "mode": mode,
        "plane": plane,
        "collectors": list(collectors),
        "read_only": read_only,
        "content_reads": False,
        "write_actions": write_actions,
        "scope_risk": "write_capable_scope_present" if write_capable_scopes else "read_only_scopes",
        "auth_scope_summary": scope_summary,
        "write_capable_scopes": write_capable_scopes,
        "events": event_rows,
        "provider_assertions": provider_assertions,
    }
