from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .profiles import get_profile
from .resources import resolve_resource_path


def load_permission_hints(path: Path) -> dict[str, dict[str, Any]]:
    path = resolve_resource_path(path)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    raw = payload.get("collector_permissions") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(name): dict(value) if isinstance(value, dict) else {} for name, value in raw.items()}


def build_diagnostics(
    result_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    permission_hints: dict[str, dict[str, Any]],
    auditor_profile: str,
) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    by_collector = defaultdict(list)
    profile = get_profile(auditor_profile)
    for row in coverage_rows:
        collector_name = row.get("collector")
        if isinstance(collector_name, str):
            by_collector[collector_name].append(row)

    for row in result_rows:
        collector_name = row["name"]
        if row["status"] in {"ok", "skipped"}:
            continue
        hints = permission_hints.get(collector_name, {})
        recommended_scopes = hints.get("graph_scopes", [])
        minimum_roles = hints.get("minimum_role_hints", [])
        command_tools = hints.get("command_tools", [])
        optional_commands = hints.get("optional_commands", [])
        notes = hints.get("notes")
        notes_detail = notes if isinstance(notes, str) else None
        issue_rows = by_collector.get(collector_name, [])
        if not issue_rows:
            failures.append(
                {
                    "collector": collector_name,
                    "status": row["status"],
                    "error": row.get("error"),
                    "error_class": "unknown",
                    "evidence": {"message": row.get("message")},
                    "recommendations": {
                        "required_graph_scopes": sorted(set(recommended_scopes)),
                        "recommended_roles": sorted(set(minimum_roles)),
                        "command_tools": sorted(set(command_tools)),
                        "optional_commands": sorted(set(optional_commands)),
                        "notes": notes_detail,
                        "auditor_profile": auditor_profile,
                        "profile_role_hints": list(profile.delegated_role_hints),
                        "optional_app_escalation_permissions": list(profile.app_escalation_permissions),
                    },
                }
            )
            continue

        for item in issue_rows:
            status = item.get("status")
            if status == "ok":
                continue
            failure: dict[str, Any] = {
                "collector": collector_name,
                "item": item.get("name"),
                "status": status,
                "endpoint": item.get("endpoint"),
                "error_class": item.get("error_class"),
                "error": item.get("error"),
                "top": item.get("top"),
                "command_type": item.get("type"),
            }
            if item.get("type") == "command":
                failure["commands_required"] = optional_commands or [str(item.get("command"))] if item.get("command") else []
                failure["recommendations"] = {
                    "required_tools": sorted(set(command_tools)),
                    "notes": notes_detail,
                    "auditor_profile": auditor_profile,
                    "profile_role_hints": list(profile.delegated_role_hints),
                }
            elif item.get("type") == "graph":
                failure["recommendations"] = {
                    "required_graph_scopes": sorted(set(recommended_scopes)),
                    "recommended_roles": sorted(set(minimum_roles)),
                    "notes": notes_detail,
                    "auditor_profile": auditor_profile,
                    "profile_role_hints": list(profile.delegated_role_hints),
                    "optional_app_escalation_permissions": list(profile.app_escalation_permissions),
                }
            else:
                failure["recommendations"] = {"notes": notes_detail, "auditor_profile": auditor_profile}
            failures.append(failure)

    return failures
