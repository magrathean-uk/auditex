from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .config import CollectorConfig
from .diagnostics import load_permission_hints
from .provider_registry import provider_collectors

GOOGLE_SCOPE_NOTES: dict[str, dict[str, str]] = {
    "https://www.googleapis.com/auth/admin.directory.user.security": {
        "risk": "write_capable",
        "note": "Google exposes user security state through a non-readonly scope; Auditex only reads posture fields.",
    },
    "https://www.googleapis.com/auth/apps.alerts": {
        "risk": "write_capable",
        "note": "Alert Center exposes one read/write scope; Auditex only lists alerts.",
    },
    "https://www.googleapis.com/auth/gmail.settings.basic": {
        "risk": "write_capable",
        "note": "Gmail settings scopes can change settings; Auditex only lists filters, forwarding, send-as, and delegates.",
    },
    "https://www.googleapis.com/auth/apps.groups.settings": {
        "risk": "write_capable",
        "note": "Groups Settings uses a read/write scope for settings; Auditex only reads group settings.",
    },
    "https://www.googleapis.com/auth/drive.readonly": {
        "risk": "content_capable",
        "note": "Drive readonly can read file content; Auditex only uses metadata/list endpoints and records no content reads.",
    },
    "https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly": {
        "risk": "read_only",
        "note": (
            "Can read inbound SAML and OIDC profiles, assignment records and SAML public-key metadata. "
            "Auditex lists assignments and retains only the OU or group target and mode."
        ),
    },
}

GOOGLE_API_ENABLEMENT = {
    "google_directory": ["Admin SDK API"],
    "google_reports": ["Admin SDK API"],
    "google_setting_events": ["Admin SDK API"],
    "google_alert_center": ["Alert Center API"],
    "google_policies": ["Cloud Identity API"],
    "google_sso_assignments": ["Cloud Identity API"],
    "google_gmail_settings": ["Gmail API", "Admin SDK API"],
    "google_devices": ["Admin SDK API"],
    "google_dns_posture": ["Admin SDK API"],
    "google_drive_posture": ["Google Drive API"],
    "google_groups_settings": ["Groups Settings API", "Admin SDK API"],
    "google_calendar_posture": ["Google Calendar API", "Admin SDK API"],
}

# APIs a collector uses only for an optional scope's read: enabled for that read alone, which falls back without it.
GOOGLE_OPTIONAL_API_ENABLEMENT = {
    # The Drive collector's optional Directory domains read (admin.directory.domain.readonly).
    "google_drive_posture": ["Admin SDK API"],
}

GOOGLE_ROLE_HINTS = ["Google Workspace super admin or delegated admin"]


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _application_permissions(value: Any) -> list[str]:
    """Application permission names from a hint such as ``{"application": "Sites.FullControl.All"}``."""
    raw = _mapping(value).get("application")
    items = raw if isinstance(raw, (list, tuple)) else [raw] if raw else []
    return _dedupe([str(item) for item in items])


def build_m365_scope_catalog(
    *,
    collector_config: CollectorConfig,
    permission_hints: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    names = sorted(set(collector_config.collectors) | {str(name) for name in permission_hints})
    for collector_name in names:
        definition = collector_config.collectors.get(collector_name)
        hint = _mapping(permission_hints.get(collector_name))
        catalog[collector_name] = {
            "collector": collector_name,
            "provider": "m365",
            "description": definition.description if definition else "",
            "required_permissions": _dedupe(
                list(definition.required_permissions if definition else [])
                + [str(item) for item in hint.get("graph_scopes") or []]
            ),
            # Optional Graph scopes widen a collector's reads but are never part of the default grant (R006).
            "optional_permissions": _dedupe([str(item) for item in hint.get("optional_graph_scopes") or []]),
            "optional_permission_notes": {
                str(scope): str(note) for scope, note in _mapping(hint.get("optional_graph_scope_notes")).items()
            },
            "minimum_role_hints": _dedupe([str(item) for item in hint.get("minimum_role_hints") or []]),
            # SharePoint (Office 365 SharePoint Online) application permissions, not Microsoft Graph scopes.
            "sharepoint_permissions": _application_permissions(hint.get("sharepoint_permissions")),
            "tool_requirements": _dedupe([str(item) for item in hint.get("command_tools") or []]),
            "optional_commands": _dedupe([str(item) for item in hint.get("optional_commands") or []]),
            "scope_warnings": [],
            "api_enablement": [],
            "notes": str(hint.get("notes") or ""),
        }
    return catalog


def load_m365_scope_catalog(
    *,
    config_path: str | Path = "configs/collector-definitions.json",
    permission_hints_path: str | Path = "configs/collector-permissions.json",
) -> dict[str, dict[str, Any]]:
    return build_m365_scope_catalog(
        collector_config=CollectorConfig.from_path(config_path),
        permission_hints=load_permission_hints(Path(permission_hints_path)),
    )


def build_google_scope_catalog(
    *,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    if registry is None:
        registry = provider_collectors("google_workspace")
    catalog: dict[str, dict[str, Any]] = {}
    for collector_name, collector in registry.items():
        required_permissions = _dedupe([str(item) for item in getattr(collector, "required_scopes", ())])
        # Optional scopes widen a collector's reads: asked for under domain-wide delegation (on a token of their own),
        # never by an OAuth sign-in unless another selected collector requires them; a refusal is not a gap.
        optional_permissions = [
            item for item in _dedupe([str(item) for item in getattr(collector, "optional_scopes", ())])
            if item not in required_permissions
        ]
        notes = _mapping(getattr(collector, "optional_scope_notes", None))
        catalog[collector_name] = {
            "collector": collector_name,
            "provider": "google_workspace",
            "description": str(getattr(collector, "description", "")),
            "required_permissions": required_permissions,
            "optional_permissions": optional_permissions,
            "optional_permission_notes": {
                scope: str(notes[scope]) for scope in optional_permissions if scope in notes
            },
            "minimum_role_hints": list(GOOGLE_ROLE_HINTS),
            "tool_requirements": [],
            "optional_commands": [],
            "scope_warnings": [
                {"scope": scope, **GOOGLE_SCOPE_NOTES[scope]}
                for scope in required_permissions
                if scope in GOOGLE_SCOPE_NOTES
            ],
            "api_enablement": list(GOOGLE_API_ENABLEMENT.get(collector_name, [])),
            "optional_api_enablement": [
                api for api in GOOGLE_OPTIONAL_API_ENABLEMENT.get(collector_name, [])
                if api not in GOOGLE_API_ENABLEMENT.get(collector_name, [])
            ],
            "notes": f"Google Workspace access metadata for {collector_name}.",
        }
    return catalog


def aggregate_catalog_rows(
    catalog: Mapping[str, Mapping[str, Any]],
    selected_collectors: list[str],
) -> dict[str, Any]:
    required_permissions: list[str] = []
    optional_permissions: list[str] = []
    minimum_role_hints: list[str] = []
    sharepoint_permissions: list[str] = []
    tool_requirements: list[str] = []
    optional_commands: list[str] = []
    api_enablement: list[str] = []
    optional_api_enablement: list[str] = []
    scope_warnings: list[dict[str, Any]] = []
    warning_keys: set[str] = set()
    collector_rows: list[dict[str, Any]] = []

    for collector_name in selected_collectors:
        row = _mapping(catalog.get(collector_name))
        if not row:
            continue
        collector_rows.append(row)
        required_permissions.extend([str(item) for item in row.get("required_permissions") or []])
        optional_permissions.extend([str(item) for item in row.get("optional_permissions") or []])
        minimum_role_hints.extend([str(item) for item in row.get("minimum_role_hints") or []])
        sharepoint_permissions.extend([str(item) for item in row.get("sharepoint_permissions") or []])
        tool_requirements.extend([str(item) for item in row.get("tool_requirements") or []])
        optional_commands.extend([str(item) for item in row.get("optional_commands") or []])
        api_enablement.extend([str(item) for item in row.get("api_enablement") or []])
        optional_api_enablement.extend([str(item) for item in row.get("optional_api_enablement") or []])
        for warning in row.get("scope_warnings") or []:
            if not isinstance(warning, Mapping):
                continue
            warning_key = str(warning.get("scope") or warning.get("permission") or "")
            if warning_key in warning_keys:
                continue
            warning_keys.add(warning_key)
            scope_warnings.append(dict(warning))

    return {
        "collectors": collector_rows,
        "required_permissions": _dedupe(required_permissions),
        # A scope one selected collector requires is required, not optional.
        "optional_permissions": [
            item for item in _dedupe(optional_permissions) if item not in set(required_permissions)
        ],
        "minimum_role_hints": _dedupe(minimum_role_hints),
        "sharepoint_permissions": _dedupe(sharepoint_permissions),
        "tool_requirements": _dedupe(tool_requirements),
        "optional_commands": _dedupe(optional_commands),
        "api_enablement": _dedupe(api_enablement),
        # An API one selected collector needs is required, not optional.
        "optional_api_enablement": [
            item for item in _dedupe(optional_api_enablement) if item not in set(api_enablement)
        ],
        "scope_warnings": scope_warnings,
    }
