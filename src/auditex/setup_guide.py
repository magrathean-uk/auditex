from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.presets import load_collector_presets
from azure_tenant_audit.profiles import get_profile
from azure_tenant_audit.selection import select_collectors


GOOGLE_PROVIDER_ALIASES = {"google", "google_workspace", "workspace"}
M365_PROVIDER_ALIASES = {"m365", "entra", "microsoft365", "microsoft_365"}

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
    "https://www.googleapis.com/auth/gmail.settings.sharing": {
        "risk": "write_capable",
        "note": "Required for sensitive Gmail settings such as forwarding and delegates; Auditex only reads settings.",
    },
    "https://www.googleapis.com/auth/apps.groups.settings": {
        "risk": "write_capable",
        "note": "Groups Settings uses a read/write scope for settings; Auditex only reads group settings.",
    },
    "https://www.googleapis.com/auth/drive.readonly": {
        "risk": "content_capable",
        "note": "Drive readonly can read file content; Auditex only uses metadata/list endpoints and records no content reads.",
    },
}

GOOGLE_API_ENABLEMENT = {
    "google_directory": ["Admin SDK API"],
    "google_reports": ["Admin SDK API"],
    "google_alert_center": ["Alert Center API"],
    "google_gmail_settings": ["Gmail API", "Admin SDK API"],
    "google_devices": ["Admin SDK API"],
    "google_dns_posture": ["Admin SDK API"],
    "google_drive_posture": ["Google Drive API"],
    "google_groups_settings": ["Groups Settings API", "Admin SDK API"],
    "google_calendar_posture": ["Google Calendar API", "Admin SDK API"],
}

GOOGLE_SOURCE_REFERENCES = [
    {
        "name": "Google Workspace domain-wide delegation",
        "url": "https://developers.google.com/workspace/guides/create-credentials",
    },
    {
        "name": "Admin SDK Directory API",
        "url": "https://developers.google.com/workspace/admin/directory/reference/rest",
    },
    {
        "name": "Reports API scopes",
        "url": "https://developers.google.com/workspace/admin/reports/auth",
    },
    {
        "name": "Alert Center API scopes",
        "url": "https://developers.google.com/workspace/admin/alertcenter/guides/auth",
    },
    {
        "name": "Gmail API scopes",
        "url": "https://developers.google.com/workspace/gmail/api/auth/scopes",
    },
    {
        "name": "Drive files.list scopes",
        "url": "https://developers.google.com/workspace/drive/api/reference/rest/v3/files/list",
    },
    {
        "name": "Calendar ACL list scopes",
        "url": "https://developers.google.com/workspace/calendar/api/v3/reference/acl/list",
    },
]

M365_SOURCE_REFERENCES = [
    {
        "name": "Microsoft Graph app-only access",
        "url": "https://learn.microsoft.com/en-us/graph/auth-v2-service",
    },
    {
        "name": "Microsoft Graph permissions reference",
        "url": "https://learn.microsoft.com/en-us/graph/permissions-reference",
    },
    {
        "name": "Microsoft Graph permissions overview",
        "url": "https://learn.microsoft.com/en-us/graph/permissions-overview",
    },
    {
        "name": "Grant tenant-wide admin consent",
        "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent",
    },
    {
        "name": "Exchange Online PowerShell",
        "url": "https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell",
    },
]

M365_WRITE_CAPABLE_TOKENS = ("ReadWrite", "ManageAsApp", "Write.")


def build_setup_guide(
    *,
    provider: str,
    collector_preset: str | None = None,
    collectors: str | list[str] | None = None,
    exclude: str | list[str] | None = None,
    auth: str = "domain-delegation",
    tenant_name: str = "CLIENT",
    tenant_id: str = "<tenant-id-or-domain>",
    domain: str = "example.com",
    customer_id: str = "my_customer",
    subject: str = "admin@example.com",
    service_account_key: str = "/path/to/service-account.json",
    oauth_client: str = "/path/to/oauth-client.json",
    token_cache: str = ".secrets/google-token.json",
    auditor_profile: str = "global-reader",
    plane: str = "full",
    mode: str = "delegated",
    include_exchange: bool = False,
    config_path: str | Path = "configs/collector-definitions.json",
    permission_hints_path: str | Path = "configs/collector-permissions.json",
) -> dict[str, Any]:
    normalized = provider.strip().lower().replace("-", "_")
    if normalized in GOOGLE_PROVIDER_ALIASES:
        return build_google_setup_guide(
            collector_preset=collector_preset or "core-security",
            collectors=collectors,
            exclude=exclude,
            auth=auth,
            tenant_name=tenant_name,
            domain=domain,
            customer_id=customer_id,
            subject=subject,
            service_account_key=service_account_key,
            oauth_client=oauth_client,
            token_cache=token_cache,
        )
    if normalized in M365_PROVIDER_ALIASES:
        return build_m365_setup_guide(
            collector_preset=collector_preset,
            collectors=collectors,
            exclude=exclude,
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            plane=plane,
            mode=mode,
            include_exchange=include_exchange,
            config_path=config_path,
            permission_hints_path=permission_hints_path,
        )
    raise ValueError(f"Unsupported provider '{provider}'. Use google or m365.")


def build_google_setup_guide(
    *,
    collector_preset: str = "core-security",
    collectors: str | list[str] | None = None,
    exclude: str | list[str] | None = None,
    auth: str = "domain-delegation",
    tenant_name: str = "CLIENT-GOOGLE",
    domain: str = "example.com",
    customer_id: str = "my_customer",
    subject: str = "admin@example.com",
    service_account_key: str = "/path/to/service-account.json",
    oauth_client: str = "/path/to/oauth-client.json",
    token_cache: str = ".secrets/google-token.json",
) -> dict[str, Any]:
    from .google_workspace.collectors import PRESETS, REGISTRY

    selected = _select_google_collectors(
        registry=REGISTRY,
        presets=PRESETS,
        collector_preset=collector_preset,
        collectors=collectors,
        exclude=exclude,
    )
    required_scopes = _dedupe(
        scope
        for name in selected
        for scope in getattr(REGISTRY[name], "required_scopes", ())
    )
    scope_warnings = [
        {"scope": scope, **GOOGLE_SCOPE_NOTES[scope]}
        for scope in required_scopes
        if scope in GOOGLE_SCOPE_NOTES
    ]
    api_enablement = _dedupe(api for name in selected for api in GOOGLE_API_ENABLEMENT.get(name, []))
    scopes_csv = ",".join(required_scopes)
    provider_assertions = {
        "read_only_audit": True,
        "production_writes": False,
        "gmail_body_reads": False,
        "drive_file_content_reads": False,
        "broad_scopes_recorded_as_scope_risk": bool(scope_warnings),
    }

    if auth not in {"domain-delegation", "oauth"}:
        raise ValueError("Google auth must be domain-delegation or oauth.")

    domain_delegation_steps = [
        "Install Auditex with google extras: python -m pip install -e '.[google]'.",
        "Create or choose a Google Cloud project and enable the listed APIs.",
        "Create a service account, enable domain-wide delegation, and copy its OAuth client ID.",
        "In Google Admin Console, open Security > Access and data control > API controls > Domain-wide delegation.",
        "Add the service account client ID and paste the exact scopes_csv value.",
        "Use a super-admin subject for probe/run, then reduce scope only if the probe proves the surface is not needed.",
    ]
    oauth_steps = [
        "Create an OAuth desktop client in Google Cloud.",
        "Configure the OAuth consent screen for the listed scopes.",
        "Run doctor/probe with --auth oauth and a local token cache.",
        "Treat OAuth results as partial when domain-wide admin surfaces are blocked.",
    ]

    return {
        "schema_version": "2026-05-22",
        "kind": "auditex_setup_guide",
        "provider": "google_workspace",
        "auth": auth,
        "collector_preset": collector_preset,
        "selected_collectors": selected,
        "api_enablement": api_enablement,
        "required_scopes": required_scopes,
        "scopes_csv": scopes_csv,
        "scope_warnings": scope_warnings,
        "provider_assertions": provider_assertions,
        "setup_steps": domain_delegation_steps if auth == "domain-delegation" else oauth_steps,
        "alternate_setup_steps": {"domain-delegation": domain_delegation_steps, "oauth": oauth_steps},
        "commands": {
            "doctor": _google_command(
                "doctor",
                auth=auth,
                domain=domain,
                customer_id=customer_id,
                subject=subject,
                service_account_key=service_account_key,
                oauth_client=oauth_client,
                token_cache=token_cache,
                collector_preset=collector_preset,
            )
            + " --json",
            "probe": _google_command(
                "probe",
                auth=auth,
                domain=domain,
                customer_id=customer_id,
                subject=subject,
                service_account_key=service_account_key,
                oauth_client=oauth_client,
                token_cache=token_cache,
                collector_preset=collector_preset,
                tenant_name=tenant_name,
                extra="--top 1 --page-size 1",
            ),
            "run": _google_command(
                "run",
                auth=auth,
                domain=domain,
                customer_id=customer_id,
                subject=subject,
                service_account_key=service_account_key,
                oauth_client=oauth_client,
                token_cache=token_cache,
                collector_preset=collector_preset,
                tenant_name=tenant_name,
                extra="--out outputs/google",
            ),
        },
        "review_artifacts": [
            "audit-plan.json",
            "live-readiness.json",
            "api-inventory.json",
            "data-handling.json",
            "reports/report-pack.json",
            "validation.json",
        ],
        "source_references": GOOGLE_SOURCE_REFERENCES,
    }


def build_m365_setup_guide(
    *,
    collector_preset: str | None = None,
    collectors: str | list[str] | None = None,
    exclude: str | list[str] | None = None,
    tenant_name: str = "CLIENT",
    tenant_id: str = "<tenant-id-or-domain>",
    auditor_profile: str = "global-reader",
    plane: str = "full",
    mode: str = "delegated",
    include_exchange: bool = False,
    config_path: str | Path = "configs/collector-definitions.json",
    permission_hints_path: str | Path = "configs/collector-permissions.json",
) -> dict[str, Any]:
    config = CollectorConfig.from_path(config_path)
    profile = get_profile(auditor_profile)
    presets = load_collector_presets()
    selected = select_collectors(
        available=config.default_order,
        profile_default_collectors=profile.default_collectors,
        preset_name=collector_preset,
        presets=presets,
        explicit_collectors=_split_values(collectors),
        excluded_collectors=_split_values(exclude),
        include_exchange=include_exchange,
    )
    hints = _load_permission_hints(permission_hints_path)

    collector_rows: list[dict[str, Any]] = []
    graph_permissions: list[str] = []
    role_hints: list[str] = list(profile.delegated_role_hints)
    tool_requirements: list[str] = list(profile.adapter_requirements)
    optional_commands: list[str] = []
    for name in selected:
        definition = config.collectors.get(name)
        hint = _mapping(hints.get(name))
        definition_permissions = list(definition.required_permissions if definition else [])
        hint_permissions = [str(item) for item in hint.get("graph_scopes") or []]
        required = _dedupe([*definition_permissions, *hint_permissions])
        graph_permissions.extend(required)
        role_hints.extend(str(item) for item in hint.get("minimum_role_hints") or [])
        tool_requirements.extend(str(item) for item in hint.get("command_tools") or [])
        optional_commands.extend(str(item) for item in hint.get("optional_commands") or [])
        collector_rows.append(
            {
                "collector": name,
                "description": definition.description if definition else "",
                "required_permissions": required,
                "minimum_role_hints": [str(item) for item in hint.get("minimum_role_hints") or []],
                "tool_requirements": [str(item) for item in hint.get("command_tools") or []],
                "notes": str(hint.get("notes") or ""),
            }
        )

    graph_permissions = _dedupe(graph_permissions)
    role_hints = _dedupe(role_hints)
    tool_requirements = _dedupe(tool_requirements)
    optional_commands = _dedupe(optional_commands)
    broad_permissions = [
        {
            "permission": permission,
            "risk": "write_capable",
            "note": "Permission name includes write/manage capability. Auditex remains audit-only and records observed calls.",
        }
        for permission in graph_permissions
        if any(token in permission for token in M365_WRITE_CAPABLE_TOKENS)
    ]

    delegated_steps = [
        "Assign the operator the minimum delegated reader role that matches the selected collectors.",
        "Run az login against the tenant with --allow-no-subscriptions.",
        "Run probe first and review live-readiness.json before the full audit.",
        "Add only the missing read permission or role shown by the probe, then rerun probe.",
    ]
    app_steps = [
        "Create a customer-owned Microsoft Entra app registration.",
        "Add the listed Microsoft Graph application permissions.",
        "Grant tenant-wide admin consent as an authorized administrator.",
        "Create a local client secret or certificate and store it outside git.",
        "Run app-mode probe before a full unattended run.",
    ]
    exchange_steps = [
        "Install Microsoft 365 CLI only if Exchange or Purview command collectors are selected.",
        "Install PowerShell and ExchangeOnlineManagement only if Exchange PowerShell policy depth is selected.",
        "Keep command adapters read-only and review api-inventory.json after each run.",
    ]

    return {
        "schema_version": "2026-05-22",
        "kind": "auditex_setup_guide",
        "provider": "m365",
        "mode": mode,
        "auditor_profile": auditor_profile,
        "plane": plane,
        "collector_preset": collector_preset,
        "selected_collectors": selected,
        "collector_permissions": collector_rows,
        "graph_permissions": graph_permissions,
        "graph_permissions_csv": ",".join(graph_permissions),
        "minimum_role_hints": role_hints,
        "tool_requirements": tool_requirements,
        "optional_commands": optional_commands,
        "scope_warnings": broad_permissions,
        "provider_assertions": {
            "read_only_audit": True,
            "production_writes": False,
            "mailbox_body_reads": False,
            "sharepoint_file_content_reads": False,
            "onedrive_file_content_reads": False,
            "broad_permissions_recorded_as_scope_risk": bool(broad_permissions),
        },
        "setup_steps": app_steps if mode == "app" else delegated_steps,
        "alternate_setup_steps": {"delegated": delegated_steps, "app": app_steps, "exchange_assisted": exchange_steps},
        "commands": {
            "delegated_login": f"az login --allow-no-subscriptions --tenant {tenant_id}",
            "delegated_probe": (
                f"auditex probe live --tenant-name {tenant_name} --tenant-id {tenant_id} "
                f"--auditor-profile {auditor_profile} --mode delegated --surface all --use-azure-cli-token"
            ),
            "delegated_run": (
                f"auditex run --tenant-name {tenant_name} --tenant-id {tenant_id} "
                f"--auditor-profile {auditor_profile} --plane {plane} --use-azure-cli-token --probe-first --throttle-mode safe"
            ),
            "app_probe": (
                f"auditex probe live --tenant-name {tenant_name} --tenant-id {tenant_id} "
                f"--auditor-profile {auditor_profile} --mode app --client-id <app-id> --client-secret <client-secret>"
            ),
            "app_run": (
                f"auditex run --tenant-name {tenant_name} --tenant-id {tenant_id} "
                f"--auditor-profile {auditor_profile} --plane {plane} --client-id <app-id> --client-secret <client-secret> "
                "--probe-first --throttle-mode safe"
            ),
        },
        "review_artifacts": [
            "audit-plan.json",
            "live-readiness.json",
            "api-inventory.json",
            "data-handling.json",
            "diagnostics.json",
            "reports/report-pack.json",
            "validation.json",
        ],
        "source_references": M365_SOURCE_REFERENCES,
    }


def render_setup_guide_markdown(payload: Mapping[str, Any]) -> str:
    provider = str(payload.get("provider") or "")
    lines = [
        f"# Auditex Setup Guide: {provider}",
        "",
        f"- Provider: {_md(payload.get('provider'))}",
        f"- Mode/Auth: {_md(payload.get('mode') or payload.get('auth'))}",
        f"- Preset: {_md(payload.get('collector_preset'))}",
        f"- Read-only audit: {_md(_mapping(payload.get('provider_assertions')).get('read_only_audit'))}",
        f"- Production writes: {_md(_mapping(payload.get('provider_assertions')).get('production_writes'))}",
        "",
        "## Selected Collectors",
        "",
    ]
    for collector in payload.get("selected_collectors") or []:
        lines.append(f"- `{collector}`")

    if provider == "google_workspace":
        lines.extend(["", "## OAuth Scopes", "", "Paste this comma-separated value into Google Admin domain-wide delegation:", "", "```text", str(payload.get("scopes_csv") or ""), "```"])
        lines.extend(["", "## APIs To Enable", ""])
        for api in payload.get("api_enablement") or []:
            lines.append(f"- {api}")
    else:
        lines.extend(["", "## Microsoft Graph Permissions", ""])
        for permission in payload.get("graph_permissions") or []:
            lines.append(f"- `{permission}`")
        lines.extend(["", "## Role Hints", ""])
        for role in payload.get("minimum_role_hints") or []:
            lines.append(f"- {role}")
        tools = payload.get("tool_requirements") or []
        if tools:
            lines.extend(["", "## Tool Requirements", ""])
            for tool in tools:
                lines.append(f"- `{tool}`")

    warnings = payload.get("scope_warnings") or []
    if warnings:
        lines.extend(["", "## Scope Risk Notes", ""])
        for warning in warnings:
            key = warning.get("scope") or warning.get("permission")
            lines.append(f"- `{key}`: {warning.get('note')}")

    lines.extend(["", "## Setup Steps", ""])
    for index, step in enumerate(payload.get("setup_steps") or [], start=1):
        lines.append(f"{index}. {step}")

    lines.extend(["", "## Verify Commands", ""])
    commands = _mapping(payload.get("commands"))
    for name, command in commands.items():
        lines.extend([f"### {name}", "", "```bash", str(command), "```", ""])

    lines.extend(["## Review Artifacts", ""])
    for artifact in payload.get("review_artifacts") or []:
        lines.append(f"- `{artifact}`")

    lines.extend(["", "## Sources", ""])
    for source in payload.get("source_references") or []:
        row = _mapping(source)
        lines.append(f"- [{_md(row.get('name'))}]({_md(row.get('url'))})")

    return "\n".join(lines).rstrip() + "\n"


def _select_google_collectors(
    *,
    registry: Mapping[str, Any],
    presets: Mapping[str, tuple[str, ...]],
    collector_preset: str,
    collectors: str | list[str] | None,
    exclude: str | list[str] | None,
) -> list[str]:
    explicit = _split_values(collectors)
    excluded = set(_split_values(exclude))
    if explicit:
        base = explicit
    else:
        if collector_preset not in presets:
            raise ValueError(f"Unknown Google collector preset '{collector_preset}'.")
        base = list(presets[collector_preset])
    unknown = [name for name in base if name not in registry]
    if unknown:
        raise ValueError(f"Unknown Google collector(s): {', '.join(unknown)}")
    selected = [name for name in base if name not in excluded]
    if not selected:
        raise ValueError("No Google collectors selected.")
    return selected


def _google_command(
    command: str,
    *,
    auth: str,
    domain: str,
    customer_id: str,
    subject: str,
    service_account_key: str,
    oauth_client: str,
    token_cache: str,
    collector_preset: str,
    tenant_name: str | None = None,
    extra: str = "",
) -> str:
    parts = ["auditex", "google", command, "--auth", auth]
    if auth == "domain-delegation":
        parts.extend(["--service-account-key", service_account_key, "--subject", subject])
    else:
        parts.extend(["--oauth-client", oauth_client, "--token-cache", token_cache])
    parts.extend(["--domain", domain, "--customer-id", customer_id, "--collector-preset", collector_preset])
    if tenant_name:
        parts.extend(["--tenant-name", tenant_name])
    if extra:
        parts.extend(extra.split())
    return " ".join(parts)


def _load_permission_hints(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(payload, dict):
        return {}
    rows = payload.get("collector_permissions")
    return rows if isinstance(rows, dict) else {}


def _split_values(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw = value.split(",")
    else:
        raw = value
    return [str(item).strip() for item in raw if str(item).strip()]


def _dedupe(values: Any) -> list[str]:
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


def _md(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|")
