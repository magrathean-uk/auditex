from __future__ import annotations

import json
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.data_handling import collector_activity_notices
from azure_tenant_audit.diagnostics import reader_roles
from azure_tenant_audit.presets import load_collector_presets
from azure_tenant_audit.profiles import get_profile
from azure_tenant_audit.scope_catalog import (
    aggregate_catalog_rows,
    build_google_scope_catalog,
    build_m365_scope_catalog,
)
from azure_tenant_audit.selection import select_collectors

# Every permission, role and setting of the reader app, for the tenant administrator (DEC-107).
READER_APP_GUIDE = "docs/guides/reader-app-permissions.md"

GOOGLE_PROVIDER_ALIASES = {"google", "google_workspace", "workspace"}
M365_PROVIDER_ALIASES = {"m365", "entra", "microsoft365", "microsoft_365"}

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

M365_WRITE_CAPABLE_TOKENS = ("ReadWrite", "ManageAsApp", "Write.", "FullControl")
# Blast radius of the SharePoint application permission the opt-in sharepoint_admin collector needs.
SHAREPOINT_FULLCONTROL_BLAST_RADIUS = (
    "Write-capable SharePoint application permission used read-only: blast radius full control of every site "
    "collection and OneDrive. Microsoft offers no read-only permission for the SharePoint admin API; Auditex sends "
    "only one body-free GET of the tenant sharing settings with it, and the read guard refuses any other request. "
    "Remove it after the engagement."
)


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
    config_path: str | Path = "configs/collector-definitions.json",
    permission_hints_path: str | Path = "configs/collector-permissions.json",
) -> dict[str, Any]:
    _refuse_control_characters(
        tenant_name=tenant_name, tenant_id=tenant_id, domain=domain, customer_id=customer_id, subject=subject,
        service_account_key=service_account_key, oauth_client=oauth_client, token_cache=token_cache,
        auditor_profile=auditor_profile, plane=plane, collector_preset=collector_preset, auth=auth,
    )
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
    catalog = build_google_scope_catalog(registry=REGISTRY)
    aggregate = aggregate_catalog_rows(catalog, selected)
    required_scopes = aggregate["required_permissions"]
    scope_warnings = aggregate["scope_warnings"]
    api_enablement = aggregate["api_enablement"]
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


# Collectors that read through the CLI for Microsoft 365 before DEC-108 D2; their guide step names the gaps.
M365_CLI_GAP_COLLECTORS = frozenset({"purview", "ediscovery", "exchange"})


def build_m365_setup_guide(
    *,
    collector_preset: str | None = None,
    collectors: str | list[str] | None = None,
    exclude: str | list[str] | None = None,
    tenant_name: str = "CLIENT",
    tenant_id: str = "<tenant-id-or-domain>",
    auditor_profile: str = "global-reader",
    plane: str = "full",
    config_path: str | Path = "configs/collector-definitions.json",
    permission_hints_path: str | Path = "configs/collector-permissions.json",
) -> dict[str, Any]:
    """The setup guide for the one Microsoft 365 way: the reader app with a certificate (DEC-107)."""
    config = CollectorConfig.from_path(config_path)
    profile = get_profile(auditor_profile)
    if plane not in profile.supported_planes:
        raise ValueError(
            f"Auditor profile {profile.name} does not support plane {plane}; "
            f"choose one of: {', '.join(profile.supported_planes)}."
        )
    presets = load_collector_presets()
    selected = select_collectors(
        available=config.default_order,
        profile_default_collectors=profile.default_collectors,
        preset_name=collector_preset, presets=presets,
        explicit_collectors=_split_values(collectors),
        excluded_collectors=_split_values(exclude),
    )
    if not selected:
        raise ValueError("No collectors selected.")
    hints = _load_permission_hints(permission_hints_path)
    catalog = build_m365_scope_catalog(
        collector_config=config,
        permission_hints=hints,
    )
    aggregate = aggregate_catalog_rows(catalog, selected)

    collector_rows: list[dict[str, Any]] = []
    graph_permissions: list[str] = list(aggregate["required_permissions"])
    role_hints: list[str] = reader_roles([*profile.delegated_role_hints, *aggregate["minimum_role_hints"]])
    optional_commands: list[str] = list(aggregate["optional_commands"])
    for name in selected:
        row = _mapping(catalog.get(name))
        collector_rows.append(
            {
                "collector": name,
                "description": row.get("description", ""),
                "required_permissions": list(row.get("required_permissions") or []),
                "minimum_role_hints": reader_roles(row.get("minimum_role_hints") or []),
                "tool_requirements": list(row.get("tool_requirements") or []),
                "notes": str(row.get("notes") or ""),
            }
        )

    # R006: optional Graph scopes stay out of the default grant; each is listed apart with its blast radius.
    optional_graph_permissions: list[dict[str, str]] = []
    for permission in aggregate["optional_permissions"]:
        if permission in graph_permissions:
            continue
        for name in selected:
            row = _mapping(catalog.get(name))
            if permission in (row.get("optional_permissions") or []):
                optional_graph_permissions.append(
                    {
                        "permission": permission,
                        "collector": name,
                        "note": str(_mapping(row.get("optional_permission_notes")).get(permission) or ""),
                    }
                )

    tool_requirements = _dedupe([*profile.adapter_requirements, *aggregate["tool_requirements"]])
    if "exchange_policy" in selected:
        tool_requirements = _dedupe([*tool_requirements, "pwsh", "ExchangeOnlineManagement"])
    elif auditor_profile in {"auto", "global-reader"}:
        tool_requirements = [tool for tool in tool_requirements if tool not in {"pwsh", "ExchangeOnlineManagement"}]
    exchange_permissions = ["Exchange.ManageAsApp"] if "exchange_policy" in selected else []
    sharepoint_permissions: list[str] = list(aggregate.get("sharepoint_permissions") or [])
    exchange_blast_radius = (
        "Write-capable Exchange application permission used read-only: read-only Get-* cmdlets only; "
        "no mutating cmdlet is issued; the Exchange.ManageAsApp role assignment gives Global Reader only. "
        "Tenant-wide Exchange policy visibility is granted; a write-capable scope does not authorise tenant writes."
    )
    broad_permissions = [
        {
            "permission": permission,
            "risk": "write_capable",
            "note": "Permission name includes write/manage capability. Auditex remains audit-only and records observed calls.",
        }
        for permission in _dedupe([*graph_permissions, *exchange_permissions, *sharepoint_permissions])
        if any(token in permission for token in M365_WRITE_CAPABLE_TOKENS)
    ]
    for warning in broad_permissions:
        if warning["permission"] == "Exchange.ManageAsApp":
            warning["note"] = exchange_blast_radius
        elif warning["permission"] in sharepoint_permissions and "FullControl" in warning["permission"]:
            warning["note"] = SHAREPOINT_FULLCONTROL_BLAST_RADIUS

    collection_notices = collector_activity_notices(selected, "app")
    setup_steps = [
        f"Give the tenant administrator {READER_APP_GUIDE}: it lists every permission, role and setting the reader "
        "app needs, exactly as the Microsoft admin centres name them, and how to remove all of it afterwards.",
        "Register one single-tenant app (the reader app) with no redirect URI, no client secret and no delegated "
        "permission.",
        "Add the listed Microsoft Graph application permissions and grant tenant-wide admin consent as an authorised "
        "administrator.",
        "Create a certificate on the audit machine, upload only its public part to the app and keep the private key "
        "in a file readable only by the person running Auditex. The private key can sign in as the app with every "
        "permission it holds; it is never copied into the run.",
        "Run the probe with the certificate before the full run, add only what the probe shows missing, then run.",
        *collection_notices,
    ]
    if "exchange_policy" in selected:
        setup_steps.append(
            "For Exchange, grant admin consent to Exchange.ManageAsApp and assign Global Reader to the reader app; "
            "install pwsh and ExchangeOnlineManagement. " + exchange_blast_radius
        )
    if sharepoint_permissions:
        setup_steps.append(
            f"For sharepoint_admin, add the SharePoint (Office 365 SharePoint Online) application permission "
            f"{', '.join(sharepoint_permissions)} and grant admin consent. " + SHAREPOINT_FULLCONTROL_BLAST_RADIUS
        )
    if "teams_policy" in selected:
        setup_steps.append(
            "Teams admin policies (teams_policy) are read with a Teams admin token minted from the certificate; the "
            "Global Reader role on the reader app allows the reads. A token that cannot be minted is recorded as "
            "teams_token_unavailable."
        )
    # DEC-108 D2: collectors whose reads went through the CLI for Microsoft 365 state what the certificate reads and
    # which reads are named gaps, from the permission metadata (configs/collector-permissions.json).
    for name in selected:
        if name in M365_CLI_GAP_COLLECTORS:
            setup_steps.append(f"{name}: {_mapping(catalog.get(name)).get('notes') or ''}".rstrip())
    # DEC-065: the one-time set-up sign-in is counted apart from the audit, which signs in to nothing.
    setup_steps.append(
        "Sign-ins, certificate route: set-up takes one administrator sign-in to the Microsoft Entra admin centre "
        "(app registration, permissions and admin consent, role assignment and the certificate upload in the same "
        "session); creating the certificate and its key needs none. The audit itself takes no interactive sign-in: "
        "an app-only certificate run mints every service token silently from the certificate."
    )

    credential = (
        "--client-id <app-id> --certificate-path <private-key-file> --certificate-thumbprint <sha1-thumbprint>"
    )
    # Every caller value is shell-quoted; the <...> placeholders in ``credential`` are the operator's to fill in.
    q = shlex.quote
    preset_flag = f" --collector-preset {q(collector_preset)}" if collector_preset else ""
    commands = {
        "probe": (
            f"auditex probe live --tenant-name {q(tenant_name)} --tenant-id {q(tenant_id)} "
            f"--auditor-profile {q(auditor_profile)} --mode app {credential} "
            f"--surface {q(','.join(_dedupe([*selected, 'windows365'])))}"
        ),
        "run": (
            f"auditex run --tenant-name {q(tenant_name)} --tenant-id {q(tenant_id)} "
            f"--auditor-profile {q(auditor_profile)} --plane {q(plane)} {credential} "
            f"--probe-first --throttle-mode safe{preset_flag} --collectors {q(','.join(selected))}"
        ),
    }

    return {
        "schema_version": "2026-05-22",
        "kind": "auditex_setup_guide",
        "provider": "m365",
        "mode": "app",
        "credential": "reader app with a certificate",
        "permissions_guide": READER_APP_GUIDE,
        "auditor_profile": auditor_profile,
        "plane": plane,
        "collector_preset": collector_preset,
        "selected_collectors": selected,
        "collector_permissions": collector_rows,
        "graph_permissions": graph_permissions,
        "graph_permissions_csv": ",".join(graph_permissions),
        "optional_graph_permissions": optional_graph_permissions,
        "exchange_application_permissions": exchange_permissions,
        "sharepoint_application_permissions": sharepoint_permissions,
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
        "setup_steps": setup_steps,
        "collection_notices": collection_notices,
        "commands": commands,
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
        f"- Mode/Auth: {_md(payload.get('credential') or payload.get('auth'))}",
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
        optional = [_mapping(row) for row in payload.get("optional_graph_permissions") or []]
        if optional:
            lines.extend(["", "## Optional Microsoft Graph Permissions (not part of the default grant)", ""])
            for row in optional:
                note = f": {row['note']}" if row.get("note") else ""
                lines.append(f"- `{row.get('permission')}` (only for `{row.get('collector')}`){note}")
        if payload.get("exchange_application_permissions"):
            lines.extend(["", "## Exchange Application Permissions", ""])
            for permission in payload["exchange_application_permissions"]:
                lines.append(f"- `{permission}` (Office 365 Exchange Online, not Microsoft Graph)")
        if payload.get("sharepoint_application_permissions"):
            lines.extend(["", "## SharePoint Application Permissions", ""])
            for permission in payload["sharepoint_application_permissions"]:
                lines.append(f"- `{permission}` (Office 365 SharePoint Online, not Microsoft Graph)")
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

    if payload.get("permissions_guide"):
        lines.extend(["", f"Every permission, role and setting of the reader app: `{payload['permissions_guide']}`."])

    lines.extend(["", "## Verify Commands", ""])

    commands = _mapping(payload.get("commands"))
    for name, command in commands.items():
        if command is None:
            continue
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
    return shlex.join(parts)


def _refuse_control_characters(**values: Any) -> None:
    """Refuse a value for a verification command that holds a line break or control character.

    Values are shell-quoted, but a line break inside quotes still ends a line of the rendered Markdown, where it could
    close the command fence and add text the operator reads as part of the guide.
    """
    for name, value in values.items():
        if isinstance(value, str) and any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError(f"{name} must not contain a line break or control character.")


def _load_permission_hints(path: str | Path) -> dict[str, Any]:
    from azure_tenant_audit.resources import read_selected_resource

    default = "configs/collector-permissions.json"
    try:
        payload = json.loads(read_selected_resource(path, default=default, field="permission-hints"))
    except FileNotFoundError:
        if str(path) != default:
            # An explicit path the operator typed must exist: a silent {} would drop role hints and tool requirements.
            raise FileNotFoundError(f"The --permission-hints file was not found: {path}") from None
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
