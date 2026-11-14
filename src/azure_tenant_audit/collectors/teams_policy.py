from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..adapters import get_adapter
from ..collection_gaps import (
    REASON_TEAMS_POWERSHELL_NOT_SUPPORTED,
    REASON_TEAMS_TOKEN_UNAVAILABLE,
    SECTION_GAP_REASON_TEXT,
    SECTION_SCOPED,
)
from .base import Collector, CollectorResult

TEAMS_OPERATIONS: tuple[str, ...] = (
    "tenantFederationConfiguration",
    "messagingPolicies",
    "meetingPolicies",
    "appPermissionPolicies",
    "appSetupPolicies",
    "broadcastPolicies",
    "clientConfiguration",
)

# Org-wide unified app settings (MS.TEAMS 5.1-5.3). Kept out of ``command_collectors`` (the configured
# PowerShell list): the cmdlet and its REST source (``teams_admin_rest.TEAMS_UNIFIED_READ_PATHS``) answer
# only a user sign-in, so this app-only collector records the named skip and never sends the read. The
# rule adapter then gives the rules ScubaGear's certificate-authentication input, and MS.TEAMS 5.1-5.3
# are judged from appPermissionPolicies, as ScubaGear judges them with certificate authentication.
APP_SETTINGS_OPERATION = "tenantAppSettings"
APP_SETTINGS_COMMAND = "Get-M365UnifiedTenantSettings | Select-Object SettingName,SettingValue"


class TeamsPolicyCollector(Collector):
    name = "teams_policy"
    description = "Teams federation, messaging, meeting, and app policy posture."
    required_permissions = []
    command_collectors = [
        (
            "tenantFederationConfiguration",
            "Get-CsTenantFederationConfiguration | Select-Object Identity,AllowFederatedUsers,AllowTeamsConsumer,AllowTeamsConsumerInbound,AllowPublicUsers,AllowedDomains,BlockedDomains",
        ),
        (
            "messagingPolicies",
            "Get-CsTeamsMessagingPolicy | Select-Object Identity,AllowOwnerDeleteMessage,AllowUserDeleteMessage,AllowUserEditMessage",
        ),
        (
            "meetingPolicies",
            "Get-CsTeamsMeetingPolicy | Select-Object Identity,AllowCloudRecording,AllowIPVideo,ScreenSharingMode,AllowExternalParticipantGiveRequestControl,AllowAnonymousUsersToStartMeeting,AutoAdmittedUsers,AllowPSTNUsersToBypassLobby",
        ),
        (
            "appPermissionPolicies",
            "Get-CsTeamsAppPermissionPolicy | Select-Object Identity,DefaultCatalogAppsType,GlobalCatalogAppsType,PrivateCatalogAppsType",
        ),
        (
            "appSetupPolicies",
            "Get-CsTeamsAppSetupPolicy | Select-Object Identity,AllowSideLoading",
        ),
        (
            "broadcastPolicies",
            "Get-CsTeamsMeetingBroadcastPolicy | Select-Object Identity,BroadcastRecordingMode",
        ),
        (
            "clientConfiguration",
            "Get-CsTeamsClientConfiguration | Select-Object Identity,AllowEmailIntoChannel",
        ),
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        from urllib.parse import urlsplit

        from ..adapters.teams_admin_rest import (
            TEAMS_ADMIN_BASE,
            TEAMS_ADMIN_SCOPE,
            TEAMS_READ_PATHS,
            TEAMS_UNIFIED_BASE,
            certificate_token,
        )
        from ..graph import GRAPH_ROOT, GraphClient

        log_event: Callable[[str, str, dict[str, Any] | None], None] | None = context.get("audit_logger")
        client = context.get("client")
        manifest = context.get("manifest") or {}
        environment = context.get("environment") or context.get("m365_environment") or manifest.get("environment")
        endpoint = (context.get("graph_endpoint") or manifest.get("graph_endpoint")
                    or getattr(client, "graph_endpoint", None)
                    or (GRAPH_ROOT if isinstance(client, GraphClient) else ""))
        if not environment and endpoint:
            parsed_endpoint = urlsplit(endpoint)
            environment = ("commercial" if parsed_endpoint.scheme == "https"
                           and parsed_endpoint.netloc == "graph.microsoft.com" else "unknown")
        if not environment and hasattr(client, "app_token_for"):
            environment = "unknown"
        auth = getattr(client, "auth", None)
        token = None
        # Only a certificate credential mints the Teams admin token: GraphClient.app_token_for
        # returns None for it otherwise, and a run with a client secret never asks, so a
        # secret-only or delegated run records teams_token_unavailable below. In app mode with a
        # certificate the five REST reads run; messaging and app setup policies (no REST read path)
        # and the unified app settings (a user sign-in only) stay named skips.
        if not getattr(auth, "client_secret", None) and getattr(auth, "auth_mode", "app") == "app":
            if environment in TEAMS_ADMIN_BASE and hasattr(client, "app_token_for"):
                try:
                    token = client.app_token_for(TEAMS_ADMIN_SCOPE)
                except Exception:  # Token errors may contain credentials; keep diagnostics out of the bundle.
                    token = None
        if not certificate_token(token):
            token = None
        rest = get_adapter("teams_admin_rest") if token else None
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0

        for name, command in (*self.command_collectors, (APP_SETTINGS_OPERATION, APP_SETTINGS_COMMAND)):
            rest_read = name in TEAMS_READ_PATHS and bool(token)
            skipped = False
            bases = TEAMS_UNIFIED_BASE if name == APP_SETTINGS_OPERATION else TEAMS_ADMIN_BASE
            if (name in TEAMS_READ_PATHS or name == APP_SETTINGS_OPERATION) and environment and environment not in bases:
                response = {"error": "unsupported_environment", "error_class": "unsupported_environment"}
            elif not token:
                # No adapter connects a Teams PowerShell session. An unavailable
                # certificate token is a named coverage gap, not a failed read.
                skipped = True
                response = {"value": [], "status": "skipped",
                            "reason": REASON_TEAMS_TOKEN_UNAVAILABLE,
                            SECTION_SCOPED: True,
                            "error_class": "teams_token_unavailable",
                            "error": SECTION_GAP_REASON_TEXT[REASON_TEAMS_TOKEN_UNAVAILABLE]}
            elif name in TEAMS_READ_PATHS and token:
                response = rest.get(name, token, environment, log_event=log_event)
            else:
                # No Teams session path exists. Never launch an unauthenticated
                # PowerShell command for operations outside the REST allowlist.
                skipped = True
                response = {"value": [], "status": "skipped",
                            "reason": REASON_TEAMS_POWERSHELL_NOT_SUPPORTED,
                            SECTION_SCOPED: True,
                            "error_class": "teams_powershell_not_supported",
                            "error": SECTION_GAP_REASON_TEXT[REASON_TEAMS_POWERSHELL_NOT_SUPPORTED]}
            response.setdefault("command", command)
            payload[name] = response
            values = response.get("value")
            item_count = len(values) if isinstance(values, list) else 0
            total += item_count
            coverage.append(
                {
                    "collector": self.name,
                    **({
                        "type": "teams_admin_rest",
                        "method": "GET",
                        "endpoint": TEAMS_ADMIN_BASE[environment] + TEAMS_READ_PATHS[name],
                    } if rest_read else {"type": "command", "command": command}),
                    "name": name,
                    "status": "skipped" if skipped else "failed" if response.get("error") else "ok",
                    "item_count": item_count,
                    "duration_ms": response.get("duration_ms", 0.0),
                    "error_class": response.get("error_class"),
                    "error": response.get("error"),
                }
            )
            if skipped:
                coverage[-1].update(reason=response["reason"], **{SECTION_SCOPED: True})

        partial = any(item.get("status") not in {"ok", "skipped"} for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message=("Teams policy collector partially completed" if partial else
                     SECTION_GAP_REASON_TEXT[REASON_TEAMS_TOKEN_UNAVAILABLE] if not token else ""),
            coverage=coverage,
        )
