from __future__ import annotations

from typing import Any, Callable, Optional

from ..adapters import get_adapter
from .base import Collector, CollectorResult


class TeamsPolicyCollector(Collector):
    name = "teams_policy"
    description = "Teams federation, messaging, meeting, and app policy posture."
    required_permissions = [
        "TeamSettings.Read.All",
    ]
    command_collectors = [
        (
            "tenantFederationConfiguration",
            "Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers,AllowTeamsConsumer,AllowPublicUsers",
        ),
        (
            "messagingPolicies",
            "Get-CsTeamsMessagingPolicy | Select-Object Identity,AllowOwnerDeleteMessage,AllowUserDeleteMessage,AllowUserEditMessage",
        ),
        (
            "meetingPolicies",
            "Get-CsTeamsMeetingPolicy | Select-Object Identity,AllowCloudRecording,AllowIPVideo,ScreenSharingMode",
        ),
        (
            "appPermissionPolicies",
            "Get-CsTeamsAppPermissionPolicy | Select-Object Identity,GlobalCatalogAppsType",
        ),
        (
            "appSetupPolicies",
            "Get-CsTeamsAppSetupPolicy | Select-Object Identity,AllowSideLoading",
        ),
    ]

    def run(self, context: dict[str, Any]) -> CollectorResult:
        log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = context.get("audit_logger")
        adapter = get_adapter("powershell_graph")
        payload: dict[str, Any] = {}
        coverage: list[dict[str, Any]] = []
        total = 0

        for name, command in self.command_collectors:
            response = adapter.run(command, log_event=log_event, session={"kind": "microsoft_teams"})
            response.setdefault("command", command)
            payload[name] = response
            values = response.get("value")
            item_count = len(values) if isinstance(values, list) else 0
            total += item_count
            coverage.append(
                {
                    "collector": self.name,
                    "type": "command",
                    "name": name,
                    "command": command,
                    "status": "failed" if response.get("error") else "ok",
                    "item_count": item_count,
                    "duration_ms": response.get("duration_ms", 0.0),
                    "error_class": response.get("error_class"),
                    "error": response.get("error"),
                }
            )

        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            name=self.name,
            status="partial" if partial else "ok",
            payload=payload,
            item_count=total,
            message="Teams policy collector partially completed" if partial else "",
            coverage=coverage,
        )
