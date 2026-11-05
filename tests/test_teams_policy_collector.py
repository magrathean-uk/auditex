from __future__ import annotations

from pathlib import Path
from typing import Any

from azure_tenant_audit.collectors.teams_policy import TEAMS_OPERATIONS, TeamsPolicyCollector
from azure_tenant_audit.config import CollectorConfig


REQUIRED = {
    "meetingPolicies": [
        "Identity",
        "AllowAnonymousUsersToStartMeeting",
        "AllowCloudRecording",
        "AllowExternalParticipantGiveRequestControl",
        "AllowPSTNUsersToBypassLobby",
        "AutoAdmittedUsers",
    ],
    "broadcastPolicies": ["Identity", "BroadcastRecordingMode"],
    "tenantFederationConfiguration": [
        "Identity",
        "AllowFederatedUsers",
        "AllowTeamsConsumer",
        "AllowTeamsConsumerInbound",
        "AllowedDomains",
    ],
    "clientConfiguration": ["Identity", "AllowEmailIntoChannel"],
    "appPermissionPolicies": [
        "Identity",
        "DefaultCatalogAppsType",
        "GlobalCatalogAppsType",
        "PrivateCatalogAppsType",
    ],
}


class _FakeAdapter:
    def __init__(self, failed_operation: str | None = None) -> None:
        self.failed_operation = failed_operation
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def run(self, command: str, *, log_event=None, session: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((command, session))
        commands = dict(TeamsPolicyCollector.command_collectors)
        if self.failed_operation and command == commands[self.failed_operation]:
            return {"error": "Policy read failed", "error_class": "permission", "value": []}
        return {"value": [{"Identity": "Global"}], "duration_ms": 1.0}


def test_command_list_matches_config() -> None:
    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    definition = config.collectors["teams_policy"]
    assert definition.command_collectors is not None
    configured = []
    for entry in definition.command_collectors:
        assert entry["category"] == "policy"
        assert len(entry["commands"]) == 1
        configured.append((entry["name"], entry["commands"][0]))
    assert TeamsPolicyCollector.command_collectors == configured
    assert TEAMS_OPERATIONS == tuple(name for name, _ in configured)
    assert definition.query_plan == list(TEAMS_OPERATIONS)


def test_rule_fields_are_selected() -> None:
    commands = dict(TeamsPolicyCollector.command_collectors)
    for name, required in REQUIRED.items():
        _, fields = commands[name].split(" | Select-Object ")
        selected = {field.strip() for field in fields.split(",")}
        assert selected.issuperset(required), name


def test_only_get_commands() -> None:
    for _, command in TeamsPolicyCollector.command_collectors:
        assert command.startswith("Get-")
        assert not any(verb in command for verb in ("Set-", "New-", "Remove-", "Grant-", "Invoke-"))


def test_failed_operation_marks_only_its_own_row(monkeypatch) -> None:
    adapter = _FakeAdapter(failed_operation="broadcastPolicies")
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", lambda _name: adapter)

    result = TeamsPolicyCollector().run({"audit_logger": None})

    assert result.status == "partial"
    assert len(result.coverage) == 7
    assert {row["name"]: row["status"] for row in result.coverage} == {
        name: "failed" if name == "broadcastPolicies" else "ok" for name in TEAMS_OPERATIONS
    }
    assert result.item_count == 6
    assert result.payload["broadcastPolicies"]["error"] == "Policy read failed"
    for name in TEAMS_OPERATIONS:
        if name != "broadcastPolicies":
            assert result.payload[name]["value"] == [{"Identity": "Global"}]


def test_all_seven_operations_collected(monkeypatch) -> None:
    expected = (
        "tenantFederationConfiguration",
        "messagingPolicies",
        "meetingPolicies",
        "appPermissionPolicies",
        "appSetupPolicies",
        "broadcastPolicies",
        "clientConfiguration",
    )
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", lambda _name: adapter)

    result = TeamsPolicyCollector().run({"audit_logger": None})

    assert TEAMS_OPERATIONS == expected
    assert tuple(result.payload) == expected
    assert tuple(row["name"] for row in result.coverage) == expected
    assert result.status == "ok"
    assert result.item_count == 7
    assert all(row["status"] == "ok" and row["item_count"] == 1 for row in result.coverage)
    assert adapter.calls == [
        (command, {"kind": "microsoft_teams"}) for _, command in TeamsPolicyCollector.command_collectors
    ]
    for name, command in TeamsPolicyCollector.command_collectors:
        assert result.payload[name]["value"] == [{"Identity": "Global"}]
        assert result.payload[name]["command"] == command
