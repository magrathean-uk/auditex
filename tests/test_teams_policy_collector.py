from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from test_teams_admin_rest import Client

from azure_tenant_audit.collectors.teams_policy import (
    TEAMS_OPERATIONS,
    TeamsPolicyCollector,
)
from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

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

    def get(self, name, token, environment, **kwargs):
        if name == self.failed_operation:
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


def test_required_permissions_match_config_and_app_recommendation() -> None:
    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    assert TeamsPolicyCollector.required_permissions == config.collectors["teams_policy"].required_permissions == []
    permissions = json.loads(Path("configs/collector-permissions.json").read_text(encoding="utf-8"))
    assert "TeamSettings.Read.All" not in permissions["global_app_recommendation"]


def test_rule_fields_are_selected() -> None:
    commands = dict(TeamsPolicyCollector.command_collectors)
    for name, required in REQUIRED.items():
        _, fields = commands[name].split(" | Select-Object ")
        selected = {field.strip() for field in fields.split(",")}
        assert selected.issuperset(required), name


def test_every_declared_cmdlet_is_in_the_permission_notes() -> None:
    path = Path(__file__).resolve().parent.parent / "configs" / "collector-permissions.json"
    permissions = json.loads(path.read_text(encoding="utf-8"))["collector_permissions"]["teams_policy"]
    for _, command in TeamsPolicyCollector.command_collectors:
        cmdlet = command.split()[0]
        assert cmdlet in permissions["optional_commands"], cmdlet


def test_global_federation_identity_pins_normalised_and_finding_ids() -> None:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads={
            "teams_policy": {
                "tenantFederationConfiguration": {
                    "value": [{
                        "Identity": "Global",
                        "AllowFederatedUsers": True,
                        "AllowTeamsConsumer": True,
                        "AllowTeamsConsumerInbound": True,
                        "AllowPublicUsers": True,
                        "AllowedDomains": "AllowAllKnownDomains",
                        "BlockedDomains": [],
                    }],
                },
                "meetingPolicies": {
                    "value": [{
                        "Identity": "Global",
                        "AllowCloudRecording": True,
                        "AllowIPVideo": True,
                        "ScreenSharingMode": "EntireScreen",
                        "AllowExternalParticipantGiveRequestControl": False,
                        "AllowAnonymousUsersToStartMeeting": False,
                        "AutoAdmittedUsers": "EveryoneInCompany",
                        "AllowPSTNUsersToBypassLobby": False,
                    }],
                },
                "messagingPolicies": {
                    "value": [{
                        "Identity": "Global",
                        "AllowOwnerDeleteMessage": False,
                        "AllowUserDeleteMessage": True,
                        "AllowUserEditMessage": True,
                    }],
                },
            },
        },
    )

    (federation,) = (
        row for row in snapshot["teams_policy_objects"]["records"]
        if row["source_name"] == "tenantFederationConfiguration"
    )
    # One-off drift for compare: old runs used tenantFederationConfiguration as the
    # normalised id and teams_policy:tenantFederationConfiguration:external_federation_open
    # as the finding id; the same finding appears resolved and new across this change.
    assert federation["id"] == "tenantFederationConfiguration:Global"
    assert federation["key"] == "teams_policy_object:tenantFederationConfiguration:Global"
    (finding,) = (
        row for row in build_findings([], normalized_snapshot=snapshot)
        if row["rule_id"] == "teams.external_federation_open"
    )
    assert finding["id"] == "teams_policy:tenantFederationConfiguration:Global:external_federation_open"
    assert finding["affected_objects"] == ["Global"]


def test_only_get_commands() -> None:
    for _, command in TeamsPolicyCollector.command_collectors:
        assert command.startswith("Get-")
        assert not any(verb in command for verb in ("Set-", "New-", "Remove-", "Grant-", "Invoke-"))


def test_failed_operation_marks_only_its_own_row(monkeypatch) -> None:
    adapter = _FakeAdapter(failed_operation="broadcastPolicies")
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", lambda _name: adapter)

    result = TeamsPolicyCollector().run({"client": Client(), "audit_logger": None})

    assert result.status == "partial"
    assert len(result.coverage) == 7
    assert {row["name"]: row["status"] for row in result.coverage} == {
        name: "failed" if name == "broadcastPolicies" else
        "skipped" if name in {"messagingPolicies", "appSetupPolicies"} else "ok" for name in TEAMS_OPERATIONS
    }
    assert result.item_count == 4
    assert result.payload["broadcastPolicies"]["error"] == "Policy read failed"
    for name in TEAMS_OPERATIONS:
        if name not in {"broadcastPolicies", "messagingPolicies", "appSetupPolicies"}:
            assert result.payload[name]["value"] == [{"Identity": "Global"}]


def test_no_token_skips_all_seven_operations_without_loading_an_adapter(monkeypatch) -> None:
    expected = (
        "tenantFederationConfiguration",
        "messagingPolicies",
        "meetingPolicies",
        "appPermissionPolicies",
        "appSetupPolicies",
        "broadcastPolicies",
        "clientConfiguration",
    )
    def forbidden_adapter(name):
        raise AssertionError(f"No adapter may be loaded without a Teams token: {name}")
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", forbidden_adapter)

    result = TeamsPolicyCollector().run({"audit_logger": None})

    assert TEAMS_OPERATIONS == expected
    assert tuple(result.payload) == expected
    assert tuple(row["name"] for row in result.coverage) == expected
    assert result.status == "ok"
    assert result.item_count == 0 and result.error is None
    assert all(row["status"] == "skipped" and row["item_count"] == 0 for row in result.coverage)
    assert all(row["reason"] == "teams_token_unavailable" and row["section_scoped"] for row in result.coverage)
    for name, command in TeamsPolicyCollector.command_collectors:
        assert result.payload[name]["value"] == []
        assert result.payload[name]["status"] == "skipped"
        assert result.payload[name]["command"] == command

    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="skipped-teams", collector_payloads={"teams_policy": result.payload},
        coverage_rows=result.coverage,
    )
    assert not snapshot.get("teams_policy_objects", {}).get("records")
    assert not [row for row in build_findings([], normalized_snapshot=snapshot) if row.get("collector") == "teams_policy"]
    gaps = snapshot["collection_gaps"]["records"]
    assert len(gaps) == 7
    assert all(row["status"] == "skipped" and row["reason"] == "teams_token_unavailable" for row in gaps)


def test_operation_outside_rest_allowlist_never_loads_powershell(monkeypatch) -> None:
    adapter = _FakeAdapter()

    def rest_only(name):
        assert name == "teams_admin_rest"
        return adapter

    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", rest_only)
    collector = TeamsPolicyCollector()
    collector.command_collectors = [*collector.command_collectors, ("futurePolicy", "Get-CsFuturePolicy")]
    result = collector.run({"client": Client()})

    assert result.status == "ok" and adapter.calls == []
    assert result.payload["futurePolicy"]["status"] == "skipped"
    assert result.payload["futurePolicy"]["reason"] == "teams_powershell_not_supported"
    assert result.coverage[-1]["reason"] == "teams_powershell_not_supported"
