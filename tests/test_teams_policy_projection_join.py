"""Collector -> raw bundle -> rule view using the reviewed v3.9.1 fixture.

Constructed rows and pack train and validation rows from v3.9.1;
held-out test and pilot rows excluded. Only constructed parents below are used.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from auditex.scuba_projection import PS_SECTIONS, project_run
from azure_tenant_audit.adapters import teams_admin_rest as rest
from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from test_teams_admin_rest import Client, Response, TOKEN, command_reader, connect


FIXTURE = json.loads((Path(__file__).parent / "fixtures/teams-rule-vectors-v39.json").read_text())
PARENTS = {
    "meeting_policies": ("meetingPolicies", "constructed:MS.TEAMS.1.1v1:clear_single"),
    "broadcast_policies": ("broadcastPolicies", "constructed:MS.TEAMS.1.7v2:good_global"),
    "client_configuration": ("clientConfiguration", "constructed:MS.TEAMS.4.1v1:clear_single"),
    "app_policies": ("appPermissionPolicies", "constructed:MS.TEAMS.5.1v2:org_none"),
    "federation_configuration": ("tenantFederationConfiguration", "constructed:MS.TEAMS.2.3v2:clear_single"),
}
FIELDS = {
    "meeting_policies": {"Identity", "AllowAnonymousUsersToStartMeeting", "AllowCloudRecording",
                         "AllowExternalParticipantGiveRequestControl", "AllowPSTNUsersToBypassLobby", "AutoAdmittedUsers"},
    "broadcast_policies": {"Identity", "BroadcastRecordingMode"},
    "client_configuration": {"Identity", "AllowEmailIntoChannel"},
    "app_policies": {"Identity", "DefaultCatalogAppsType", "GlobalCatalogAppsType", "PrivateCatalogAppsType"},
    "federation_configuration": {"Identity", "AllowFederatedUsers", "AllowTeamsConsumer",
                                 "AllowTeamsConsumerInbound", "AllowedDomains"},
}


def fixture_rows():
    assert FIXTURE["_meta"]["spec_version"] == "3.9.1 FINAL"
    assert FIXTURE["_meta"]["provenance"] == (
        "constructed rows and pack train and validation rows from v3.9.1; held-out test and pilot rows excluded"
    )
    # Choose allowed origins before selecting section rows; keep each vector_id in PARENTS.
    allowed = {row["vector_id"]: row for row in FIXTURE["vectors"]
               if row["vector_id"].split(":", 1)[0] in {"constructed", "pack-train", "pack-validation", "packlic-train"}}
    return {section: deepcopy(allowed[vector_id]["sections"][section])
            for section, (_, vector_id) in PARENTS.items()}


def collect_bundle(monkeypatch, tmp_path, failed_operation=None, malformed_operation=None):
    rows = fixture_rows()
    by_operation = {operation: rows[section] for section, (operation, _) in PARENTS.items()}
    if malformed_operation:
        by_operation[malformed_operation][0].pop("Identity")
    responses = [Response(403 if operation == failed_operation else 200,
                          parsed={"value": by_operation[operation]})
                 for operation, _ in TeamsPolicyCollector.command_collectors if operation in rest.TEAMS_READ_PATHS]
    session = connect(monkeypatch, responses)
    commands = command_reader(monkeypatch)
    events = []
    result = TeamsPolicyCollector().run({"client": Client(), "audit_logger": lambda *args: events.append(args)})
    (tmp_path / "raw").mkdir()
    (tmp_path / "raw/teams_policy.json").write_text(json.dumps(result.payload))
    (tmp_path / "run-manifest.json").write_text(json.dumps({
        "run_id": "constructed-teams-join", "platform": "m365",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "graph_endpoint": "https://graph.microsoft.com/v1.0",
    }))
    (tmp_path / "collector-coverage.json").write_text(json.dumps({"coverage": result.coverage}))
    (tmp_path / "audit-log.jsonl").write_text("\n".join(json.dumps(event) for event in events))
    assert len(session.calls) == 5 and len(commands.calls) == 2
    assert all(TOKEN.encode() not in path.read_bytes() for path in tmp_path.rglob("*") if path.is_file())
    return result, project_run(tmp_path, redact=False), rows


def test_collector_bundle_projects_all_five_sections(monkeypatch, tmp_path):
    result, projection, rows = collect_bundle(monkeypatch, tmp_path)
    assert result.status == "partial"  # The two unverified command paths stay coverage gaps.
    for section, (operation, _) in PARENTS.items():
        assert result.payload[operation]["status"] == "ok"
        expected = [{key: value for key, value in row.items() if key in FIELDS[section]} for row in rows[section]]
        assert projection.rule_sections[section] == expected
        assert all(set(row) == FIELDS[section] for row in projection.rule_sections[section])
    assert projection.rule_sections["tenant_app_settings"] == NOT_COLLECTED
    assert "tenant_app_settings" not in result.payload
    assert set(PS_SECTIONS["meeting_policies"][2]) == FIELDS["meeting_policies"]


@pytest.mark.parametrize("failed_operation", rest.TEAMS_READ_PATHS)
def test_error_never_projects_as_pass(monkeypatch, tmp_path, failed_operation):
    result, projection, _ = collect_bundle(monkeypatch, tmp_path, failed_operation=failed_operation)
    for section, (operation, _) in PARENTS.items():
        if operation == failed_operation:
            assert result.payload[operation]["error_class"] == "command_not_authenticated"
            assert projection.rule_sections[section] == NOT_COLLECTED
        else:
            assert projection.rule_sections[section] != NOT_COLLECTED


@pytest.mark.parametrize("malformed_operation", rest.TEAMS_READ_PATHS)
def test_missing_required_field_is_withheld(monkeypatch, tmp_path, malformed_operation):
    _, projection, _ = collect_bundle(monkeypatch, tmp_path, malformed_operation=malformed_operation)
    section = next(section for section, (operation, _) in PARENTS.items() if operation == malformed_operation)
    assert projection.rule_sections[section] == NOT_COLLECTED
