from __future__ import annotations

import json
from pathlib import Path

from test_finalize_idempotent import _prepare_bundle_for_finalize

from azure_tenant_audit.api_inventory import (
    ApiInventoryRecorder,
    build_api_call_inventory,
)
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.finalize import finalize_bundle_contract


def test_api_inventory_maps_observed_calls_to_read_only_customer_ledger() -> None:
    inventory = build_api_call_inventory(
        platform="m365",
        selected_collectors=["identity"],
        capability_rows=[
            {
                "collector": "identity",
                "status": "supported_exact_scope",
                "required_permissions": ["Directory.Read.All"],
                "observed_permissions": ["Directory.Read.All"],
                "missing_permissions": [],
            }
        ],
        coverage_rows=[
            {
                "collector": "identity",
                "name": "users",
                "endpoint": "/users",
                "status": "ok",
                "item_count": 2,
                "duration_ms": 1.5,
            }
        ],
        data_handling={
            "platform": "m365",
            "plane": "inventory",
            "read_only": True,
            "content_reads": False,
            "write_actions": False,
            "scope_risk": "read_only_scopes",
            "write_capable_scopes": [],
        },
        collector_catalog={
            "identity": {
                "description": "Directory posture",
                "minimum_role_hints": ["Global Reader", "Security Reader"],
                "tool_requirements": [],
            }
        },
    )

    assert inventory["safety"]["read_only"] is True
    assert inventory["safety"]["no_content_reads"] is True
    assert inventory["counts"]["observed_calls"] == 1
    assert inventory["declared_collectors"][0]["description"] == "Directory posture"
    assert inventory["declared_collectors"][0]["minimum_role_hints"] == ["Global Reader", "Security Reader"]
    assert inventory["declared_collectors"][0]["tool_requirements"] == []
    call = inventory["observed_calls"][0]
    assert call["method"] == "GET"
    assert call["access_mode"] == "read"
    assert call["data_class"] == "directory_identity"
    assert call["required_permissions"] == ["Directory.Read.All"]


def test_finalize_writes_api_inventory_and_report_evidence_path(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    writer.write_index_records(
        [
            {
                "collector": "identity",
                "name": "users",
                "endpoint": "/users",
                "status": "ok",
                "item_count": 1,
                "duration_ms": 1.0,
            }
        ]
    )

    finalize_bundle_contract(**kwargs)

    run_dir = writer.run_dir
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    inventory = json.loads((run_dir / manifest["api_inventory_path"]).read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))

    assert manifest["api_inventory_path"] == "api-inventory.json"
    assert inventory["observed_calls"][0]["endpoint"] == "/users"
    assert inventory["safety"]["read_only"] is True
    assert "api-inventory.json" in report_pack["evidence_paths"]
    assert validation["valid"] is True, validation["issues"]


def test_contract_rejects_audit_plane_mutating_api_inventory(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    run_dir = writer.run_dir
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    inventory_path = run_dir / manifest["api_inventory_path"]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["safety"]["read_only"] = False
    inventory["safety"]["write_actions"] = True
    inventory["observed_calls"].append(
        {
            "id": "identity:bad:1",
            "collector": "identity",
            "name": "bad",
            "endpoint": "/users",
            "method": "PATCH",
            "content_reads": False,
            "write_actions": True,
        }
    )
    inventory_path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir)

    assert report["valid"] is False
    assert "invalid_api_inventory_safety" in {item["code"] for item in report["issues"]}


def test_api_inventory_recorder_maps_graph_call_permissions() -> None:
    recorder = ApiInventoryRecorder(
        platform="m365",
        capability_rows=[
            {
                "collector": "identity",
                "required_permissions": ["Directory.Read.All"],
                "missing_permissions": [],
            }
        ],
    )

    recorder.record(
        {
            "collector": "identity",
            "name": "users",
            "endpoint": "/users",
            "method": "GET",
            "status": "ok",
            "item_count": 2,
        }
    )

    call = recorder.observed_calls()[0]
    assert call["id"] == "identity:users:1"
    assert call["access_mode"] == "read"
    assert call["required_permissions"] == ["Directory.Read.All"]
    assert recorder.observed_counts()["identity"] == 1


def test_api_inventory_recorder_maps_command_calls_to_read_command() -> None:
    recorder = ApiInventoryRecorder(platform="m365", capability_rows=[])

    recorder.record(
        {
            "collector": "exchange_policy",
            "type": "command",
            "name": "remoteDomains",
            "endpoint": "Get-RemoteDomain",
            "status": "ok",
        }
    )

    call = recorder.observed_calls()[0]
    assert call["method"] == "COMMAND"
    assert call["access_mode"] == "read_command"
    assert call["data_class"] == "mail_metadata_and_settings"


def test_api_inventory_recorder_maps_google_device_rows() -> None:
    recorder = ApiInventoryRecorder(
        platform="google_workspace",
        capability_rows=[
            {
                "collector": "google_devices",
                "required_permissions": ["https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly"],
                "missing_permissions": [],
            }
        ],
    )

    recorder.record(
        {
            "collector": "google_devices",
            "name": "chromeosDevices",
            "endpoint": "chromeosDevices",
            "status": "ok",
            "item_count": 3,
        }
    )

    call = recorder.observed_calls()[0]
    assert call["platform"] == "google_workspace"
    assert call["data_class"] == "device_inventory_and_policy"
    assert call["required_permissions"] == [
        "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly"
    ]


def test_compliance_session_reads_are_declared_read_only_commands() -> None:
    """M08-T05: each Security & Compliance read is on the read allow-list and inside the declared command set."""
    from azure_tenant_audit.adapters.read_guard import check_command
    from azure_tenant_audit.api_inventory import observe_audit_events
    from azure_tenant_audit.collectors.exchange_policy import (
        IPPS_OPERATIONS,
        ExchangePolicyCollector,
    )
    from azure_tenant_audit.secret_hygiene import redact_command_string

    commands = dict(ExchangePolicyCollector.command_collectors)
    declared = [
        {"collector": "exchange_policy", "type": "command", "name": name, "endpoint": name, "method": "COMMAND",
         "command": command}
        for name, command in commands.items()
    ]
    events = [
        {"event": "command.started", "details": {
            "adapter": "powershell_graph", "command": redact_command_string(commands[name]),
            "command_words": list(check_command("powershell_graph", commands[name]))}}
        for name in sorted(IPPS_OPERATIONS)
    ]
    ledger = observe_audit_events(events, declared_calls=declared)
    executed = {row["family"]: row for row in ledger["commands"]["executed"]}
    assert set(executed) == {"get-protectionalert", "get-command", "get-dlpcompliancepolicy", "get-dlpcompliancerule"}
    assert all(row["read_only"] for row in executed.values())
    assert ledger["commands"]["write_calls"] == [] and ledger["outside_declared"]["count"] == 0

    # A write cmdlet in the same session is outside the declaration and is not a read.
    write = "Set-DlpCompliancePolicy -Identity P1 -Mode Disable"
    ledger = observe_audit_events(
        [*events, {"event": "command.started", "details": {
            "adapter": "powershell_graph", "command": write, "command_words": ["Set-DlpCompliancePolicy"]}}],
        declared_calls=declared,
    )
    assert ledger["commands"]["write_calls"] == [{"adapter": "powershell_graph", "command": "Set-DlpCompliancePolicy"}]
    assert ledger["outside_declared"]["commands"] == [{"adapter": "powershell_graph", "command": "Set-DlpCompliancePolicy"}]


SHAREPOINT_ADMIN_ROW = {
    "collector": "sharepoint_admin", "type": "sharepoint_admin_rest", "method": "GET", "name": "tenantSettings",
    "endpoint": "https://{tenant}-admin.sharepoint.com/_api/SPO.Tenant", "status": "ok", "item_count": 1,
}


def _sharepoint_event(method: str = "GET", path: str = "/_api/SPO.Tenant", status: int | None = 200) -> dict:
    return {"event": "sharepoint_admin_rest.request", "details": {
        "method": method, "host": "{tenant}-admin.sharepoint.com", "path": path, "status_code": status}}


def _sharepoint_inventory(events: list[dict]) -> dict:
    return build_api_call_inventory(platform="m365", selected_collectors=["sharepoint_admin"], capability_rows=[],
                                    coverage_rows=[SHAREPOINT_ADMIN_ROW], data_handling={"read_only": True},
                                    audit_events=[{"event": "run.started", "details": {}}, *events])


def test_the_sharepoint_admin_read_is_a_declared_observed_get() -> None:
    inventory = _sharepoint_inventory([_sharepoint_event(status=429), _sharepoint_event()])
    [call] = inventory["observed_calls"]
    assert call["method"] == "GET" and call["access_mode"] == "read" and not call["write_actions"]
    ledger = inventory["observed_ledger"]["sharepoint_admin_rest"]
    assert ledger["request_attempts"] == 2 and ledger["methods_seen"] == ["GET"] and ledger["write_calls"] == []
    assert ledger["endpoints"][0]["endpoint"] == SHAREPOINT_ADMIN_ROW["endpoint"]
    assert ledger["endpoints"][0]["statuses"] == {"429": 1, "200": 1}
    assert inventory["observed_ledger"]["outside_declared"]["sharepoint_admin_rest"] == []
    assert inventory["counts"]["observed_sharepoint_admin_rest_requests"] == 2
    assert inventory["safety"]["read_only"] is True and "GET" in inventory["safety"]["observed_methods"]


def test_a_non_get_or_refused_sharepoint_admin_call_is_never_read_only() -> None:
    written = _sharepoint_inventory([_sharepoint_event(method="POST")])
    assert written["safety"]["read_only"] is False and written["safety"]["write_actions"] is True
    assert {"method": "POST", "endpoint": SHAREPOINT_ADMIN_ROW["endpoint"]} in written["safety"]["observed_write_calls"]
    refused = _sharepoint_inventory([{"event": "sharepoint_admin_rest.refused", "details": {
        "method": "GET", "host": "{tenant}-admin.sharepoint.com", "path": "/_api/SPO.Tenant", "reason": "query"}}])
    assert refused["safety"]["refused_calls"] == 1 and refused["safety"]["read_only"] is False


def test_an_undeclared_sharepoint_admin_path_is_listed_outside_the_declaration() -> None:
    inventory = _sharepoint_inventory([_sharepoint_event(path="/_api/SPO.Tenant/sites")])
    outside = inventory["observed_ledger"]["outside_declared"]
    assert outside["sharepoint_admin_rest"] == [
        {"method": "GET", "endpoint": "https://{tenant}-admin.sharepoint.com/_api/SPO.Tenant/sites"}]
    assert outside["count"] == 1


def test_a_ledger_written_before_the_sharepoint_section_still_applies() -> None:
    from azure_tenant_audit.api_inventory import _apply_ledger, observe_audit_events

    ledger = observe_audit_events([{"event": "run.started", "details": {}}])
    del ledger["sharepoint_admin_rest"]
    applied = _apply_ledger({"safety": {"read_only": True}, "counts": {}}, ledger)
    assert applied["counts"]["observed_sharepoint_admin_rest_requests"] == 0


def test_the_role_assignment_schedule_instance_read_is_a_declared_v1_get_without_content() -> None:
    """``identity_governance`` reads the active schedule instances for the privileged roles (DEC-096): GET, v1.0, no content."""
    from pim_support import collect

    result = collect()
    inventory = build_api_call_inventory(platform="m365", selected_collectors=["identity_governance"], capability_rows=[],
                                         coverage_rows=result.coverage, data_handling={"platform": "m365", "read_only": True})
    call = next(item for item in inventory["observed_calls"] if item["name"] == "roleAssignmentScheduleInstances")

    assert call["endpoint"] == "/roleManagement/directory/roleAssignmentScheduleInstances"
    assert (call["method"], call["api_version"], call["access_mode"]) == ("GET", "v1.0", "read")
    assert call["content_reads"] is False and call["write_actions"] is False
    assert inventory["safety"]["read_only"] is True and inventory["safety"]["no_content_reads"] is True
