"""Regression tests for the findings, normalisation and framework-mapping review lane."""
from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

_REPO = Path(__file__).resolve().parent.parent
_MAPPINGS = json.loads((_REPO / "configs" / "control-mappings.json").read_text(encoding="utf-8"))


def _snapshot(payloads: dict) -> dict:
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads)


def _rule_findings(snapshot: dict, rule_id: str) -> list[dict]:
    return [item for item in build_findings([], normalized_snapshot=snapshot) if item.get("rule_id") == rule_id]


# ---- R009: owners never read are unknown, not zero --------------------------------------------------------------


def _consent_payload(*, owners: list[dict] | None) -> dict:
    payload = {
        "servicePrincipals": {"value": [{"id": "sp-11", "displayName": "Low risk app", "appId": "app-11"}]},
        "oauth2PermissionGrants": {
            "value": [
                {
                    "id": "grant-1",
                    "clientId": "sp-11",
                    "resourceId": "graph",
                    "scope": "openid profile User.Read",
                    "consentType": "AllPrincipals",
                }
            ]
        },
    }
    if owners is not None:
        payload["servicePrincipalOwners"] = {"value": [{"servicePrincipalId": "sp-11", "owners": owners}]}
    return {"app_consent": payload}


def test_r009_unread_owners_are_unknown_and_raise_no_weak_ownership_finding() -> None:
    snapshot = _snapshot(_consent_payload(owners=None))
    (record,) = snapshot["application_consents"]["records"]
    assert record.get("owner_count") is None
    assert _rule_findings(snapshot, "app_consent.high_privilege") == []


def test_r009_owners_read_as_empty_still_raise_weak_ownership() -> None:
    snapshot = _snapshot(_consent_payload(owners=[]))
    (record,) = snapshot["application_consents"]["records"]
    assert record["owner_count"] == 0
    (finding,) = _rule_findings(snapshot, "app_consent.high_privilege")
    assert finding["severity"] == "medium"


def test_r009_per_grant_rule_claims_no_user_consent_setting_control() -> None:
    mapping = _MAPPINGS["app_consent.high_privilege"]
    assert "5.1.5.1" not in (mapping.get("cis_m365_v7") or [])
    assert "MS.AAD.5.2v1" not in (mapping.get("cisa_scuba") or [])
    finding = {"id": "f-1", "rule_id": "app_consent.high_privilege", "status": "open", "severity": "high"}
    alignment = build_baseline_alignment([finding])
    for framework, control in (("cis_m365_v7", "5.1.5.1"), ("cisa_scuba", "MS.AAD.5.2v1")):
        rows = [row for row in alignment["frameworks"][framework]["controls"] if row["control_id"] == control]
        assert all("f-1" not in row["finding_ids"] for row in rows), (framework, control)


# ---- R010: per-item findings never decide tenant-setting controls ----------------------------------------------

_SETTING_CONTROLS = {
    "sharepoint.broad_link": {"cis_m365_v7": {"7.2.3", "7.2.7"}, "cisa_scuba": {"MS.SHAREPOINT.1.1v1", "MS.SHAREPOINT.2.1v1"}},
    "sharepoint.external_principal": {
        "cis_m365_v7": {"7.2.3", "7.2.6"},
        "cisa_scuba": {"MS.SHAREPOINT.1.1v1", "MS.SHAREPOINT.1.3v1"},
    },
    "mailbox_forwarding.external_inbox_rule": {"cis_m365_v7": {"6.2.1"}, "cisa_scuba": {"MS.EXO.1.1v2"}},
}


def test_r010_per_item_rules_claim_no_tenant_setting_controls() -> None:
    for rule_id, frameworks in _SETTING_CONTROLS.items():
        mapping = _MAPPINGS[rule_id]
        for framework, controls in frameworks.items():
            assert not controls & set(mapping.get(framework) or []), (rule_id, framework)
        # The per-item evidence keeps its NIST, ISO and ATT&CK anchors.
        assert mapping.get("nist_800_53") and mapping.get("iso_27001") and mapping.get("mitre_attack"), rule_id


def test_r010_a_guest_on_one_site_does_not_fail_the_sharing_setting_controls() -> None:
    findings = [
        {"id": "f-ext", "rule_id": "sharepoint.external_principal", "status": "open", "severity": "medium"},
        {"id": "f-link", "rule_id": "sharepoint.broad_link", "status": "open", "severity": "medium"},
        {"id": "f-fwd", "rule_id": "mailbox_forwarding.external_inbox_rule", "status": "open", "severity": "high"},
    ]
    alignment = build_baseline_alignment(findings)
    for frameworks in _SETTING_CONTROLS.values():
        for framework, controls in frameworks.items():
            for row in alignment["frameworks"][framework]["controls"]:
                if row["control_id"] in controls:
                    assert not {"f-ext", "f-link", "f-fwd"} & set(row["finding_ids"]), (framework, row["control_id"])


# ---- R048: only directory-role changes and tier-0 app permission grants are privilege changes --------------------


def _audit_snapshot(*events: dict) -> dict:
    return _snapshot({"security": {"directoryAudits": {"value": list(events)}}})


def _audit(event_id: str, category: str, activity: str, targets: list[dict] | None = None) -> dict:
    return {
        "id": event_id,
        "activityDateTime": "2026-11-20T08:00:00Z",
        "category": category,
        "activityDisplayName": activity,
        "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}},
        "targetResources": targets or [],
    }


def _role_target(name: str) -> dict:
    return {"type": "User", "displayName": "Someone", "modifiedProperties": [{"displayName": "Role.DisplayName", "newValue": f'"{name}"'}]}


def _app_role_target(value: str) -> dict:
    return {"type": "ServicePrincipal", "displayName": "App", "modifiedProperties": [{"displayName": "AppRole.Value", "newValue": f'"{value}"'}]}


def test_r048_routine_enterprise_app_assignments_are_not_privilege_changes() -> None:
    snapshot = _audit_snapshot(
        _audit("a-1", "ApplicationManagement", "Add app role assignment grant to user", [{"type": "User"}]),
        _audit("a-2", "ApplicationManagement", "Add app role assignment to service principal", [_app_role_target("User.Read.All")]),
    )
    assert _rule_findings(snapshot, "security.privilege_change_event") == []


def test_r048_tier0_app_permission_grant_is_still_a_privilege_change() -> None:
    snapshot = _audit_snapshot(
        _audit("a-3", "ApplicationManagement", "Add app role assignment to service principal",
               [_app_role_target("RoleManagement.ReadWrite.Directory")]),
    )
    (finding,) = _rule_findings(snapshot, "security.privilege_change_event")
    assert finding["severity"] == "high"


def test_r048_severity_follows_whether_the_role_is_tier0() -> None:
    snapshot = _audit_snapshot(
        _audit("r-1", "RoleManagement", "Add member to role", [_role_target("Global Administrator")]),
        _audit("r-2", "RoleManagement", "Add eligible member to role", [_role_target("Reports Reader")]),
    )
    severities = {item["id"].split(":")[1]: item["severity"] for item in _rule_findings(snapshot, "security.privilege_change_event")}
    assert severities == {"r-1": "high", "r-2": "medium"}

