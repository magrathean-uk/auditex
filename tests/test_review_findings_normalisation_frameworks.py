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
