"""Verify findings carry compliance-framework mappings end-to-end."""
from __future__ import annotations

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _findings_for_dns_missing_dmarc() -> list[dict[str, object]]:
    payloads = {
        "dns_posture": {
            "domains": {"value": []},
            "domainPosture": {
                "value": [
                    {
                        "domain": "contoso.com",
                        "managed_by_microsoft": False,
                        "spf": {"present": True, "all_qualifier": "-"},
                        "dmarc": {"present": False},
                        "dkim": {"selectors_present": ["selector1", "selector2"], "selectors_missing": []},
                        "mta_sts": {"dns_present": True},
                        "bimi": {"present": False},
                    }
                ]
            },
        }
    }
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="run-1", collector_payloads=payloads
    )
    return build_findings([], normalized_snapshot=snapshot)


def test_dns_findings_include_cis_m365_and_mitre_attack_mappings() -> None:
    findings = _findings_for_dns_missing_dmarc()
    finding = next(f for f in findings if f["id"] == "dns_posture:contoso.com:dmarc_missing")
    mappings = finding["framework_mappings"]
    assert mappings["cis_m365_v7"] == ["2.1.10"]
    assert mappings["cisa_scuba"] == ["MS.EXO.4.1v1"]
    assert "cis_m365_v3" not in mappings
    assert "mitre_attack" in mappings
    assert any(token.startswith("T1566") for token in mappings["mitre_attack"])


def test_external_inbox_rule_has_t1114_attack_mapping() -> None:
    payloads = {
        "mailbox_forwarding": {
            "messageRules": {
                "value": [
                    {
                        "rule_id": "rule-1",
                        "user_id": "u1",
                        "user_principal_name": "alice@contoso.com",
                        "display_name": "External",
                        "is_enabled": True,
                        "forwards_externally": True,
                        "forwards_internally": False,
                        "external_recipients": ["attacker@evil.example"],
                        "internal_recipients": [],
                        "hide_from_user": False,
                        "delete_action": False,
                    }
                ]
            },
            "mailboxSettings": {"value": []},
        }
    }
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads)
    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(f for f in findings if f["id"] == "mailbox_forwarding:u1:rule-1:external_forward")
    mappings = finding["framework_mappings"]
    assert "T1114.003" in mappings.get("mitre_attack", [])
    assert "nist_800_53" in mappings


def test_app_credential_secret_expired_has_iso_27001_mapping() -> None:
    from datetime import datetime, timedelta, timezone

    expired_iso = (datetime.now(tz=timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payloads = {
        "app_credentials": {
            "applicationCredentials": {
                "value": [
                    {
                        "id": "app-1",
                        "display_name": "Expired",
                        "app_id": "1",
                        "sign_in_audience": "AzureADMyOrg",
                        "password_credentials": [{"key_id": "k1", "end_date_time": expired_iso}],
                        "key_credentials": [],
                        "redirect_uris": [],
                        "owner_count": 1,
                        "federated_credentials": [],
                    }
                ]
            },
            "servicePrincipalCredentials": {"value": []},
        }
    }
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads)
    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(f for f in findings if f["id"] == "app_credentials:app-1:secret_expired")
    mappings = finding["framework_mappings"]
    assert "iso_27001" in mappings
    assert "nis2" in mappings


def test_cross_tenant_partner_no_mfa_has_t1199_attack_mapping() -> None:
    payloads = {
        "cross_tenant_access": {
            "crossTenantAccessPolicy": {"value": [{"displayName": "X"}]},
            "defaultPolicy": {"value": []},
            "partnerConfigurations": {
                "value": [
                    {
                        "tenant_id": "11111111-1111-1111-1111-111111111111",
                        "is_service_provider": False,
                        "b2b_direct_connect_inbound_access": "allowed",
                        "b2b_direct_connect_outbound_access": "blocked",
                        "inbound_trust_mfa_accepted": False,
                    }
                ]
            },
        }
    }
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads)
    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        f
        for f in findings
        if f["id"]
        == "cross_tenant_access:partner:11111111-1111-1111-1111-111111111111:b2b_direct_connect_no_mfa"
    )
    mappings = finding["framework_mappings"]
    assert "T1199" in mappings.get("mitre_attack", [])
    assert "soc2" in mappings
