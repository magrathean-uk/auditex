from __future__ import annotations

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot_with_rules(rules: list[dict[str, object]]) -> dict[str, object]:
    payloads = {
        "mailbox_forwarding": {
            "messageRules": {"value": rules},
            "mailboxSettings": {"value": []},
        }
    }
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=payloads,
    )


def test_normalize_emits_inbox_rule_records() -> None:
    snapshot = _snapshot_with_rules(
        [
            {
                "rule_id": "rule-1",
                "user_id": "u1",
                "user_principal_name": "alice@contoso.com",
                "display_name": "Forward",
                "is_enabled": True,
                "forwards_externally": True,
                "forwards_internally": False,
                "external_recipients": ["attacker@evil.example"],
                "internal_recipients": [],
                "hide_from_user": False,
                "delete_action": False,
            }
        ]
    )

    section = snapshot.get("inbox_rule_objects")
    assert section is not None
    assert section["records"][0]["display_name"] == "Forward"


def test_findings_flag_external_forwarding_inbox_rule_critical() -> None:
    snapshot = _snapshot_with_rules(
        [
            {
                "rule_id": "rule-1",
                "user_id": "u1",
                "user_principal_name": "alice@contoso.com",
                "display_name": "Forward to external",
                "is_enabled": True,
                "forwards_externally": True,
                "forwards_internally": False,
                "external_recipients": ["attacker@evil.example"],
                "internal_recipients": [],
                "hide_from_user": False,
                "delete_action": False,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "mailbox_forwarding:u1:rule-1:external_forward"), None
    )
    assert finding is not None
    assert finding["severity"] == "critical"


def test_findings_flag_hide_from_user_pattern_high() -> None:
    snapshot = _snapshot_with_rules(
        [
            {
                "rule_id": "rule-1",
                "user_id": "u1",
                "user_principal_name": "alice@contoso.com",
                "display_name": ".",
                "is_enabled": True,
                "forwards_externally": False,
                "forwards_internally": False,
                "external_recipients": [],
                "internal_recipients": [],
                "hide_from_user": True,
                "delete_action": True,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "mailbox_forwarding:u1:rule-1:hide_from_user"), None
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_skip_disabled_rules() -> None:
    snapshot = _snapshot_with_rules(
        [
            {
                "rule_id": "rule-1",
                "user_id": "u1",
                "user_principal_name": "alice@contoso.com",
                "display_name": "Disabled",
                "is_enabled": False,
                "forwards_externally": True,
                "forwards_internally": False,
                "external_recipients": ["attacker@evil.example"],
                "internal_recipients": [],
                "hide_from_user": False,
                "delete_action": False,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    rule_findings = [f for f in findings if "mailbox_forwarding:u1:rule-1" in f["id"]]
    assert rule_findings == []


def test_findings_flag_external_exchange_transport_redirect() -> None:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads={
            "exchange_policy": {
                "acceptedDomains": {"value": [{"Name": "contoso.com", "DomainName": "contoso.com"}]},
                "transportRules": {
                    "value": [
                        {
                            "Name": "Redirect invoices",
                            "State": "Enabled",
                            "Mode": "Enforce",
                            "RedirectMessageTo": ["finance@evil.example"],
                            "BlindCopyTo": ["audit@contoso.com"],
                        }
                    ]
                },
            }
        },
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["rule_id"] == "exchange.transport_external_redirect"), None)

    assert finding is not None
    assert finding["severity"] == "critical"
    assert finding["returned_value"] == ["finance@evil.example"]


def test_findings_flag_remote_domain_auto_forward_policy() -> None:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads={
            "exchange_policy": {
                "remoteDomains": {
                    "value": [
                        {
                            "Name": "Default",
                            "DomainName": "*",
                            "AutoForwardEnabled": True,
                        },
                        {
                            "Name": "Partner",
                            "DomainName": "partner.example",
                            "AutoForwardEnabled": False,
                        },
                    ]
                },
            }
        },
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next((f for f in findings if f["rule_id"] == "exchange.remote_domain_auto_forward_enabled"), None)

    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["affected_objects"] == ["Default"]
