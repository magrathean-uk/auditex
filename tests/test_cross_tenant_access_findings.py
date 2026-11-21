from __future__ import annotations

from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot(default: dict[str, object] | None = None, partners: list[dict[str, object]] | None = None) -> dict[str, object]:
    payloads = {
        "cross_tenant_access": {
            "crossTenantAccessPolicy": {"value": [{"displayName": "X"}]},
            "defaultPolicy": {"value": [default] if default else []},
            "partnerConfigurations": {"value": partners or []},
        }
    }
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=payloads,
    )


def test_normalize_emits_default_and_partner_records() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "allowed",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "blocked",
            "inbound_trust_mfa_accepted": True,
        },
        partners=[
            {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "b2b_direct_connect_inbound_access": "allowed",
                "b2b_direct_connect_outbound_access": "blocked",
                "is_service_provider": False,
            }
        ],
    )

    assert snapshot.get("cross_tenant_default_objects") is not None
    assert snapshot.get("cross_tenant_partner_objects") is not None


def test_findings_flag_default_b2b_direct_connect_open() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "blocked",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "allowed",
            "inbound_trust_mfa_accepted": False,
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (f for f in findings if f["id"] == "cross_tenant_access:default:b2b_direct_connect_inbound_open"), None
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_partner_inbound_trust_without_mfa() -> None:
    snapshot = _snapshot(
        partners=[
            {
                "tenant_id": "11111111-1111-1111-1111-111111111111",
                "b2b_direct_connect_inbound_access": "allowed",
                "b2b_direct_connect_outbound_access": "blocked",
                "inbound_trust_mfa_accepted": False,
                "is_service_provider": False,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (
            f
            for f in findings
            if f["id"]
            == "cross_tenant_access:partner:11111111-1111-1111-1111-111111111111:b2b_direct_connect_no_mfa"
        ),
        None,
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_skip_microsoft_service_provider_partner() -> None:
    snapshot = _snapshot(
        partners=[
            {
                "tenant_id": "22222222-2222-2222-2222-222222222222",
                "b2b_direct_connect_inbound_access": "allowed",
                "b2b_direct_connect_outbound_access": "allowed",
                "inbound_trust_mfa_accepted": False,
                "is_service_provider": True,
            }
        ]
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    partner_findings = [f for f in findings if "cross_tenant_access:partner" in f["id"]]
    assert partner_findings == []


# ----- A5: previously-unflagged combinations -----


def test_findings_flag_default_b2b_collaboration_inbound_open() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "blocked",
            "b2b_collaboration_inbound_access": "allowed",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "blocked",
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (
            f
            for f in findings
            if f["id"] == "cross_tenant_access:default:b2b_collaboration_inbound_open"
        ),
        None,
    )
    assert finding is not None
    assert finding["severity"] == "high"


def test_findings_flag_default_direct_connect_outbound_open() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "blocked",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "allowed",
            "b2b_direct_connect_inbound_access": "blocked",
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(
        (
            f
            for f in findings
            if f["id"] == "cross_tenant_access:default:b2b_direct_connect_outbound_open"
        ),
        None,
    )
    assert finding is not None
    assert finding["severity"] == "medium"


def test_findings_flag_auto_user_consent_inbound() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "blocked",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "blocked",
            "automatic_user_consent_inbound_allowed": True,
            "automatic_user_consent_outbound_allowed": False,
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    inbound = next(
        (
            f
            for f in findings
            if f["id"] == "cross_tenant_access:default:auto_user_consent_inbound_enabled"
        ),
        None,
    )
    outbound = next(
        (
            f
            for f in findings
            if f["id"] == "cross_tenant_access:default:auto_user_consent_outbound_enabled"
        ),
        None,
    )
    assert inbound is not None
    assert inbound["severity"] == "medium"
    assert outbound is None


def test_findings_flag_auto_user_consent_outbound() -> None:
    snapshot = _snapshot(
        default={
            "is_service_default": False,
            "b2b_collaboration_outbound_access": "blocked",
            "b2b_collaboration_inbound_access": "blocked",
            "b2b_direct_connect_outbound_access": "blocked",
            "b2b_direct_connect_inbound_access": "blocked",
            "automatic_user_consent_inbound_allowed": False,
            "automatic_user_consent_outbound_allowed": True,
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    outbound = next(
        (
            f
            for f in findings
            if f["id"] == "cross_tenant_access:default:auto_user_consent_outbound_enabled"
        ),
        None,
    )
    assert outbound is not None
    assert outbound["severity"] == "low"


def test_collector_normalizes_automatic_user_consent_settings() -> None:
    """Collector layer must surface automaticUserConsentSettings on the default policy."""
    from azure_tenant_audit.collectors.cross_tenant_access import (
        _normalize_default_policy,
    )

    raw = {
        "isServiceDefault": False,
        "b2bCollaborationInbound": {"applications": {"accessType": "blocked"}},
        "automaticUserConsentSettings": {"inboundAllowed": True, "outboundAllowed": False},
    }
    normalized = _normalize_default_policy(raw)
    assert normalized["automatic_user_consent_inbound_allowed"] is True
    assert normalized["automatic_user_consent_outbound_allowed"] is False


# ----- R034: partner settings left null inherit the default policy -----

_PARTNER = "33333333-3333-3333-3333-333333333333"
_PARTNER_NO_MFA_ID = f"cross_tenant_access:partner:{_PARTNER}:b2b_direct_connect_no_mfa"


def _ids(snapshot: dict[str, object]) -> set[str]:
    return {item["id"] for item in build_findings([], normalized_snapshot=snapshot)}


def test_r034_partner_inheriting_a_default_that_trusts_mfa_raises_no_finding() -> None:
    snapshot = _snapshot(
        default={"b2b_direct_connect_inbound_access": "blocked", "inbound_trust_mfa_accepted": True},
        partners=[{"tenant_id": _PARTNER, "b2b_direct_connect_inbound_access": "allowed", "inbound_trust_mfa_accepted": None}],
    )
    (partner,) = snapshot["cross_tenant_partner_objects"]["records"]
    assert partner["inbound_trust_mfa_accepted"] is True
    assert partner["inherited_from_default"] == ["inbound_trust_mfa_accepted"]
    assert _PARTNER_NO_MFA_ID not in _ids(snapshot)


def test_r034_partner_inheriting_direct_connect_is_evaluated_against_its_own_trust() -> None:
    snapshot = _snapshot(
        default={"b2b_direct_connect_inbound_access": "allowed", "inbound_trust_mfa_accepted": True},
        partners=[{"tenant_id": _PARTNER, "b2b_direct_connect_inbound_access": None, "inbound_trust_mfa_accepted": False}],
    )
    (partner,) = snapshot["cross_tenant_partner_objects"]["records"]
    assert partner["b2b_direct_connect_inbound_access"] == "allowed"
    assert _PARTNER_NO_MFA_ID in _ids(snapshot)


def test_r034_partner_trust_unknown_without_a_default_raises_no_finding() -> None:
    snapshot = _snapshot(
        partners=[{"tenant_id": _PARTNER, "b2b_direct_connect_inbound_access": "allowed", "inbound_trust_mfa_accepted": None}],
    )
    assert _PARTNER_NO_MFA_ID not in _ids(snapshot)
