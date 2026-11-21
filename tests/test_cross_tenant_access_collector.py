from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.cross_tenant_access import CrossTenantAccessCollector


class _FakeClient:
    def __init__(
        self,
        *,
        root: dict[str, Any] | Exception,
        default_policy: dict[str, Any] | Exception,
        partners: list[dict[str, Any]] | Exception,
    ) -> None:
        self._root = root
        self._default = default_policy
        self._partners = partners
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.calls.append((path, dict(params or {})))
        if path == "/policies/crossTenantAccessPolicy":
            if isinstance(self._root, Exception):
                raise self._root
            return self._root
        if path == "/policies/crossTenantAccessPolicy/default":
            if isinstance(self._default, Exception):
                raise self._default
            return self._default
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.calls.append((path, dict(params or {})))
        if path == "/policies/crossTenantAccessPolicy/partners":
            if isinstance(self._partners, Exception):
                raise self._partners
            return list(self._partners)
        raise AssertionError(f"unexpected path: {path}")


def test_collector_returns_root_default_and_partners() -> None:
    client = _FakeClient(
        root={"displayName": "Cross Tenant Access"},
        default_policy={
            "isServiceDefault": False,
            "b2bCollaborationOutbound": {"applications": {"accessType": "allowed", "targets": [{"target": "AllApplications"}]}},
            "b2bCollaborationInbound": {"applications": {"accessType": "blocked"}},
            "b2bDirectConnectOutbound": {"applications": {"accessType": "blocked"}},
            "inboundTrust": {"isMfaAccepted": True, "isCompliantDeviceAccepted": False, "isHybridAzureADJoinedDeviceAccepted": False},
        },
        partners=[
            {
                "tenantId": "11111111-1111-1111-1111-111111111111",
                "isServiceProvider": False,
                "b2bDirectConnectInbound": {"applications": {"accessType": "allowed", "targets": [{"target": "AllApplications"}]}},
                "b2bDirectConnectOutbound": {"applications": {"accessType": "blocked"}},
                "inboundTrust": {"isMfaAccepted": False, "isCompliantDeviceAccepted": False, "isHybridAzureADJoinedDeviceAccepted": False},
            }
        ],
    )

    collector = CrossTenantAccessCollector()
    result = collector.run({"client": client, "top": 100})

    assert result.status == "ok"
    assert result.payload["crossTenantAccessPolicy"]["value"][0]["displayName"] == "Cross Tenant Access"
    default = result.payload["defaultPolicy"]["value"][0]
    assert default["b2b_collaboration_outbound_access"] == "allowed"
    partners = result.payload["partnerConfigurations"]["value"]
    assert partners[0]["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    assert partners[0]["b2b_direct_connect_inbound_access"] == "allowed"


def test_collector_handles_partial_failure_gracefully() -> None:
    from azure_tenant_audit.graph import GraphError

    client = _FakeClient(
        root={"displayName": "Cross Tenant Access"},
        default_policy={"isServiceDefault": True},
        partners=GraphError("forbidden", status=403, request="/policies/crossTenantAccessPolicy/partners"),
    )

    collector = CrossTenantAccessCollector()
    result = collector.run({"client": client, "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    assert any(row["name"] == "partners" and row["status"] == "failed" for row in coverage)


def test_collector_handles_missing_client() -> None:
    collector = CrossTenantAccessCollector()
    result = collector.run({"client": None, "top": 100})

    assert result.status == "partial"
    assert all(row["status"] == "failed" for row in (result.coverage or []))


def test_r034_partner_null_inbound_trust_stays_inherited() -> None:
    client = _FakeClient(
        root={"displayName": "Cross Tenant Access"},
        default_policy={"inboundTrust": {"isMfaAccepted": True}},
        partners=[
            {
                "tenantId": "11111111-1111-1111-1111-111111111111",
                "b2bDirectConnectInbound": {"applications": {"accessType": "allowed"}},
                "inboundTrust": None,
            }
        ],
    )

    result = CrossTenantAccessCollector().run({"client": client, "top": 100})

    (partner,) = result.payload["partnerConfigurations"]["value"]
    # null means "inherit the default policy", never "not accepted".
    assert partner["inbound_trust_mfa_accepted"] is None
    assert partner["inbound_trust_compliant_device_accepted"] is None
    assert partner["inbound_trust_hybrid_aad_joined_accepted"] is None
