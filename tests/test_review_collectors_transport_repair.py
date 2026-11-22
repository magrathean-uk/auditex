"""Repair-round regression tests for the collectors-transport lane (independent review blockers)."""
from __future__ import annotations

import pytest
from support import fake_graph_client, graph_response

from azure_tenant_audit.collectors.base import run_graph_endpoints


def test_licence_coded_403_with_generic_text_is_license_required(monkeypatch) -> None:
    """R004: the licence error code alone, with a generic message, classes the read license_required."""
    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None
    monkeypatch.setattr(
        client.session,
        "request",
        lambda *a, **k: graph_response(403, {"error": {"code": "AadPremiumLicenseRequired", "message": "Forbidden"}}),
    )
    _payload, coverage = run_graph_endpoints(
        "identity_governance",
        client,
        {"roleEligibilitySchedules": {"endpoint": "/roleManagement/directory/roleEligibilitySchedules"}},
        None,
    )
    assert coverage[0]["status"] == "failed"
    assert coverage[0]["error_class"] == "license_required"


@pytest.mark.parametrize("error_name", ["ReadTimeout", "ConnectionError"])
def test_exhausted_transport_retries_are_graph_transient(monkeypatch, error_name) -> None:
    """R033: a read whose transport retries all fail is recorded as graph_transient, not client_error."""
    import requests.exceptions as rex

    client = fake_graph_client(throttle_mode="safe")
    client.sleep = lambda _seconds: None

    def _request(*_a, **_k):
        raise getattr(rex, error_name)("network blip")

    monkeypatch.setattr(client.session, "request", _request)
    _payload, coverage = run_graph_endpoints(
        "conditional_access",
        client,
        {"conditionalAccessPolicies": {"endpoint": "/identity/conditionalAccess/policies"}},
        None,
    )
    assert coverage[0]["status"] == "failed"
    assert coverage[0]["error_class"] == "graph_transient"


def test_a_falsey_injected_dns_resolver_is_used_not_a_crash() -> None:
    """X1 / R164: an injected resolver whose truth value is false (an empty cache) is still the resolver used."""
    from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

    class _EmptyResolver:
        def __init__(self) -> None:
            self.asked: list[tuple[str, str]] = []

        def __len__(self) -> int:
            return 0

        def query(self, name: str, record_type: str) -> list[str]:
            self.asked.append((name, record_type))
            return []

    class _Client:
        def get_all(self, _path, params=None):  # noqa: ARG002
            return [{"id": "example.com", "isVerified": True}]

    resolver = _EmptyResolver()
    assert not resolver
    result = DnsPostureCollector().run({"client": _Client(), "dns_resolver": resolver, "public_lookups": False})
    assert result.status in {"ok", "partial"}
    assert ("example.com", "TXT") in resolver.asked or any(n.endswith("example.com") for n, _ in resolver.asked)
