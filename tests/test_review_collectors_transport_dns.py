"""X1 (R164 wiring): dns_posture uses the run's DoH resolver choice, and a bad choice is a config error, not a crash."""
from __future__ import annotations

import pytest

from azure_tenant_audit.collectors import dns_posture
from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector
from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT, DOH_ENDPOINT_ENV


@pytest.fixture
def endpoints(monkeypatch) -> list[str]:
    seen: list[str] = []

    class _Doh:
        def __init__(self, endpoint: str = DEFAULT_DOH_ENDPOINT, **_kwargs) -> None:
            seen.append(endpoint)

    monkeypatch.setattr(dns_posture, "DohClient", _Doh)
    monkeypatch.delenv(DOH_ENDPOINT_ENV, raising=False)
    return seen


@pytest.mark.parametrize("bad", ["http://dns.example/dns-query", "https://user:pw@dns.example/q", "https://dns.example/q?k=1"])
def test_a_refused_doh_endpoint_is_a_config_error_not_a_crash(endpoints, bad) -> None:
    result = DnsPostureCollector().run({"doh_endpoint": bad, "public_lookups": False})
    assert result.status == "failed"
    row = next(r for r in result.coverage if r["name"] == "dohEndpoint")
    assert row["status"] == "failed" and row["error_class"] == "client_error" and row["reason"] == "doh_endpoint_refused"
    assert bad not in str(row["error"]) and bad not in result.message
    assert endpoints == []


def test_a_refused_environment_choice_is_a_config_error(endpoints, monkeypatch) -> None:
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "ftp://dns.example/q")
    result = DnsPostureCollector().run({"public_lookups": False})
    assert result.status == "failed" and endpoints == []


def test_the_chosen_resolver_is_used(endpoints, monkeypatch) -> None:
    DnsPostureCollector().run({"doh_endpoint": "https://dns.example/dns-query", "public_lookups": False})
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://env.example/dns-query")
    DnsPostureCollector().run({"public_lookups": False})
    monkeypatch.delenv(DOH_ENDPOINT_ENV)
    DnsPostureCollector().run({"public_lookups": False})
    assert endpoints == ["https://dns.example/dns-query", "https://env.example/dns-query", DEFAULT_DOH_ENDPOINT]
