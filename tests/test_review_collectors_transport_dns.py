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


# Bot wave 2 item 13: a transport failure's library text (which can repeat the configured resolver URL, whose path can
# hold an account token) never reaches the DoH error, the raw posture's resolver_error or the coverage rows.

_TOKEN = "acct-token-zz9"
_ENDPOINT = f"https://dns.corp.example/{_TOKEN}"


class _FailingSession:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def get(self, url: str, **_kwargs):
        raise self.exc


class _Domains:
    def get_all(self, _path: str, params=None):
        return [{"id": "contoso.example", "isVerified": True}]


def _http_error() -> Exception:
    import requests

    response = requests.Response()
    response.status_code = 503
    response.reason = "Service Unavailable"
    response.url = f"{_ENDPOINT}?name=contoso.example&type=TXT"
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        return exc
    raise AssertionError("raise_for_status did not raise")


@pytest.mark.parametrize("make_exc, detail", [
    (_http_error, "HTTP 503"),
    (lambda: OSError(f"Max retries exceeded with url: /{_TOKEN}?name=contoso.example (Caused by {_ENDPOINT})"),
     "request failed"),
])
def test_w2_13_doh_transport_diagnostics_keep_only_the_resolver_host(make_exc, detail) -> None:
    import json

    from azure_tenant_audit.dns_lookup import DohClient, DohError

    client = DohClient(session=_FailingSession(make_exc()), endpoint=_ENDPOINT)
    with pytest.raises(DohError) as caught:
        client.query_detailed("contoso.example", "TXT")
    message = str(caught.value)
    assert _TOKEN not in message
    assert "https://dns.corp.example" in message and detail in message

    result = DnsPostureCollector().run({"client": _Domains(), "dns_resolver": client, "public_lookups": False})
    dumped = json.dumps({"coverage": result.coverage, "payload": result.payload, "message": result.message}, default=str)
    assert _TOKEN not in dumped
    failed = [row for row in result.coverage if row.get("error_class") == "dns_resolver_error"]
    assert failed and all("dns.corp.example" in str(row["error"]) for row in failed)
