from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit.collectors.dns_posture import (
    DEFAULT_DKIM_SELECTORS,
    FALLBACK_DKIM_SELECTORS,
    DnsPostureCollector,
)
from azure_tenant_audit.dns_lookup import (
    DohClient,
    DohError,
    collect_domain_posture,
    parse_bimi,
    parse_dmarc,
    parse_mta_sts,
    parse_spf,
)


# ----- Record parsers -----


def test_parse_spf_extracts_mechanisms_and_qualifier() -> None:
    record = parse_spf("v=spf1 include:spf.protection.outlook.com -all")
    assert record is not None
    assert record["version"] == "spf1"
    assert "include:spf.protection.outlook.com" in record["mechanisms"]
    assert record["all_qualifier"] == "-"


def test_parse_spf_returns_none_when_not_spf() -> None:
    assert parse_spf("google-site-verification=abc") is None


def test_parse_spf_handles_missing_all() -> None:
    record = parse_spf("v=spf1 include:spf.protection.outlook.com")
    assert record is not None
    assert record["all_qualifier"] is None


def test_parse_dmarc_extracts_policy_and_aggregate_addresses() -> None:
    record = parse_dmarc("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; pct=100")
    assert record is not None
    assert record["policy"] == "reject"
    assert record["subdomain_policy"] == "quarantine"
    assert record["aggregate_addresses"] == ["mailto:dmarc@example.com"]
    assert record["pct"] == 100


def test_parse_dmarc_returns_none_when_missing_marker() -> None:
    assert parse_dmarc("v=spf1 -all") is None


def test_parse_dmarc_handles_p_none_default_pct() -> None:
    record = parse_dmarc("v=DMARC1; p=none")
    assert record is not None
    assert record["policy"] == "none"
    assert record["pct"] == 100  # DMARC default per RFC


def test_parse_mta_sts_extracts_id() -> None:
    record = parse_mta_sts("v=STSv1; id=20231201T000000")
    assert record is not None
    assert record["version"] == "STSv1"
    assert record["id"] == "20231201T000000"


def test_parse_mta_sts_returns_none_when_missing_marker() -> None:
    assert parse_mta_sts("v=spf1 -all") is None


def test_parse_bimi_extracts_logo_and_authority() -> None:
    record = parse_bimi("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
    assert record is not None
    assert record["logo_url"] == "https://example.com/logo.svg"
    assert record["authority_url"] == "https://example.com/vmc.pem"


def test_parse_bimi_returns_none_when_missing_marker() -> None:
    assert parse_bimi("v=DMARC1; p=none") is None


# ----- DoH client -----


class _FakeSession:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, params: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        self.calls.append((url, dict(params or {})))
        key = (url, params.get("name") if params else None, params.get("type") if params else None)
        response = self.responses.get(key)
        if response is None:
            response = self.responses.get((params.get("name") if params else None, params.get("type") if params else None))
        if response is None:
            raise AssertionError(f"no fake response for {url} {params}")
        return _FakeResponse(response)


class _FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code
        self.text = "fake"

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


def test_doh_client_query_returns_txt_records() -> None:
    payload = {
        "Status": 0,
        "Answer": [
            {"name": "example.com.", "type": 16, "TTL": 300, "data": "\"v=spf1 -all\""},
        ],
    }
    session = _FakeSession({("example.com", "TXT"): payload})
    client = DohClient(session=session, endpoint="https://dns.example/dns-query")

    records = client.query("example.com", "TXT")

    assert records == ["v=spf1 -all"]


def test_doh_client_query_concatenates_multistring_txt() -> None:
    payload = {
        "Status": 0,
        "Answer": [
            {"name": "_dmarc.example.com.", "type": 16, "data": "\"v=DMARC1; \" \"p=reject\""},
        ],
    }
    session = _FakeSession({("_dmarc.example.com", "TXT"): payload})
    client = DohClient(session=session, endpoint="https://dns.example/dns-query")

    records = client.query("_dmarc.example.com", "TXT")

    assert records == ["v=DMARC1; p=reject"]


def test_doh_client_query_empty_answer_returns_empty_list() -> None:
    payload = {"Status": 0}
    session = _FakeSession({("example.com", "TXT"): payload})
    client = DohClient(session=session, endpoint="https://dns.example/dns-query")

    assert client.query("example.com", "TXT") == []


def test_doh_client_query_raises_doh_error_on_transport_failure() -> None:
    class _BrokenSession:
        def get(self, *args, **kwargs):  # noqa: ANN001
            raise RuntimeError("boom")

    client = DohClient(session=_BrokenSession(), endpoint="https://dns.example/dns-query")
    with pytest.raises(DohError):
        client.query("example.com", "TXT")


# ----- Collector -----


class _GraphClientStub:
    def __init__(self, payload: list[dict[str, Any]] | Exception) -> None:
        self._payload = payload

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        if isinstance(self._payload, Exception):
            raise self._payload
        assert path == "/domains"
        return list(self._payload)

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        if isinstance(self._payload, Exception):
            raise self._payload
        assert path == "/domains"
        return {"value": list(self._payload)}


class _DnsResolverStub:
    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records
        self.queries: list[tuple[str, str]] = []

    def query(self, name: str, record_type: str) -> list[str]:
        self.queries.append((name, record_type))
        return list(self.records.get((name, record_type), []))


def test_dns_posture_collector_returns_assessment_per_domain() -> None:
    domains = [
        {"id": "contoso.com", "isVerified": True, "isDefault": False, "authenticationType": "Managed"},
        {"id": "contoso.onmicrosoft.com", "isVerified": True, "isDefault": True, "authenticationType": "Managed"},
    ]
    resolver = _DnsResolverStub(
        {
            ("contoso.com", "TXT"): ["v=spf1 include:spf.protection.outlook.com -all"],
            ("_dmarc.contoso.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@contoso.com"],
            ("selector1._domainkey.contoso.com", "TXT"): ["v=DKIM1; k=rsa; p=AAAA"],
            ("selector2._domainkey.contoso.com", "TXT"): ["v=DKIM1; k=rsa; p=BBBB"],
            ("_mta-sts.contoso.com", "TXT"): ["v=STSv1; id=20231201T000000"],
            ("default._bimi.contoso.com", "TXT"): [],
            ("contoso.onmicrosoft.com", "TXT"): [],
            ("_dmarc.contoso.onmicrosoft.com", "TXT"): [],
            ("selector1._domainkey.contoso.onmicrosoft.com", "TXT"): [],
            ("selector2._domainkey.contoso.onmicrosoft.com", "TXT"): [],
            ("_mta-sts.contoso.onmicrosoft.com", "TXT"): [],
            ("default._bimi.contoso.onmicrosoft.com", "TXT"): [],
        }
    )

    collector = DnsPostureCollector()
    result = collector.run(
        {
            "client": _GraphClientStub(domains),
            "top": 500,
            "dns_resolver": resolver,
        }
    )

    assert result.status == "ok"
    assessments = result.payload["domainPosture"]["value"]
    assert len(assessments) == 2

    contoso = next(item for item in assessments if item["domain"] == "contoso.com")
    assert contoso["spf"]["present"] is True
    assert contoso["spf"]["all_qualifier"] == "-"
    assert contoso["dmarc"]["present"] is True
    assert contoso["dmarc"]["policy"] == "reject"
    assert contoso["dkim"]["selectors_present"] == ["selector1", "selector2"]
    assert contoso["mta_sts"]["dns_present"] is True
    assert contoso["bimi"]["present"] is False

    onms = next(item for item in assessments if item["domain"] == "contoso.onmicrosoft.com")
    assert onms["managed_by_microsoft"] is True
    assert onms["spf"]["present"] is False


def test_dns_posture_collector_marks_missing_records_for_unprotected_domain() -> None:
    domains = [
        {"id": "naked.example", "isVerified": True, "isDefault": False, "authenticationType": "Managed"},
    ]
    resolver = _DnsResolverStub({})

    collector = DnsPostureCollector()
    result = collector.run({"client": _GraphClientStub(domains), "top": 500, "dns_resolver": resolver})

    assert result.status == "ok"
    record = result.payload["domainPosture"]["value"][0]
    assert record["spf"]["present"] is False
    assert record["dmarc"]["present"] is False
    assert record["dkim"]["selectors_present"] == []
    assert record["mta_sts"]["dns_present"] is False
    assert record["bimi"]["present"] is False


def test_dns_posture_collector_skips_unverified_domains() -> None:
    domains = [
        {"id": "pending.example", "isVerified": False, "isDefault": False, "authenticationType": "Managed"},
        {"id": "live.example", "isVerified": True, "isDefault": False, "authenticationType": "Managed"},
    ]
    resolver = _DnsResolverStub({("live.example", "TXT"): ["v=spf1 -all"]})

    collector = DnsPostureCollector()
    result = collector.run({"client": _GraphClientStub(domains), "top": 500, "dns_resolver": resolver})

    domains_assessed = [item["domain"] for item in result.payload["domainPosture"]["value"]]
    assert domains_assessed == ["live.example"]


def test_dns_posture_collector_handles_graph_failure_gracefully() -> None:
    from azure_tenant_audit.graph import GraphError

    collector = DnsPostureCollector()
    result = collector.run(
        {
            "client": _GraphClientStub(GraphError("forbidden", status=403, request="/domains")),
            "top": 500,
            "dns_resolver": _DnsResolverStub({}),
        }
    )

    assert result.status == "partial"
    coverage = result.coverage or []
    assert coverage[0]["status"] == "failed"
    assert coverage[0]["error_class"] == "insufficient_permissions"


def test_dns_posture_collector_records_resolver_failures_per_domain() -> None:
    class _BrokenResolver:
        def query(self, name: str, record_type: str) -> list[str]:
            raise DohError("resolver down")

    domains = [{"id": "contoso.com", "isVerified": True, "isDefault": False, "authenticationType": "Managed"}]
    collector = DnsPostureCollector()
    result = collector.run(
        {"client": _GraphClientStub(domains), "top": 500, "dns_resolver": _BrokenResolver()}
    )

    record = result.payload["domainPosture"]["value"][0]
    assert record["resolver_error"] is not None
    # Unknown, never "absent": a resolver failure says nothing about what the domain publishes.
    assert record["spf"]["present"] is None
    assert record["dmarc"]["present"] is None
    assert record["dkim"]["selectors_missing"] == []


# ----- Tiered DKIM probe (A2) -----


def test_dkim_default_selectors_hit_skips_fallback_probes() -> None:
    """When M365 selectors resolve, the fallback list must NOT generate extra DNS queries."""
    resolver = _DnsResolverStub(
        {
            ("contoso.com", "TXT"): ["v=spf1 -all"],
            ("_dmarc.contoso.com", "TXT"): ["v=DMARC1; p=reject"],
            ("_mta-sts.contoso.com", "TXT"): [],
            ("default._bimi.contoso.com", "TXT"): [],
            ("selector1._domainkey.contoso.com", "TXT"): ["v=DKIM1; k=rsa; p=AAAA"],
            ("selector2._domainkey.contoso.com", "TXT"): ["v=DKIM1; k=rsa; p=BBBB"],
        }
    )

    posture = collect_domain_posture(
        "contoso.com",
        resolver,
        dkim_selectors=DEFAULT_DKIM_SELECTORS,
        dkim_fallback_selectors=FALLBACK_DKIM_SELECTORS,
    )

    # Only the M365 DKIM selectors should appear in queries — none of the fallbacks.
    queried_dkim = [
        name for (name, _kind) in resolver.queries if name.endswith("._domainkey.contoso.com")
    ]
    assert queried_dkim == [
        "selector1._domainkey.contoso.com",
        "selector2._domainkey.contoso.com",
    ]
    assert posture["dkim"]["selectors_present"] == ["selector1", "selector2"]


def test_dkim_default_selectors_miss_triggers_fallback_probes() -> None:
    """When M365 selectors miss, every fallback selector must be probed exactly once."""
    resolver = _DnsResolverStub(
        {
            ("contoso.com", "TXT"): [],
            ("_dmarc.contoso.com", "TXT"): [],
            ("_mta-sts.contoso.com", "TXT"): [],
            ("default._bimi.contoso.com", "TXT"): [],
            # All M365 + fallback selectors miss → returns empty per stub default.
        }
    )

    posture = collect_domain_posture(
        "contoso.com",
        resolver,
        dkim_selectors=DEFAULT_DKIM_SELECTORS,
        dkim_fallback_selectors=FALLBACK_DKIM_SELECTORS,
    )

    queried_dkim_selectors = [
        name.split("._domainkey.")[0]
        for (name, _kind) in resolver.queries
        if name.endswith("._domainkey.contoso.com")
    ]
    assert queried_dkim_selectors == [
        *DEFAULT_DKIM_SELECTORS,
        *FALLBACK_DKIM_SELECTORS,
    ]
    assert posture["dkim"]["selectors_present"] == []
    # Missing list must enumerate every probed selector for downstream reporting.
    assert set(posture["dkim"]["selectors_missing"]) == {
        *DEFAULT_DKIM_SELECTORS,
        *FALLBACK_DKIM_SELECTORS,
    }


def test_dkim_fallback_selector_can_resolve() -> None:
    """A non-M365 selector (e.g. ``google``) resolving must be reported as present."""
    resolver = _DnsResolverStub(
        {
            ("contoso.com", "TXT"): [],
            ("_dmarc.contoso.com", "TXT"): [],
            ("_mta-sts.contoso.com", "TXT"): [],
            ("default._bimi.contoso.com", "TXT"): [],
            ("google._domainkey.contoso.com", "TXT"): ["v=DKIM1; k=rsa; p=ZZZZ"],
        }
    )

    posture = collect_domain_posture(
        "contoso.com",
        resolver,
        dkim_selectors=DEFAULT_DKIM_SELECTORS,
        dkim_fallback_selectors=FALLBACK_DKIM_SELECTORS,
    )

    assert posture["dkim"]["selectors_present"] == ["google"]
    # selector_details must surface the resolved key for the auditor.
    assert posture["dkim"]["selector_details"]["google"]["present"] is True


def test_dns_posture_collector_uses_fallback_selectors_by_default() -> None:
    """The collector defaults to FALLBACK_DKIM_SELECTORS when context omits the override."""
    domains = [{"id": "naked.example", "isVerified": True, "isDefault": False, "authenticationType": "Managed"}]
    resolver = _DnsResolverStub({})

    collector = DnsPostureCollector()
    result = collector.run({"client": _GraphClientStub(domains), "top": 500, "dns_resolver": resolver})

    queried_dkim = [
        name.split("._domainkey.")[0]
        for (name, _kind) in resolver.queries
        if "._domainkey.naked.example" in name
    ]
    # Both primary + fallback should have been probed exactly once each.
    assert queried_dkim == [*DEFAULT_DKIM_SELECTORS, *FALLBACK_DKIM_SELECTORS]
    record = result.payload["domainPosture"]["value"][0]
    assert record["dkim"]["selectors_present"] == []
