"""MTA-STS policy, TLS-RPT, and public tenant-discovery lookups (no network)."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector
from azure_tenant_audit.dns_lookup import collect_domain_posture, parse_tls_rpt
from azure_tenant_audit.exposure_lookup import (
    RequestsHttpsFetcher,
    fetch_mta_sts_policy,
    fetch_tenant_discovery,
    parse_mta_sts_policy,
    parse_openid_configuration,
    summarize_public_footprint,
)
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OIDC_BODY = (
    '{"issuer": "https://login.microsoftonline.com/' + TENANT_ID + '/v2.0",'
    ' "token_endpoint": "https://login.microsoftonline.com/' + TENANT_ID + '/oauth2/v2.0/token",'
    ' "tenant_region_scope": "EU", "cloud_instance_name": "microsoftonline.com"}'
)


class _Fetcher:
    def __init__(self, responses: dict[str, tuple[int | None, str, str | None]]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def get_text(self, url: str) -> tuple[int | None, str, str | None]:
        self.urls.append(url)
        return self.responses.get(url, (404, "", None))


class _Resolver:
    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = records
        self.queries: list[tuple[str, str]] = []

    def query(self, name: str, record_type: str) -> list[str]:
        self.queries.append((name, record_type))
        return list(self.records.get((name, record_type), []))


class _Graph:
    def __init__(self, domains: list[dict[str, Any]]) -> None:
        self.domains = domains

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        assert path == "/domains"
        return list(self.domains)


# ----- parsers -----


def test_parse_tls_rpt_and_posture_query() -> None:
    parsed = parse_tls_rpt("v=TLSRPTv1; rua=mailto:tls@contoso.com,https://r.example/report")
    assert parsed is not None
    assert parsed["rua"] == ["mailto:tls@contoso.com", "https://r.example/report"]
    assert parse_tls_rpt("v=spf1 -all") is None

    resolver = _Resolver({("_smtp._tls.contoso.com", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@contoso.com"]})
    posture = collect_domain_posture("contoso.com", resolver)
    assert posture["tls_rpt"]["present"] is True
    assert ("_smtp._tls.contoso.com", "TXT") in resolver.queries
    assert collect_domain_posture("other.example", _Resolver({}))["tls_rpt"]["present"] is False


def test_parse_mta_sts_policy_modes() -> None:
    policy = parse_mta_sts_policy(
        "version: STSv1\nmode: enforce\nmx: *.mail.protection.outlook.com\nmax_age: 604800\n"
    )
    assert policy == {
        "version": "STSv1",
        "mode": "enforce",
        "mode_valid": True,
        "mx": ["*.mail.protection.outlook.com"],
        "max_age": 604800,
    }
    assert parse_mta_sts_policy("version: STSv1\nmode: testing\n")["mode"] == "testing"
    assert parse_mta_sts_policy("<html>not a policy</html>") is None
    assert parse_mta_sts_policy("") is None


def test_fetch_mta_sts_policy_statuses() -> None:
    url = "https://mta-sts.contoso.com/.well-known/mta-sts.txt"
    ok = fetch_mta_sts_policy("contoso.com", _Fetcher({url: (200, "version: STSv1\nmode: testing\n", None)}))
    assert ok["fetch_status"] == "ok" and ok["mode"] == "testing"
    assert fetch_mta_sts_policy("contoso.com", _Fetcher({}))["fetch_status"] == "http_error"
    assert fetch_mta_sts_policy("contoso.com", _Fetcher({url: (None, "", "timeout")}))["fetch_status"] == "unreachable"
    assert fetch_mta_sts_policy("contoso.com", _Fetcher({url: (200, "junk", None)}))["fetch_status"] == "invalid_policy"
    rejected = _Fetcher({})
    assert fetch_mta_sts_policy("bad host/../x", rejected)["fetch_status"] == "skipped"
    assert rejected.urls == []


def test_openid_discovery_parsing_keeps_tenant_facts_only() -> None:
    parsed = parse_openid_configuration(
        {"issuer": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0", "tenant_region_scope": "EU", "jwks_uri": "x"}
    )
    assert parsed["tenant_id"] == TENANT_ID
    assert parsed["tenant_region_scope"] == "EU"
    assert "jwks_uri" not in parsed
    assert parse_openid_configuration(["not", "a", "dict"]) is None

    url = f"https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration"
    result = fetch_tenant_discovery("contoso.com", _Fetcher({url: (200, OIDC_BODY, None)}))
    assert result["discovery_status"] == "ok"
    assert result["tenant_id"] == TENANT_ID
    assert fetch_tenant_discovery("unknown.example", _Fetcher({}))["discovery_status"] == "not_found"


def test_requests_fetcher_refuses_plain_http_and_disables_redirects() -> None:
    class _Raw:
        def read(self, amount: int, decode_content: bool = False) -> bytes:
            return b"version: STSv1\nmode: enforce\n"

    class _Response:
        status_code = 200
        raw = _Raw()

    class _Session:
        def __init__(self) -> None:
            self.kwargs: dict[str, Any] = {}

        def get(self, url: str, **kwargs: Any) -> _Response:
            self.kwargs = kwargs
            return _Response()

    session = _Session()
    fetcher = RequestsHttpsFetcher(session=session)
    assert fetcher.get_text("http://mta-sts.contoso.com/x") == (None, "", "refused_non_https_url")
    status, body, error = fetcher.get_text("https://mta-sts.contoso.com/.well-known/mta-sts.txt")
    assert (status, error) == (200, None)
    assert "STSv1" in body
    assert session.kwargs["allow_redirects"] is False


# ----- collector -----


def _domains() -> list[dict[str, Any]]:
    return [
        {"id": "contoso.com", "isVerified": True, "isDefault": True, "authenticationType": "Federated"},
        {"id": "pending.example", "isVerified": False, "authenticationType": "Managed"},
    ]


def test_collector_fetches_policy_and_footprint_for_verified_domains_only() -> None:
    resolver = _Resolver({("_mta-sts.contoso.com", "TXT"): ["v=STSv1; id=1"]})
    fetcher = _Fetcher(
        {
            "https://mta-sts.contoso.com/.well-known/mta-sts.txt": (200, "version: STSv1\nmode: enforce\n", None),
            "https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration": (200, OIDC_BODY, None),
        }
    )
    result = DnsPostureCollector().run({"client": _Graph(_domains()), "dns_resolver": resolver, "https_fetcher": fetcher})

    assert result.status == "ok"
    posture = result.payload["domainPosture"]["value"][0]
    assert posture["mta_sts"]["policy"]["mode"] == "enforce"
    footprint = result.payload["publicFootprint"]["value"]
    assert [row["domain"] for row in footprint] == ["contoso.com"]
    assert footprint[0]["tenant_id"] == TENANT_ID
    assert all("pending.example" not in url for url in fetcher.urls)
    assert not any("getuserrealm" in url for url in fetcher.urls)


def test_collector_skips_https_lookups_without_fetcher_when_resolver_injected() -> None:
    resolver = _Resolver({("_mta-sts.contoso.com", "TXT"): ["v=STSv1; id=1"]})
    result = DnsPostureCollector().run({"client": _Graph(_domains()), "dns_resolver": resolver})
    assert "publicFootprint" not in result.payload
    assert "policy" not in result.payload["domainPosture"]["value"][0]["mta_sts"]


def test_public_lookups_can_be_disabled() -> None:
    fetcher = _Fetcher({})
    result = DnsPostureCollector().run(
        {"client": _Graph(_domains()), "dns_resolver": _Resolver({}), "https_fetcher": fetcher, "public_lookups": False}
    )
    assert fetcher.urls == []
    assert "publicFootprint" not in result.payload


def test_failed_discovery_is_a_coverage_row_not_a_crash() -> None:
    fetcher = _Fetcher(
        {"https://login.microsoftonline.com/contoso.com/v2.0/.well-known/openid-configuration": (None, "", "timeout")}
    )
    result = DnsPostureCollector().run({"client": _Graph(_domains()), "dns_resolver": _Resolver({}), "https_fetcher": fetcher})
    row = next(item for item in result.coverage if item["name"] == "public_footprint:contoso.com")
    assert row["status"] == "failed"
    assert row["error_class"] == "public_lookup_error"
    assert result.status == "partial"


# ----- findings -----


def _findings(posture: dict[str, Any], footprint: list[dict[str, Any]] | None = None) -> set[str]:
    payload: dict[str, Any] = {"domains": {"value": []}, "domainPosture": {"value": [posture]}}
    if footprint is not None:
        payload["publicFootprint"] = {"value": footprint}
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads={"dns_posture": payload})
    return {item["id"] for item in build_findings([], normalized_snapshot=snapshot)}


def _posture(**overrides: Any) -> dict[str, Any]:
    base = {
        "domain": "contoso.com",
        "managed_by_microsoft": False,
        "spf": {"present": True, "all_qualifier": "-"},
        "dmarc": {"present": True, "policy": "reject"},
        "dkim": {"selectors_present": ["selector1"], "selectors_missing": []},
        "mta_sts": {"dns_present": True, "policy": {"fetch_status": "ok", "mode": "enforce"}},
        "tls_rpt": {"present": True},
        "bimi": {"present": False},
    }
    base.update(overrides)
    return base


def test_transport_security_findings() -> None:
    assert not {i for i in _findings(_posture()) if "mta_sts" in i or "tls_rpt" in i}
    assert "dns_posture:contoso.com:mta_sts_missing" in _findings(_posture(mta_sts={"dns_present": False}))
    assert "dns_posture:contoso.com:mta_sts_testing_mode" in _findings(
        _posture(mta_sts={"dns_present": True, "policy": {"fetch_status": "ok", "mode": "testing"}})
    )
    assert "dns_posture:contoso.com:mta_sts_policy_invalid" in _findings(
        _posture(mta_sts={"dns_present": True, "policy": {"fetch_status": "http_error", "http_status": 404}})
    )
    assert "dns_posture:contoso.com:tls_rpt_missing" in _findings(_posture(tls_rpt={"present": False}))


def test_transport_findings_need_collected_evidence() -> None:
    # Policy never fetched (offline / older bundle) and no TLS-RPT data: no finding.
    legacy = _posture(mta_sts={"dns_present": True})
    legacy.pop("tls_rpt")
    ids = _findings(legacy)
    assert not {i for i in ids if "mta_sts" in i or "tls_rpt" in i}
    # Resolver failures never produce "missing" findings.
    broken = _posture(mta_sts={"dns_present": False}, tls_rpt={"present": False}, resolver_error="down")
    assert not {i for i in _findings(broken) if "mta_sts" in i or "tls_rpt" in i}


def test_federated_domain_exposure_is_low_and_managed_is_silent() -> None:
    federated = [{"domain": "contoso.com", "authentication_type": "Federated", "discovery_status": "ok"}]
    managed = [{"domain": "contoso.com", "authentication_type": "Managed", "discovery_status": "ok"}]
    assert "exposure:contoso.com:federated_domain_metadata_public" in _findings(_posture(), federated)
    assert "exposure:contoso.com:federated_domain_metadata_public" not in _findings(_posture(), managed)


def test_public_footprint_summary_is_informational() -> None:
    summary = summarize_public_footprint(
        [
            {"domain": "b.example", "authentication_type": "Managed", "tenant_id": TENANT_ID, "key": "public_footprint:b.example"},
            {"domain": "a.example", "authentication_type": "Federated"},
        ]
    )
    assert summary["informational"] is True
    assert [row["domain"] for row in summary["domains"]] == ["a.example", "b.example"]
    assert summary["federated_domain_count"] == 1
    assert summary["tenant_ids_observed"] == [TENANT_ID]
