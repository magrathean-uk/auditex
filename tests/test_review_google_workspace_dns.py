"""Deep-review regressions for the Google DNS posture collector: the configured DNS-over-HTTPS resolver (R164
wiring), a bad resolver as a run-level configuration error, and the data-handling notice with its off switch."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import collectors as google_collectors
from auditex.google_workspace import run as google_run
from auditex.google_workspace.collectors import GoogleDnsPostureCollector
from auditex.google_workspace.run import GoogleRunConfig, run_google_live
from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT, DOH_ENDPOINT_ENV


class _Resolver:
    def __init__(self, endpoint: str = DEFAULT_DOH_ENDPOINT, **_kwargs: Any) -> None:
        self.endpoint = endpoint


@pytest.fixture
def resolvers(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    endpoints: list[str] = []

    def client(*, endpoint: str = DEFAULT_DOH_ENDPOINT, **_kwargs: Any) -> _Resolver:
        endpoints.append(endpoint)
        return _Resolver(endpoint)

    monkeypatch.setattr(google_collectors, "DohClient", client)
    monkeypatch.setattr(google_collectors, "collect_domain_posture", lambda domain, _resolver, **_k: {"domain": domain})
    return endpoints


def test_x1_collector_uses_the_configured_doh_endpoint(monkeypatch: pytest.MonkeyPatch, resolvers: list[str]) -> None:
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://dns.example.net/dns-query")
    result = GoogleDnsPostureCollector().run({"domain": "example.com"})
    assert resolvers == ["https://dns.example.net/dns-query"]
    assert result.status == "ok"


def test_x1_collector_records_a_bad_endpoint_as_a_config_error_not_a_crash(resolvers: list[str]) -> None:
    result = GoogleDnsPostureCollector().run({"domain": "example.com", "doh_endpoint": "http://user:pw@dns.example.net/q"})
    assert resolvers == []
    (row,) = result.coverage
    assert row["status"] == "failed" and row["error_class"] == "config_error"
    assert "pw" not in json.dumps(row)


def _fake_dns_run(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    from azure_tenant_audit.collectors.base import CollectorResult

    contexts: list[dict[str, Any]] = []

    class _Collector:
        name = "google_dns_posture"
        required_scopes = ("scope://domains",)

        def run(self, context: dict[str, Any]) -> CollectorResult:
            contexts.append(dict(context))
            return CollectorResult(self.name, "ok", {}, 0, coverage=[{"collector": self.name, "name": "x", "status": "ok", "item_count": 0}])

    monkeypatch.setattr(google_run, "REGISTRY", {"google_dns_posture": _Collector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    return contexts


def test_x1_bad_doh_endpoint_stops_the_run_before_any_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    contexts = _fake_dns_run(monkeypatch)
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "ftp://dns.example.net/q")
    rc = run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, collectors="google_dns_posture"))
    assert rc == 2 and contexts == []
    assert json.loads(capsys.readouterr().err)["error"] == "invalid_doh_endpoint"
    assert not any(tmp_path.iterdir())


def test_l6_google_dns_lookups_carry_the_notice_and_off_switch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    contexts = _fake_dns_run(monkeypatch)
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://dns.example.net/dns-query")
    with caplog.at_level(logging.INFO, logger="auditex.google_workspace"):
        run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, run_name="dns", collectors="google_dns_posture"))
    notice = " ".join(record.getMessage() for record in caplog.records)
    assert "resolver at dns.example.net" in notice
    assert "--exclude google_dns_posture" in notice
    assert contexts[0]["doh_endpoint"] == "https://dns.example.net/dns-query"
    events = (tmp_path / "Example-dns" / "audit-log.jsonl").read_text(encoding="utf-8")
    assert "--exclude google_dns_posture" in events


def test_l6_no_notice_when_dns_posture_is_not_selected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from azure_tenant_audit.collectors.base import CollectorResult

    class _Collector:
        name = "google_directory"
        required_scopes = ("scope://users",)

        def run(self, _context: dict[str, Any]) -> CollectorResult:
            return CollectorResult(self.name, "ok", {}, 0, coverage=[])

    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": _Collector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "ftp://ignored")
    with caplog.at_level(logging.INFO, logger="auditex.google_workspace"):
        rc = run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, collectors="google_directory"))
    assert rc == 0
    assert "DNS-over-HTTPS" not in " ".join(record.getMessage() for record in caplog.records)


def test_l6_notice_names_only_the_host_of_a_configured_resolver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _fake_dns_run(monkeypatch)
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://dns.example.net/profile-abc123")
    with caplog.at_level(logging.INFO, logger="auditex.google_workspace"):
        run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, run_name="dns", collectors="google_dns_posture"))
    notice = " ".join(record.getMessage() for record in caplog.records)
    assert "dns.example.net" in notice and "profile-abc123" not in notice
    assert "profile-abc123" not in (tmp_path / "Example-dns" / "audit-log.jsonl").read_text(encoding="utf-8")


def test_l6_data_handling_record_carries_the_dns_notice(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_dns_run(monkeypatch)
    monkeypatch.setenv(DOH_ENDPOINT_ENV, "https://dns.example.net/profile-abc123")
    run_google_live(GoogleRunConfig(tenant_name="Example", out=tmp_path, run_name="dns", collectors="google_dns_posture"))
    record = json.loads((tmp_path / "Example-dns" / "data-handling.json").read_text(encoding="utf-8"))
    notices = " ".join(record["collection_notices"])
    assert "--exclude google_dns_posture" in notices
    assert "dns.example.net" in notices and "profile-abc123" not in notices
