"""Review leftovers (November 2026, group D): the chosen DNS-over-HTTPS resolver reaches the console notice,
data-handling.json and the Google run's option (R164 follow-up)."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest


def _m365_dns_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *extra: str) -> Any:
    from support import FAKE_CERTIFICATE_ARGS, use_fake_certificate

    from azure_tenant_audit import cli
    from azure_tenant_audit.collectors.base import CollectorResult

    use_fake_certificate(monkeypatch)
    monkeypatch.delenv("AUDITEX_DOH_ENDPOINT", raising=False)

    class _Dns:
        name = "dns_posture"

        def run(self, _context: dict[str, Any]) -> CollectorResult:
            return CollectorResult(name=self.name, status="ok", item_count=0, message="ok", payload={})

    class _Client:
        def __init__(self, auth: Any, **_: Any) -> None:
            self.auth = auth

        def token_claims(self) -> dict[str, Any]:
            return {}

    monkeypatch.setattr(cli, "GraphClient", _Client)
    monkeypatch.setattr(cli, "REGISTRY", {"dns_posture": _Dns()})
    return cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "contoso.onmicrosoft.com", "--client-id", "app-id",
        *FAKE_CERTIFICATE_ARGS, "--collectors", "dns_posture", "--no-probe-first", "--out", str(tmp_path), *extra,
    ])


def _data_handling(tmp_path: Path) -> dict[str, Any]:
    (path,) = tmp_path.glob("acme-*/data-handling.json")
    return json.loads(path.read_text(encoding="utf-8"))


def test_r164_m365_notice_and_data_handling_name_the_chosen_resolver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from azure_tenant_audit import cli

    args = _m365_dns_run(monkeypatch, tmp_path, "--doh-endpoint", "https://dns.corp.example/dns-query")
    with caplog.at_level(logging.INFO):
        cli.run_live(args)

    console = " ".join(record.getMessage() for record in caplog.records)
    assert "dns.corp.example" in console and "cloudflare" not in console.lower()
    record = _data_handling(tmp_path)
    assert record["dns_resolver"] == "dns.corp.example"
    notices = " ".join(record["collection_notices"])
    assert "dns.corp.example" in notices and "cloudflare" not in notices.lower()


def test_r164_m365_default_resolver_is_still_named_cloudflare(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from azure_tenant_audit import cli

    args = _m365_dns_run(monkeypatch, tmp_path)
    with caplog.at_level(logging.INFO):
        cli.run_live(args)

    assert "cloudflare-dns.com" in " ".join(record.getMessage() for record in caplog.records)
    assert _data_handling(tmp_path)["dns_resolver"] == "cloudflare-dns.com"


def test_r164_resolver_gap_reason_does_not_claim_cloudflare_for_a_chosen_resolver() -> None:
    from azure_tenant_audit.collection_gaps import _COLLECTOR_FAILURE_REASON_TEXT

    text = _COLLECTOR_FAILURE_REASON_TEXT["dns_resolver_error"]
    assert "public Cloudflare DNS-over-HTTPS resolver could not" not in text
    assert "--doh-endpoint" in text and "AUDITEX_DOH_ENDPOINT" in text

