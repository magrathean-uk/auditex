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


# The Google run takes --doh-endpoint like the Microsoft 365 run: never abbreviated, redacted from recorded
# command lines, and named (by host) in the console notice and data-handling.json.

def _fake_google_dns_run(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    from auditex.google_workspace import run as google_run
    from azure_tenant_audit.collectors.base import CollectorResult

    monkeypatch.delenv("AUDITEX_DOH_ENDPOINT", raising=False)
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


def test_r164_google_run_option_reaches_the_collector_notice_and_data_handling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from auditex import cli as product_cli

    contexts = _fake_google_dns_run(monkeypatch)
    rc = product_cli.main([
        "google", "run", "--tenant-name", "Example", "--out", str(tmp_path), "--run-name", "dns",
        "--collectors", "google_dns_posture", "--doh-endpoint", "https://dns.corp.example/profile-abc123",
    ])

    assert rc == 0
    assert contexts[0]["doh_endpoint"] == "https://dns.corp.example/profile-abc123"
    err = capsys.readouterr().err
    assert "dns.corp.example" in err and "profile-abc123" not in err and "--doh-endpoint" in err
    run_dir = tmp_path / "Example-dns"
    record = json.loads((run_dir / "data-handling.json").read_text(encoding="utf-8"))
    assert record["dns_resolver"] == "dns.corp.example"
    assert "dns.corp.example" in " ".join(record["collection_notices"])
    assert "profile-abc123" not in (run_dir / "run-manifest.json").read_text(encoding="utf-8")


def test_r164_google_run_refuses_a_malformed_option_before_any_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from auditex import cli as product_cli

    contexts = _fake_google_dns_run(monkeypatch)
    canary = "constructed-doh-token-zz9"
    rc = product_cli.main([
        "google", "run", "--tenant-name", "Example", "--out", str(tmp_path),
        "--collectors", "google_dns_posture", "--doh-endpoint", f"http://dns.corp.example/{canary}",
    ])

    assert rc == 2 and contexts == []
    err = capsys.readouterr().err
    assert json.loads(err)["error"] == "invalid_doh_endpoint" and canary not in err
    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize("inline", [False, True])
def test_r164_google_doh_endpoint_refuses_abbreviations_without_echo(inline: bool, capsys: pytest.CaptureFixture[str]) -> None:
    from auditex.cli import _build_google_parser

    parsed = _build_google_parser().parse_args(["run", "--doh-endpoint", "https://dns.corp.example/q"])
    assert parsed.doh_endpoint == "https://dns.corp.example/q"
    canary = "constructed-canary-argv-zz9"
    for length in range(3, len("--doh-endpoint")):
        option = "--doh-endpoint"[:length]
        with pytest.raises(SystemExit) as exc:
            _build_google_parser().parse_args(["run", f"{option}={canary}"] if inline else ["run", option, canary])
        assert exc.value.code == 2
        assert canary not in capsys.readouterr().err


def test_r164_doh_endpoint_is_redacted_by_every_command_line_scrubber() -> None:
    from auditex.command_runner import SENSITIVE_ARGS, redact_command
    from auditex.google_workspace.run import _SENSITIVE_COMMAND_FLAGS, scrub_google_command_line
    from azure_tenant_audit.secret_hygiene import SENSITIVE_ARG_FLAGS, redact_argv

    secret = "https://dns.corp.example/tok-zz9"
    for flags, scrub in ((_SENSITIVE_COMMAND_FLAGS, scrub_google_command_line), (SENSITIVE_ARGS, redact_command),
                         (SENSITIVE_ARG_FLAGS, redact_argv)):
        assert "--doh-endpoint" in flags
        assert secret not in scrub(["auditex", "google", "run", "--doh-endpoint", secret])
        assert secret not in scrub(["auditex", "google", "run", f"--doh-endpoint={secret}"])


def test_r164_docs_name_the_google_doh_option() -> None:
    root = Path(__file__).resolve().parents[1]
    privacy = " ".join((root / "docs/reference/security-privacy.md").read_text(encoding="utf-8").split())
    assert "it has no `--doh-endpoint` option" not in privacy
    assert "`auditex google run`" in privacy
    setup = " ".join((root / "docs/guides/setup-guide.md").read_text(encoding="utf-8").split())
    google = setup[setup.index("Google DNS posture (`google_dns_posture`"):]
    assert "--doh-endpoint" in google[: google.index("--exclude google_dns_posture")]
