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
    from auditex.google_workspace.run import (
        _SENSITIVE_COMMAND_FLAGS,
        scrub_google_command_line,
    )
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


# Compare/diff/MCP and local-answer wording the November docs pass could not add before that code landed.

def _flat_doc(relative: str) -> str:
    return " ".join((Path(__file__).resolve().parents[1] / relative).read_text(encoding="utf-8").split())


def test_output_contract_states_the_diff_gate_and_undated_runs() -> None:
    text = _flat_doc("docs/reference/output-contract.md")
    for needle in ("`auditex diff`", "`auditex_diff_runs`", "same_tenant_required", "tenant_id_mismatch",
                   "run_unverified:<baseline|current>:<problem>", "run_created_utc_missing"):
        assert needle in text, needle


def test_output_contract_states_the_mcp_summary_cap_and_command_timeout() -> None:
    from auditex.command_runner import (
        COMMAND_TIMEOUT_ENV,
        DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    from auditex.mcp_server import SUMMARY_RESPONSE_BUDGET_BYTES

    text = _flat_doc("docs/reference/output-contract.md")
    assert SUMMARY_RESPONSE_BUDGET_BYTES == 48_000 and "48,000 bytes" in text
    for needle in ("`summary_truncated`", "`omitted_sections`", "`read_with`", COMMAND_TIMEOUT_ENV, "`partial_run_dir`"):
        assert needle in text, needle
    assert DEFAULT_COMMAND_TIMEOUT_SECONDS == 4 * 3600 and "four hours" in text


def test_local_answer_guide_states_the_licence_in_the_notice_and_record() -> None:
    text = _flat_doc("docs/guides/local-answer.md")
    assert "names the model's licence" in text and "`local_answer.json`" in text


# Integration review of the R164 follow-up: a custom resolver is disclosed by host only (its path can hold an account
# token), and the DNS coverage gap names the configured resolver for both providers.

_TOKEN = "acct-token-zz9"


def test_r164_custom_resolver_disclosure_never_shows_the_path() -> None:
    from azure_tenant_audit.data_handling import collector_activity_notices
    from azure_tenant_audit.dns_lookup import doh_resolver_disclosure

    text = doh_resolver_disclosure(f"https://dns.corp.example/{_TOKEN}")
    assert "dns.corp.example" in text and _TOKEN not in text
    notices = " ".join(collector_activity_notices(["dns_posture"], "live", f"https://dns.corp.example/{_TOKEN}"))
    assert "dns.corp.example" in notices and _TOKEN not in notices


def test_r164_m365_run_never_writes_the_resolver_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from azure_tenant_audit import cli

    args = _m365_dns_run(monkeypatch, tmp_path, "--doh-endpoint", f"https://dns.corp.example/{_TOKEN}")
    with caplog.at_level(logging.INFO):
        cli.run_live(args)

    console = " ".join(record.getMessage() for record in caplog.records)
    assert "dns.corp.example" in console and _TOKEN not in console
    (path,) = tmp_path.glob("acme-*/data-handling.json")
    assert _TOKEN not in path.read_text(encoding="utf-8")
    assert "dns.corp.example" in " ".join(_data_handling(tmp_path)["collection_notices"])


class _ServfailSession:
    def get(self, _url: str, **_kwargs: Any) -> Any:
        class _Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> dict[str, Any]:
                return {"Status": 2}

        return _Response()


@pytest.mark.parametrize("provider", ["m365", "google"])
def test_r164_servfail_gap_reason_names_the_configured_resolver(provider: str) -> None:
    from azure_tenant_audit.collection_gaps import collector_gap_reason
    from azure_tenant_audit.dns_lookup import DohClient

    resolver = DohClient(session=_ServfailSession(), endpoint=f"https://dns.corp.example/{_TOKEN}")
    if provider == "m365":
        from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

        class _Domains:
            def get_all(self, _path: str, params: Any = None) -> list[dict[str, Any]]:
                return [{"id": "contoso.example", "isVerified": True}]

        collector = "dns_posture"
        result = DnsPostureCollector().run({"client": _Domains(), "dns_resolver": resolver, "public_lookups": False})
    else:
        from auditex.google_workspace.collectors import GoogleDnsPostureCollector

        collector = "google_dns_posture"
        result = GoogleDnsPostureCollector().run({"domain": "example.com", "dns_resolver": resolver})
    rows = [row for row in result.coverage if row.get("error_class") == "dns_resolver_error"]
    assert rows
    for row in rows:
        reason = collector_gap_reason(collector, row["error_class"], doh_endpoint=row.get("doh_endpoint"))
        assert reason is not None
        assert "https://dns.corp.example" in reason and _TOKEN not in reason
        assert "Cloudflare" not in reason and collector in reason


@pytest.mark.parametrize("collector", ["dns_posture", "google_dns_posture"])
def test_r164_gap_reason_without_a_known_resolver_stays_generic(collector: str) -> None:
    from azure_tenant_audit.collection_gaps import collector_gap_reason

    reason = collector_gap_reason(collector, "dns_resolver_error", "Failed at https://untrusted.example/p")
    assert reason is not None and "endpoint unknown" in reason
    assert "untrusted.example" not in reason and "Cloudflare" not in reason


def test_output_contract_matches_the_code_on_compare_time_omissions_and_timeouts() -> None:
    import inspect

    from auditex import command_runner, mcp_server
    from auditex.run_bundle import RunBundle

    text = _flat_doc("docs/reference/output-contract.md")
    # Compare: the creation time falls back from the evidence index to the manifest to summary.json.
    source = inspect.getsource(RunBundle.metadata)
    assert 'indexed.get("created_utc") or manifest.get("created_utc") or summary.get("created_utc")' in source
    assert "else `run-manifest.json`, else `summary.json`" in text
    assert "orders runs by the run manifest's `created_utc`" not in text
    # MCP summary cap: the manifest artifact list is dropped without a read_with.
    assert mcp_server._MANIFEST_ARTIFACTS not in mcp_server._SUMMARY_DROPPABLE_SECTIONS
    assert "(entry `manifest.artifacts`) has no `read_with`" in text
    # Command timeout: every tool that launches a command is named, and partial_run_dir is conditional.
    handlers = mcp_server.tool_handlers()
    launching = sorted(name for name, handler in handlers.items()
                       if "run_cli_command(" in inspect.getsource(inspect.unwrap(handler)))
    assert launching, "no command-launching tools found"
    for name in launching:
        assert f"`{name}`" in text[text.index("The MCP tools that launch an Auditex command"):], name
    runner = inspect.getsource(command_runner.run_cli_command)
    assert "len(new_folders) == 1" in runner and "if partial is not None:" in runner
    assert "`partial_run_dir` is absent" in text


# Repair round 2 of the R164 follow-up: one safe display form for a configured resolver (scheme and host, IPv6
# bracketed, a port only when not the default; never user info, path, query or fragment), used wherever the resolver
# is shown or stored, and no transport log line carrying the request target while a DoH request runs.

_SECRET_PARTS = ("synthetic-user-zz9", "synthetic-pass-zz9", "path-tok-zz9", "query-tok-zz9", "frag-tok-zz9")


@pytest.mark.parametrize(("endpoint", "display"), [
    ("https://dns.corp.example/path-tok-zz9", "https://dns.corp.example"),
    ("HTTPS://DNS.Corp.Example:443/path-tok-zz9", "https://dns.corp.example"),
    ("https://dns.corp.example:8443/path-tok-zz9", "https://dns.corp.example:8443"),
    ("https://[2001:db8::53]:8443/dns-query", "https://[2001:db8::53]:8443"),
    ("https://[2001:db8::53]/dns-query", "https://[2001:db8::53]"),
    ("https://192.0.2.53/dns-query", "https://192.0.2.53"),
    ("http://dns.corp.example:80/x", "http://dns.corp.example"),
    ("https://synthetic-user-zz9:synthetic-pass-zz9@dns.corp.example/path-tok-zz9?k=query-tok-zz9#frag-tok-zz9",
     "https://dns.corp.example"),
    ("https://dns.corp.example\\path-tok-zz9/dns-query", None),
    ("https://dns.corp.example%2Fpath-tok-zz9/q", None),
    ("https://2001:db8::53:8443/dns-query", None),
    ("ftp://dns.corp.example/path-tok-zz9", None),
    ("not a url path-tok-zz9", None),
])
def test_r164_resolver_display_form(endpoint: str, display: str | None) -> None:
    from azure_tenant_audit.dns_lookup import (
        doh_resolver_disclosure,
        doh_resolver_display,
    )

    assert doh_resolver_display(endpoint) == display
    text = doh_resolver_disclosure(endpoint)
    assert not any(part in text for part in _SECRET_PARTS)
    if display is not None:
        assert display.split("://", 1)[1] in text


@pytest.mark.parametrize("endpoint", [
    "https://dns.corp.example\\path-tok-zz9/dns-query",
    "https://dns.corp.example/path tok-zz9",
    "https://dns.corp.example\t/path-tok-zz9",
    "https://dns.corp.éxample/path-tok-zz9",
    "https://dns.corp.example%2Fpath-tok-zz9/q",
    "https://synthetic-user-zz9@dns.corp.example/path-tok-zz9",
    "https://dns.corp.example/path-tok-zz9?k=query-tok-zz9",
])
def test_r164_resolve_refuses_an_endpoint_it_cannot_display_safely(endpoint: str) -> None:
    from azure_tenant_audit.data_handling import dns_resolver_host
    from azure_tenant_audit.dns_lookup import resolve_doh_endpoint

    with pytest.raises(ValueError) as exc:
        resolve_doh_endpoint(endpoint)
    assert not any(part in str(exc.value) for part in _SECRET_PARTS)
    assert dns_resolver_host(["dns_posture"], endpoint) is None


def test_r164_ipv6_resolver_is_named_with_brackets_and_port() -> None:
    from azure_tenant_audit.data_handling import dns_resolver_host
    from azure_tenant_audit.dns_lookup import doh_resolver_disclosure

    endpoint = "https://[2001:db8::53]:8443/dns-query"
    assert "[2001:db8::53]:8443" in doh_resolver_disclosure(endpoint)
    assert dns_resolver_host(["dns_posture"], endpoint) == "[2001:db8::53]"


@pytest.mark.parametrize("provider", ["m365", "google"])
def test_r164_ipv6_servfail_gap_reason_keeps_the_whole_origin(provider: str) -> None:
    from azure_tenant_audit.collection_gaps import collector_gap_reason
    from azure_tenant_audit.dns_lookup import DohClient

    resolver = DohClient(session=_ServfailSession(), endpoint="https://[2001:db8::53]:8443/path-tok-zz9")
    if provider == "m365":
        from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

        class _Domains:
            def get_all(self, _path: str, params: Any = None) -> list[dict[str, Any]]:
                return [{"id": "contoso.example", "isVerified": True}]

        collector = "dns_posture"
        result = DnsPostureCollector().run({"client": _Domains(), "dns_resolver": resolver, "public_lookups": False})
    else:
        from auditex.google_workspace.collectors import GoogleDnsPostureCollector

        collector = "google_dns_posture"
        result = GoogleDnsPostureCollector().run({"domain": "example.com", "dns_resolver": resolver})
    rows = [row for row in result.coverage if row.get("error_class") == "dns_resolver_error"]
    assert rows
    for row in rows:
        assert "path-tok-zz9" not in json.dumps(row)
        reason = collector_gap_reason(collector, row["error_class"], doh_endpoint=row.get("doh_endpoint"))
        assert reason is not None and "https://[2001:db8::53]:8443 " in reason


@pytest.mark.parametrize("collector", ["dns_posture", "google_dns_posture"])
def test_r164_configured_endpoint_only_shows_its_origin_in_the_gap_reason(collector: str) -> None:
    from azure_tenant_audit.collection_gaps import collector_gap_reason

    endpoint = "https://synthetic-user-zz9:synthetic-pass-zz9@dns.corp.example/path-tok-zz9?k=query-tok-zz9"
    reason = collector_gap_reason(collector, "dns_resolver_error", doh_endpoint=endpoint)
    assert reason is not None and "https://dns.corp.example " in reason
    assert not any(part in reason for part in _SECRET_PARTS)


def test_r164_invalid_configured_ipv6_origin_is_unknown() -> None:
    from azure_tenant_audit.collection_gaps import collector_gap_reason

    reason = collector_gap_reason("dns_posture", "dns_resolver_error", doh_endpoint="https://2001:db8::53:8443")
    assert reason is not None and "endpoint unknown" in reason


class _FakeHttps:
    """Real Requests and urllib3 down to the connection: no socket is opened, and every request gets a canned answer
    (an empty NOERROR DoH answer from the resolver host, 404 from anything else)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import io

        import urllib3.connection
        import urllib3.connectionpool
        from urllib3.response import HTTPResponse

        self.targets: list[str] = []
        fake = self

        def _request(conn: Any, method: str, url: str, **_kwargs: Any) -> None:
            conn._auditex_fake = (conn.host, url)
            fake.targets.append(f"{conn.host}{url}")

        def _getresponse(conn: Any) -> HTTPResponse:
            host, _url = getattr(conn, "_auditex_fake", ("", ""))
            doh = host == "dns.corp.example"
            body = json.dumps({"Status": 0, "Answer": []}).encode() if doh else b"not found"
            return HTTPResponse(body=io.BytesIO(body), status=200 if doh else 404, version=11,
                                version_string="HTTP/1.1", preload_content=False, request_method="GET",
                                headers={"content-type": "application/dns-json" if doh else "text/plain"})

        monkeypatch.setattr(urllib3.connectionpool.HTTPSConnectionPool, "_validate_conn", lambda _self, _conn: None)
        monkeypatch.setattr(urllib3.connection.HTTPConnection, "connect", lambda _self: None)
        monkeypatch.setattr(urllib3.connection.HTTPConnection, "request", _request)
        monkeypatch.setattr(urllib3.connection.HTTPConnection, "getresponse", _getresponse)


def _assert_nothing_shows(parts: tuple[str, ...], tmp_path: Path, console: str, caplog: pytest.LogCaptureFixture) -> None:
    logged = caplog.text + "\n".join(f"{record.name} {record.getMessage()} {record.args!r}" for record in caplog.records)
    for part in parts:
        assert part not in console, part
        assert part not in logged, part
        for path in tmp_path.rglob("*"):
            if path.is_file():
                assert part.encode() not in path.read_bytes(), (part, path.name)


_SWEEP_ENDPOINTS = [
    # Refused before any read: user info, a path token and a query.
    "https://synthetic-user-zz9:synthetic-pass-zz9@dns.corp.example/path-tok-zz9?key=query-tok-zz9",
    # Refused: Requests would send it to dns.corp.example with the token in the path.
    "https://dns.corp.example\\path-tok-zz9/dns-query",
    # Accepted: the token is in the path of every DoH request.
    "https://dns.corp.example/path-tok-zz9",
]


def _echoing_resolver(endpoint: str) -> Any:
    from azure_tenant_audit.dns_lookup import DohError

    class EchoedEndpoint(DohError):
        def __str__(self) -> str:
            return f"Request to {endpoint}?key=query-tok-zz9 failed"

    class Resolver:
        def query(self, name: str, record_type: str) -> list[str]:
            raise EchoedEndpoint()

    return Resolver()


@pytest.mark.parametrize("endpoint", [*_SWEEP_ENDPOINTS, "https://[2001:db8::53]:8443/path-tok-zz9"])
def test_r164_m365_sweep_never_shows_the_resolver_secret(
    endpoint: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str],
) -> None:
    from azure_tenant_audit import cli, collectors
    from azure_tenant_audit.collectors.dns_posture import DnsPostureCollector

    transport = _FakeHttps(monkeypatch)
    args = _m365_dns_run(monkeypatch, tmp_path, "--doh-endpoint", endpoint)

    class _Client:
        def __init__(self, auth: Any, **_: Any) -> None:
            self.auth = auth

        def token_claims(self) -> dict[str, Any]:
            return {}

        def get_all(self, _path: str, params: Any = None) -> list[dict[str, Any]]:
            return [{"id": "contoso.example", "isVerified": True, "supportedServices": ["Email"]}]

    monkeypatch.setattr(cli, "GraphClient", _Client)
    monkeypatch.setattr(cli, "REGISTRY", {"dns_posture": DnsPostureCollector()})
    echo = "[2001:db8::53]" in endpoint
    if echo:
        monkeypatch.setattr(collectors.dns_posture, "DohClient", _echoing_resolver)
    caplog.set_level(logging.DEBUG)
    cli.run_live(args)

    captured = capsys.readouterr()
    if echo:
        (raw,) = tmp_path.glob("acme-*/raw/dns_posture.json")
        payload = json.loads(raw.read_text(encoding="utf-8"))
        assert payload["spf_records"]["status"] == "failed"
        assert payload["domainPosture"]["value"][0]["resolver_error"]
        gaps = json.loads((raw.parents[1] / "run-manifest.json").read_text(encoding="utf-8"))["coverage_gaps"]
        assert "resolver at https://[2001:db8::53]:8443 " in json.dumps(gaps)
    elif endpoint.endswith("/path-tok-zz9"):
        assert any("path-tok-zz9" in target for target in transport.targets)   # the requests did go out
        assert (next(tmp_path.glob("acme-*/data-handling.json"))).is_file()
    else:
        assert transport.targets == []
    _assert_nothing_shows(_SECRET_PARTS, tmp_path, captured.out + captured.err, caplog)
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "?name=" not in logged and "type=TXT" not in logged


@pytest.mark.parametrize("endpoint", [*_SWEEP_ENDPOINTS, "https://[2001:db8::53]:8443/path-tok-zz9"])
def test_r164_google_sweep_never_shows_the_resolver_secret(
    endpoint: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str],
) -> None:
    from auditex import cli as product_cli
    from auditex.google_workspace import collectors
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.collectors import GoogleDnsPostureCollector

    transport = _FakeHttps(monkeypatch)
    _fake_google_dns_run(monkeypatch)

    class _Client:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            return [{"domainName": "example.com", "verified": True, "isPrimary": True}]

    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", _Client)
    monkeypatch.setattr(google_run, "REGISTRY", {"google_dns_posture": GoogleDnsPostureCollector()})
    echo = "[2001:db8::53]" in endpoint
    if echo:
        monkeypatch.setattr(collectors, "DohClient", _echoing_resolver)
    caplog.set_level(logging.DEBUG)
    product_cli.main([
        "google", "run", "--tenant-name", "Example", "--out", str(tmp_path), "--run-name", "dns",
        "--collectors", "google_dns_posture", "--doh-endpoint", endpoint,
    ])

    captured = capsys.readouterr()
    if echo:
        raw = tmp_path / "Example-dns" / "raw" / "google_dns_posture.json"
        payload = json.loads(raw.read_text(encoding="utf-8"))
        assert payload["domainPosture"]["value"][0]["resolver_error"]
        gaps = json.loads((raw.parents[1] / "run-manifest.json").read_text(encoding="utf-8"))["coverage_gaps"]
        assert "resolver at https://[2001:db8::53]:8443 " in json.dumps(gaps)
    elif endpoint.endswith("/path-tok-zz9"):
        assert any("path-tok-zz9" in target for target in transport.targets)
        assert (tmp_path / "Example-dns" / "data-handling.json").is_file()
    else:
        assert transport.targets == []
    _assert_nothing_shows(_SECRET_PARTS, tmp_path, captured.out + captured.err, caplog)
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "?name=" not in logged and "type=TXT" not in logged
