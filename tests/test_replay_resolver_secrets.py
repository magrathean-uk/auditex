"""Resolver URLs read from an older bundle are untrusted on the offline replay path (follow-up to #179, R164).

A legacy sample's DNS posture records and sections may name the resolver by its full URL: user info (here with a
literal parenthesis), a path token and a query. Replaying it for Microsoft 365 or Google Workspace must show the
resolver by its safe display form only, in every written file, the console and the logs (DEBUG included).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

_SECRETS = ("synthetic-user-zz9", "synthetic-pass-zz9", "path-tok-zz9", "query-tok-zz9", "fragment-tok-zz9",
            "percent-user%40zz9", "percent-pass%28zz9", "percent-path%2Fzz9", "percent-query%2Bzz9")
_LEGACY_URL = ("https://synthetic-user-zz9(x:synthetic-pass-zz9@[2001:db8::53]:8443/"
               "path-tok-zz9?key=query-tok-zz9#fragment-tok-zz9")
_DISPLAY = "https://[2001:db8::53]:8443"
_CONFIGURED_DISPLAY = "https://[2001:db8::54]:8443"
_LEGACY_ERRORS = (
    f"DoH resolver at {_LEGACY_URL} could not answer TXT contoso.example: SERVFAIL",
    f"DoH query failed for TXT contoso.example at {_LEGACY_URL} (HTTP 503)",
)
# The wording before R164: the library text names the path without a scheme.
_PRE_R164_ERROR = ("DoH query failed for TXT contoso.example: HTTPSConnectionPool(host='2001:db8::53', port=8443): "
                   "Max retries exceeded with url: /path-tok-zz9?key=query-tok-zz9&name=contoso.example")
_NESTED_TARGET = _PRE_R164_ERROR.replace("/path-tok-zz9", "/https://fake-host-zz9.example/path-tok-zz9")
_FUZZ_DIAGNOSTICS = (
    (_LEGACY_ERRORS[0], f"DoH resolver at {_DISPLAY} could not answer TXT contoso.example: SERVFAIL"),
    ("request to https://synthetic-user-zz9(@x):synthetic-pass-zz9@dns.example/path-tok-zz9 failed",
     "request to https://dns.example failed"),
    ("request to https://percent-user%40zz9:percent-pass%28zz9@dns.example/percent-path%2Fzz9"
     "?k=percent-query%2Bzz9#fragment-tok-zz9 failed", "request to https://dns.example failed"),
    ("from https://dns.example/https://fake-host-zz9.example/path-tok-zz9 to http://[::1]:8080/query-tok-zz9",
     "from https://dns.example to http://[::1]:8080"),
    ("failed at (https://[2001:db8::53]:8443), retrying at https://retry.example.",
     "failed at (https://[2001:db8::53]:8443), retrying at https://retry.example."),
    ('failed at "https://u:p@dns.example/path-tok-zz9"', 'failed at "https://dns.example"'),
)


def _dns_payload(domain_key: str, scenario: str) -> dict[str, Any]:
    if scenario == "nested_target":
        return {"domainPosture": {"value": [{"domain": "contoso.example", "resolver_error": _NESTED_TARGET}]}}
    if scenario == "unclassified":
        return {"spfRecords": {"value": [], "status": "failed", "error": _LEGACY_ERRORS[1],
                               "message": _LEGACY_ERRORS[0], "reason": _LEGACY_URL, "diagnostic": _LEGACY_URL}}
    return {
        "doh_endpoint": _LEGACY_URL.replace("db8::53", "db8::54"),
        "domains": {"value": [{domain_key: "contoso.example", "isVerified": True, "verified": True}]},
        "domainPosture": {"value": [
            {"domain": "contoso.example", "resolver_error": _LEGACY_ERRORS[0],
             "spf": {"present": None}, "dmarc": {"present": None}},
            {"domain": "fabrikam.example", "resolver_error": _LEGACY_ERRORS[1],
             "spf": {"present": None}, "dmarc": {"present": None}},
            {"domain": "tailspin.example", "resolver_error": _PRE_R164_ERROR,
             "spf": {"present": None}, "dmarc": {"present": None}},
        ]},
        "spfRecords": {"value": [], "status": "failed", "error_class": "dns_resolver_error",
                       "error": _LEGACY_ERRORS[1], "diagnostics": [text for text, _ in _FUZZ_DIAGNOSTICS]},
    }


def _assert_clean(tmp_path: Path, console: str, caplog: pytest.LogCaptureFixture) -> str:
    logged = caplog.text + "\n".join(f"{record.name} {record.getMessage()} {record.args!r}" for record in caplog.records)
    written = ""
    for path in sorted(tmp_path.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            for part in _SECRETS:
                assert part.encode() not in data, (part, path.relative_to(tmp_path).as_posix())
            written += data.decode("utf-8", "replace")
    for part in _SECRETS:
        assert part not in console, part
        assert part not in logged, part
    return written


def _gap_text(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest.get("coverage_gaps"))


@pytest.mark.parametrize(("collector", "domain_key"), [("dns_posture", "id"), ("google_dns_posture", "domainName")])
@pytest.mark.parametrize("scenario", ["configured", "nested_target", "unclassified"])
def test_replay_sweeps_legacy_dns_diagnostics(
    collector: str, domain_key: str, scenario: str, tmp_path: Path,
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str],
) -> None:
    from auditex.google_workspace.run import run_google_offline
    from azure_tenant_audit.cli import run_offline

    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({collector: _dns_payload(domain_key, scenario)}), encoding="utf-8")
    out = tmp_path / "out"
    caplog.set_level(logging.DEBUG)
    if collector == "dns_posture":
        run_offline(sample, out, "contoso", "replay", auditor_profile="global-reader", plane="inventory")
    else:
        run_google_offline(sample_path=sample, out=out, tenant_name="Example", run_name="replay",
                           domain="contoso.example", customer_id=None)
    captured = capsys.readouterr()

    (manifest_path,) = out.glob("*/run-manifest.json")
    gaps = _gap_text(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert "fake-host-zz9" not in gaps
    written = _assert_clean(out, captured.out + captured.err, caplog)
    assert "fake-host-zz9" not in written
    assert f"resolver at {_DISPLAY} " not in gaps
    if scenario == "configured":
        assert f"resolver at {_CONFIGURED_DISPLAY} " in gaps
    if scenario == "nested_target":
        assert "endpoint unknown" in gaps
    if scenario == "unclassified":
        coverage = json.loads((manifest_path.parent / "coverage.json").read_text(encoding="utf-8"))
        (row,) = [row for row in coverage if row["name"] == "spfRecords"]
        assert row["status"] == "failed" and row["error_class"] == "unknown"
        assert _DISPLAY in row["error"]
    if scenario != "nested_target":
        assert _DISPLAY in written


@pytest.mark.parametrize(("text", "expected"), _FUZZ_DIAGNOSTICS,
                         ids=("ipv6", "userinfo", "percent-encoding", "two-urls", "punctuation", "quotes"))
def test_dns_diagnostic_scrubs_each_url(text: str, expected: str) -> None:
    from azure_tenant_audit.dns_lookup import safe_resolver_diagnostic

    assert safe_resolver_diagnostic(text) == expected
    assert safe_resolver_diagnostic(expected) == expected


@pytest.mark.parametrize("text", [*_LEGACY_ERRORS, _PRE_R164_ERROR,
                                  "DoH resolver at https://synthetic user-zz9:pw@dns.corp.example/x could not answer"])
def test_safe_resolver_diagnostic_drops_every_secret_and_is_stable(text: str) -> None:
    from azure_tenant_audit.dns_lookup import safe_resolver_diagnostic

    safe = safe_resolver_diagnostic(text)
    assert not any(part in safe for part in (*_SECRETS, "user-zz9"))
    assert safe_resolver_diagnostic(safe) == safe


@pytest.mark.parametrize("text", [
    "HTTP 503.https://dns.corp.example/sec-path?key=sec-query",
    "status 7https://dns.corp.example/sec-path?key=sec-query",
    "x+https://dns.corp.example/sec-path?key=sec-query",
    "retry-https://dns.corp.example/sec-path?key=sec-query",
])
def test_url_glued_to_preceding_text_is_scrubbed(text: str) -> None:
    from azure_tenant_audit.dns_lookup import safe_resolver_diagnostic

    safe = safe_resolver_diagnostic(text)
    assert "sec-path" not in safe and "sec-query" not in safe
    assert "dns.corp.example" in safe
    assert safe_resolver_diagnostic(safe) == safe


@pytest.mark.parametrize("text", [
    "DoH query failed for TXT contoso.example at https://[2001:db8::53]:8443 (HTTP 503)",
    "DoH resolver at https://dns.corp.example could not answer TXT selector1._domainkey.contoso.example: SERVFAIL",
    "DoH response from https://cloudflare-dns.com was truncated (TC) for TXT contoso.example",
    "DoH query failed for TXT contoso.example at the DNS-over-HTTPS resolver (request failed: ConnectionError)",
    "SERVFAIL",
])
def test_safe_resolver_diagnostic_keeps_auditex_wording(text: str) -> None:
    from azure_tenant_audit.dns_lookup import safe_resolver_diagnostic

    assert safe_resolver_diagnostic(text) == text
