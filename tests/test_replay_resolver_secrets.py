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

_SECRETS = ("synthetic-user-zz9", "synthetic-pass-zz9", "path-tok-zz9", "query-tok-zz9")
_LEGACY_URL = "https://synthetic-user-zz9(x:synthetic-pass-zz9@[2001:db8::53]:8443/path-tok-zz9?key=query-tok-zz9"
_DISPLAY = "https://[2001:db8::53]:8443"
_LEGACY_ERRORS = (
    f"DoH resolver at {_LEGACY_URL} could not answer TXT contoso.example: SERVFAIL",
    f"DoH query failed for TXT contoso.example at {_LEGACY_URL} (HTTP 503)",
)
# The wording before R164: the library text names the path without a scheme.
_PRE_R164_ERROR = ("DoH query failed for TXT contoso.example: HTTPSConnectionPool(host='2001:db8::53', port=8443): "
                   "Max retries exceeded with url: /path-tok-zz9?key=query-tok-zz9&name=contoso.example")


def _dns_payload(domain_key: str) -> dict[str, Any]:
    return {
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
                       "error": _LEGACY_ERRORS[1]},
    }


def _assert_clean(tmp_path: Path, console: str, caplog: pytest.LogCaptureFixture) -> str:
    logged = "\n".join(f"{record.name} {record.getMessage()} {record.args!r}" for record in caplog.records)
    written = ""
    for path in sorted(tmp_path.rglob("*")):
        if path.is_file() and path.name != "sample.json":
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


def test_m365_replay_of_a_legacy_resolver_url_shows_only_its_host(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"dns_posture": _dns_payload("id")}), encoding="utf-8")
    out = tmp_path / "out"
    caplog.set_level(logging.DEBUG)
    run_offline(sample, out, "contoso", "replay", auditor_profile="global-reader", plane="inventory")
    captured = capsys.readouterr()

    written = _assert_clean(out, captured.out + captured.err, caplog)
    (manifest_path,) = out.glob("*/run-manifest.json")
    gaps = _gap_text(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert f"resolver at {_DISPLAY} " in gaps
    assert _DISPLAY in written


def test_google_replay_of_a_legacy_resolver_url_shows_only_its_host(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    from auditex.google_workspace.run import run_google_offline

    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"google_dns_posture": _dns_payload("domainName")}), encoding="utf-8")
    out = tmp_path / "out"
    caplog.set_level(logging.DEBUG)
    run_google_offline(sample_path=sample, out=out, tenant_name="Example", run_name="replay",
                       domain="contoso.example", customer_id=None)
    captured = capsys.readouterr()

    written = _assert_clean(out, captured.out + captured.err, caplog)
    (manifest_path,) = out.glob("*/run-manifest.json")
    gaps = _gap_text(json.loads(manifest_path.read_text(encoding="utf-8")))
    assert f"resolver at {_DISPLAY} " in gaps
    assert _DISPLAY in written


@pytest.mark.parametrize(("text", "named"), [
    (_LEGACY_ERRORS[0], _DISPLAY),
    (_LEGACY_ERRORS[1], _DISPLAY),
    (f"DoH resolver at {_LEGACY_URL}) could not answer", _DISPLAY),
    # User info with a space: the host cannot be told apart from the user name, so none is named.
    ("DoH resolver at https://synthetic user-zz9:pw@dns.corp.example/x could not answer", None),
    (_PRE_R164_ERROR, None),
    ("DoH resolver at https://2001:db8::53:8443 could not answer TXT x: SERVFAIL", None),
    # Two different resolvers: neither is named.
    ("at https://a.example/x and https://b.example/y", None),
])
def test_resolver_named_in_untrusted_text(text: str, named: str | None) -> None:
    from azure_tenant_audit.dns_lookup import resolver_named_in

    assert resolver_named_in(text) == named


@pytest.mark.parametrize("text", [*_LEGACY_ERRORS, _PRE_R164_ERROR,
                                  "DoH resolver at https://synthetic user-zz9:pw@dns.corp.example/x could not answer"])
def test_safe_resolver_diagnostic_drops_every_secret_and_is_stable(text: str) -> None:
    from azure_tenant_audit.dns_lookup import safe_resolver_diagnostic

    safe = safe_resolver_diagnostic(text)
    assert not any(part in safe for part in (*_SECRETS, "user-zz9"))
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
