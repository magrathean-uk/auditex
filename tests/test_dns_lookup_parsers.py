"""Table-driven RFC-grade tests for DNS / email-auth parsers.

Hardens parsers in ``azure_tenant_audit.dns_lookup`` against:

* SPF — qualifier coverage, multiple-record detection, includes/redirect.
* DMARC — ``sp=`` subdomain policy, ``pct<100`` partial enforcement, ``rua=``/``ruf=``
  URI list parsing with RFC 5322-ish mailbox validation, default ``pct=100``.
* MTA-STS — DNS record id presence (the ``mode=`` knob lives in the HTTPS policy
  file, not the DNS record; out of scope here, see TODO below).
* BIMI — ``l=`` HTTPS requirement, optional ``a=`` VMC presence.

The DoH client and the live collector continue to be exercised in
``test_dns_posture_collector.py``; this file is parser-only fuzzing.
"""
from __future__ import annotations

import pytest

from azure_tenant_audit.dns_lookup import (
    _summarize_bimi,
    _summarize_dmarc,
    _summarize_spf,
    parse_bimi,
    parse_dmarc,
    parse_mta_sts,
    parse_spf,
)

# ---------- SPF ----------


@pytest.mark.parametrize(
    "record,expected_qualifier",
    [
        ("v=spf1 -all", "-"),
        ("v=spf1 ~all", "~"),
        ("v=spf1 +all", "+"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 all", "+"),  # bare ``all`` defaults to +all per RFC 7208 §4.6.2
        ("v=spf1 include:spf.protection.outlook.com -all", "-"),
        ("v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all", "~"),
        ("v=spf1 redirect=spf.example.com", None),  # redirect, no all
        ("v=spf1 mx a:host.example.com -all", "-"),
    ],
)
def test_parse_spf_extracts_qualifier(record: str, expected_qualifier: str | None) -> None:
    parsed = parse_spf(record)
    assert parsed is not None
    assert parsed["all_qualifier"] == expected_qualifier


@pytest.mark.parametrize(
    "record",
    [
        "google-site-verification=abc",
        "MS=ms123456",
        "",
        "v=DMARC1; p=none",
        "v=DKIM1; k=rsa; p=AAAA",
    ],
)
def test_parse_spf_returns_none_for_non_spf(record: str) -> None:
    assert parse_spf(record) is None


def test_parse_spf_preserves_include_and_redirect_mechanisms() -> None:
    parsed = parse_spf(
        "v=spf1 include:spf.protection.outlook.com include:_spf.google.com redirect=spf.example.com -all"
    )
    assert parsed is not None
    mechanisms = parsed["mechanisms"]
    assert "include:spf.protection.outlook.com" in mechanisms
    assert "include:_spf.google.com" in mechanisms
    assert "redirect=spf.example.com" in mechanisms
    assert "-all" in mechanisms


def test_parse_spf_treats_version_token_case_insensitively() -> None:
    parsed = parse_spf("V=SPF1 -ALL")
    assert parsed is not None
    assert parsed["all_qualifier"] == "-"


# ---------- DMARC ----------


def test_parse_dmarc_extracts_subdomain_policy() -> None:
    record = parse_dmarc("v=DMARC1; p=reject; sp=quarantine")
    assert record is not None
    assert record["policy"] == "reject"
    assert record["subdomain_policy"] == "quarantine"


def test_parse_dmarc_default_pct_is_100() -> None:
    """RFC 7489 §6.3 — when ``pct`` is omitted the default is 100 (full enforcement)."""
    record = parse_dmarc("v=DMARC1; p=quarantine")
    assert record is not None
    assert record["pct"] == 100


@pytest.mark.parametrize(
    "record,expected_pct",
    [
        ("v=DMARC1; p=quarantine; pct=100", 100),
        ("v=DMARC1; p=quarantine; pct=50", 50),
        ("v=DMARC1; p=reject; pct=10", 10),
        ("v=DMARC1; p=reject; pct=0", 0),
        ("v=DMARC1; p=none; pct=25", 25),
    ],
)
def test_parse_dmarc_pct_value(record: str, expected_pct: int) -> None:
    parsed = parse_dmarc(record)
    assert parsed is not None
    assert parsed["pct"] == expected_pct


def test_parse_dmarc_invalid_pct_yields_none() -> None:
    parsed = parse_dmarc("v=DMARC1; p=reject; pct=not-an-int")
    assert parsed is not None
    assert parsed["pct"] is None


def test_parse_dmarc_rua_multiple_addresses() -> None:
    parsed = parse_dmarc(
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:reports@partner.example,https://rua.example/dmarc"
    )
    assert parsed is not None
    assert parsed["aggregate_addresses"] == [
        "mailto:dmarc@example.com",
        "mailto:reports@partner.example",
        "https://rua.example/dmarc",
    ]


def test_parse_dmarc_ruf_addresses() -> None:
    parsed = parse_dmarc("v=DMARC1; p=reject; ruf=mailto:forensic@example.com")
    assert parsed is not None
    assert parsed["forensic_addresses"] == ["mailto:forensic@example.com"]


@pytest.mark.parametrize(
    "rua,expected_invalid",
    [
        # Valid mailto + https → no invalid entries.
        ("mailto:dmarc@example.com,https://example.com/rua", []),
        # Missing mailto: scheme → invalid.
        ("dmarc@example.com", ["dmarc@example.com"]),
        # mailto: without @ → invalid.
        ("mailto:nope", ["mailto:nope"]),
        # http (not https) URL → invalid for DMARC reporting URIs.
        ("http://reports.example/rua", ["http://reports.example/rua"]),
        # Empty list → no invalid entries.
        ("", []),
    ],
)
def test_parse_dmarc_flags_invalid_rua(rua: str, expected_invalid: list[str]) -> None:
    record = f"v=DMARC1; p=reject; rua={rua}" if rua else "v=DMARC1; p=reject"
    parsed = parse_dmarc(record)
    assert parsed is not None
    assert parsed.get("aggregate_addresses_invalid") == expected_invalid


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 -all",
        "google-site-verification=abc",
        "",
    ],
)
def test_parse_dmarc_returns_none_for_non_dmarc(record: str) -> None:
    assert parse_dmarc(record) is None


# ---------- MTA-STS ----------


def test_parse_mta_sts_extracts_id() -> None:
    parsed = parse_mta_sts("v=STSv1; id=20231201T000000")
    assert parsed is not None
    assert parsed["id"] == "20231201T000000"


def test_parse_mta_sts_id_missing_returns_record_without_id() -> None:
    """The DNS record is allowed to advertise STS without an id; policy fetch happens out-of-band."""
    parsed = parse_mta_sts("v=STSv1")
    assert parsed is not None
    assert parsed["id"] is None


@pytest.mark.parametrize("record", ["v=spf1 -all", "v=DMARC1; p=none", ""])
def test_parse_mta_sts_returns_none_for_non_sts(record: str) -> None:
    assert parse_mta_sts(record) is None


# NOTE: ``mode=testing`` vs ``mode=enforce`` lives in the HTTPS policy file at
# https://mta-sts.<domain>/.well-known/mta-sts.txt, not in the DNS TXT record.
# Fetching and parsing the policy file is a separate enhancement (queued, not A1).


# ---------- BIMI ----------


def test_parse_bimi_extracts_l_and_a() -> None:
    parsed = parse_bimi("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
    assert parsed is not None
    assert parsed["logo_url"] == "https://example.com/logo.svg"
    assert parsed["authority_url"] == "https://example.com/vmc.pem"
    assert parsed["logo_url_is_https"] is True
    assert parsed["authority_url_is_https"] is True


def test_parse_bimi_flags_non_https_logo() -> None:
    parsed = parse_bimi("v=BIMI1; l=http://example.com/logo.svg")
    assert parsed is not None
    assert parsed["logo_url_is_https"] is False


def test_parse_bimi_authority_optional() -> None:
    """RFC draft permits BIMI without VMC (a=) — common for self-asserted brands."""
    parsed = parse_bimi("v=BIMI1; l=https://example.com/logo.svg")
    assert parsed is not None
    assert parsed["authority_url"] is None
    assert parsed["authority_url_is_https"] is None


def test_parse_bimi_empty_logo_means_opt_out() -> None:
    """``l=`` with empty value is the documented BIMI opt-out signal."""
    parsed = parse_bimi("v=BIMI1; l=")
    assert parsed is not None
    assert parsed["logo_url"] == ""
    assert parsed["logo_url_is_https"] is False


# ---------- Collection-level summarisers ----------


def test_summarize_spf_detects_multiple_records() -> None:
    summary = _summarize_spf(
        ["v=spf1 include:spf.protection.outlook.com -all", "v=spf1 ip4:198.51.100.0/24 ~all"]
    )
    assert summary["present"] is True
    assert summary["multiple_records"] is True


def test_summarize_spf_single_record_is_not_multiple() -> None:
    summary = _summarize_spf(["v=spf1 -all", "google-site-verification=abc"])
    assert summary["present"] is True
    assert summary["multiple_records"] is False


def test_summarize_spf_absent_when_no_record_parses() -> None:
    summary = _summarize_spf(["google-site-verification=abc", "ms=ms123"])
    assert summary["present"] is False


@pytest.mark.parametrize(
    "record,expected_partial",
    [
        ("v=DMARC1; p=reject", False),
        ("v=DMARC1; p=reject; pct=100", False),
        ("v=DMARC1; p=quarantine; pct=50", True),
        ("v=DMARC1; p=reject; pct=0", True),
        ("v=DMARC1; p=none; pct=100", False),
    ],
)
def test_summarize_dmarc_pct_partial_flag(record: str, expected_partial: bool) -> None:
    summary = _summarize_dmarc([record])
    assert summary["pct_partial"] is expected_partial


def test_summarize_dmarc_forwards_invalid_uris() -> None:
    summary = _summarize_dmarc(["v=DMARC1; p=reject; rua=dmarc@example.com,mailto:ok@example.com"])
    assert summary["aggregate_addresses_invalid"] == ["dmarc@example.com"]


def test_summarize_bimi_forwards_https_flags() -> None:
    summary = _summarize_bimi(["v=BIMI1; l=http://example.com/logo.svg"])
    assert summary["logo_url_is_https"] is False
    assert summary["authority_url_is_https"] is None
