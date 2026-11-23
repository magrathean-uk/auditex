"""Bot review findings on the DNS, MTA-STS and Defender fixes (PR #150), verified against the code.

Each section names the finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import threading
import time
import zlib

import pytest

from azure_tenant_audit import dns_lookup, exposure_lookup
from azure_tenant_audit.value_rules import assess

MTA_STS_URL = "https://mta-sts.contoso.example/.well-known/mta-sts.txt"


class _TxtResolver:
    def __init__(self, answers):
        self.answers = answers

    def query(self, name, record_type):
        return list(self.answers.get(name, []))


# ---- An inherited DMARC record needs a valid p= before its sp= counts (RFC 7489 6.6.3) ----

@pytest.mark.parametrize("parent,cell", [
    ("v=DMARC1; sp=reject", "domain_noncompliant.p_absent"),
    ("v=DMARC1; p=bogus; sp=reject", "domain_noncompliant.p_invalid"),
    ("v=DMARC1; p=none; p=reject; sp=reject", "domain_unusable.tag_duplicated"),
])
def test_inherited_dmarc_record_without_a_valid_p_is_not_reject(parent, cell):
    entry = dns_lookup.scuba_dmarc_record("mail.contoso.example", _TxtResolver({"_dmarc.contoso.example": [parent]}))
    assert entry["rdata"] == [parent]
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [entry]})
    assert record["verdict"] != "met"
    assert record["cell"] == cell


def test_inherited_dmarc_record_with_p_none_and_sp_reject_still_passes():
    parent = "v=DMARC1; p=none; sp=reject"
    entry = dns_lookup.scuba_dmarc_record("mail.contoso.example", _TxtResolver({"_dmarc.contoso.example": [parent]}))
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [entry]})
    assert (record["verdict"], record["cell"]) == ("met", "all_compliant")


# ---- The posture DMARC parser accepts spaces around v = DMARC1 (RFC 7489 6.4 allows whitespace) ----

def test_spaced_dmarc_version_tag_is_a_record():
    summary = dns_lookup._summarize_dmarc(["v = DMARC1; p=reject"])
    assert summary["present"] is True and summary["policy"] == "reject"


def test_two_spaced_dmarc_records_are_multiple_records():
    summary = dns_lookup._summarize_dmarc(["v = DMARC1; p=reject", "v =DMARC1; p=none"])
    assert summary["present"] is False
    assert summary["multiple_records"] is True and summary["record_count"] == 2


def test_text_without_a_dmarc_version_tag_is_still_not_a_record():
    assert dns_lookup.parse_dmarc("v=spf1 -all") is None
    assert dns_lookup.parse_dmarc("note=v=dmarc1x") is None


# ---- MTA-STS: every mx value must be a host pattern; max_age is 1-10 ASCII digits (RFC 8461 3.2) ----

class _BodyFetcher:
    def __init__(self, body):
        self.body = body

    def get_text(self, url):
        return 200, self.body, None


def _policy(mode="enforce", mx=("mail.contoso.example",), max_age="86400"):
    lines = ["version: STSv1", f"mode: {mode}", *(f"mx: {m}" for m in mx), f"max_age: {max_age}"]
    return exposure_lookup.fetch_mta_sts_policy("contoso.example", _BodyFetcher("\n".join(lines) + "\n"))


@pytest.mark.parametrize("mode", ["enforce", "testing"])
def test_mta_sts_mx_value_that_is_not_a_host_is_invalid(mode):
    policy = _policy(mode=mode, mx=("mail.contoso.example", "not a host!"))
    assert policy["fetch_status"] == "invalid_policy"
    assert policy["invalid_reasons"] == ["mx_invalid"]


def test_mta_sts_wildcard_mx_and_plain_hosts_stay_valid():
    policy = _policy(mx=("*.mail.protection.outlook.example", "mx1.contoso.example"))
    assert policy["fetch_status"] == "ok" and "invalid_reasons" not in policy


def test_mta_sts_mode_none_does_not_judge_mx_values():
    assert _policy(mode="none", mx=("not a host!",))["fetch_status"] == "ok"


@pytest.mark.parametrize("raw", ["+86400", "86_400", "٨٦٤٠٠", "12345678901", "-0"])
def test_mta_sts_max_age_must_be_ascii_digits(raw):
    assert exposure_lookup.parse_mta_sts_policy(f"version: STSv1\nmode: enforce\nmx: a.example\nmax_age: {raw}\n")[
        "max_age"] is None
    policy = _policy(max_age=raw)
    assert policy["fetch_status"] == "invalid_policy" and "max_age_invalid" in policy["invalid_reasons"]


def test_mta_sts_max_age_of_plain_digits_is_read():
    assert exposure_lookup.parse_mta_sts_policy("version: STSv1\nmode: none\nmax_age: 0604800\n")["max_age"] == 604800


# ---- Deflate bodies: a zlib stream with a small window is still zlib-wrapped ----

BODY = b"version: STSv1\nmode: enforce\nmx: mail.contoso.example\nmax_age: 604800\n"


@pytest.mark.parametrize("wbits", [9, 10, 12, 15])
def test_zlib_wrapped_deflate_body_with_any_window_decodes(wbits):
    compressor = zlib.compressobj(wbits=wbits)
    raw = compressor.compress(BODY) + compressor.flush()
    assert exposure_lookup._decode_body(raw, "deflate") == BODY


def test_raw_deflate_body_still_decodes():
    compressor = zlib.compressobj(wbits=-15)
    raw = compressor.compress(BODY) + compressor.flush()
    assert exposure_lookup._decode_body(raw, "deflate") == BODY

