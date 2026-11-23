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

