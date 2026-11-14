"""D5: a DMARC lookup whose every tree-walk step is an authoritative NXDomain reads no record; other empties stay unusable."""
from __future__ import annotations

import pytest

from azure_tenant_audit import dns_lookup as dns
from azure_tenant_audit.value_rules import assess

POLICIES = ("MS.EXO.4.1v1", "MS.EXO.4.2v1", "MS.EXO.4.3v1", "MS.EXO.4.4v1")


class Resolver:
    def __init__(self, answers):
        self.answers = answers

    def query(self, name, record_type):
        return self.query_detailed(name, record_type).records

    def query_detailed(self, name, record_type):
        value = self.answers.get(name, dns.DnsAnswer([], "nxdomain"))
        if isinstance(value, Exception):
            raise value
        return value


def entry(domain, resolver):
    return dns.scuba_dmarc_record(domain, resolver)


def verdict(policy, row):
    record = assess(policy, {"dmarc_records": [row]})
    return record["verdict"], record["cell"]


def test_every_step_is_recorded_with_its_outcome():
    row = entry("a.b.example", Resolver({}))
    assert [(s["query_name"], s["outcome"]) for s in row["log"]] == [
        ("_dmarc.a.b.example", "nxdomain"), ("_dmarc.b.example", "nxdomain"), ("_dmarc.example", "nxdomain")]
    assert row["rdata"] == []


@pytest.mark.parametrize("policy", POLICIES)
def test_all_nxdomain_steps_read_no_record(policy):
    assert verdict(policy, entry("a.b.example", Resolver({}))) == ("not_met", "domain_noncompliant.no_record")


@pytest.mark.parametrize("policy", POLICIES)
def test_a_noerror_empty_step_stays_unusable(policy):
    resolver = Resolver({"_dmarc.b.example": dns.DnsAnswer([], "empty")})
    row = entry("a.b.example", resolver)
    assert [s["outcome"] for s in row["log"]] == ["nxdomain", "empty", "nxdomain"]
    assert verdict(policy, row) == ("not_assessed", "domain_unusable.rdata_empty")


@pytest.mark.parametrize("policy", POLICIES)
def test_an_entry_without_step_outcomes_reads_as_before(policy):
    row = {"domain": "a.example", "rdata": [], "log": [{"query_name": "_dmarc.a.example", "query_result": "Query returned NXDomain"}]}
    assert verdict(policy, row) == ("not_assessed", "domain_unusable.rdata_empty")
    assert verdict(policy, {"domain": "a.example", "rdata": []}) == ("not_assessed", "domain_unusable.rdata_empty")


@pytest.mark.parametrize("log", [[], None, "x", [{"outcome": "nxdomain"}, "x"], [{"outcome": "failed"}]])
def test_a_malformed_or_failed_step_log_stays_unusable(log):
    row = {"domain": "a.example", "rdata": [], "log": log}
    assert verdict("MS.EXO.4.1v1", row) == ("not_assessed", "domain_unusable.rdata_empty")


def test_a_failed_or_timed_out_step_never_becomes_an_entry():
    resolver = Resolver({"_dmarc.b.example": dns.DohError("DoH resolver could not answer TXT _dmarc.b.example: SERVFAIL")})
    with pytest.raises(dns.DohError):
        entry("a.b.example", resolver)


def test_a_published_record_still_wins_over_the_walk():
    row = entry("a.example", Resolver({"_dmarc.a.example": dns.DnsAnswer(["v=DMARC1; p=reject"], "answers")}))
    assert verdict("MS.EXO.4.2v1", row) == ("met", "all_compliant")


def test_nxdomain_beside_a_good_domain_is_not_met():
    good = {"domain": "b.example", "rdata": ["v=DMARC1; p=reject"]}
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [good, entry("a.example", Resolver({}))]})
    assert (record["verdict"], record["cell"]) == ("not_met", "domain_noncompliant.no_record")


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _Session:
    def __init__(self, payload):
        self.payload = payload

    def get(self, *args, **kwargs):
        return _Response(self.payload)


@pytest.mark.parametrize("policy", POLICIES)
def test_servfail_with_an_answer_never_reaches_assessment(policy):
    payload = {"Status": 2, "Answer": [{"type": 16, "data": '"v=DMARC1; p=reject"'}]}
    client = dns.DohClient(session=_Session(payload))
    with pytest.raises(dns.DohError, match="SERVFAIL"):
        entry("example.com", client)
