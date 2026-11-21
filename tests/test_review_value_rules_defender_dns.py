"""Deep-review fixes for the Defender and DNS value rules and their evidence (lane value-rules-defender-dns).

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex.scuba_projection import project_run
from azure_tenant_audit import dns_lookup, exposure_lookup
from azure_tenant_audit.collectors.exchange_defender_commands import DEFENDER_COMMANDS
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.value_rules import assess

ACCEPTED = [{"DomainName": "contoso.example"}]
EVERYONE = {key: None for key in (
    "SentTo", "SentToMemberOf", "RecipientDomainIs", "ExceptIfSentTo", "ExceptIfSentToMemberOf",
    "ExceptIfRecipientDomainIs")}


def _write_run(root: Path, operations: dict[str, list[dict]]) -> Path:
    (root / "raw").mkdir(parents=True, exist_ok=True)
    (root / "run-manifest.json").write_text(json.dumps({"run_id": "synthetic-review", "platform": "m365"}) + "\n")
    payload = {name: {"value": rows, "status": "ok"} for name, rows in operations.items()}
    (root / "raw/exchange_policy.json").write_text(json.dumps(payload) + "\n")
    return root


# ---- R002: the EOP preset rule's policy links reach the spam cascade ----

def test_r002_eop_preset_rule_read_selects_policy_links():
    command = dict(DEFENDER_COMMANDS)["eopProtectionPolicyRules"]
    fields = command.split("Select-Object ", 1)[1].rstrip(")").split(",")
    for link in ("HostedContentFilterPolicy", "AntiPhishPolicy", "MalwareFilterPolicy"):
        assert link in fields


def _spam_policy(identity, kind, default=False, action="Quarantine"):
    return {"Identity": identity, "IsDefault": default, "RecommendedPolicyType": kind, "SpamAction": action,
            "HighConfidenceSpamAction": action, "PhishSpamAction": action, "HighConfidencePhishAction": "Quarantine",
            "AllowedSenderDomains": []}


def test_r002_collector_shaped_standard_preset_answers_spam_rows(tmp_path):
    preset = "Standard Preset Security Policy1700000000000"
    run = _write_run(tmp_path, {
        "eopProtectionPolicyRules": [{"Identity": preset, "State": "Enabled", "HostedContentFilterPolicy": preset,
                                      "AntiPhishPolicy": preset, "MalwareFilterPolicy": preset, **EVERYONE}],
        "hostedContentFilterPolicies": [_spam_policy("Default", "Custom", default=True, action="MoveToJmf"),
                                        _spam_policy(preset, "Standard")],
        "hostedContentFilterRules": [],
    })
    sections = dict(project_run(run, redact=False).rule_sections)
    assert sections["protection_policy_rules"][0]["HostedContentFilterPolicy"] == preset
    sections["accepted_domains"] = ACCEPTED
    for policy in ("MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"):
        record = assess(policy, sections)
        assert (record["verdict"], record["cell"]) == ("met", "standard_covers_compliant"), policy


# ---- R102: SPF compliance reads the terminal all mechanism's qualifier, not substrings ----

class _TxtResolver:
    def __init__(self, answers):
        self.answers = answers

    def query(self, name, record_type):
        return list(self.answers.get(name, []))


@pytest.mark.parametrize("record,compliant", [
    ("v=spf1 include:spf.star-alliance.example ?all", False),
    ("v=spf1 +all redirect=_spf.contoso.example", False),       # RFC 7208 6.1: redirect is ignored beside all
    ("v=spf1 include:redirector.example.net +all", False),
    ("v=spf1 include:_spf-all.example ?all", False),
    ("v=spf1 ip4:192.0.2.0/24 -all", True),
    ("v=spf1 ip4:192.0.2.0/24 ~all", True),
    ("v=spf1 -ALL", True),                                       # mechanism names are case-insensitive
    ("v=spf1 REDIRECT=_spf.contoso.example", True),
    ("v=spf1 redirect=_spf.contoso.example", True),
    ("v=spf1 -all +all", True),                                  # evaluation stops at the first all
    ("v=spf1 all", False),
    ("v=spf1 include:spf.contoso.example", False),
])
def test_r102_spf_compliance_tokenises_the_record(record, compliant):
    entry = dns_lookup.scuba_spf_record("contoso.example", _TxtResolver({"contoso.example": [record]}))
    assert entry["compliant"] is compliant
    record = assess("MS.EXO.2.2v3", {"spf_records": [entry]})
    assert record["verdict"] == ("met" if compliant else "not_met")


# ---- R029: an accepted subdomain that inherits its parent's DMARC record is judged on sp= ----

@pytest.mark.parametrize("parent,verdict,cell", [
    ("v=DMARC1; p=reject; sp=none; rua=mailto:d@contoso.example", "not_met", "domain_noncompliant.p_not_reject"),
    ("v=DMARC1; p=reject; sp=quarantine", "not_met", "domain_noncompliant.p_not_reject"),
    ("v=DMARC1; p=reject; sp=bogus", "not_met", "domain_noncompliant.p_not_reject"),   # RFC 7489 6.6.3: invalid sp acts as none
    ("v=DMARC1; p=reject; sp=none; sp=reject", "not_assessed", "domain_unusable.tag_duplicated"),
    ("v=DMARC1; p=none; sp=reject", "met", "all_compliant"),
    ("v=DMARC1; p=reject", "met", "all_compliant"),                                     # no sp: p applies to subdomains
    ("v=DMARC1; p=reject; sp=reject", "met", "all_compliant"),
])
def test_r029_inherited_dmarc_record_reads_sp(parent, verdict, cell):
    entry = dns_lookup.scuba_dmarc_record("mail.contoso.example", _TxtResolver({"_dmarc.contoso.example": [parent]}))
    assert entry["rdata"] == [parent]
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [entry]})
    assert (record["verdict"], record["cell"]) == (verdict, cell)


def test_r029_author_record_still_reads_p_only():
    own = "v=DMARC1; p=reject; sp=none"
    entry = dns_lookup.scuba_dmarc_record("contoso.example", _TxtResolver({"_dmarc.contoso.example": [own]}))
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [entry]})
    assert (record["verdict"], record["cell"]) == ("met", "all_compliant")


def test_r029_entry_without_a_log_keeps_the_scubagear_reading():
    entry = {"domain": "mail.contoso.example", "rdata": ["v=DMARC1; p=reject; sp=none"]}
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [entry]})
    assert (record["verdict"], record["cell"]) == ("met", "all_compliant")


# ---- R109: several DMARC records mean no DMARC policy applies (RFC 7489 6.6.3) ----

def test_r109_several_dmarc_records_are_not_a_published_policy():
    summary = dns_lookup._summarize_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert summary["present"] is False
    assert summary["multiple_records"] is True and summary["record_count"] == 2
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads={"dns_posture": {
        "domains": {"value": []},
        "domainPosture": {"value": [{"domain": "contoso.example", "managed_by_microsoft": False,
                                     "spf": {"present": True, "all_qualifier": "-"}, "dmarc": summary,
                                     "dkim": {"selectors_present": ["selector1"], "selectors_missing": []},
                                     "mta_sts": {"dns_present": True}, "bimi": {"present": False}}]}}})
    ids = {finding["id"] for finding in build_findings([], normalized_snapshot=snapshot)}
    assert "dns_posture:contoso.example:dmarc_missing" in ids


def test_r109_one_dmarc_record_beside_other_txt_is_still_read():
    summary = dns_lookup._summarize_dmarc(["unrelated", "v=DMARC1; p=reject"])
    assert summary["present"] is True and summary["policy"] == "reject"
    assert summary["multiple_records"] is False


# ---- R113: an MTA-STS policy that RFC 8461 senders reject is invalid, not enforcing ----

MTA_STS_URL = "https://mta-sts.contoso.example/.well-known/mta-sts.txt"


class _PolicyFetcher:
    def __init__(self, body):
        self.body = body

    def get_text(self, url):
        return 200, self.body, None


@pytest.mark.parametrize("body,reasons", [
    ("version: STSv1\nmode: enforcing\nmx: mail.contoso.example\nmax_age: 604800\n", ["mode_invalid"]),
    ("version: STSv1\nmode: enforce\nmx: mail.contoso.example\n", ["max_age_invalid"]),
    ("version: STSv1\nmode: enforce\nmx: mail.contoso.example\nmax_age: 31557601\n", ["max_age_invalid"]),
    ("version: STSv1\nmode: enforce\nmax_age: 604800\n", ["mx_missing"]),
    ("version: STSv1\nmode: testing\nmax_age: 86400\n", ["mx_missing"]),
])
def test_r113_invalid_mta_sts_policy_is_reported_invalid(body, reasons):
    policy = exposure_lookup.fetch_mta_sts_policy("contoso.example", _PolicyFetcher(body))
    assert policy["fetch_status"] == "invalid_policy" and policy["invalid_reasons"] == reasons
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads={"dns_posture": {
        "domains": {"value": []},
        "domainPosture": {"value": [{"domain": "contoso.example", "managed_by_microsoft": False,
                                     "spf": {"present": True, "all_qualifier": "-"},
                                     "dmarc": {"present": True, "policy": "reject"},
                                     "dkim": {"selectors_present": ["selector1"], "selectors_missing": []},
                                     "mta_sts": {"dns_present": True, "policy": policy},
                                     "tls_rpt": {"present": True}, "bimi": {"present": False}}]}}})
    ids = {finding["id"] for finding in build_findings([], normalized_snapshot=snapshot)}
    assert "dns_posture:contoso.example:mta_sts_policy_invalid" in ids


@pytest.mark.parametrize("body", [
    "version: STSv1\nmode: enforce\nmx: mail.contoso.example\nmax_age: 604800\n",
    "version: STSv1\nmode: none\nmax_age: 86400\n",                     # mode none needs no mx
])
def test_r113_valid_mta_sts_policy_stays_ok(body):
    policy = exposure_lookup.fetch_mta_sts_policy("contoso.example", _PolicyFetcher(body))
    assert policy["fetch_status"] == "ok" and "invalid_reasons" not in policy
