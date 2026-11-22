"""Deep-review fixes for the Defender and DNS value rules and their evidence (lane value-rules-defender-dns).

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from auditex.scuba_projection import project_run
from azure_tenant_audit import dns_lookup, exposure_lookup
from azure_tenant_audit.collectors.exchange_defender_commands import DEFENDER_COMMANDS
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.value_rules import assess
from azure_tenant_audit.value_rules.catalogue import catalogue
from azure_tenant_audit.value_rules.defender_resolution import safelinks_resolution

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
    # Duplicates are their own finding (remove the extra records), not dmarc_missing (publish a record).
    assert "dns_posture:contoso.example:dmarc_multiple_records" in ids
    assert "dns_posture:contoso.example:dmarc_missing" not in ids


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


# ---- R163: a host that trickles its MTA-STS policy cannot hold the run past one wall-clock deadline ----

class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _TrickleRaw:
    """Each read waits just under the per-read socket timeout and yields one byte per four seconds."""

    def __init__(self, clock):
        self.clock, self.calls = clock, 0

    def _bytes(self, amount):
        self.calls += 1
        self.clock.now += 4.0 * amount
        return b"x" * amount

    def read(self, amount, decode_content=False):
        return self._bytes(amount)

    def read1(self, amount=None, decode_content=None):
        return self._bytes(1)


class _TrickleSession:
    def __init__(self, clock):
        self.response = type("Response", (), {"status_code": 200, "closed": False})()
        self.response.raw = _TrickleRaw(clock)
        self.response.close = lambda: setattr(self.response, "closed", True)

    def get(self, url, **kwargs):
        return self.response


def test_r163_policy_fetch_stops_at_the_wall_clock_deadline():
    clock = _Clock()
    session = _TrickleSession(clock)
    fetcher = exposure_lookup.RequestsHttpsFetcher(session=session, clock=clock)
    start = clock.now
    policy = exposure_lookup.fetch_mta_sts_policy("contoso.example", fetcher)
    assert policy["fetch_status"] == "unreachable" and policy["error"] == "fetch_deadline_exceeded"
    assert clock.now - start <= exposure_lookup.DEFAULT_FETCH_DEADLINE_SECONDS + 4.0
    assert session.response.closed is True


def test_r163_prompt_policy_is_read_whole():
    body = b"version: STSv1\nmode: enforce\nmx: mail.contoso.example\nmax_age: 604800\n"

    class Raw:
        def __init__(self):
            self.left = body

        def read1(self, amount=None, decode_content=None):
            chunk, self.left = self.left[:16], self.left[16:]
            return chunk

    session = type("S", (), {"get": lambda self, url, **kw: type("R", (), {"status_code": 200, "raw": Raw()})()})()
    status, text, error = exposure_lookup.RequestsHttpsFetcher(session=session).get_text(MTA_STS_URL)
    assert (status, text, error) == (200, body.decode(), None)


# ---- R164: the DoH resolver is configurable (option or AUDITEX_DOH_ENDPOINT), Cloudflare stays the default ----

def test_r164_doh_endpoint_defaults_to_cloudflare(monkeypatch):
    monkeypatch.delenv(dns_lookup.DOH_ENDPOINT_ENV, raising=False)
    assert dns_lookup.resolve_doh_endpoint() == dns_lookup.DEFAULT_DOH_ENDPOINT == "https://cloudflare-dns.com/dns-query"
    assert dns_lookup.DohClient().endpoint == dns_lookup.DEFAULT_DOH_ENDPOINT


def test_r164_environment_and_option_choose_the_resolver(monkeypatch):
    monkeypatch.setenv(dns_lookup.DOH_ENDPOINT_ENV, "https://dns.example.net/dns-query")
    assert dns_lookup.resolve_doh_endpoint() == "https://dns.example.net/dns-query"
    assert dns_lookup.DohClient().endpoint == "https://dns.example.net/dns-query"
    assert dns_lookup.resolve_doh_endpoint("https://doh.example.org/q") == "https://doh.example.org/q"


@pytest.mark.parametrize("endpoint", [
    "http://dns.example.net/dns-query", "dns.example.net", "https://", "https://user:pw@dns.example.net/q",
    "https://dns.example.net/q#frag", " ",
])
def test_r164_only_plain_https_endpoints_are_accepted(endpoint, monkeypatch):
    with pytest.raises(ValueError) as caught:
        dns_lookup.resolve_doh_endpoint(endpoint)
    assert "pw" not in str(caught.value)
    monkeypatch.setenv(dns_lookup.DOH_ENDPOINT_ENV, endpoint)
    if endpoint.strip():
        with pytest.raises(ValueError):
            dns_lookup.resolve_doh_endpoint()
    else:
        assert dns_lookup.resolve_doh_endpoint() == dns_lookup.DEFAULT_DOH_ENDPOINT


def test_r164_disclosure_names_the_resolver_in_use():
    assert dns_lookup.doh_resolver_disclosure(dns_lookup.DEFAULT_DOH_ENDPOINT) == (
        "the public Cloudflare DNS-over-HTTPS resolver (https://cloudflare-dns.com/dns-query)")
    assert dns_lookup.doh_resolver_disclosure("https://dns.example.net/dns-query") == (
        "the configured DNS-over-HTTPS resolver (https://dns.example.net/dns-query)")


# ---- R101 / R103: anti-phish precedence with an orphan rule, a missing preset policy or a decisive custom policy ----

PHISH_DEFAULT = {"Identity": "Office365 AntiPhish Default", "Name": "Office365 AntiPhish Default", "IsDefault": True,
                 "Enabled": True, "EnableOrganizationDomainsProtection": True, "TargetedDomainProtectionAction": "Quarantine"}
SCOPE_ALL = {**EVERYONE, "ExceptIfSentTo": [], "ExceptIfSentToMemberOf": [], "ExceptIfRecipientDomainIs": []}
GROUP_ONLY = {**SCOPE_ALL, "SentToMemberOf": ["recipient"]}


def _phish(policies, rules, presets=(), atp=()):
    return {"accepted_domains": ACCEPTED, "anti_phish_policies": list(policies), "anti_phish_rules": list(rules),
            "atp_policy_rules": list(atp), "defender_license": True, "protection_policy_rules": list(presets)}


def _phish_rule(policy, scope):
    return {"Identity": f"{policy} rule", "State": "Enabled", "AntiPhishPolicy": policy, **scope}


def _custom(name, org_domains):
    return {"Identity": name, "Name": name, "IsDefault": False, "Enabled": True,
            "EnableOrganizationDomainsProtection": org_domains, "TargetedDomainProtectionAction": "Quarantine"}


@pytest.mark.parametrize("scope", [SCOPE_ALL, GROUP_ONLY])
def test_r101_rule_naming_an_unexported_policy_withholds_the_default(scope):
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT], [_phish_rule("Exec policy", scope)]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


@pytest.mark.parametrize("scope", [SCOPE_ALL, GROUP_ONLY])
def test_r101_orphan_rule_without_a_qualifier_keeps_the_reference_not_met(scope):
    # Unexported evidence only withholds a lower qualifier; it never counts as a policy that could qualify (the v3.9.1
    # reference rules a preset whose policy is missing the same way).
    default = {**PHISH_DEFAULT, "EnableOrganizationDomainsProtection": False}
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([default], [_phish_rule("Exec policy", scope)]))
    assert (record["verdict"], record["cell"]) == ("not_met", "no_qualifying_policy")


def test_r101_enabled_preset_rule_without_its_policy_withholds_the_default():
    preset = "Standard Preset Security Policy1700000000000"
    rule = {"Identity": preset, "State": "Enabled", **EVERYONE}
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT], [], presets=[rule], atp=[rule]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


def test_r101_exported_policy_is_not_an_orphan():
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT, _custom("Exec policy", True)],
                                                     [_phish_rule("Exec policy", SCOPE_ALL)]))
    assert (record["verdict"], record["cell"]) == ("met", "custom_qualifies")


def test_r103_covering_noncompliant_custom_policy_outranks_the_qualifying_default():
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT, _custom("Exec policy", False)],
                                                     [_phish_rule("Exec policy", SCOPE_ALL)]))
    assert (record["verdict"], record["cell"]) == ("not_met", "no_qualifying_policy")


def test_r103_same_tier_custom_order_stays_undecided():
    record = assess("MS.SECURITYSUITE.2.2v1", _phish(
        [PHISH_DEFAULT, _custom("Bad", False), _custom("Unknown", None)],
        [_phish_rule("Bad", SCOPE_ALL), _phish_rule("Unknown", SCOPE_ALL)]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


def test_r103_covering_noncompliant_preset_keeps_the_reference_withholding():
    preset = "Strict Preset Security Policy1700000000000"
    rule = {"Identity": preset, "State": "Enabled", **EVERYONE}
    strict = {**_custom(preset, False), "Name": "Strict Preset Security Policy"}
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT, strict], [], presets=[rule], atp=[rule]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


def test_r103_partial_noncompliant_custom_policy_stays_undecided():
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT, _custom("Exec policy", False)],
                                                     [_phish_rule("Exec policy", GROUP_ONLY)]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


# ---- R003 / R099: Safe Links reads the Built-In Protection rule's exclusions once the 7.x rows list that section ----
# These tests call the kind with a row that lists built_in_protection_rules; the shipped rows list it since lane
# rules-followup (tests/test_review_rules_followup.py pins the shipped answers).

SL_FLAGS = {"EnableSafeLinksForEmail": True, "EnableSafeLinksForTeams": True, "EnableSafeLinksForOffice": True,
            "EnableForInternalSenders": True, "ScanUrls": True, "DeliverMessageAfterScan": True, "TrackClicks": True}
SL_BUILTIN = {"Identity": "Built-In Protection Policy", **SL_FLAGS}


def _safelinks(rules, policies, built_in=None):
    sections = {"atp_policy_rules": [], "defender_license": True, "protection_policy_rules": [],
                "safe_links_policies": list(policies), "safe_links_rules": list(rules), "accepted_domains": ACCEPTED}
    if built_in is not None:
        sections["built_in_protection_rules"] = built_in
    return sections


def _sl_rule(policy, scope, priority=0, state="Enabled"):
    return {"Identity": f"{policy} rule", "State": state, "Priority": priority, "SafeLinksPolicy": policy, **scope}


SL_POLICY = "MS.SECURITYSUITE.7.2v1"
BI_ALL = [{"Identity": "ATP Built-In Protection Rule", "ExceptIfSentTo": None, "ExceptIfSentToMemberOf": None,
           "ExceptIfRecipientDomainIs": None}]
BI_EXCLUDES = [{**BI_ALL[0], "ExceptIfSentTo": ["recipient"]}]
BI_UNREADABLE = [{"Identity": "ATP Built-In Protection Rule"}]
SL_SCOPE_ALL = SCOPE_ALL


def _bi_row():
    row = deepcopy(catalogue()["policies"][SL_POLICY])
    row["sections"] = sorted([*row["sections"], "built_in_protection_rules"])
    return row


def _kind(sections):
    return safelinks_resolution(SL_POLICY, _bi_row(), sections)


def test_r003_built_in_exclusions_without_a_covering_rule_are_not_met():
    partial_compliant = [_sl_rule("x", GROUP_ONLY)]
    shipped = assess(SL_POLICY, _safelinks(partial_compliant, [SL_BUILTIN, {"Identity": "x", **SL_FLAGS}], BI_EXCLUDES))
    assert (shipped["verdict"], shipped["cell"]) == ("not_assessed", "partial_tier_may_cover")   # fixed on the shipped row
    record = _kind(_safelinks([], [SL_BUILTIN], BI_EXCLUDES))
    assert (record["verdict"], record["cell"], record["reason_code"]) == (
        "not_met", "no_policy_covers_all", "no_policy_covers_all_recipients")
    may_cover = _kind(_safelinks(partial_compliant, [SL_BUILTIN, {"Identity": "x", **SL_FLAGS}], BI_EXCLUDES))
    assert (may_cover["verdict"], may_cover["cell"]) == ("not_assessed", "partial_tier_may_cover")


def test_r003_partly_scoped_preset_may_cover_the_excluded_recipients():
    preset = {"Identity": "Standard Preset Security Policy1700000000000", "State": "Enabled", **GROUP_ONLY}
    sections = _safelinks([], [SL_BUILTIN], BI_EXCLUDES)
    sections["protection_policy_rules"] = sections["atp_policy_rules"] = [preset]
    record = _kind(sections)
    assert (record["verdict"], record["cell"]) == ("not_assessed", "partial_tier_may_cover")


def test_r003_unreadable_built_in_rule_is_not_assessed():
    for built_in in (BI_UNREADABLE, []):
        record = _kind(_safelinks([], [SL_BUILTIN], built_in))
        assert (record["verdict"], record["cell"], record["cited_sections"]) == (
            "not_assessed", "builtin_rule_unusable", ["built_in_protection_rules"])
    record = _kind(_safelinks([], [SL_BUILTIN], {"bad": 1}))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "section_not_a_list")


def test_r003_covering_rule_or_preset_needs_no_built_in_reading():
    rules = [_sl_rule("cover", SL_SCOPE_ALL)]
    record = _kind(_safelinks(rules, [{"Identity": "cover", **SL_FLAGS}], BI_UNREADABLE))
    assert (record["verdict"], record["cell"]) == ("met", "policy_flags_ok")


def test_r099_empty_rule_lists_follow_the_built_in_policy():
    shipped = assess(SL_POLICY, _safelinks([], [SL_BUILTIN], BI_ALL))
    disabled = assess(SL_POLICY, _safelinks([_sl_rule("x", GROUP_ONLY, state="Disabled")], [SL_BUILTIN], BI_ALL))
    assert (shipped["verdict"], disabled["verdict"]) == ("met", "met")                 # fixed on the shipped row
    for rules in ([], [_sl_rule("x", GROUP_ONLY, state="Disabled")]):
        record = _kind(_safelinks(rules, [SL_BUILTIN], BI_ALL))
        assert (record["verdict"], record["cell"]) == ("met", "policy_flags_ok")
        record = _kind(_safelinks(rules, [], BI_ALL))
        assert (record["verdict"], record["cell"]) == ("not_assessed", "policy_not_in_export")
        record = _kind(_safelinks(rules, [{**SL_BUILTIN, "ScanUrls": False}], BI_ALL))
        assert (record["verdict"], record["cell"]) == ("not_met", "policy_flag_off")


# ---- Repair round 1: independent review of 530ecb9..f96d653 ----

def test_review_spf_double_qualifier_is_not_a_fail_all():
    assert dns_lookup.spf_fails_unapproved_senders("v=spf1 --all +all") is False
    assert dns_lookup.spf_fails_unapproved_senders("v=spf1 -all") is True


def test_review_dmarc_answer_from_an_unrelated_name_is_not_inherited():
    entry = {"domain": "a.example.com", "rdata": ["v=DMARC1; p=reject; sp=none"], "log": [
        {"query_name": "_dmarc.a.example.com", "query_answers": [], "outcome": "empty"},
        {"query_name": "_dmarc.other.com", "query_answers": ["v=DMARC1; p=reject; sp=none"], "outcome": "answers"}]}
    record = assess("MS.EXO.4.2v1", {"dmarc_records": [entry]})
    assert (record["verdict"], record["cell"]) == ("met", "all_compliant")


def test_review_text_mentioning_dmarc_is_not_a_second_record():
    summary = dns_lookup._summarize_dmarc(["note: use v=DMARC1", "v=DMARC1; p=reject"])
    assert (summary["present"], summary["policy"], summary["multiple_records"]) == (True, "reject", False)


def test_review_blank_mx_line_is_no_mx():
    policy = exposure_lookup.fetch_mta_sts_policy(
        "contoso.example", _PolicyFetcher("version: STSv1\nmode: testing\nmx:\nmax_age: 10\n"))
    assert policy["fetch_status"] == "invalid_policy" and policy["invalid_reasons"] == ["mx_missing"]


class _RecordingSession:
    def __init__(self, response):
        self.response, self.kwargs = response, {}

    def get(self, url, **kwargs):
        self.kwargs = kwargs
        return self.response


def test_review_redirect_body_is_never_consumed_by_requests():
    session = _RecordingSession(type("R", (), {"status_code": 200, "raw": None})())
    exposure_lookup.RequestsHttpsFetcher(session=session).get_text(MTA_STS_URL)
    hook = session.kwargs["hooks"]["response"]
    redirect = type("R", (), {"status_code": 302, "is_redirect": True, "closed": False})()
    redirect.close = lambda: setattr(redirect, "closed", True)
    redirect.raw = None
    hook(redirect)
    assert redirect._content == b"" and redirect._content_consumed is True and redirect.closed is True
    assert session.kwargs["headers"]["Accept-Encoding"] == "identity"


def test_review_compressed_policy_is_decoded_after_the_bounded_raw_read():
    import gzip
    body = b"version: STSv1\nmode: enforce\nmx: mail.contoso.example\nmax_age: 604800\n"
    packed = gzip.compress(body)

    class Raw:
        def __init__(self):
            self.left, self.decode = packed, []

        def read1(self, amount=None, decode_content=None):
            self.decode.append(decode_content)
            chunk, self.left = self.left[:7], self.left[7:]
            return chunk

    response = type("R", (), {"status_code": 200, "headers": {"Content-Encoding": "gzip"}, "raw": Raw()})()
    status, text, error = exposure_lookup.RequestsHttpsFetcher(session=_RecordingSession(response)).get_text(MTA_STS_URL)
    assert (status, text, error) == (200, body.decode(), None)
    assert set(response.raw.decode) == {False}


@pytest.mark.parametrize("endpoint", ["https://resolver.example:bad/dns-query", "https://resolver.example/dns-query#",
                                      "https://resolver.example/dns-query?token=secret"])
def test_review_doh_endpoint_rejects_bad_port_fragment_and_query(endpoint):
    with pytest.raises(ValueError) as caught:
        dns_lookup.resolve_doh_endpoint(endpoint)
    assert "secret" not in str(caught.value)


def test_review_blank_environment_value_means_the_default(monkeypatch):
    monkeypatch.setenv(dns_lookup.DOH_ENDPOINT_ENV, "  ")
    assert dns_lookup.DohClient().endpoint == dns_lookup.DEFAULT_DOH_ENDPOINT


def test_review_missing_preset_without_its_defender_rule_changes_nothing():
    preset = "Standard Preset Security Policy1700000000000"
    rule = {"Identity": preset, "State": "Enabled", **EVERYONE}
    for presets in ([rule], [rule, {**rule, "Identity": preset + "b"}]):
        record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT], [], presets=presets))
        assert (record["verdict"], record["cell"], record["detail"]) == ("met", "default_qualifies", {})


def test_review_ambiguous_rules_of_a_missing_preset_withhold_the_default():
    preset = "Standard Preset Security Policy1700000000000"
    rule = {"Identity": preset, "State": "Enabled", **EVERYONE}
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT], [], presets=[rule, {**rule, "Identity": preset + "b"}],
                                                     atp=[rule]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


def test_review_preset_with_unreadable_defender_scope_may_cover_the_excluded():
    name = "Standard Preset Security Policy1700000000000"
    sections = _safelinks([], [SL_BUILTIN], BI_EXCLUDES)
    sections["protection_policy_rules"] = [{"Identity": name, "State": "Enabled", **GROUP_ONLY}]
    sections["atp_policy_rules"] = [{"Identity": name, "State": "Enabled"}]
    record = _kind(sections)
    assert (record["verdict"], record["cell"]) == ("not_assessed", "partial_tier_may_cover")


# ---- Repair round 2 ----

def test_review2_spaced_dmarc_record_beside_a_note_does_not_crash():
    summary = dns_lookup._summarize_dmarc(["v = DMARC1; p=reject", "note: use v=DMARC1"])
    assert summary["present"] is True and summary["multiple_records"] is False


def test_review2_multi_member_gzip_policy_is_decoded_whole():
    import gzip
    first, second = b"version: STSv1\nmode: enforce\n", b"mx: mail.contoso.example\nmax_age: 604800\n"
    assert exposure_lookup._decode_body(gzip.compress(first) + gzip.compress(second), "gzip") == first + second
    bomb = gzip.compress(b"a" * (exposure_lookup.MAX_POLICY_BYTES * 4)) * 3
    assert len(exposure_lookup._decode_body(bomb, "gzip")) == exposure_lookup.MAX_POLICY_BYTES + 1


# ---- Impact prediction 2: the posture SPF parser reads the all mechanism the same way ----

@pytest.mark.parametrize("record,qualifier", [
    ("v=spf1 include:spf.examplemall +all", "+"),
    ("v=spf1 include:spf.examplemall -all", "-"),
    ("v=spf1 -ALL", "-"),
    ("v=spf1 all", "+"),
    ("v=spf1 --all +all", "+"),
    ("v=spf1 redirect=_spf.contoso.example", None),
])
def test_impact_parse_spf_reads_the_first_all_mechanism(record, qualifier):
    assert dns_lookup.parse_spf(record)["all_qualifier"] == qualifier
