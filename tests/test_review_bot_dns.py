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


# ---- The fetch deadline holds while one read (trailers) or the request itself (100 Continue lines) blocks ----

class _Socket:
    def __init__(self, release):
        self.release, self.shut = release, False

    def shutdown(self, how):
        self.shut = True
        self.release.set()


class _BlockingRaw:
    """One read1 that stays inside http.client (an endless chunked trailer) until its socket is shut down."""

    def __init__(self, release):
        self.release = release
        self.connection = type("Connection", (), {"sock": _Socket(release)})()

    def read1(self, amount=None, decode_content=None):
        self.release.wait(5.0)
        raise OSError("connection closed")


class _Response:
    status_code = 200
    headers: dict = {}

    def __init__(self, release):
        self.raw = _BlockingRaw(release)
        self.closed = False
        self._release = release

    def close(self):
        self.closed = True
        self._release.set()


def _wait_closed(response):
    deadline = time.monotonic() + 5.0
    while not response.closed and time.monotonic() < deadline:
        time.sleep(0.01)
    return response.closed


def _timed_fetch(session):
    fetcher = exposure_lookup.RequestsHttpsFetcher(session=session, deadline=0.3)
    started = time.monotonic()
    result = fetcher.get_text(MTA_STS_URL)
    return result, time.monotonic() - started


def test_deadline_holds_while_one_body_read_blocks():
    release = threading.Event()
    response = _Response(release)
    session = type("S", (), {"get": lambda self, url, **kw: response})()
    try:
        (status, body, error), elapsed = _timed_fetch(session)
    finally:
        release.set()
    assert (status, body, error) == (None, "", "fetch_deadline_exceeded")
    assert elapsed < 2.0
    assert response.raw.connection.sock.shut is True
    assert _wait_closed(response), "the fetch thread closes the response once its read is interrupted"


def test_deadline_holds_while_the_request_blocks_before_headers():
    release = threading.Event()
    late = _Response(release)

    def get(self, url, **kw):
        release.wait(5.0)
        return late

    session = type("S", (), {"get": get})()
    try:
        (status, body, error), elapsed = _timed_fetch(session)
    finally:
        release.set()
    assert (status, body, error) == (None, "", "fetch_deadline_exceeded")
    assert elapsed < 2.0
    assert _wait_closed(late), "a response that arrives after the deadline is closed by the fetch thread"


def test_deadline_ends_a_real_endless_chunked_trailer():
    """A real socket and the real requests/urllib3 stack: the trailer never ends, so one read1 never returns."""
    import socket as socket_module

    server = socket_module.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    disconnected = threading.Event()

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n")
            try:
                for _ in range(200):
                    conn.sendall(b"X-Trailer: more\r\n")
                    time.sleep(0.05)
            except OSError:
                disconnected.set()

    threading.Thread(target=serve, daemon=True).start()
    url = f"http://127.0.0.1:{server.getsockname()[1]}/.well-known/mta-sts.txt"
    fetcher = exposure_lookup.RequestsHttpsFetcher(deadline=0.5, timeout=5.0)
    started = time.monotonic()
    try:
        result = fetcher._fetch_within_deadline(lambda: fetcher.session.get(url, stream=True, timeout=5.0), started)
        elapsed = time.monotonic() - started
        assert result == (None, "", "fetch_deadline_exceeded")
        assert elapsed < 2.0
        assert disconnected.wait(5.0), "the abandoned fetch drops the connection instead of reading trailers forever"
    finally:
        server.close()


# ---- Anti-phish: an enabled rule with no readable policy link shadows the Default ----

ACCEPTED = [{"DomainName": "contoso.example"}]
SCOPE_ALL = {key: None for key in ("SentTo", "SentToMemberOf", "RecipientDomainIs")} | {
    "ExceptIfSentTo": [], "ExceptIfSentToMemberOf": [], "ExceptIfRecipientDomainIs": []}
PHISH_DEFAULT = {"Identity": "Office365 AntiPhish Default", "Name": "Office365 AntiPhish Default", "IsDefault": True,
                 "Enabled": True, "EnableOrganizationDomainsProtection": True, "TargetedDomainProtectionAction": "Quarantine"}


def _phish(policies, rules):
    return {"accepted_domains": ACCEPTED, "anti_phish_policies": list(policies), "anti_phish_rules": list(rules),
            "atp_policy_rules": [], "defender_license": True, "protection_policy_rules": []}


@pytest.mark.parametrize("link", [None, "absent", 7])
def test_enabled_rule_with_unreadable_policy_link_withholds_the_default(link):
    rule = {"Identity": "Unknown rule", "State": "Enabled", **SCOPE_ALL}
    if link != "absent":
        rule["AntiPhishPolicy"] = link
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT], [rule]))
    assert (record["verdict"], record["cell"]) == ("not_assessed", "qualifier_shadowed")


def test_disabled_rule_with_unreadable_policy_link_changes_nothing():
    rule = {"Identity": "Unknown rule", "State": "Disabled", "AntiPhishPolicy": None, **SCOPE_ALL}
    record = assess("MS.SECURITYSUITE.2.2v1", _phish([PHISH_DEFAULT], [rule]))
    assert (record["verdict"], record["cell"]) == ("met", "default_qualifies")


# ---- Repair round 1 (review of 346e97fc) ----

def test_dmarc_version_tag_must_be_the_first_tag():
    """RFC 7489 6.4: a record starts with v=DMARC1; a version tag later in the string does not make it a record."""
    assert dns_lookup.parse_dmarc("p=reject; v = DMARC1") is None
    assert dns_lookup.parse_dmarc("p=reject; v=DMARC1") is None
    summary = dns_lookup._summarize_dmarc(["p=reject; v = DMARC1"])
    assert summary["present"] is False


def test_mta_sts_mx_a_label_host_is_valid():
    policy = _policy(mx=("mail.example.xn--p1ai", "*.xn--80ak6aa92e.example"))
    assert policy["fetch_status"] == "ok" and "invalid_reasons" not in policy


@pytest.mark.parametrize("host", ["mail.examp\u212ae.com", "mail.\u0131xample.com", "mail.contoso.example\n"])
def test_host_name_outside_ascii_ldh_is_not_safe(host):
    """RFC 5321 Domain labels are ASCII letters, digits and hyphens; Unicode case folding must not admit a Kelvin sign
    or a dotless i, and a trailing newline is not part of a host name."""
    assert exposure_lookup.is_safe_domain_name(host) is False


@pytest.mark.parametrize("host", ["mail.examp\u212ae.com", "mail.\u0131xample.com"])
def test_mta_sts_mx_host_outside_ascii_ldh_is_invalid(host):
    policy = _policy(mx=("mail.contoso.example", host))
    assert policy["fetch_status"] == "invalid_policy" and policy["invalid_reasons"] == ["mx_invalid"]
