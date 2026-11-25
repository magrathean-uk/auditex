from __future__ import annotations

import json
from typing import Any

import pytest
import requests

from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.collectors import GoogleDnsPostureCollector
from auditex.google_workspace.findings import build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from azure_tenant_audit.data_handling import collector_activity_notices
from azure_tenant_audit.dns_lookup import DohClient, DohError, dmarc_with_tree_walk
from azure_tenant_audit.offline_replay import replay_coverage_rows


class FakeResolver:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.names: list[str] = []

    def query(self, name: str, record_type: str) -> list[str]:
        assert record_type == "TXT"
        self.names.append(name)
        answer = self.answers.get(name, [])
        if isinstance(answer, Exception):
            raise answer
        return answer


class FakeDirectory:
    def __init__(self, rows: Any) -> None:
        self.rows = rows
        self.calls: list[str] = []

    def list_directory(self, resource: str, *, top: int | None) -> list[dict[str, Any]]:
        self.calls.append(resource)
        return self.rows


def test_collection_notice_discloses_aliases_parents_and_selector_count() -> None:
    notice, _off_switch = collector_activity_notices(
        ["google_dns_posture"], "live", doh_endpoint="https://dns.example.net/private-token",
    )
    assert "verified alias names" in notice and "parent DNS names" in notice and "up to eight DKIM" in notice
    assert "dns.example.net" in notice and "private-token" not in notice


@pytest.mark.parametrize(("record", "subdomain_policy"), [
    ("v=DMARC1; p=none; sp=reject", "reject"),
    ("v=DMARC1; p=reject", None),
])
def test_dmarc_selects_parent_and_retains_sp(record: str, subdomain_policy: str | None) -> None:
    resolver = FakeResolver({"_dmarc.example.com": [record], "_dmarc.com": ["v=DMARC1; p=none; psd=y"]})
    dmarc = dmarc_with_tree_walk("mail.example.com", resolver)
    assert resolver.names == ["_dmarc.mail.example.com", "_dmarc.example.com", "_dmarc.com"]
    assert (dmarc["query_name"], dmarc["inherited"], dmarc["subdomain_policy"], dmarc["records"]) == (
        "_dmarc.example.com", True, subdomain_policy, [record],
    )


def test_dmarc_discards_multiple_at_a_node_then_tries_the_parent() -> None:
    multiple = ["v=DMARC1; p=reject", "v=DMARC1; p=none"]
    resolver = FakeResolver({
        "_dmarc.mail.example.com": multiple,
        "_dmarc.example.com": ["v=DMARC1; p=reject; psd=n", "", "unrelated TXT"],
    })
    inherited = dmarc_with_tree_walk("mail.example.com", resolver)
    assert resolver.names == ["_dmarc.mail.example.com", "_dmarc.example.com"]
    assert inherited["records"] == ["v=DMARC1; p=reject; psd=n", "", "unrelated TXT"]

    absent = dmarc_with_tree_walk("example.com", FakeResolver({"_dmarc.example.com": multiple}))
    assert (absent["present"], absent["multiple_records"], absent["records"]) == (False, True, [])


def test_dmarc_jumps_to_seven_labels_and_uses_psd_when_its_child_has_no_record() -> None:
    resolver = FakeResolver({
        "_dmarc.b.c.d.mail.example.com": ["v=DMARC1;p=reject;p=none"],
        "_dmarc.mail.example.com": ["v=DMARC1;p=reject"],
        "_dmarc.com": ["v = DMARC1 ; p = none ; psd = y"],
    })
    dmarc = dmarc_with_tree_walk("x.y.a.b.c.d.mail.example.com", resolver)
    assert resolver.names[:2] == ["_dmarc.x.y.a.b.c.d.mail.example.com", "_dmarc.a.b.c.d.mail.example.com"]
    assert (dmarc["query_name"], dmarc["inherited"], dmarc["records"]) == (
        "_dmarc.com", True, ["v = DMARC1 ; p = none ; psd = y"],
    )


def test_dmarc_author_match_does_not_query_a_parent() -> None:
    resolver = FakeResolver({"_dmarc.mail.example.com": ["v=DMARC1;p=reject"]})
    dmarc = dmarc_with_tree_walk("mail.example.com", resolver)
    assert (dmarc["query_name"], dmarc["inherited"], dmarc["records"]) == (
        "_dmarc.mail.example.com", False, ["v=DMARC1;p=reject"],
    )
    assert resolver.names == ["_dmarc.mail.example.com"]


def test_domains_alias_and_selectors_reach_normalised_evidence() -> None:
    directory = FakeDirectory([{
        "domainName": "example.com", "isPrimary": True, "verified": True,
        "domainAliases": [
            {"domainAliasName": "mail.example.org", "verified": True, "parentDomainName": "example.com"},
            {"domainAliasName": "example.net", "verified": False},
        ],
        "customerId": "C0123synthetic",
    }])
    resolver = FakeResolver({
        "example.com": ["v=spf1 -all", "unrelated TXT"],
        "selector1._domainkey.example.com": ["v=DKIM1; p=QUJD"],
        "_dmarc.example.com": ["v=DMARC1; p=reject"],
        "_dmarc.example.org": ["v=DMARC1; p=none; sp=reject; psd=n"],
    })
    result = GoogleDnsPostureCollector().run({"client": directory, "dns_resolver": resolver})
    assert result.status == "ok" and directory.calls == ["domains"]
    assert resolver.names == [
        "example.com", "_dmarc.example.com", "_mta-sts.example.com", "_smtp._tls.example.com",
        "default._bimi.example.com", "google._domainkey.example.com", "selector1._domainkey.example.com",
        "selector2._domainkey.example.com", "_dmarc.mail.example.org", "_dmarc.example.org",
    ]
    assert "C0123synthetic" not in json.dumps(result.payload)
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="dns", collector_payloads={"google_dns_posture": result.payload},
    )
    base, alias = snapshot["google_dns_posture"]["records"]
    assert (base["alias"], base["resolver_error"], base["spf"]["records"], base["dkim"]["selectors"]) == (
        False, False, ["v=spf1 -all"], {"google": [], "selector1": ["v=DKIM1; p=QUJD"], "selector2": []},
    )
    assert (alias["domain"], alias["alias"], alias["resolver_error"], alias["dmarc"]["query_name"],
            alias["dmarc"]["inherited"], alias["dmarc"]["records"]) == (
        "mail.example.org", True, False, "_dmarc.example.org", True, ["v=DMARC1; p=none; sp=reject; psd=n"],
    )
    assert "spf" not in alias and "dkim" not in alias
    assert not [finding for finding in build_google_findings(snapshot) if finding["rule_id"].startswith("google.dns_")]


def test_cut_inventory_keeps_all_the_aliases_of_a_read_domain_and_the_existing_dkim_fallbacks() -> None:
    directory = FakeDirectory([
        {"domainName": "example.com", "domainAliases": [{"domainAliasName": "example.org"}]},
        {"domainName": "example.net"},
    ])
    resolver = FakeResolver({"s1._domainkey.example.com": ["v=DKIM1; p=QUJD"]})
    result = GoogleDnsPostureCollector().run({"client": directory, "dns_resolver": resolver, "top": 1})
    assert result.status == "partial" and result.payload["domains"]["status"] == "partial"
    assert result.coverage[0]["collection_truncated"] is True
    (replayed,) = replay_coverage_rows("google_dns_posture", result.payload)
    assert (replayed["name"], replayed["status"], replayed["truncation_reason"]) == (
        "domains", "partial", "operator_limit",
    )
    base, alias = result.payload["domainPosture"]["value"]
    assert (base["domain"], alias["domain"]) == ("example.com", "example.org")
    assert base["dkim"]["selectors_present"] == ["s1"]
    assert [name for name in resolver.names if "._domainkey." in name] == [
        "google._domainkey.example.com", "selector1._domainkey.example.com", "selector2._domainkey.example.com",
        "s1._domainkey.example.com", "s2._domainkey.example.com", "default._domainkey.example.com",
        "k1._domainkey.example.com", "mail._domainkey.example.com",
    ]


@pytest.mark.parametrize("answer", [
    None, 1, {}, "v=DMARC1;p=reject", [None],
    DohError("SERVFAIL for mail.example.com at https://dns.example.net/private-token"),
])
def test_unreadable_parent_does_not_turn_into_record_absence(answer: Any) -> None:
    resolver = FakeResolver({"_dmarc.example.com": answer, "_dmarc.com": ["v=DMARC1; p=reject"]})
    result = GoogleDnsPostureCollector().run({"domain": "mail.example.com", "dns_resolver": resolver})
    (posture,) = result.payload["domainPosture"]["value"]
    (row,) = result.coverage
    assert result.status == "partial" and row["error_class"] == "dns_resolver_error"
    assert "mail.example.com" not in row["error"] and "private-token" not in json.dumps(result.payload)
    assert posture["dmarc"]["present"] is None and "_dmarc.com" not in resolver.names
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="dns", collector_payloads={"google_dns_posture": result.payload},
    )
    assert snapshot["google_dns_posture"]["records"][0]["resolver_error"] is True


@pytest.mark.parametrize("rows", [
    None, {}, [], [None], [{"domainName": ""}], [{"domainName": 123}], [{"domainName": "example.com", "verified": None}],
    [{"domainName": "example.com", "domainAliases": None}],
    [{"domainName": "example.com", "domainAliases": {}}],
    [{"domainName": "example.com", "domainAliases": [None]}],
    [{"domainName": "example.com", "domainAliases": [{"domainAliasName": False}]}],
    [{"domainName": "example.com", "domainAliases": [{"domainAliasName": "example.org", "verified": "true"}]}],
])
def test_unreadable_directory_inventory_cannot_look_complete(rows: Any) -> None:
    resolver = FakeResolver({})
    result = GoogleDnsPostureCollector().run({"client": FakeDirectory(rows), "dns_resolver": resolver})
    assert result.status == "partial" and result.payload["domains"]["status"] == "partial"
    assert "_dmarc.example.org" not in resolver.names
    (replayed,) = replay_coverage_rows("google_dns_posture", result.payload)
    assert (replayed["name"], replayed["error_class"]) == ("domains", "malformed_response")


def test_live_domains_envelope_cannot_silently_discard_a_bad_row(monkeypatch: pytest.MonkeyPatch) -> None:
    class Service:
        def domains(self) -> Service:
            return self

        def list(self, *, customer: str) -> Service:
            return self

        def execute(self) -> dict[str, Any]:
            return {"domains": [{"domainName": "example.com"}, None]}

    monkeypatch.setattr(GoogleWorkspaceClient, "_service", lambda *_args: Service())
    result = GoogleDnsPostureCollector().run({
        "client": GoogleWorkspaceClient(None), "dns_resolver": FakeResolver({}),
    })
    assert result.status == "partial" and result.payload["domains"]["status"] == "partial"
    assert result.payload["domainPosture"]["value"][0]["domain"] == "example.com"


@pytest.mark.parametrize("injected", [False, True])
@pytest.mark.parametrize("message", [
    {"Status": 0, "TC": "true"}, {"Status": 0, "Answer": None}, {"Status": 0, "Answer": [None]},
    {"Status": 0, "Answer": [{"type": 16, "data": None}]},
    {"Status": 0, "Answer": [{"type": 16, "data": "\"v=DMARC1;p=reject"}]},
    {"Status": 3, "Answer": [{"type": 16, "data": "\"v=DMARC1;p=reject\""}]},
    {"Status": 0.5}, {"TC": False}, {"Status": 2}, {"Status": 0, "TC": True},
])
def test_live_doh_does_not_silently_discard_an_unreadable_answer(
    message: dict[str, Any], injected: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_send(_session: requests.Session, request: requests.PreparedRequest, **_kwargs: Any) -> requests.Response:
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(message).encode()
        response.request = request
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)
    context = {"domain": "example.com", "dns_resolver": DohClient() if injected else None}
    result = GoogleDnsPostureCollector().run(context)
    assert result.status == "partial"
    assert result.coverage[0]["error_class"] == "dns_resolver_error"
    assert result.payload["domainPosture"]["value"][0]["spf"]["present"] is None
