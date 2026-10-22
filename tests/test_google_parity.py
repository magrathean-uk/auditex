"""Google Workspace parity with Microsoft 365 (CE+ product review, action 7).

Subject scope of the per-user collectors, the internal domain set from the Directory domains list,
the 2-step verification, stale-account and device rules, ``--waiver-file`` and one collector issue per
surface. Everything here runs offline against fakes; the Google SDKs are not installed in the test venv.
"""
from __future__ import annotations

import json
import sys
import types
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from auditex import cli as auditex_cli
from auditex.google_workspace import auth as google_auth
from auditex.google_workspace import collectors as google_collectors
from auditex.google_workspace import run as google_run
from auditex.google_workspace.client import GoogleWorkspaceClient
from auditex.google_workspace.collectors import (
    MAILBOX_FANOUT_LIMIT,
    GoogleCalendarPostureCollector,
    GoogleDrivePostureCollector,
    GoogleGmailSettingsCollector,
    GooglePoliciesCollector,
)
from auditex.google_workspace.findings import _GOOGLE_FRAMEWORK_MAPPINGS, build_google_findings, google_rule_metadata
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from auditex.google_workspace.run import GoogleRunConfig, build_google_capability_rows, run_google_live, run_google_offline

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "examples" / "google_workspace_sample.json"

NEW_RULES = {
    "google.user_2sv_not_enforced",
    "google.org_2sv_policy_not_enforced",
    "google.stale_user",
    "google.never_logged_in_user",
    "google.chromeos_device_past_aue",
    "google.mobile_device_encryption_off",
    "google.internal_domains_unknown",
    "google.evidence_unknown",
}


def _ago(days: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ahead(days: int) -> str:
    return (datetime.now(tz=timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _snapshot(
    *,
    domain: str | None = "example.com",
    users: list[dict[str, Any]] | None = None,
    domains: list[dict[str, Any]] | None = None,
    directory_extra: dict[str, Any] | None = None,
    org_units: list[dict[str, Any]] | None = None,
    policies: list[dict[str, Any]] | None = None,
    mobile: list[dict[str, Any]] | None = None,
    chromeos: list[dict[str, Any]] | None = None,
    gmail: list[dict[str, Any]] | None = None,
    drive: list[dict[str, Any]] | None = None,
    calendar_acls: list[dict[str, Any]] | None = None,
    group_members: list[dict[str, Any]] | None = None,
    coverage_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payloads: dict[str, dict[str, Any]] = {"google_directory": dict(directory_extra or {})}
    if users is not None:
        payloads["google_directory"]["users"] = {"value": users}
    if domains is not None:
        payloads["google_directory"]["domains"] = {"value": domains}
    if org_units is not None:
        payloads["google_directory"]["orgUnits"] = {"value": org_units}
    if group_members is not None:
        payloads["google_directory"]["groupMembers"] = {"value": group_members}
    if policies is not None:
        payloads["google_policies"] = {"twoStepVerificationPolicies": {"value": policies}}
    if mobile is not None or chromeos is not None:
        payloads["google_devices"] = {"mobileDevices": {"value": mobile or []}, "chromeosDevices": {"value": chromeos or []}}
    if gmail is not None:
        payloads["google_gmail_settings"] = {"mailboxSettings": {"value": gmail}}
    if drive is not None:
        payloads["google_drive_posture"] = {"driveFiles": {"value": drive}}
    if calendar_acls is not None:
        payloads["google_calendar_posture"] = {"calendarAcls": {"value": calendar_acls}}
    return build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        domain=domain,
        customer_id="C123",
        collector_payloads=payloads,
        coverage_rows=coverage_rows,
    )


def _rules(findings: list[dict[str, Any]]) -> list[str]:
    return [item["rule_id"] for item in findings]


def _by_rule(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [item for item in findings if item["rule_id"] == rule_id]


def _user(email: str, **fields: Any) -> dict[str, Any]:
    return {"id": f"id-{email}", "primaryEmail": email, "isAdmin": False, "suspended": False, **fields}


# ---- subject scope: Gmail settings are read per user, Drive and Calendar are labelled -----------------


class _GmailClient:
    """A client with the per-user surface of the real one; ``delegated`` decides whether it can act as a user."""

    def __init__(self, emails: list[str], *, delegated: bool, fail_for: set[str] | None = None) -> None:
        self.emails = emails
        self.per_user_delegation = delegated
        self.fail_for = fail_for or set()
        self.read: list[str] = []

    def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
        return [_user(email) for email in self.emails] if resource == "users" else []

    def get_gmail_settings_for_user(self, user_email: str) -> dict[str, Any]:
        self.read.append(user_email)
        if user_email in self.fail_for:
            raise RuntimeError(f"403 delegation denied for {user_email}")
        return {"userEmail": user_email, "autoForwarding": {"enabled": False}}


def test_gmail_settings_are_read_as_each_user_and_labelled_user_scoped() -> None:
    client = _GmailClient(["a@example.com", "b@example.com", "c@example.com"], delegated=True)

    result = GoogleGmailSettingsCollector().run({"client": client})

    assert client.read == ["a@example.com", "b@example.com", "c@example.com"]
    assert result.status == "ok"
    rows = [row for row in result.coverage if row["name"].startswith("mailboxSettings:")]
    assert len(rows) == 3 and {row["subject_scoped"] for row in rows} == {"user"}


def test_suspended_mailboxes_are_skipped_and_the_skip_is_recorded() -> None:
    client = _GmailClient(["a@example.com"], delegated=True)
    client.list_directory = lambda resource, **_k: [  # type: ignore[method-assign]
        _user("a@example.com"),
        _user("gone@example.com", suspended=True),
        _user("old@example.com", archived=True),
    ]

    result = GoogleGmailSettingsCollector().run({"client": client})

    assert client.read == ["a@example.com"]
    skipped = next(row for row in result.coverage if row["name"] == "mailboxSettingsSkipped")
    assert skipped["status"] == "ok" and skipped["skipped_suspended"] == 2 and "not read" in skipped["note"]


def test_the_mailbox_fan_out_is_bounded_and_the_cut_is_a_coverage_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(google_collectors, "MAILBOX_FANOUT_LIMIT", 3)
    client = _GmailClient([f"u{i}@example.com" for i in range(5)], delegated=True)

    result = GoogleGmailSettingsCollector().run({"client": client})

    assert len(client.read) == 3
    gap = next(row for row in result.coverage if row["name"] == "mailboxSettingsFanout")
    assert gap["status"] == "partial" and gap["truncation_reason"] == "fanout_limit" and gap["fanout_total"] == 5
    assert result.status == "partial"
    # An operator limit above the user count raises the bound, so the same domain reads in full.
    full = _GmailClient([f"u{i}@example.com" for i in range(5)], delegated=True)
    assert GoogleGmailSettingsCollector().run({"client": full, "top": 10}).status == "ok" and len(full.read) == 5
    assert MAILBOX_FANOUT_LIMIT == 500


def test_without_delegation_only_the_signed_in_mailbox_is_read_and_it_is_labelled_admin() -> None:
    client = _GmailClient(["a@example.com", "b@example.com"], delegated=False)

    result = GoogleGmailSettingsCollector().run({"client": client})

    assert client.read == ["me"]
    scope = next(row for row in result.coverage if row["name"] == "mailboxSettingsScope")
    assert scope["status"] == "partial" and scope["error_class"] == "subject_scope" and scope["subject_scoped"] == "admin"
    assert "other 2 users" in scope["error"]
    assert next(row for row in result.coverage if row["name"] == "mailboxSettings:me")["subject_scoped"] == "admin"
    assert result.status == "partial"


def test_a_missing_delegation_raises_one_finding_that_says_to_use_domain_wide_delegation() -> None:
    client = _GmailClient([f"u{i}@example.com" for i in range(4)], delegated=False)
    result = GoogleGmailSettingsCollector().run({"client": client})
    diagnostics = [row for row in result.coverage if row.get("status") != "ok"]
    snapshot = _snapshot(
        gmail=[{"userEmail": "me", "imap": {"enabled": True}}], coverage_rows=result.coverage
    )

    findings = build_google_findings(snapshot, diagnostics=diagnostics)

    (issue,) = _by_rule(findings, "google.collector_issue")
    assert issue["id"] == "google.collector_issue:google_gmail_settings:mailboxSettingsScope"
    assert "domain-wide delegation" in issue["remediation"]
    # Evidence from the signed-in mailbox alone is never presented as the domain's.
    imap = _by_rule(findings, "google.gmail_imap_enabled")[0]
    assert imap["subject_scoped"] == "admin" and "not a tenant-wide statement" in imap["description"]
    assert snapshot["snapshot"]["subject_scope"]["google_gmail_settings"] == "admin"


def test_drive_and_calendar_coverage_capability_and_findings_say_they_are_admin_scoped() -> None:
    class Client:
        def list_drive_files(self, **_k: Any) -> list[dict[str, Any]]:
            return [
                {
                    "id": "f1",
                    "name": "Plan",
                    "permissions": [{"id": "p1", "type": "anyone", "role": "reader", "allowFileDiscovery": False}],
                }
            ]

        def list_shared_drives(self, **_k: Any) -> list[dict[str, Any]]:
            return []

        def list_calendar_resources(self, **_k: Any) -> list[dict[str, Any]]:
            return [{"resourceId": "room-1", "resourceEmail": "room@example.com"}]

        def list_calendar_list(self, **_k: Any) -> list[dict[str, Any]]:
            return [{"id": "primary@example.com"}]

        def list_calendar_acl(self, calendar_id: str, **_k: Any) -> list[dict[str, Any]]:
            return [{"id": "default", "role": "reader", "scope": {"type": "default"}}]

    drive = GoogleDrivePostureCollector().run({"client": Client()})
    calendar = GoogleCalendarPostureCollector().run({"client": Client()})

    labelled = {row["name"]: row.get("subject_scoped") for row in [*drive.coverage, *calendar.coverage]}
    assert labelled["driveFiles"] == labelled["sharedDrives"] == labelled["calendars"] == "admin"
    assert labelled["calendarAcls:primary@example.com"] == "admin"
    # The resource directory is a tenant-wide Directory inventory, not the admin's view.
    assert labelled["calendarResources"] is None

    snapshot = _snapshot(
        drive=drive.payload["driveFiles"]["value"],
        calendar_acls=[{"calendarId": "primary@example.com", **row} for row in calendar.payload["calendarAcls"]["value"]],
        coverage_rows=[*drive.coverage, *calendar.coverage],
    )
    findings = build_google_findings(snapshot)
    scoped = [item for item in findings if item["collector"] in {"google_drive_posture", "google_calendar_posture"}]
    assert {item["rule_id"] for item in scoped} == {"google.drive_anyone_with_link", "google.calendar_public_acl"}
    assert all(item["subject_scoped"] == "admin" and "delegated admin subject" in item["evidence_scope"] for item in scoped)
    assert snapshot["snapshot"]["subject_scope"] == {"google_calendar_posture": "admin", "google_drive_posture": "admin"}

    rows = build_google_capability_rows(
        ["google_drive_posture", "google_calendar_posture", "google_directory"],
        auth_mode="domain-delegation",
        dependency_status={"available": True},
        coverage_rows=[*drive.coverage, *calendar.coverage],
    )
    by_collector = {row["collector"]: row for row in rows}
    assert by_collector["google_drive_posture"]["subject_scoped"] == by_collector["google_calendar_posture"]["subject_scoped"] == "admin"
    assert "not tenant-wide" in by_collector["google_drive_posture"]["notes"]
    assert "subject_scoped" not in by_collector["google_directory"]


def test_gmail_capability_row_is_user_scoped_with_delegation_and_admin_scoped_without() -> None:
    delegated = GoogleGmailSettingsCollector().run({"client": _GmailClient(["a@example.com"], delegated=True)})
    undelegated = GoogleGmailSettingsCollector().run({"client": _GmailClient(["a@example.com"], delegated=False)})

    def scope(result: Any) -> str:
        (row,) = build_google_capability_rows(
            ["google_gmail_settings"],
            auth_mode="domain-delegation",
            dependency_status={"available": True},
            coverage_rows=result.coverage,
        )
        return row["subject_scoped"]

    assert scope(delegated) == "user"
    assert scope(undelegated) == "admin"


def test_auth_context_states_the_subject_scope_per_selected_collector() -> None:
    config = GoogleRunConfig(tenant_name="T", out=Path("."), collector_preset="everything", subject="admin@example.com")
    delegated = google_auth.GoogleAuthConfig(auth_mode="domain-delegation", scopes=("s",), subject="admin@example.com")
    oauth = google_auth.GoogleAuthConfig(auth_mode="oauth", scopes=("s",))

    with_delegation = google_run.build_google_auth_context_payload(config, delegated)
    without = google_run.build_google_auth_context_payload(config, oauth)

    assert with_delegation["per_user_delegation"] is True and without["per_user_delegation"] is False
    assert with_delegation["subject_scope"] == {
        "google_drive_posture": "admin",
        "google_calendar_posture": "admin",
        "google_gmail_settings": "user",
    }
    assert without["subject_scope"]["google_gmail_settings"] == "admin"


# ---- the real client acts as each user and keeps the credentials apart ---------------------------------


class _Credentials:
    def __init__(self, subject: str | None = None, scopes: tuple[str, ...] = ()) -> None:
        self.subject = subject
        self.scopes = scopes

    def with_subject(self, subject: str) -> "_Credentials":
        return _Credentials(subject, self.scopes)

    def with_scopes(self, scopes: list[str]) -> "_Credentials":
        return _Credentials(self.subject, tuple(scopes))


class _Request:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def execute(self) -> dict[str, Any]:
        return self.payload


class _Listing:
    def __init__(self, key: str, rows: list[dict[str, Any]], calls: list[dict[str, Any]]) -> None:
        self.key, self.rows, self.calls = key, rows, calls

    def list(self, **kwargs: Any) -> _Request:
        self.calls.append(kwargs)
        size = kwargs.get("pageSize") or 100
        start = int(kwargs.get("pageToken") or 0)
        payload: dict[str, Any] = {self.key: self.rows[start : start + size]}
        if start + size < len(self.rows):
            payload["nextPageToken"] = str(start + size)
        return _Request(payload)


class _FakeGmailService:
    def __init__(self, owner: str) -> None:
        self.owner = owner

    def users(self) -> "_FakeGmailService":
        return self

    def settings(self) -> "_FakeGmailService":
        return self

    def getAutoForwarding(self, **_k: Any) -> _Request:  # noqa: N802
        return _Request({"enabled": False})

    def getImap(self, **_k: Any) -> _Request:  # noqa: N802
        return _Request({"enabled": False})

    def getPop(self, **_k: Any) -> _Request:  # noqa: N802
        return _Request({"accessWindow": "disabled"})

    def getVacation(self, **_k: Any) -> _Request:  # noqa: N802
        return _Request({"enableAutoReply": False})

    def filters(self) -> Any:
        return _Listing("filter", [], [])

    def forwardingAddresses(self) -> Any:  # noqa: N802
        return _Listing("forwardingAddresses", [], [])

    def sendAs(self) -> Any:  # noqa: N802
        return _Listing("sendAs", [], [])

    def delegates(self) -> Any:
        return _Listing("delegates", [], [])


@pytest.fixture
def fake_discovery(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Stand in for ``googleapiclient.discovery.build``; each call is recorded with its credentials."""
    built: list[dict[str, Any]] = []

    def build(api: str, version: str, *, credentials: Any, cache_discovery: bool) -> Any:
        built.append({"api": api, "version": version, "credentials": credentials})
        return _FakeGmailService(getattr(credentials, "subject", None) or "shared")

    package = types.ModuleType("googleapiclient")
    discovery = types.ModuleType("googleapiclient.discovery")
    discovery.build = build  # type: ignore[attr-defined]
    package.discovery = discovery  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "googleapiclient", package)
    monkeypatch.setitem(sys.modules, "googleapiclient.discovery", discovery)
    return built


def test_a_delegated_client_acts_as_each_user_and_a_non_delegated_one_never_does(fake_discovery: list[dict[str, Any]]) -> None:
    admin = _Credentials("admin@example.com", ("https://www.googleapis.com/auth/admin.directory.user.security", "https://www.googleapis.com/auth/drive.readonly"))
    delegated = GoogleWorkspaceClient(admin, delegated=True)

    one = delegated.get_gmail_settings_for_user("a@example.com")
    two = delegated.get_gmail_settings_for_user("b@example.com")
    delegated.get_gmail_settings_for_user("a@example.com")

    assert one["userEmail"] == "a@example.com" and two["userEmail"] == "b@example.com"
    assert [item["credentials"].subject for item in fake_discovery] == ["a@example.com", "b@example.com"]
    assert admin.subject == "admin@example.com"  # the admin credentials were copied, not changed
    # The token that can act as any user holds the two Gmail settings scopes and nothing else.
    shared = ("https://www.googleapis.com/auth/admin.directory.user.security", "https://www.googleapis.com/auth/drive.readonly")
    for item in fake_discovery:
        assert item["credentials"].scopes == google_auth.GMAIL_SETTINGS_SCOPES
        assert not set(item["credentials"].scopes) & set(shared)
    assert google_auth.GMAIL_SETTINGS_SCOPES == (
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.settings.sharing",
    )
    assert delegated.per_user_delegation is True

    fake_discovery.clear()
    oauth = GoogleWorkspaceClient(_Credentials(), delegated=False)
    oauth.get_gmail_settings_for_user("me")
    assert [item["credentials"].subject for item in fake_discovery] == [None]
    assert oauth.per_user_delegation is False
    # A delegated flag without credentials that can act as someone else is not delegation.
    assert GoogleWorkspaceClient(object(), delegated=True).per_user_delegation is False


def test_per_user_services_are_cached_in_a_small_bounded_window(fake_discovery: list[dict[str, Any]]) -> None:
    client = GoogleWorkspaceClient(_Credentials("admin@example.com"), delegated=True)

    for index in range(20):
        client.get_gmail_settings_for_user(f"u{index}@example.com")

    assert isinstance(client._subject_services, OrderedDict) and len(client._subject_services) <= 8
    assert len(fake_discovery) == 20


def test_user_delegated_credentials_are_narrowed_only_when_asked() -> None:
    admin = _Credentials("admin@example.com", ("wide-a", "wide-b"))

    kept = google_auth.user_delegated_credentials(admin, "a@example.com")
    narrowed = google_auth.user_delegated_credentials(admin, "a@example.com", scopes=("only-this",))

    assert kept.scopes == ("wide-a", "wide-b") and narrowed.scopes == ("only-this",)
    assert narrowed.subject == "a@example.com" and admin.scopes == ("wide-a", "wide-b")


def test_user_delegated_credentials_refuse_what_cannot_act_as_a_user() -> None:
    assert google_auth.user_delegated_credentials(_Credentials(), "a@example.com").subject == "a@example.com"
    with pytest.raises(ValueError, match="not an email"):
        google_auth.user_delegated_credentials(_Credentials(), "a")
    with pytest.raises(ValueError, match="domain-wide delegation is required"):
        google_auth.user_delegated_credentials(object(), "a@example.com")
    assert google_auth.GoogleAuthConfig(auth_mode="domain-delegation").supports_user_delegation is True
    assert google_auth.GoogleAuthConfig(auth_mode="oauth").supports_user_delegation is False
    assert google_auth.safe_auth_summary(google_auth.GoogleAuthConfig(auth_mode="oauth"))["per_user_delegation"] is False


# ---- Directory lists use the customer and the domain flag is a label ----------------------------------


def test_users_and_groups_are_listed_for_the_customer_whatever_the_domain_flag() -> None:
    calls: list[dict[str, Any]] = []
    client = GoogleWorkspaceClient(credentials=None, page_size=100)
    assert client._services is not None
    client._services[("admin", "directory_v1")] = types.SimpleNamespace(
        users=lambda: _Listing("users", [{"primaryEmail": "a@example.org"}], calls),
        groups=lambda: _Listing("groups", [{"email": "g@example.net"}], calls),
    )

    users = client.list_directory("users")
    groups = client.list_directory("groups")

    assert [row["primaryEmail"] for row in users] == ["a@example.org"] and [row["email"] for row in groups] == ["g@example.net"]
    assert len(calls) == 2
    for call in calls:
        assert call["customer"] == "my_customer"
        assert "domain" not in call
    assert not hasattr(client, "domain")


# ---- internal domains from domains.list ----------------------------------------------------------------


_DOMAINS = [
    {"domainName": "example.com", "isPrimary": True, "verified": True},
    {
        "domainName": "example.org",
        "isPrimary": False,
        "verified": True,
        "domainAliases": [{"domainAliasName": "example.net", "parentDomainName": "example.org", "verified": True}],
    },
]


def test_the_internal_domain_set_is_primary_secondary_and_alias_domains() -> None:
    snapshot = _snapshot(domain=None, domains=_DOMAINS)

    records = {item["domain_name"]: item for item in snapshot["google_domains"]["records"]}
    assert {name: item["domain_kind"] for name, item in records.items()} == {
        "example.com": "primary",
        "example.org": "secondary",
        "example.net": "alias",
    }
    assert records["example.net"]["parent_domain"] == "example.org"
    assert snapshot["snapshot"]["internal_domains"] == ["example.com", "example.net", "example.org"]
    assert snapshot["snapshot"]["internal_domains_status"] == "known"
    assert snapshot["snapshot"]["internal_domains_source"] == "directory"
    assert snapshot["snapshot"]["object_counts"]["google_domains"] == 3


def test_the_domain_label_joins_the_directory_set_and_never_replaces_it() -> None:
    snapshot = _snapshot(domain="extra.example", domains=_DOMAINS)

    assert snapshot["snapshot"]["internal_domains"] == ["example.com", "example.net", "example.org", "extra.example"]
    assert snapshot["snapshot"]["internal_domains_source"] == "directory+label"


def test_external_principal_checks_treat_every_internal_domain_as_internal() -> None:
    snapshot = _snapshot(
        domain=None,
        domains=_DOMAINS,
        gmail=[
            {
                "userEmail": "a@example.com",
                "autoForwarding": {"enabled": True, "emailAddress": "partner@example.net"},
                "delegates": [
                    {"delegateEmail": "assistant@example.org", "verificationStatus": "accepted"},
                    {"delegateEmail": "outsider@other.test", "verificationStatus": "accepted"},
                ],
            }
        ],
        drive=[
            {
                "id": "f1",
                "name": "Plan",
                "permissions": [
                    {"id": "p1", "type": "user", "role": "reader", "emailAddress": "colleague@example.net"},
                    {"id": "p2", "type": "domain", "role": "reader", "domain": "example.org"},
                    {"id": "p3", "type": "domain", "role": "reader", "domain": "other.test"},
                ],
            }
        ],
        group_members=[
            {"groupEmail": "all@example.com", "id": "m1", "email": "alias-user@example.net"},
            {"groupEmail": "all@example.com", "id": "m2", "email": "stranger@other.test"},
        ],
        calendar_acls=[
            {"calendarId": "c", "id": "d1", "role": "reader", "scope": {"type": "domain", "value": "example.net"}},
            {"calendarId": "c", "id": "u1", "role": "reader", "scope": {"type": "user", "value": "x@other.test"}},
        ],
    )

    findings = build_google_findings(snapshot)

    assert "google.gmail_external_forwarding" not in _rules(findings)
    (delegate,) = _by_rule(findings, "google.gmail_external_delegate")
    assert delegate["returned_value"] == "outsider@other.test"
    external = _by_rule(findings, "google.drive_external_permission")
    assert [item["returned_value"]["permission"]["id"] for item in external] == ["p3"]
    assert [item["returned_value"]["permission"]["id"] for item in _by_rule(findings, "google.drive_domain_permission")] == ["p2"]
    (member,) = _by_rule(findings, "google.group_external_member")
    assert member["returned_value"]["member"] == "stranger@other.test"
    assert sorted(item["rule_id"] for item in findings if item["rule_id"].startswith("google.calendar_")) == [
        "google.calendar_domain_acl",
        "google.calendar_external_acl",
    ]
    external_acl = _by_rule(findings, "google.calendar_external_acl")[0]
    assert external_acl["returned_value"]["scope"]["value"] == "x@other.test"
    assert "google.internal_domains_unknown" not in _rules(findings)


def test_without_a_domain_flag_or_a_domain_list_the_external_checks_are_unknown_not_silent() -> None:
    snapshot = _snapshot(
        domain=None,
        gmail=[{"userEmail": "a@example.com", "autoForwarding": {"enabled": True, "emailAddress": "outside@other.test"}}],
        drive=[{"id": "f1", "name": "Plan", "permissions": [{"id": "p1", "type": "user", "role": "reader", "emailAddress": "x@other.test"}]}],
    )

    findings = build_google_findings(snapshot)

    assert snapshot["snapshot"]["internal_domains_status"] == "unknown" and snapshot["snapshot"]["internal_domains"] == []
    assert "google.gmail_external_forwarding" not in _rules(findings)
    assert "google.drive_external_permission" not in _rules(findings)
    (unknown,) = _by_rule(findings, "google.internal_domains_unknown")
    assert unknown["returned_value"]["status"] == "unknown"
    assert "google.gmail_external_forwarding" in unknown["returned_value"]["rules_affected"]
    assert "were not evaluated" in unknown["description"]
    refs = {ref["artifact_path"] for ref in unknown["evidence_refs"]}
    assert refs == {"normalized/google_mailbox_settings.json", "normalized/google_drive_files.json"}


def test_with_only_the_label_the_checks_run_and_the_limit_is_reported() -> None:
    snapshot = _snapshot(
        domain="example.com",
        gmail=[{"userEmail": "a@example.com", "autoForwarding": {"enabled": True, "emailAddress": "outside@other.test"}}],
    )

    findings = build_google_findings(snapshot)

    assert snapshot["snapshot"]["internal_domains_status"] == "label_only"
    assert "google.gmail_external_forwarding" in _rules(findings)
    (unknown,) = _by_rule(findings, "google.internal_domains_unknown")
    assert unknown["returned_value"]["internal_domains"] == ["example.com"]
    assert "secondary or alias domain address may be reported as external" in unknown["description"]


@pytest.mark.parametrize(
    "row",
    [
        {"collector": "google_directory", "name": "domains", "status": "partial", "collection_truncated": True, "error_class": "collection_limit"},
        {"collector": "google_directory", "name": "domains", "status": "failed", "error_class": "client_error"},
        {"collector": "google_directory", "name": "domains", "status": "ok", "collection_truncated": True},
    ],
)
def test_a_cut_or_partly_read_domains_list_is_partial_and_runs_the_rules_with_a_warning(row: dict[str, Any]) -> None:
    snapshot = _snapshot(
        domain=None,
        domains=[{"domainName": "example.com", "isPrimary": True, "verified": True}],
        coverage_rows=[row],
        group_members=[
            {"groupEmail": "all@example.com", "id": "m1", "email": "person@example.org"},
            {"groupEmail": "all@example.com", "id": "m2", "email": "stranger@other.test"},
        ],
    )

    findings = build_google_findings(snapshot)

    assert snapshot["snapshot"]["internal_domains_status"] == "partial"
    assert snapshot["snapshot"]["internal_domains"] == ["example.com"]
    # The rules run against what is known, like the label-only case, so the secondary domain's member is
    # reported; the diagnostic says that finding may be an internal address on a domain that was not listed.
    assert sorted(item["returned_value"]["member"] for item in _by_rule(findings, "google.group_external_member")) == [
        "person@example.org",
        "stranger@other.test",
    ]
    (diagnostic,) = _by_rule(findings, "google.internal_domains_unknown")
    assert diagnostic["returned_value"]["status"] == "partial"
    assert "cut short or only partly read" in diagnostic["description"]
    assert "google.group_external_member" in diagnostic["returned_value"]["rules_affected"]


def test_a_cut_domains_list_in_an_offline_payload_is_partial_too() -> None:
    snapshot = _snapshot(
        domain="example.com",
        directory_extra={"domains": {"value": [{"domainName": "example.com", "isPrimary": True}], "collection_truncated": True}},
    )

    assert snapshot["snapshot"]["internal_domains_status"] == "partial"


def test_a_domains_list_that_was_read_in_full_stays_known_whatever_else_failed() -> None:
    snapshot = _snapshot(
        domain=None,
        domains=_DOMAINS,
        coverage_rows=[
            {"collector": "google_directory", "name": "domains", "status": "ok", "collection_truncated": False},
            {"collector": "google_directory", "name": "users", "status": "partial", "collection_truncated": True},
            {"collector": "google_dns_posture", "name": "domains", "status": "failed"},
        ],
    )

    assert snapshot["snapshot"]["internal_domains_status"] == "known"


def test_no_unknown_domain_finding_when_nothing_needs_the_domain_set() -> None:
    snapshot = _snapshot(domain=None, users=[_user("a@example.com", isEnforcedIn2Sv=True, lastLoginTime=_ago(1))])

    assert "google.internal_domains_unknown" not in _rules(build_google_findings(snapshot))


# ---- privileged flag: delegated admins get the admin severity ------------------------------------------


def test_every_user_row_carries_the_privileged_flag() -> None:
    snapshot = _snapshot(
        users=[
            _user("super@example.com", isAdmin=True),
            _user("delegated@example.com", isDelegatedAdmin=True),
            _user("plain@example.com"),
        ]
    )

    flags = {row["primary_email"]: (row["is_admin"], row["is_delegated_admin"], row["is_privileged"]) for row in snapshot["google_users"]["records"]}
    assert flags == {
        "super@example.com": (True, False, True),
        "delegated@example.com": (False, True, True),
        "plain@example.com": (False, False, False),
    }


def test_a_delegated_admin_gets_the_admin_rules_and_severities() -> None:
    snapshot = _snapshot(
        users=[
            _user(
                "delegated@example.com",
                isDelegatedAdmin=True,
                isEnrolledIn2Sv=False,
                isEnforcedIn2Sv=False,
                lastLoginTime=_ago(400),
            ),
            _user("gone@example.com", isDelegatedAdmin=True, suspended=True, isEnforcedIn2Sv=True, lastLoginTime=_ago(1)),
        ]
    )

    findings = build_google_findings(snapshot)

    by_rule = {(item["rule_id"], item["affected_objects"][0]): item["severity"] for item in findings}
    assert by_rule[("google.admin_2sv_not_enforced", "delegated@example.com")] == "high"
    assert by_rule[("google.admin_2sv_not_enrolled", "delegated@example.com")] == "high"
    assert ("google.admin_stale_login", "delegated@example.com") in by_rule
    assert ("google.suspended_admin", "gone@example.com") in by_rule
    # The ordinary-user rules do not also fire for a privileged account.
    assert not {"google.user_2sv_not_enrolled", "google.user_2sv_not_enforced", "google.stale_user"} & set(_rules(findings))


def test_super_admin_counts_stay_on_is_admin_alone() -> None:
    delegated_only = _snapshot(users=[_user(f"d{i}@example.com", isDelegatedAdmin=True) for i in range(7)])
    one_super = _snapshot(users=[_user("s@example.com", isAdmin=True), _user("d@example.com", isDelegatedAdmin=True)])

    assert not {"google.super_admin_sprawl", "google.super_admin_singleton"} & set(_rules(build_google_findings(delegated_only)))
    assert "google.super_admin_singleton" in _rules(build_google_findings(one_super))


# ---- 2-step verification: enforcement against enrolment, and the organisation policy --------------------


def test_a_user_who_enrolled_but_is_not_forced_is_reported_as_not_enforced() -> None:
    snapshot = _snapshot(
        users=[
            _user("enrolled@example.com", isEnrolledIn2Sv=True, isEnforcedIn2Sv=False, lastLoginTime=_ago(1)),
            _user("forced@example.com", isEnrolledIn2Sv=True, isEnforcedIn2Sv=True, lastLoginTime=_ago(1)),
            _user("suspended@example.com", isEnforcedIn2Sv=False, suspended=True),
        ],
        policies=[],
    )

    findings = build_google_findings(snapshot)

    (not_enforced,) = _by_rule(findings, "google.user_2sv_not_enforced")
    assert not_enforced["affected_objects"] == ["enrolled@example.com"] and not_enforced["severity"] == "medium"
    assert not_enforced["returned_value"] == {
        "user": "enrolled@example.com",
        "enrolled": True,
        "enforced": False,
        "org_policy": "not_enforced",
    }
    assert "google.user_2sv_not_enrolled" not in _rules(findings)


def test_the_user_enforcement_rule_is_unknown_when_google_returns_no_enforcement_flag() -> None:
    snapshot = _snapshot(users=[_user("a@example.com", isEnrolledIn2Sv=True, lastLoginTime=_ago(1)), _user("b@example.com", lastLoginTime=_ago(1))])

    findings = build_google_findings(snapshot)

    assert "google.user_2sv_not_enforced" not in _rules(findings)
    (unknown,) = _by_rule(findings, "google.evidence_unknown")
    assert unknown["id"] == "google.evidence_unknown:user_2sv_enforcement"
    assert unknown["returned_value"]["objects_without_field"] == 2 and unknown["returned_value"]["objects_total"] == 2
    assert unknown["returned_value"]["rules_not_evaluated"] == ["google.user_2sv_not_enforced"]


def _policy(
    setting: str, *, enforced_from: str | None = None, org_unit: str = "orgUnits/root", group: str = "", **value: Any
) -> dict[str, Any]:
    body = dict(value)
    if enforced_from:
        body["enforcedFrom"] = enforced_from
    return {
        "name": f"policies/{setting}-{org_unit.split('/')[-1]}{('-' + group.split('/')[-1]) if group else ''}",
        "customer": "customers/C123",
        "policyQuery": {"orgUnit": org_unit, "group": group, "sortOrder": 1},
        "setting": {"type": f"settings/security.{setting}", "value": body},
        "type": "ADMIN",
    }


_ROOT_ONLY: list[dict[str, Any]] = []  # an org unit list that was read and is empty: the root is the only unit
_WITH_SALES = [{"orgUnitId": "id:sales", "parentOrgUnitId": "id:root", "parentOrgUnitPath": "/", "orgUnitPath": "/Sales"}]
_ENFORCING = "2020-01-01T00:00:00Z"


@pytest.mark.parametrize(
    ("policies", "org_units", "status"),
    [
        ([_policy("two_step_verification_enforcement", enforced_from=_ENFORCING)], _ROOT_ONLY, "enforcing"),
        ([_policy("two_step_verification_enforcement", enforced_from="2099-01-01T00:00:00Z")], _ROOT_ONLY, "scheduled"),
        ([_policy("two_step_verification_enforcement")], _ROOT_ONLY, "not_enforced"),
        ([_policy("two_step_verification_enrollment", allowEnrollment=True)], _ROOT_ONLY, "not_enforced"),
        ([], _ROOT_ONLY, "not_enforced"),
        # With sub-units the root is the parent of the top-level unit, and only its policy is organisation-wide.
        ([_policy("two_step_verification_enforcement", enforced_from=_ENFORCING, org_unit="orgUnits/root")], _WITH_SALES, "enforcing"),
        (
            [
                _policy("two_step_verification_enforcement", org_unit="orgUnits/root"),
                _policy("two_step_verification_enforcement", enforced_from=_ENFORCING, org_unit="orgUnits/sales"),
            ],
            _WITH_SALES,
            "partial",
        ),
        ([_policy("two_step_verification_enforcement", enforced_from=_ENFORCING, org_unit="orgUnits/sales")], _WITH_SALES, "partial"),
        # A group-scoped policy at the root unit is not the organisation's.
        ([_policy("two_step_verification_enforcement", enforced_from=_ENFORCING, group="groups/staff")], _ROOT_ONLY, "partial"),
        # The root unit cannot be told without the org unit list, so an enforcing policy cannot be placed.
        ([_policy("two_step_verification_enforcement", enforced_from=_ENFORCING)], None, "unknown"),
    ],
)
def test_the_organisation_policy_status_needs_the_organisation_level_policy_to_enforce(
    policies: list[dict[str, Any]], org_units: list[dict[str, Any]] | None, status: str
) -> None:
    snapshot = _snapshot(policies=policies, org_units=org_units)

    assert snapshot["snapshot"]["two_step_policy_status"] == status
    findings = build_google_findings(snapshot)
    assert bool(_by_rule(findings, "google.org_2sv_policy_not_enforced")) is (status in {"not_enforced", "partial"})


def test_a_partial_policy_finding_names_the_units_that_are_enforced() -> None:
    snapshot = _snapshot(
        policies=[
            _policy("two_step_verification_enforcement", org_unit="orgUnits/root"),
            _policy("two_step_verification_enforcement", enforced_from=_ENFORCING, org_unit="orgUnits/sales"),
            _policy("two_step_verification_enforcement", enforced_from=_ENFORCING, group="groups/staff"),
        ],
        org_units=_WITH_SALES,
    )

    records = {item["id"]: item["policy_scope"] for item in snapshot["google_two_step_policies"]["records"]}
    assert sorted(records.values()) == ["group", "org_unit", "organisation"]
    (finding,) = _by_rule(build_google_findings(snapshot), "google.org_2sv_policy_not_enforced")
    assert finding["severity"] == "medium"
    assert finding["returned_value"]["status"] == "partial" and finding["returned_value"]["organisation_level"] == "not in force"
    assert sorted(item["scope"] for item in finding["returned_value"]["enforced_scopes"]) == ["group", "org_unit"]
    assert "only some organisational units or groups" in finding["description"]
    # The enforcing policies are cited beside the first record, and every cited record exists.
    keys = {ref["record_key"] for ref in finding["evidence_refs"]}
    assert keys <= {f"google_two_step_policy:{name}" for name in records}
    assert len(keys) >= 2


def test_a_policy_status_with_a_failed_org_unit_read_cannot_place_an_enforcing_policy() -> None:
    snapshot = _snapshot(
        policies=[_policy("two_step_verification_enforcement", enforced_from=_ENFORCING)],
        org_units=[],
        coverage_rows=[{"collector": "google_directory", "name": "orgUnits", "status": "failed", "error_class": "client_error"}],
    )

    assert snapshot["snapshot"]["two_step_policy_status"] == "unknown"
    assert snapshot["google_two_step_policies"]["records"][0]["policy_scope"] == "unclassified"


def test_an_unreadable_or_absent_policy_read_is_unknown_not_not_enforced() -> None:
    failed = _snapshot(
        policies=[],
        coverage_rows=[{"collector": "google_policies", "name": "twoStepVerificationPolicies", "status": "failed", "error_class": "insufficient_permissions"}],
    )
    cut = _snapshot(
        policies=[_policy("two_step_verification_enrollment", allowEnrollment=True)],
        coverage_rows=[{"collector": "google_policies", "name": "twoStepVerificationPolicies", "status": "partial", "collection_truncated": True}],
    )
    never_ran = _snapshot(users=[_user("a@example.com")])

    for snapshot in (failed, cut, never_ran):
        assert snapshot["snapshot"]["two_step_policy_status"] == "unknown"
        assert "google.org_2sv_policy_not_enforced" not in _rules(build_google_findings(snapshot))


def test_the_policy_finding_cites_a_record_that_exists() -> None:
    with_policy = build_google_findings(_snapshot(policies=[_policy("two_step_verification_enforcement")]))
    without = build_google_findings(_snapshot(policies=[]))

    (cited,) = _by_rule(with_policy, "google.org_2sv_policy_not_enforced")
    (stand_in,) = _by_rule(without, "google.org_2sv_policy_not_enforced")
    assert cited["evidence_refs"][0]["artifact_path"] == "normalized/google_two_step_policies.json"
    assert stand_in["evidence_refs"][0]["record_key"] == "coverage_ledger:google_policies"
    assert cited["severity"] == "high"


def test_policy_records_are_normalised_with_their_scope_and_enforcement_date() -> None:
    snapshot = _snapshot(
        policies=[
            _policy("two_step_verification_enforcement", enforced_from="2020-01-01T00:00:00Z", org_unit="orgUnits/sales"),
            _policy("two_step_verification_enforcement_factor", allowedSignInFactorSet="PASSKEY_ONLY"),
            _policy("two_step_verification_grace_period", enrollmentGracePeriod="604800s"),
        ]
    )

    records = {item["setting_type"]: item for item in snapshot["google_two_step_policies"]["records"]}
    assert records["security.two_step_verification_enforcement"]["policy_scope"] == "unclassified"  # no org unit list
    assert records["security.two_step_verification_enforcement"]["org_unit"] == "orgUnits/sales"
    assert records["security.two_step_verification_enforcement"]["enforced_from"] == "2020-01-01T00:00:00Z"
    assert records["security.two_step_verification_enforcement_factor"]["allowed_sign_in_factor_set"] == "PASSKEY_ONLY"
    assert records["security.two_step_verification_grace_period"]["enrollment_grace_period"] == "604800s"


def test_the_policies_collector_and_client_read_the_cloud_identity_policies(fake_discovery: list[dict[str, Any]]) -> None:
    class Policies:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def policies(self) -> Any:
            return _Listing("policies", [_policy("two_step_verification_enforcement") for _ in range(3)], self.calls)

    service = Policies()
    client = GoogleWorkspaceClient(_Credentials("admin@example.com"), customer_id="C123", page_size=2, delegated=True)
    assert client._services is not None
    client._services[("cloudidentity", "v1")] = service

    result = GooglePoliciesCollector().run({"client": client})

    assert result.status == "ok" and len(result.payload["twoStepVerificationPolicies"]["value"]) == 3
    assert len(service.calls) == 2  # two pages
    # CEL takes the regex escape as two backslashes inside the string, as the API's own examples write it.
    two_backslashes = "\\" * 2
    expected = (
        'customer == "customers/C123" && '
        "setting.type.matches('^settings/security" + two_backslashes + ".two_step_verification_.*$')"
    )
    assert service.calls[0]["filter"] == expected
    assert service.calls[0]["filter"].count("\\") == 2 and "\\." not in service.calls[0]["filter"].replace(two_backslashes + ".", "")
    assert GooglePoliciesCollector.required_scopes == (google_auth.POLICIES_SCOPE,)

    # The service for this API is built on credentials narrowed to its own scope.
    fresh = GoogleWorkspaceClient(_Credentials("admin@example.com", ("shared-scope",)), delegated=True)
    fresh._service("cloudidentity", "v1", scopes=(google_auth.POLICIES_SCOPE,))
    assert fake_discovery[-1]["credentials"].scopes == (google_auth.POLICIES_SCOPE,)
    assert fake_discovery[-1]["credentials"].subject == "admin@example.com"


def test_a_client_without_the_policies_resource_fails_with_an_actionable_message() -> None:
    client = GoogleWorkspaceClient(_Credentials(), delegated=True)
    assert client._services is not None
    client._services[("cloudidentity", "v1")] = object()

    result = GooglePoliciesCollector().run({"client": client})

    assert result.status == "partial"
    (row,) = result.coverage
    assert row["status"] == "failed" and "upgrade it" in row["error"]


def test_the_policy_scope_is_requested_on_its_own_token_so_a_missing_grant_fails_only_that_read(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Factory:
        @staticmethod
        def from_service_account_file(path: str, *, scopes: list[str]) -> _Credentials:
            captured["path"], captured["scopes"] = path, scopes
            return _Credentials(None, tuple(scopes))

    service_account = types.ModuleType("google.oauth2.service_account")
    service_account.Credentials = _Factory  # type: ignore[attr-defined]
    oauth2 = types.ModuleType("google.oauth2")
    oauth2.service_account = service_account  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google.oauth2.service_account", service_account)
    monkeypatch.setitem(sys.modules, "google", types.ModuleType("google"))
    monkeypatch.setitem(sys.modules, "google.oauth2", oauth2)
    monkeypatch.setattr(google_auth, "_module_available", lambda _module: True)
    config = google_run._auth_config(
        GoogleRunConfig(tenant_name="T", out=Path("."), subject="admin@example.com", service_account_key=Path("/key.json"), collectors="google_directory,google_policies"),
        ["google_directory", "google_policies"],
    )

    credentials = google_auth.build_google_credentials(config)

    assert google_auth.POLICIES_SCOPE in config.scopes and config.isolated_scopes == (google_auth.POLICIES_SCOPE,)
    assert captured["scopes"] == [scope for scope in config.scopes if scope != google_auth.POLICIES_SCOPE]
    assert "https://www.googleapis.com/auth/admin.directory.user.readonly" in captured["scopes"]
    assert credentials.subject == "admin@example.com"
    # The doctor still lists every scope the operator must authorise.
    payload = google_run.google_doctor(GoogleRunConfig(tenant_name="T", out=Path("."), collectors="google_directory,google_policies"))
    assert google_auth.POLICIES_SCOPE in payload["auth"]["scopes"]
    assert payload["auth"]["isolated_scopes"] == [google_auth.POLICIES_SCOPE]


# ---- stale and never-logged-in users ---------------------------------------------------------------------


def test_an_active_user_with_no_login_for_90_days_is_stale_by_default() -> None:
    snapshot = _snapshot(
        users=[
            _user("old@example.com", isEnforcedIn2Sv=True, lastLoginTime=_ago(120)),
            _user("recent@example.com", isEnforcedIn2Sv=True, lastLoginTime=_ago(30)),
            _user("gone@example.com", isEnforcedIn2Sv=True, lastLoginTime=_ago(500), suspended=True),
        ]
    )

    findings = build_google_findings(snapshot)

    (stale,) = _by_rule(findings, "google.stale_user")
    assert stale["affected_objects"] == ["old@example.com"] and stale["severity"] == "medium"
    assert stale["returned_value"]["threshold_days"] == 90 and stale["returned_value"]["privileged"] is False
    assert "google.never_logged_in_user" not in _rules(findings)


def test_the_stale_threshold_is_configurable() -> None:
    snapshot = _snapshot(users=[_user("a@example.com", isEnforcedIn2Sv=True, lastLoginTime=_ago(45))])

    assert "google.stale_user" not in _rules(build_google_findings(snapshot))
    (stale,) = _by_rule(build_google_findings(snapshot, stale_user_days=30), "google.stale_user")
    assert stale["returned_value"]["threshold_days"] == 30 and "30 days" in stale["description"]


def test_a_privileged_account_stale_for_90_days_is_high_and_not_reported_twice() -> None:
    snapshot = _snapshot(
        users=[
            _user("delegated@example.com", isDelegatedAdmin=True, isEnforcedIn2Sv=True, isEnrolledIn2Sv=True, lastLoginTime=_ago(120)),
            _user("ancient@example.com", isAdmin=True, isEnforcedIn2Sv=True, isEnrolledIn2Sv=True, lastLoginTime=_ago(500)),
        ]
    )

    findings = build_google_findings(snapshot)

    (stale,) = _by_rule(findings, "google.stale_user")
    assert stale["affected_objects"] == ["delegated@example.com"] and stale["severity"] == "high"
    # Past 365 days the existing admin rule already reports it.
    (admin_stale,) = _by_rule(findings, "google.admin_stale_login")
    assert admin_stale["affected_objects"] == ["ancient@example.com"]


def test_never_logged_in_users_are_reported_unless_the_account_is_new() -> None:
    epoch = "1970-01-01T00:00:00.000Z"
    snapshot = _snapshot(
        users=[
            _user("unused@example.com", isEnforcedIn2Sv=True, lastLoginTime=epoch, creationTime=_ago(200)),
            _user("unknown-age@example.com", isEnforcedIn2Sv=True, lastLoginTime=epoch),
            _user("new@example.com", isEnforcedIn2Sv=True, lastLoginTime=epoch, creationTime=_ago(3)),
            _user("admin@example.com", isAdmin=True, isEnforcedIn2Sv=True, isEnrolledIn2Sv=True, lastLoginTime=epoch),
        ]
    )

    findings = build_google_findings(snapshot)

    never = _by_rule(findings, "google.never_logged_in_user")
    assert sorted(item["affected_objects"][0] for item in never) == ["unknown-age@example.com", "unused@example.com"]
    assert {item["severity"] for item in never} == {"low"}
    # A never-signed-in admin is the existing admin rule's, not this one's, and never also counts as stale.
    assert [item["affected_objects"] for item in _by_rule(findings, "google.admin_stale_login")] == [["admin@example.com"]]
    assert "google.stale_user" not in _rules(findings)


def test_stale_and_never_logged_in_are_unknown_without_login_data() -> None:
    snapshot = _snapshot(users=[_user("a@example.com", isEnforcedIn2Sv=True), _user("b@example.com", isEnforcedIn2Sv=True, lastLoginTime=_ago(1))])

    findings = build_google_findings(snapshot)

    assert not {"google.stale_user", "google.never_logged_in_user"} & set(_rules(findings))
    (unknown,) = _by_rule(findings, "google.evidence_unknown")
    assert unknown["id"] == "google.evidence_unknown:user_login_time"
    assert unknown["returned_value"]["examples"] == ["a@example.com"]
    assert unknown["returned_value"]["rules_not_evaluated"] == ["google.stale_user", "google.never_logged_in_user"]
    assert unknown["evidence_refs"][0]["record_key"] == "google_user:id-a@example.com"


# ---- device posture ---------------------------------------------------------------------------------------


def test_mobile_posture_fields_are_normalised_from_the_real_api_names() -> None:
    snapshot = _snapshot(
        mobile=[
            {
                "resourceId": "m1",
                "email": ["a@example.com"],
                "os": "Android 14",
                "type": "ANDROID",
                "deviceCompromisedStatus": "No compromise detected",
                "encryptionStatus": "Encrypted",
                "devicePasswordStatus": "On",
                "securityPatchLevel": "1760000000",
                "releaseVersion": "14",
            },
            {"resourceId": "m2", "encryptionStatus": "Not encrypted", "devicePasswordStatus": "Off", "securityPatchLevel": "1577836800000"},
            {"resourceId": "m3", "encryptionStatus": "Mystery state", "securityPatchLevel": "20200105"},
            {"resourceId": "m4"},
        ]
    )

    rows = {row["id"]: row for row in snapshot["google_mobile_devices"]["records"]}
    assert rows["m1"]["encryption"] == "encrypted" and rows["m1"]["device_lock_policy"] == "enabled"
    assert rows["m1"]["security_patch_date"] == "2025-10-09T08:53:20Z" and rows["m1"]["os_release"] == "14"
    assert rows["m1"]["compromised_status"] == "No compromise detected"
    assert rows["m2"]["encryption"] == "not_encrypted" and rows["m2"]["device_lock_policy"] == "disabled"
    assert rows["m2"]["security_patch_date"] == "2020-01-01T00:00:00Z"
    # An unrecognised value stays unknown, with the raw text kept; an absent field leaves no value at all.
    assert "encryption" not in rows["m3"] and rows["m3"]["encryption_status"] == "Mystery state"
    assert rows["m3"]["security_patch_date"] == "2020-01-05T00:00:00Z"
    assert "encryption" not in rows["m4"] and "security_patch_date" not in rows["m4"]
    assert "password" not in json.dumps(snapshot["google_mobile_devices"]).lower()


def test_chromeos_auto_update_expiration_comes_from_the_current_field_then_the_deprecated_one() -> None:
    snapshot = _snapshot(
        chromeos=[
            {"deviceId": "c1", "autoUpdateThrough": "2023-06-01T00:00:00Z", "autoUpdateExpiration": "1500000000000", "platformVersion": "15000.1", "model": "Chromebook"},
            {"deviceId": "c2", "autoUpdateExpiration": "1685577600000"},
            {"deviceId": "c3", "autoUpdateExpiration": "0"},
            {"deviceId": "c4"},
        ]
    )

    rows = {row["id"]: row for row in snapshot["google_chromeos_devices"]["records"]}
    assert rows["c1"]["auto_update_expiration"] == "2023-06-01T00:00:00Z" and rows["c1"]["auto_update_source"] == "autoUpdateThrough"
    assert rows["c1"]["platform_version"] == "15000.1" and rows["c1"]["model"] == "Chromebook"
    assert rows["c2"]["auto_update_expiration"] == "2023-06-01T00:00:00Z" and rows["c2"]["auto_update_source"] == "autoUpdateExpiration"
    assert "auto_update_expiration" not in rows["c3"] and "auto_update_expiration" not in rows["c4"]


def test_a_chromeos_device_past_aue_is_high_and_an_inactive_one_is_left_to_its_own_rule() -> None:
    snapshot = _snapshot(
        chromeos=[
            {"deviceId": "past", "status": "ACTIVE", "autoUpdateThrough": _ago(30), "lastSync": _ago(1), "osVersion": "100"},
            {"deviceId": "supported", "status": "ACTIVE", "autoUpdateThrough": _ahead(300), "lastSync": _ago(1)},
            {"deviceId": "retired", "status": "DEPROVISIONED", "autoUpdateThrough": _ago(300), "lastSync": _ago(1)},
        ]
    )

    findings = build_google_findings(snapshot)

    (past,) = _by_rule(findings, "google.chromeos_device_past_aue")
    assert past["affected_objects"] == ["past"] and past["severity"] == "high"
    assert past["returned_value"]["os_version"] == "100"
    assert set(past["framework_mappings"]["cyber_essentials"]) == {"ce.sum.supported_software", "ce.sum.vulnerability_fixes_14_days"}
    assert "google.evidence_unknown" not in _rules(findings)


def test_the_aue_rule_is_unknown_for_an_active_device_without_the_field() -> None:
    snapshot = _snapshot(chromeos=[{"deviceId": "a", "status": "ACTIVE", "lastSync": _ago(1)}, {"deviceId": "b", "status": "ACTIVE", "autoUpdateThrough": _ahead(10), "lastSync": _ago(1)}])

    findings = build_google_findings(snapshot)

    assert "google.chromeos_device_past_aue" not in _rules(findings)
    (unknown,) = _by_rule(findings, "google.evidence_unknown")
    assert unknown["id"] == "google.evidence_unknown:chromeos_auto_update_expiration"
    assert unknown["returned_value"]["objects_without_field"] == 1 and unknown["returned_value"]["objects_total"] == 2


def test_a_mobile_device_with_encryption_off_is_reported_and_one_without_the_field_is_unknown() -> None:
    snapshot = _snapshot(
        mobile=[
            {"resourceId": "off", "status": "APPROVED", "encryptionStatus": "Not encrypted", "devicePasswordStatus": "Off", "lastSync": _ago(1)},
            {"resourceId": "on", "status": "APPROVED", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "blocked", "status": "BLOCKED", "encryptionStatus": "Not encrypted", "lastSync": _ago(1)},
            {"resourceId": "silent", "status": "APPROVED", "lastSync": _ago(1)},
        ]
    )

    findings = build_google_findings(snapshot)

    (off,) = _by_rule(findings, "google.mobile_device_encryption_off")
    assert off["affected_objects"] == ["off"]
    assert off["returned_value"] == {"encryption_status": "Not encrypted", "device_lock_status": "Off"}
    (unknown,) = _by_rule(findings, "google.evidence_unknown")
    assert unknown["id"] == "google.evidence_unknown:mobile_encryption" and unknown["returned_value"]["examples"] == ["silent"]


def test_the_compromised_status_uses_the_real_field_and_ignores_a_clean_value() -> None:
    snapshot = _snapshot(
        mobile=[
            {"resourceId": "clean", "deviceCompromisedStatus": "No compromise detected", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "bad", "deviceCompromisedStatus": "Compromised", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
            {"resourceId": "legacy", "compromisedStatus": "Compromised", "encryptionStatus": "Encrypted", "lastSync": _ago(1)},
        ]
    )

    findings = build_google_findings(snapshot)

    assert sorted(item["affected_objects"][0] for item in _by_rule(findings, "google.mobile_device_compromised")) == ["bad", "legacy"]


def test_device_requests_name_the_posture_fields_and_nothing_else() -> None:
    calls: list[dict[str, Any]] = []

    class _Devices:
        def __init__(self, key: str) -> None:
            self.key = key

        def list(self, **kwargs: Any) -> _Request:
            calls.append({"resource": self.key, **kwargs})
            return _Request({self.key: []})

    client = GoogleWorkspaceClient(credentials=None, customer_id="C1")
    assert client._services is not None
    client._services[("admin", "directory_v1")] = types.SimpleNamespace(
        mobiledevices=lambda: _Devices("mobiledevices"), chromeosdevices=lambda: _Devices("chromeosdevices")
    )

    client.list_devices("mobile")
    client.list_devices("chromeos")

    mobile, chromeos = calls
    assert mobile["projection"] == chromeos["projection"] == "FULL"
    for field in ("encryptionStatus", "devicePasswordStatus", "securityPatchLevel", "deviceCompromisedStatus"):
        assert field in mobile["fields"]
    for field in ("autoUpdateThrough", "autoUpdateExpiration", "osVersion"):
        assert field in chromeos["fields"]
    # Installed apps and recent users come with the FULL projection; the field mask keeps them out.
    assert "applications" not in mobile["fields"] and "recentUsers" not in chromeos["fields"]


# ---- one collector issue per surface ---------------------------------------------------------------------


def test_per_object_failures_collapse_into_one_finding_per_surface_with_the_object_count() -> None:
    diagnostics = [
        {
            "collector": "google_directory",
            "name": f"oauthGrants:u{i}@example.com",
            "status": "failed",
            "error_class": "insufficient_permissions",
            "error": "403 token scope missing",
        }
        for i in range(300)
    ] + [
        {"collector": "google_directory", "name": f"aliases:u{i}@example.com", "status": "failed", "error_class": "client_error", "error": "boom"}
        for i in range(12)
    ]

    findings = build_google_findings({"snapshot": {"workspace_domain": "example.com"}}, diagnostics=diagnostics)

    assert len(findings) == 2
    grants = next(item for item in findings if item["id"].endswith(":oauth-grants"))
    assert grants["rule_id"] == "google.collector_issue" and grants["severity"] == "high" and grants["category"] == "permission"
    assert grants["returned_value"]["object_count"] == 300
    assert len(grants["returned_value"]["objects"]) == 50 and grants["returned_value"]["objects_truncated"] is True
    assert grants["returned_value"]["error_classes"] == {"insufficient_permissions": 300}
    assert grants["returned_value"]["errors"] == [{"error_class": "insufficient_permissions", "error": "403 token scope missing", "count": 300}]
    assert len(grants["affected_objects"]) == 50
    assert grants["evidence_refs"][0]["record_key"] == "coverage_ledger:google_directory"
    aliases = next(item for item in findings if item["id"].endswith(":aliases"))
    assert aliases["severity"] == "medium" and aliases["returned_value"]["object_count"] == 12


def test_a_failure_seen_by_the_coverage_row_and_the_error_section_counts_once() -> None:
    diagnostics = [{"collector": "google_directory", "name": "groupMembers:all@example.com", "status": "failed", "error_class": "client_error", "error": "denied"}]
    snapshot = _snapshot(
        directory_extra={"groupMembersErrors": {"value": [{"groupEmail": "all@example.com", "error_class": "client_error", "error": "denied"}]}}
    )

    (issue,) = build_google_findings(snapshot, diagnostics=diagnostics)

    assert issue["returned_value"]["object_count"] == 1 and issue["id"] == "google.collector_issue:google_directory:group-members"
    paths = [ref["artifact_path"] for ref in issue["evidence_refs"]]
    assert paths == ["normalized/google_group_member_errors.json", "normalized/coverage_ledger.json"]


def test_per_mailbox_surface_errors_collapse_per_sub_surface() -> None:
    mailboxes = [
        {"userEmail": f"u{i}@example.com", "delegates_error": {"error_class": "insufficient_permissions", "error": "delegates scope missing"}, "imap": {"enabled": True}}
        for i in range(5)
    ]
    snapshot = _snapshot(gmail=mailboxes)

    findings = build_google_findings(snapshot)

    (issue,) = _by_rule(findings, "google.collector_issue")
    assert issue["id"] == "google.collector_issue:google_gmail_settings:delegates" and issue["returned_value"]["object_count"] == 5
    # The protocol findings are still one per mailbox.
    assert len(_by_rule(findings, "google.gmail_imap_enabled")) == 5


def test_a_single_failed_list_keeps_its_id_and_error_text() -> None:
    diagnostics = [{"collector": "google_directory", "name": "users", "status": "partial", "error_class": "collection_limit", "error": "users: collection stopped at 10 rows"}]

    (issue,) = build_google_findings({"snapshot": {"workspace_domain": "example.com"}}, diagnostics=diagnostics)

    assert issue["id"] == "google.collector_issue:google_directory:users"
    assert issue["returned_value"] == "users: collection stopped at 10 rows"
    assert issue["affected_objects"] == ["google_directory:users"]
    assert "--top" in issue["remediation"]


def test_a_fan_out_cut_tells_the_operator_to_raise_top_above_the_user_count(monkeypatch: pytest.MonkeyPatch) -> None:
    # A bound under the user count, as the default bound is under a large domain's.
    monkeypatch.setattr(google_collectors, "MAILBOX_FANOUT_LIMIT", 2)
    cut = GoogleGmailSettingsCollector().run({"client": _GmailClient([f"u{i}@example.com" for i in range(4)], delegated=True)})
    diagnostics = [row for row in cut.coverage if row.get("status") != "ok"]

    (issue,) = build_google_findings({"snapshot": {"workspace_domain": "example.com"}}, diagnostics=diagnostics)

    assert issue["id"] == "google.collector_issue:google_gmail_settings:mailboxSettingsFanout"
    assert "--top" in issue["remediation"] and "number of users" in issue["remediation"]


# ---- the rule registry --------------------------------------------------------------------------------------


def test_every_new_rule_has_metadata_a_baseline_and_framework_mappings() -> None:
    metadata = google_rule_metadata()

    for rule_id in NEW_RULES:
        assert rule_id in metadata, rule_id
        for field in ("title", "risk_rating", "description", "impact", "remediation", "expected_value"):
            assert metadata[rule_id].get(field), (rule_id, field)
        mapping = _GOOGLE_FRAMEWORK_MAPPINGS[rule_id]
        assert mapping.get("google_workspace_baseline")
        assert mapping.get("nist_800_53") and mapping.get("iso_27001") and mapping.get("soc2")


def test_new_rule_findings_use_the_registry_title_and_remediation(tmp_path: Path) -> None:
    metadata = google_rule_metadata()
    _code, run_dir = _offline(tmp_path, "registry")
    seen: set[str] = set()

    for finding in _findings(run_dir).values():
        if finding["rule_id"] in NEW_RULES:
            seen.add(finding["rule_id"])
            assert finding["title"] == metadata[finding["rule_id"]]["title"], finding["id"]
            assert finding["remediation"] == metadata[finding["rule_id"]]["remediation"], finding["id"]
            # Stale is high for a privileged account and the organisation policy is medium when only some units enforce.
            assert finding["severity"] == metadata[finding["rule_id"]]["risk_rating"] or finding["rule_id"] in {
                "google.stale_user",
                "google.org_2sv_policy_not_enforced",
            }
    assert seen == NEW_RULES - {"google.internal_domains_unknown"}


def test_diagnostic_rules_claim_no_cyber_essentials_requirement() -> None:
    for rule_id in ("google.internal_domains_unknown", "google.evidence_unknown", "google.collector_issue"):
        assert "cyber_essentials" not in _GOOGLE_FRAMEWORK_MAPPINGS[rule_id]


def test_new_cyber_essentials_mappings_match_the_shipped_confidence_table() -> None:
    mappings = json.loads((REPO / "configs" / "control-mappings.json").read_text(encoding="utf-8"))["_cyber_essentials_confidence"]

    assert mappings["google.user_2sv_not_enforced"] == {"ce.uac.mfa_cloud_services": "full"}
    assert mappings["google.org_2sv_policy_not_enforced"] == {"ce.uac.mfa_admin_accounts": "partial", "ce.uac.mfa_cloud_services": "full"}
    assert mappings["google.stale_user"]["ce.uac.remove_unused_accounts"] == "full"
    assert mappings["google.never_logged_in_user"]["ce.uac.remove_unused_accounts"] == "partial"
    assert mappings["google.chromeos_device_past_aue"] == {"ce.sum.supported_software": "full", "ce.sum.vulnerability_fixes_14_days": "partial"}
    for rule_id in NEW_RULES:
        declared = set(mappings.get(rule_id, {}))
        assert declared == set(_GOOGLE_FRAMEWORK_MAPPINGS[rule_id].get("cyber_essentials", [])), rule_id


# ---- waivers ---------------------------------------------------------------------------------------------------


def _write_waivers(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_text(json.dumps({"waivers": rows}), encoding="utf-8")
    return path


def _offline(tmp_path: Path, name: str, **kwargs: Any) -> tuple[int, Path]:
    code = run_google_offline(
        sample_path=SAMPLE,
        out=tmp_path,
        tenant_name="Example",
        run_name=name,
        domain="example.com",
        customer_id="C123",
        **kwargs,
    )
    return code, tmp_path / f"Example-{name}"


def _findings(run_dir: Path) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))}


def test_a_waiver_turns_a_google_finding_into_accepted_risk(tmp_path: Path) -> None:
    waivers = _write_waivers(
        tmp_path / "waivers.json",
        [
            {"rule_id": "google.stale_user", "owner": "g@example.com", "reason": "Seasonal contractor", "expires_on": "2099-01-01"},
            {"finding_id": "google.drive_anyone_with_link:file-1", "owner": "g@example.com", "reason": "Public brochure", "expires_on": "2099-01-01"},
        ],
    )

    code, run_dir = _offline(tmp_path, "waived", waiver_file=waivers)

    findings = _findings(run_dir)
    assert code == 0
    stale = findings["google.stale_user:u-user"]
    assert stale["status"] == "accepted_risk" and stale["waiver_applied"] is True and stale["waiver"]["owner"] == "g@example.com"
    assert findings["google.drive_anyone_with_link:file-1"]["status"] == "accepted_risk"
    assert findings["google.user_2sv_not_enforced:u-user"]["status"] == "open"
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["waiver_path"] == str(waivers)
    assert json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))["valid"] is True
    report = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    assert report["summary"]["accepted_count"] == 2 and report["summary"]["status_counts"]["accepted_risk"] == 2


def test_google_waivers_match_on_every_populated_field_and_ignore_expired_ones(tmp_path: Path) -> None:
    waivers = _write_waivers(
        tmp_path / "waivers.json",
        [
            {"rule_id": "google.stale_user", "collector": "google_devices", "owner": "o", "reason": "r", "expires_on": "2099-01-01"},
            {"rule_id": "google.user_2sv_not_enforced", "owner": "o", "reason": "r", "expires_on": "2020-01-01"},
            {"rule_id": "google.never_logged_in_user", "category": "identity", "owner": "o", "reason": "r", "expires_on": "2099-01-01"},
        ],
    )

    code, run_dir = _offline(tmp_path, "and-match", waiver_file=waivers)

    findings = _findings(run_dir)
    assert code == 0
    assert findings["google.stale_user:u-user"]["status"] == "open"  # the collector does not match
    assert findings["google.user_2sv_not_enforced:u-user"]["status"] == "open"  # expired
    assert findings["google.never_logged_in_user:u-never"]["status"] == "accepted_risk"  # AND of rule and category


def test_a_waiver_with_no_finding_or_rule_id_fails_the_run_before_anything_is_written(tmp_path: Path) -> None:
    waivers = _write_waivers(tmp_path / "waivers.json", [{"collector": "google_directory", "owner": "o", "reason": "r"}])

    code, run_dir = _offline(tmp_path, "bad-waiver", waiver_file=waivers)

    assert code == 2
    assert not run_dir.exists()
    assert not list(tmp_path.glob("Example-bad-waiver*"))


def test_a_missing_or_unparseable_waiver_file_fails_the_run(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    assert _offline(tmp_path, "missing", waiver_file=tmp_path / "absent.json")[0] == 2
    assert _offline(tmp_path, "broken", waiver_file=broken)[0] == 2
    assert not list(tmp_path.glob("Example-missing*")) and not list(tmp_path.glob("Example-broken*"))


def test_a_live_run_reads_the_waiver_file_before_any_api_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    waivers = _write_waivers(tmp_path / "waivers.json", [{"owner": "o"}])
    touched: list[str] = []
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: touched.append("dependencies") or {"available": True})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: touched.append("credentials"))
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_a, **_k: touched.append("client"))

    code = run_google_live(
        GoogleRunConfig(tenant_name="T", out=tmp_path / "out", auth="oauth", waiver_file=waivers),
        command_line=[],
    )

    assert code == 2
    assert touched == []
    assert not (tmp_path / "out").exists()


def test_a_live_run_applies_the_waivers_it_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    waivers = _write_waivers(tmp_path / "waivers.json", [{"rule_id": "google.user_2sv_not_enforced", "owner": "o", "reason": "r", "expires_on": "2099-01-01"}])

    class Client:
        per_user_delegation = False

        def list_directory(self, resource: str, **_k: Any) -> list[dict[str, Any]]:
            if resource == "users":
                return [_user("a@example.com", isEnrolledIn2Sv=True, isEnforcedIn2Sv=False, lastLoginTime=_ago(1))]
            if resource == "domains":
                return [{"domainName": "example.com", "isPrimary": True, "verified": True}]
            return []

    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_a, **_k: Client())

    code = run_google_live(
        GoogleRunConfig(tenant_name="T", out=tmp_path / "out", auth="oauth", collectors="google_directory", waiver_file=waivers, page_size=10),
        command_line=[],
    )

    (run_dir,) = (tmp_path / "out").iterdir()
    assert code == 0
    assert _findings(run_dir)["google.user_2sv_not_enforced:id-a@example.com"]["status"] == "accepted_risk"


def test_the_cli_accepts_waiver_file_and_stale_days_on_run_only(tmp_path: Path) -> None:
    parser = auditex_cli._build_google_parser()

    args = parser.parse_args(["run", "--waiver-file", str(tmp_path / "w.json"), "--stale-user-days", "45"])
    config = auditex_cli._google_config_from_args(args)

    assert config.waiver_file == tmp_path / "w.json" and config.stale_user_days == 45
    assert auditex_cli._google_config_from_args(parser.parse_args(["run"])).waiver_file is None
    assert auditex_cli._google_config_from_args(parser.parse_args(["run"])).stale_user_days == 90
    for rejected in (["probe", "--waiver-file", "w.json"], ["run", "--stale-user-days", "0"], ["run", "--stale-user-days", "soon"]):
        with pytest.raises(SystemExit):
            parser.parse_args(rejected)


def test_the_cli_offline_run_applies_the_waiver_and_the_stale_threshold(tmp_path: Path) -> None:
    waivers = _write_waivers(tmp_path / "w.json", [{"rule_id": "google.org_2sv_policy_not_enforced", "owner": "o", "reason": "r", "expires_on": "2099-01-01"}])

    code = auditex_cli.main(
        [
            "google", "run", "--offline", "--sample", str(SAMPLE), "--domain", "example.com", "--tenant-name", "Cli", "--run-name", "w",
            "--out", str(tmp_path), "--waiver-file", str(waivers), "--stale-user-days", "99999",
        ]
    )

    findings = _findings(tmp_path / "Cli-w")
    assert code == 0
    assert findings["google.org_2sv_policy_not_enforced:organisation"]["status"] == "accepted_risk"
    assert "google.stale_user:u-user" not in findings

    bad = auditex_cli.main(
        ["google", "run", "--offline", "--sample", str(SAMPLE), "--tenant-name", "Cli", "--run-name", "bad", "--out", str(tmp_path), "--waiver-file", str(tmp_path / "none.json")]
    )
    assert bad == 2 and not (tmp_path / "Cli-bad").exists()


# ---- the offline sample exercises the new rules ------------------------------------------------------------------


def test_the_offline_sample_exercises_every_new_rule_and_the_bundle_validates(tmp_path: Path) -> None:
    code, run_dir = _offline(tmp_path, "sample")

    findings = _findings(run_dir)
    rules = {item["rule_id"] for item in findings.values()}
    assert code == 0
    assert NEW_RULES - {"google.internal_domains_unknown"} <= rules
    assert json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))["valid"] is True
    snapshot = json.loads((run_dir / "normalized" / "snapshot.json").read_text(encoding="utf-8"))
    assert snapshot["internal_domains"] == ["example.com", "example.net", "example.org"]
    assert snapshot["internal_domains_status"] == "known" and snapshot["two_step_policy_status"] == "partial"
    assert snapshot["subject_scope"] == {"google_calendar_posture": "admin", "google_drive_posture": "admin"}
    # The alias domain's user is internal, and the secondary domain's domain-wide share is a domain share.
    assert not any(
        "colleague@example.net" in json.dumps(item["returned_value"]) for item in findings.values() if item["rule_id"] == "google.drive_external_permission"
    )
    assert {item["returned_value"]["permission"]["id"] for item in findings.values() if item["rule_id"] == "google.drive_domain_permission"} == {
        "p-domain-internal",
        "p-secondary-domain",
    }
    # The delegated admin is treated as an admin; the unknown-evidence findings name what could not be checked.
    assert "google.admin_2sv_not_enforced:u-delegated" in findings and "google.admin_stale_login:u-delegated" in findings
    unknown = {item["id"] for item in findings.values() if item["rule_id"] == "google.evidence_unknown"}
    assert unknown == {
        "google.evidence_unknown:user_login_time",
        "google.evidence_unknown:mobile_encryption",
        "google.evidence_unknown:chromeos_auto_update_expiration",
    }
    drive = findings["google.drive_anyone_with_link:file-1"]
    assert drive["subject_scoped"] == "admin"


def test_the_sample_without_a_domain_list_or_label_reports_the_external_checks_as_unknown(tmp_path: Path) -> None:
    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    del sample["google_directory"]["domains"]
    path = tmp_path / "no-domains.json"
    path.write_text(json.dumps(sample), encoding="utf-8")

    code = run_google_offline(sample_path=path, out=tmp_path, tenant_name="Example", run_name="nodom", domain=None, customer_id=None)

    findings = _findings(tmp_path / "Example-nodom")
    rules = {item["rule_id"] for item in findings.values()}
    assert code == 0
    assert "google.internal_domains_unknown" in rules
    assert not {"google.gmail_external_forwarding", "google.drive_external_permission", "google.group_external_member", "google.calendar_external_acl"} & rules
    assert json.loads((tmp_path / "Example-nodom" / "validation.json").read_text(encoding="utf-8"))["valid"] is True


# ---- a live run over every collector -------------------------------------------------------------------------------


class _EverythingClient:
    """Answers every call the collectors make, with one mailbox that fails and a user list longer than the bound."""

    per_user_delegation = True

    def __init__(self) -> None:
        self.mailboxes: list[str] = []

    def list_directory(self, resource: str, **_k: Any) -> list[dict[str, Any]]:
        if resource == "users":
            return [
                _user("a@example.com", isEnrolledIn2Sv=True, isEnforcedIn2Sv=False, lastLoginTime=_ago(200)),
                _user("b@example.com", isEnrolledIn2Sv=True, isEnforcedIn2Sv=True, lastLoginTime=_ago(1)),
                _user("c@example.com", isEnrolledIn2Sv=True, isEnforcedIn2Sv=True, lastLoginTime=_ago(1)),
                _user("gone@example.com", suspended=True, isEnforcedIn2Sv=True, lastLoginTime=_ago(1)),
            ]
        if resource == "domains":
            return [{"domainName": "example.com", "isPrimary": True, "verified": True, "domainAliases": [{"domainAliasName": "example.net"}]}]
        if resource == "groups":
            return [{"id": "g1", "email": "all@example.com"}]
        return []

    def list_group_members(self, group_email: str, **_k: Any) -> list[dict[str, Any]]:
        return [{"id": "m1", "email": "me@example.net"}]

    def list_user_aliases(self, user_key: str, **_k: Any) -> list[dict[str, Any]]:
        raise RuntimeError(f"403 alias scope missing for {user_key}")

    def list_user_tokens(self, user_key: str, **_k: Any) -> list[dict[str, Any]]:
        return []

    def list_policies(self, **_k: Any) -> list[dict[str, Any]]:
        return [_policy("two_step_verification_enforcement")]

    def list_report_activities(self, application: str, **_k: Any) -> list[dict[str, Any]]:
        return []

    def list_alerts(self, **_k: Any) -> list[dict[str, Any]]:
        return []

    def get_gmail_settings_for_user(self, user_email: str) -> dict[str, Any]:
        self.mailboxes.append(user_email)
        if user_email == "b@example.com":
            raise RuntimeError("403 delegation denied")
        return {"userEmail": user_email, "imap": {"enabled": True}}

    def list_devices(self, resource: str, **_k: Any) -> list[dict[str, Any]]:
        if resource == "mobile":
            return [{"resourceId": "m1", "status": "APPROVED", "encryptionStatus": "Not encrypted", "lastSync": _ago(1)}]
        return [{"deviceId": "c1", "status": "ACTIVE", "autoUpdateThrough": _ago(10), "lastSync": _ago(1)}]

    def list_drive_files(self, **_k: Any) -> list[dict[str, Any]]:
        return []

    def list_shared_drives(self, **_k: Any) -> list[dict[str, Any]]:
        return []

    def get_group_settings(self, group_email: str) -> dict[str, Any]:
        return {"whoCanJoin": "CAN_REQUEST_TO_JOIN"}

    def list_calendar_resources(self, **_k: Any) -> list[dict[str, Any]]:
        return []

    def list_calendar_list(self, **_k: Any) -> list[dict[str, Any]]:
        return []

    def list_calendar_acl(self, calendar_id: str, **_k: Any) -> list[dict[str, Any]]:
        return []


def test_a_live_run_over_every_collector_writes_a_valid_bundle_with_scope_and_collapsed_issues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _EverythingClient()
    monkeypatch.setattr(google_collectors, "MAILBOX_FANOUT_LIMIT", 2)
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_a, **_k: client)

    code = run_google_live(
        GoogleRunConfig(
            tenant_name="T",
            out=tmp_path,
            auth="domain-delegation",
            subject="admin@example.com",
            collectors=(
                "google_directory,google_policies,google_gmail_settings,google_devices,"
                "google_drive_posture,google_calendar_posture,google_groups_settings"
            ),
        ),
        command_line=[],
    )

    (run_dir,) = tmp_path.iterdir()
    findings = _findings(run_dir)
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert validation["valid"] is True, validation["issues"]
    assert code == 1 and manifest["overall_status"] == "partial"  # the failed mailbox and the cut fan-out are gaps
    # a@ and b@ are read (the bound is 2); c@ is cut and recorded; the suspended account is skipped and counted.
    assert client.mailboxes == ["a@example.com", "b@example.com"]
    assert json.loads((run_dir / "normalized" / "snapshot.json").read_text(encoding="utf-8"))["subject_scope"] == {
        "google_calendar_posture": "admin",
        "google_drive_posture": "admin",
        "google_gmail_settings": "user",
    }
    assert findings["google.collector_issue:google_gmail_settings:mailboxSettingsFanout"]["severity"] == "medium"
    mailbox = findings["google.collector_issue:google_gmail_settings:mailbox-settings"]
    assert mailbox["returned_value"]["objects"] == ["b@example.com"] and mailbox["evidence_refs"][0]["record_key"] == "coverage_ledger:google_gmail_settings"
    assert findings["google.collector_issue:google_directory:aliases"]["returned_value"]["object_count"] == 4
    assert "google.org_2sv_policy_not_enforced:organisation" in findings
    assert "google.user_2sv_not_enforced:id-a@example.com" in findings and "google.stale_user:id-a@example.com" in findings
    assert "google.chromeos_device_past_aue:c1" in findings and "google.mobile_device_encryption_off:m1" in findings
    # me@example.net belongs to the alias domain from the Directory list, so it is not an external member.
    assert not [item for item in findings.values() if item["rule_id"] == "google.group_external_member"]
    capability = {row["collector"]: row for row in json.loads((run_dir / "normalized" / "capability_matrix.json").read_text(encoding="utf-8"))["records"]}
    assert capability["google_gmail_settings"]["subject_scoped"] == "user"
    assert capability["google_drive_posture"]["subject_scoped"] == "admin" and "subject_scoped" not in capability["google_directory"]
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    assert auth_context["per_user_delegation"] is True and auth_context["subject_scope"]["google_gmail_settings"] == "user"
    snapshot = json.loads((run_dir / "normalized" / "snapshot.json").read_text(encoding="utf-8"))
    assert snapshot["mailbox_settings_skipped_suspended"] == 1 and snapshot["internal_domains"] == ["example.com", "example.net"]
