"""LIVE-FIX-3: a My Drive file owned wholly outside the tenant is not the organisation's sharing exposure.

Its permissions are not read one by one and it is not a ``drivePermissions`` gap; the coverage row counts it. Only a
positive answer leaves a file out: unknown or incomplete tenant domains, a shared drive, or owners that are missing,
empty, malformed, without an email or inside the tenant keep the file in scope (read, or recorded as a gap).
"""

from __future__ import annotations

from typing import Any

import pytest

from auditex.google_workspace import client as google_client
from auditex.google_workspace.client import CollectedRows, GoogleWorkspaceClient
from auditex.google_workspace.collectors import GoogleDrivePostureCollector
from auditex.google_workspace.drive_scope import (
    DOMAIN_SCOPE,
    owned_outside,
    owner_domains,
    read_tenant_domains,
    tenant_domain_names,
)

TENANT = frozenset({"example.com", "example.net"})
UNREADABLE = (
    "Sharing of {n} of {n} Drive files (shared-drive items or files the subject cannot share) could not be read, "
    "so their exposure is unknown (insufficient_permissions)."
)


class _HttpError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.resp = type("Resp", (), {"status": status})()


class _Request:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    def execute(self) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(google_client, "_sleep", lambda _delay: None, raising=False)


def _owned(*emails: Any, **extra: Any) -> dict[str, Any]:
    return {"owners": [{"emailAddress": email} for email in emails], **extra}


# ---- the tenant's domains: only a complete Directory domains list is an answer ------------------------------------


def test_tenant_domains_hold_every_domain_and_alias_lower_cased_verified_or_not() -> None:
    rows = [
        {"domainName": "Example.COM", "verified": True, "isPrimary": True,
         "domainAliases": [{"domainAliasName": "Alias.Example.org", "verified": False}]},
        {"domainName": "example.net", "verified": False},
    ]
    assert tenant_domain_names(rows) == frozenset({"example.com", "alias.example.org", "example.net"})


@pytest.mark.parametrize(
    "rows",
    [
        None,
        "example.com",
        {"domains": [{"domainName": "example.com"}]},
        [],
        ["example.com"],
        [{"domainName": "example.com"}, None],
        [{}],
        [{"domainName": None}],
        [{"domainName": ""}],
        [{"domainName": 7}],
        [{"domainName": "not a domain"}],
        [{"domainName": "example.com", "domainAliases": None}],
        [{"domainName": "example.com", "domainAliases": "alias.example.org"}],
        [{"domainName": "example.com", "domainAliases": [None]}],
        [{"domainName": "example.com", "domainAliases": [{}]}],
        [{"domainName": "example.com", "domainAliases": [{"domainAliasName": ""}]}],
        [{"domainName": "example.com", "domainAliases": [{"domainAliasName": ["alias.example.org"]}]}],
        CollectedRows([{"domainName": "example.com"}], page_error=RuntimeError("later page")),
        CollectedRows([{"domainName": "example.com"}], truncated=True),
    ],
)
def test_incomplete_or_malformed_domain_lists_are_unknown(rows: Any) -> None:
    assert tenant_domain_names(rows) is None


# ---- the owners: only well-formed emails of a My Drive file are an answer ------------------------------------------


@pytest.mark.parametrize(
    ("drive_file", "expected"),
    [
        (_owned("a@example.org"), frozenset({"example.org"})),
        (_owned("a@Example.ORG", "b@example.com"), frozenset({"example.org", "example.com"})),
        (_owned("a@example.org", driveId="d1"), None),
        (_owned("a@example.org", driveId=None), None),
        ({}, None),
        ({"owners": None}, None),
        ({"owners": []}, None),
        ({"owners": "a@example.org"}, None),
        ({"owners": [None]}, None),
        ({"owners": [{"displayName": "Someone"}]}, None),
        (_owned(None), None),
        (_owned(""), None),
        (_owned(42), None),
        (_owned("example.org"), None),
        (_owned("@example.org"), None),
        (_owned("a@b@example.org"), None),
        (_owned("a@"), None),
        (_owned("a@not a domain"), None),
        (_owned("a@example.org", None), None),
        (None, None),
        ([], None),
    ],
)
def test_owner_domains(drive_file: Any, expected: Any) -> None:
    assert owner_domains(drive_file) == expected


@pytest.mark.parametrize(
    ("drive_file", "domains", "expected"),
    [
        (_owned("a@example.org"), TENANT, True),
        (_owned("a@example.org", "b@example.co.uk"), TENANT, True),
        (_owned("a@EXAMPLE.com"), TENANT, False),
        (_owned("a@example.org", "b@example.net"), TENANT, False),
        # Exact domains only: neither a suffix nor a parent domain is a match, so both are outside.
        (_owned("a@example.com.evil.test"), TENANT, True),
        (_owned("a@sub.example.com"), TENANT, True),
        (_owned("a@example.org"), None, False),
        (_owned("a@example.org"), frozenset(), False),
        (_owned("a@example.org", driveId="d1"), TENANT, False),
        ({"owners": []}, TENANT, False),
        (_owned(""), TENANT, False),
    ],
)
def test_owned_outside(drive_file: Any, domains: Any, expected: bool) -> None:
    assert owned_outside(drive_file, domains) is expected


# ---- the domains read: its own token, and any failure is unknown --------------------------------------------------


def test_read_tenant_domains_asks_for_the_domain_scope_alone() -> None:
    asked: list[tuple[str, ...]] = []

    class _Narrowed:
        def list_directory(self, resource: str, **_k: Any) -> list[dict[str, Any]]:
            assert resource == "domains"
            return [{"domainName": "example.com"}]

    class _Client:
        def for_scopes(self, scopes: tuple[str, ...]) -> _Narrowed:
            asked.append(scopes)
            return _Narrowed()

        def list_directory(self, *_a: Any, **_k: Any) -> Any:
            raise AssertionError("the Drive token is not used for the domains list")

    assert read_tenant_domains(_Client()) == frozenset({"example.com"})
    assert asked == [("https://www.googleapis.com/auth/admin.directory.domain.readonly",)]
    assert DOMAIN_SCOPE == "https://www.googleapis.com/auth/admin.directory.domain.readonly"


@pytest.mark.parametrize(
    "client",
    [
        type("C", (), {"list_directory": lambda self, *_a, **_k: (_ for _ in ()).throw(_HttpError(403))})(),
        type("C", (), {"for_scopes": lambda self, _s: (_ for _ in ()).throw(RuntimeError("no token"))})(),
        type("C", (), {"list_directory": lambda self, *_a, **_k: [{"domainName": None}]})(),
        type("C", (), {})(),
        None,
    ],
)
def test_read_tenant_domains_failures_are_unknown(client: Any) -> None:
    assert read_tenant_domains(client) is None


# ---- the Drive listing and the collector ---------------------------------------------------------------------------


def _client(files: list[dict[str, Any]], domains: Any, calls: list[str]) -> GoogleWorkspaceClient:
    class _Files:
        def list(self, **_kwargs: Any) -> _Request:
            calls.append("files.list")
            return _Request({"files": [dict(item) for item in files]})

    class _Permissions:
        def list(self, **kwargs: Any) -> _Request:
            calls.append(f"permissions.list:{kwargs['fileId']}")
            return _Request(_HttpError(403))

    class _Drives:
        def list(self, **_kwargs: Any) -> _Request:
            return _Request({"drives": []})

    class _Domains:
        def list(self, **_kwargs: Any) -> _Request:
            calls.append("domains.list")
            return _Request(domains)

    drive = type("Drive", (), {"files": lambda self: _Files(), "permissions": lambda self: _Permissions(),
                               "drives": lambda self: _Drives()})()
    admin = type("Admin", (), {"domains": lambda self: _Domains()})()
    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("drive", "v3")] = drive
    client._services[("admin", "directory_v1")] = admin
    return client


DOMAINS = {"domains": [{"domainName": "example.com", "domainAliases": [{"domainAliasName": "example.net"}]}]}
OUTSIDE = [
    {"id": "f1", "name": "Theirs", "owners": [{"emailAddress": "a@example.org"}]},
    {"id": "f2", "name": "Lookalike", "owners": [{"emailAddress": "b@example.com.evil.test"}]},
]


def test_files_owned_outside_are_counted_not_read() -> None:
    calls: list[str] = []
    inside = {"id": "f3", "name": "Ours", "owners": [{"emailAddress": "c@Example.NET"}]}
    client = _client([*OUTSIDE, inside], DOMAINS, calls)
    files = client.list_drive_files(tenant_domains=lambda: read_tenant_domains(client))
    assert calls == ["files.list", "domains.list", "permissions.list:f3"]
    assert files.permission_out_of_scope == 2
    assert files.permission_reads == 0
    assert [error["fileId"] for error in files.permission_errors or []] == ["f3"]
    assert [item["id"] for item in files] == ["f1", "f2", "f3"]
    assert "permissions" not in files[0]


@pytest.mark.parametrize(
    "drive_file",
    [
        {"id": "f1", "driveId": "d1", "owners": [{"emailAddress": "a@example.org"}]},
        {"id": "f1"},
        {"id": "f1", "owners": []},
        {"id": "f1", "owners": [{"displayName": "Someone"}]},
        {"id": "f1", "owners": [{"emailAddress": "a@example.org"}, {"emailAddress": "b@example.com"}]},
        {"id": "f1", "owners": [{"emailAddress": "a@example.org"}, "b@example.org"]},
    ],
)
def test_files_not_positively_outside_are_still_read(drive_file: dict[str, Any]) -> None:
    calls: list[str] = []
    client = _client([drive_file], DOMAINS, calls)
    files = client.list_drive_files(tenant_domains=lambda: read_tenant_domains(client))
    assert [call for call in calls if call.startswith("permissions.list")] == ["permissions.list:f1"]
    assert files.permission_out_of_scope == 0
    assert [error["fileId"] for error in files.permission_errors or []] == ["f1"]


@pytest.mark.parametrize(
    "domains",
    [
        _HttpError(403),
        {},
        {"domains": None},
        {"domains": []},
        {"domains": [{"domainName": "example.com"}], "nextPageToken": "more"},
        {"domains": [{"domainName": "example.com"}, "example.net"]},
        {"domains": [{"domainName": "example.com", "domainAliases": [{"verified": True}]}]},
    ],
)
def test_unknown_tenant_domains_keep_every_file_in_scope(domains: Any) -> None:
    calls: list[str] = []
    client = _client(OUTSIDE, domains, calls)
    files = client.list_drive_files(tenant_domains=lambda: read_tenant_domains(client))
    assert calls == ["files.list", "domains.list", "permissions.list:f1", "permissions.list:f2"]
    assert files.permission_out_of_scope == 0
    assert [error["fileId"] for error in files.permission_errors or []] == ["f1", "f2"]


def test_no_domain_reader_keeps_the_current_behaviour_and_no_candidate_reads_no_domains() -> None:
    calls: list[str] = []
    files = _client(OUTSIDE, DOMAINS, calls).list_drive_files()
    assert calls == ["files.list", "permissions.list:f1", "permissions.list:f2"]
    assert files.permission_out_of_scope == 0

    calls.clear()
    asked: list[bool] = []
    client = _client([{"id": "f1", "driveId": "d1"}, {"id": "f2", "permissions": []}], DOMAINS, calls)
    client.list_drive_files(tenant_domains=lambda: asked.append(True) or TENANT)
    assert asked == []
    assert calls == ["files.list", "permissions.list:f1"]


def test_collector_counts_out_of_scope_files_and_reports_only_in_scope_gaps() -> None:
    calls: list[str] = []
    inside = {"id": "f3", "name": "Ours", "owners": [{"emailAddress": "c@example.com"}]}
    result = GoogleDrivePostureCollector().run({"client": _client([*OUTSIDE, inside], DOMAINS, calls)})
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert (row["status"], row["item_count"], row["error_class"], row["error"], row["out_of_scope_files"]) == (
        "failed", 0, "insufficient_permissions", UNREADABLE.format(n=1), 2,
    )
    assert calls.count("domains.list") == 1
    assert result.status == "partial"


def test_collector_with_only_out_of_scope_files_is_complete() -> None:
    calls: list[str] = []
    result = GoogleDrivePostureCollector().run({"client": _client(OUTSIDE, DOMAINS, calls)})
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert {key: row.get(key) for key in ("status", "item_count", "error_class", "error", "out_of_scope_files")} == {
        "status": "ok", "item_count": 0, "error_class": None, "error": None, "out_of_scope_files": 2,
    }
    assert [call for call in calls if call.startswith("permissions.list")] == []
    assert result.status == "ok"
    assert result.payload["driveFiles"]["value"] == [
        {"id": "f1", "name": "Theirs", "owners": [{"emailAddress": "a@example.org"}]},
        {"id": "f2", "name": "Lookalike", "owners": [{"emailAddress": "b@example.com.evil.test"}]},
    ]


def test_collector_with_unreadable_domains_records_the_gap_as_before() -> None:
    calls: list[str] = []
    result = GoogleDrivePostureCollector().run({"client": _client(OUTSIDE, _HttpError(403), calls)})
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert (row["status"], row["error"], "out_of_scope_files" in row) == ("failed", UNREADABLE.format(n=2), False)
    assert result.status == "partial"


def test_out_of_scope_files_raise_no_drive_findings() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    calls: list[str] = []
    files = _client(OUTSIDE, DOMAINS, calls).list_drive_files(
        tenant_domains=lambda: frozenset({"example.com"}),
    )
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="r1", domain="example.com",
        collector_payloads={"google_drive_posture": {"driveFiles": {"value": list(files)}, "sharedDrives": {"value": []}}},
    )
    assert [item["rule_id"] for item in build_google_findings(snapshot) if item["rule_id"].startswith("google.drive")] == []


# ---- LIVE-FIX-5 B3: an owner address proves its domain only in its plain form ------------------------------------

MALFORMED_OWNERS = [
    " @example.org",
    "@example.org",
    "a @example.org",
    " a@example.org",
    "a@example.org ",
    "a@ example.org",
    "a\t@example.org",
    "a\n@example.org",
    "a@example.org\n",
    "a\x00b@example.org",
    "a\x7f@example.org",
    "a b@example.org",
    "a@exa mple.org",
    "a@b@example.org",
    "a@@example.org",
    "a@",
    "@",
    "",
    " ",
    ".a@example.org",
    "a.@example.org",
    "a..b@example.org",
    '"a b"@example.org',
    "é@example.org",
    "a@example.org.",
    "a@-example.org",
    "a@example",
    "a" * 65 + "@example.org",
    None,
    42,
    ["a@example.org"],
    {"emailAddress": "a@example.org"},
]


@pytest.mark.parametrize("email", MALFORMED_OWNERS)
def test_live_fix_5_b3_a_malformed_owner_address_is_unknown(email: Any) -> None:
    assert owner_domains(_owned(email)) is None
    assert owner_domains(_owned("b@example.org", email)) is None
    assert owned_outside(_owned(email), TENANT) is False


@pytest.mark.parametrize(("email", "domain"), [
    ("a@example.org", "example.org"),
    ("first.last+tag@Example.ORG", "example.org"),
    ("o'brien_x-y@sub.example.org", "sub.example.org"),
])
def test_live_fix_5_b3_a_plain_owner_address_still_proves_its_domain(email: str, domain: str) -> None:
    assert owner_domains(_owned(email)) == frozenset({domain})


@pytest.mark.parametrize("email", [" @example.org", "a @example.org", "a@example.org ", "a@b@example.org", ""])
def test_live_fix_5_b3_reviewer_scenario_a_malformed_owner_keeps_the_permissions_gap(email: str) -> None:
    calls: list[str] = []
    drive_file = {"id": "f1", "name": "Theirs", "owners": [{"emailAddress": email}]}
    result = GoogleDrivePostureCollector().run({"client": _client([drive_file], DOMAINS, calls)})
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert [call for call in calls if call.startswith("permissions.list")] == ["permissions.list:f1"]
    assert (row["status"], row["error"], "out_of_scope_files" in row) == ("failed", UNREADABLE.format(n=1), False)
    assert result.status == "partial"


# ---- LIVE-FIX-5 M1: the Drive collector declares its optional read-only domain scope -------------------------------

def test_live_fix_5_m1_drive_alone_requests_and_inventories_the_domain_scope() -> None:
    from auditex.google_workspace.run import (
        REGISTRY,
        _collector_client,
        scopes_for_collectors,
    )
    from auditex.setup_guide import build_google_setup_guide
    from azure_tenant_audit.scope_catalog import (
        aggregate_catalog_rows,
        build_google_scope_catalog,
    )

    assert DOMAIN_SCOPE == "https://www.googleapis.com/auth/admin.directory.domain.readonly"
    assert scopes_for_collectors(["google_drive_posture"]) == (
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    )
    # Required scopes first, then optional ones; a scope another collector requires is listed once.
    assert scopes_for_collectors(["google_drive_posture", "google_dns_posture"]).count(DOMAIN_SCOPE) == 1

    catalog = build_google_scope_catalog(registry=REGISTRY)
    drive = catalog["google_drive_posture"]
    assert drive["required_permissions"] == [
        "https://www.googleapis.com/auth/drive.metadata.readonly", "https://www.googleapis.com/auth/drive.readonly"]
    assert drive["optional_permissions"] == ["https://www.googleapis.com/auth/admin.directory.domain.readonly"]
    note = drive["optional_permission_notes"]["https://www.googleapis.com/auth/admin.directory.domain.readonly"]
    assert "read-only" in note and "blast radius" in note and "domain and alias names" in note
    assert aggregate_catalog_rows(catalog, ["google_drive_posture"])["optional_permissions"] == [
        "https://www.googleapis.com/auth/admin.directory.domain.readonly"]
    # A collector that requires it lists it as required, not optional.
    assert aggregate_catalog_rows(catalog, ["google_drive_posture", "google_dns_posture"])["optional_permissions"] == []

    guide = build_google_setup_guide(collectors="google_drive_posture")
    assert guide["scopes_csv"].split(",") == list(scopes_for_collectors(["google_drive_posture"]))
    assert [(row["scope"], row["collector"]) for row in guide["optional_scopes"]] == [
        ("https://www.googleapis.com/auth/admin.directory.domain.readonly", "google_drive_posture")]

    # The Drive reads' own token never carries it, so a delegation without it fails only the domains read.
    asked: list[tuple[str, ...]] = []

    class _Client:
        def for_scopes(self, scopes: tuple[str, ...]) -> _Client:
            asked.append(tuple(scopes))
            return self

    _collector_client(_Client(), "google_drive_posture")
    assert asked == [("https://www.googleapis.com/auth/drive.metadata.readonly",
                      "https://www.googleapis.com/auth/drive.readonly")]


def test_live_fix_5_m1_a_drive_only_run_asks_for_the_domain_scope_in_its_one_sign_in() -> None:
    from auditex.google_workspace.run import (
        GoogleRunConfig,
        _auth_config,
        _selected_collectors,
    )

    config = GoogleRunConfig(tenant_name="Example", out=None, domain="example.com", collectors="google_drive_posture")
    auth = _auth_config(config, _selected_collectors(config))
    assert auth.scopes == (
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    )
