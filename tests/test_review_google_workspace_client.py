"""Deep-review regressions for the Google Workspace client and collectors (retries, partial pages, Gmail
settings status, shared-drive permissions, user field mask)."""
from __future__ import annotations

from typing import Any

import pytest

from auditex.google_workspace import client as google_client
from auditex.google_workspace.client import CollectedRows, GoogleWorkspaceClient
from auditex.google_workspace.collectors import GoogleDirectoryCollector


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
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(google_client, "_sleep", slept.append, raising=False)
    return slept


def _paged(outcomes: dict[str | None, list[Any]]) -> Any:
    """A request factory: each page token answers with its queued outcomes in order."""

    def factory(token: str | None) -> _Request:
        return _Request(outcomes[token].pop(0))

    return factory


# ---- R058: 429 and 5xx are retried, and a failed later page keeps the rows already read -----------------------


def test_r058_transient_errors_are_retried_with_backoff(_no_backoff_sleep: list[float]) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    factory = _paged({
        None: [_HttpError(503), {"users": [{"id": "u1"}], "nextPageToken": "p2"}],
        "p2": [_HttpError(429), _HttpError(500), {"users": [{"id": "u2"}]}],
    })
    rows = client._collect_pages(factory, "users", limit=None)
    assert [row["id"] for row in rows] == ["u1", "u2"]
    assert getattr(rows, "truncated", False) is False
    assert len(_no_backoff_sleep) == 3


def test_r058_permission_errors_are_not_retried(_no_backoff_sleep: list[float]) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    with pytest.raises(_HttpError):
        client._collect_pages(_paged({None: [_HttpError(403)]}), "users", limit=None)
    assert _no_backoff_sleep == []


def test_r058_a_failed_later_page_keeps_earlier_rows_as_a_partial_list() -> None:
    client = GoogleWorkspaceClient(credentials=None)
    factory = _paged({
        None: [{"users": [{"id": "u1", "primaryEmail": "u1@example.com"}], "nextPageToken": "p2"}],
        "p2": [_HttpError(503)] * 10,
    })
    rows = client._collect_pages(factory, "users", limit=None)
    assert [row["id"] for row in rows] == ["u1"]
    assert isinstance(rows, CollectedRows) and rows.truncated is True


def test_r058_collector_records_a_failed_later_page_as_partial_not_empty() -> None:
    class _Client:
        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            if resource == "users":
                client = GoogleWorkspaceClient(credentials=None)
                return client._collect_pages(_paged({
                    None: [{"users": [{"id": "u1", "primaryEmail": "u1@example.com"}], "nextPageToken": "p2"}],
                    "p2": [_HttpError(503)] * 10,
                }), "users", limit=None)
            return []

    result = GoogleDirectoryCollector().run({"client": _Client()})
    users_row = next(row for row in result.coverage if row["name"] == "users")
    assert result.payload["users"]["value"] == [{"id": "u1", "primaryEmail": "u1@example.com"}]
    assert users_row["status"] == "partial"
    assert users_row["error_class"] == "google_transient"
    assert users_row["collection_truncated"] is True
    assert users_row["truncation_reason"] == "pagination_failed"
    assert result.status == "partial"


def test_r058_single_call_reads_are_retried(_no_backoff_sleep: list[float]) -> None:
    outcomes = [_HttpError(429), {"aliases": [{"alias": "a@example.com"}]}]
    aliases = type("Aliases", (), {"list": lambda self, **_k: _Request(outcomes.pop(0))})()
    users = type("Users", (), {"aliases": lambda self: aliases})()
    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("admin", "directory_v1")] = type("Dir", (), {"users": lambda self: users})()
    assert client.list_user_aliases("u1@example.com") == [{"alias": "a@example.com"}]
    assert len(_no_backoff_sleep) == 1


# ---- R055: Gmail settings reads that fail are not recorded as ok ----------------------------------------------


class _GmailSettings:
    """Every Gmail settings call answers with ``outcome`` (an error to raise, or a payload) unless named in ``ok``."""

    def __init__(self, outcome: Any, ok: tuple[str, ...] = ()) -> None:
        self.outcome = outcome
        self.ok = ok

    def __getattr__(self, name: str) -> Any:
        def call(*_args: Any, **_kwargs: Any) -> Any:
            if name in self.ok:
                return _Request({})
            if name in {"filters", "forwardingAddresses", "sendAs", "delegates"}:
                return _GmailSettings(self.outcome, ok=("list",) if name in self.ok else ())
            return _Request(self.outcome)

        return call


def _gmail_client(settings: _GmailSettings) -> GoogleWorkspaceClient:
    users = type("Users", (), {"settings": lambda self: settings})()
    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("gmail", "v1")] = type("Gmail", (), {"users": lambda self: users})()
    return client


def test_r055_every_settings_read_failing_fails_the_mailbox_row_and_the_probe() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector
    from auditex.google_workspace.run import build_google_capability_rows, build_google_preflight_rows

    client = _gmail_client(_GmailSettings(_HttpError(403)))
    result = GoogleGmailSettingsCollector().run({"client": client, "users": [{"primaryEmail": "me@example.com"}]})
    row = next(item for item in result.coverage if item["name"] == "mailboxSettings:me")
    assert row["status"] == "failed"
    assert row["error_class"] == "insufficient_permissions"
    assert result.status == "partial"

    preflight = build_google_preflight_rows(client, ["google_gmail_settings"], domain="example.com")
    assert preflight[0]["status"] == "failed" and preflight[0]["error_class"] == "insufficient_permissions"
    capability = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="oauth", dependency_status={"available": True}, coverage_rows=preflight
    )
    assert capability[0]["status"] == "blocked_by_scope"


def test_r055_some_settings_reads_failing_make_the_mailbox_row_partial() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    client = _gmail_client(_GmailSettings(_HttpError(404), ok=("getAutoForwarding", "getImap", "getPop", "getVacation")))
    result = GoogleGmailSettingsCollector().run({"client": client, "users": [{"primaryEmail": "me@example.com"}]})
    row = next(item for item in result.coverage if item["name"] == "mailboxSettings:me")
    assert row["status"] == "partial"
    assert row["error_class"] == "resource_not_found"
    assert result.payload["mailboxSettings"]["value"][0]["userEmail"] == "me"


def test_r055_clean_settings_reads_stay_ok() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    client = _gmail_client(_GmailSettings({}))
    result = GoogleGmailSettingsCollector().run({"client": client, "users": []})
    assert [(row["name"], row["status"]) for row in result.coverage] == [("mailboxSettings:me", "ok")]
    assert result.status == "ok"


# ---- R115: users are read through a field mask, so recovery contacts never reach the bundle --------------------


def test_r115_users_list_names_only_the_fields_the_audit_reads() -> None:
    calls: list[dict[str, Any]] = []

    class _Users:
        def list(self, **kwargs: Any) -> _Request:
            calls.append(kwargs)
            return _Request({"users": [{"id": "u1", "primaryEmail": "u1@example.com"}]})

    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("admin", "directory_v1")] = type("Dir", (), {"users": lambda self: _Users()})()
    client.list_directory("users")
    fields = str(calls[0].get("fields") or "")
    assert fields.startswith("nextPageToken,users(")
    for name in ("id", "primaryEmail", "isAdmin", "isDelegatedAdmin", "suspended", "archived", "isEnrolledIn2Sv",
                 "isEnforcedIn2Sv", "lastLoginTime", "creationTime", "orgUnitPath", "name/fullName"):
        assert name in fields
    for name in ("recoveryEmail", "recoveryPhone", "phones", "addresses", "notes", "organizations"):
        assert name not in fields


# ---- R057: files whose sharing files.list does not return (shared drives) get their permissions read ----------


def _drive_client(files: list[dict[str, Any]], permissions: Any, calls: list[dict[str, Any]]) -> GoogleWorkspaceClient:
    class _Files:
        def list(self, **kwargs: Any) -> _Request:
            calls.append({"files.list": kwargs})
            return _Request({"files": [dict(item) for item in files]})

    class _Permissions:
        def list(self, **kwargs: Any) -> _Request:
            calls.append({"permissions.list": kwargs})
            return _Request(permissions)

    drive = type("Drive", (), {"files": lambda self: _Files(), "permissions": lambda self: _Permissions()})()
    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("drive", "v3")] = drive
    return client


def test_r057_shared_drive_file_permissions_are_read_and_public_sharing_is_found() -> None:
    from auditex.google_workspace.findings import build_google_findings
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    calls: list[dict[str, Any]] = []
    anyone = {"id": "anyoneWithLink", "type": "anyone", "role": "reader", "allowFileDiscovery": False}
    client = _drive_client(
        [{"id": "f1", "name": "Budget", "driveId": "d1", "permissionIds": ["anyoneWithLink"]},
         {"id": "f2", "name": "Mine", "permissions": []}],
        {"permissions": [anyone]},
        calls,
    )
    files = client.list_drive_files()
    assert "driveId" in calls[0]["files.list"]["fields"]
    permission_calls = [call["permissions.list"] for call in calls if "permissions.list" in call]
    assert [call["fileId"] for call in permission_calls] == ["f1"]
    assert permission_calls[0]["supportsAllDrives"] is True
    assert files[0]["permissions"] == [anyone]

    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="r1", domain="example.com",
        collector_payloads={"google_drive_posture": {"driveFiles": {"value": list(files)}, "sharedDrives": {"value": []}}},
    )
    rule_ids = [item["rule_id"] for item in build_google_findings(snapshot)]
    assert "google.drive_anyone_with_link" in rule_ids


def test_r057_unreadable_shared_drive_permissions_are_a_coverage_gap_not_clean() -> None:
    from auditex.google_workspace.collectors import GoogleDrivePostureCollector

    calls: list[dict[str, Any]] = []
    client = _drive_client([{"id": "f1", "name": "Budget", "driveId": "d1"}], _HttpError(403), calls)
    result = GoogleDrivePostureCollector().run({"client": client})
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert row["status"] == "failed"
    assert row["error_class"] == "insufficient_permissions"
    assert result.status == "partial"
