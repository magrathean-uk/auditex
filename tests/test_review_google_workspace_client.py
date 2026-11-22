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
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

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


def test_r055_clean_settings_reads_leave_only_the_oauth_delegates_gap() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    client = _gmail_client(_GmailSettings({}))
    result = GoogleGmailSettingsCollector().run({"client": client, "users": []})
    # No read failed; the one gap is delegates, which an OAuth sign-in cannot list (repair round 2).
    assert [(row["name"], row["status"], row.get("error_class")) for row in result.coverage] == [
        ("mailboxSettings:me", "partial", "subject_scope")
    ]


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

    class _Drives:
        def list(self, **kwargs: Any) -> _Request:
            calls.append({"drives.list": kwargs})
            return _Request({"drives": [{"id": "d1", "name": "Finance"}]})

    drive = type(
        "Drive", (), {"files": lambda self: _Files(), "permissions": lambda self: _Permissions(), "drives": lambda self: _Drives()}
    )()
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
    # Every other read succeeds, so the unreadable sharing alone makes the collector partial.
    assert next(item for item in result.coverage if item["name"] == "sharedDrives")["status"] == "ok"
    assert result.status == "partial"


def test_r055_offline_replay_of_failed_gmail_settings_reads_is_partial(tmp_path: Any) -> None:
    import json

    from auditex.google_workspace.run import run_google_offline

    error = {"error_class": "insufficient_permissions", "error": "denied"}
    failed = {"userEmail": "a@example.com", **{f"{name}_error": error for name in google_client.GMAIL_SETTING_NAMES}}
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"google_gmail_settings": {"mailboxSettings": {"value": [failed]}}}), encoding="utf-8")

    rc = run_google_offline(sample_path=sample, out=tmp_path / "out", tenant_name="T", run_name="r",
                            domain="example.com", customer_id=None)

    assert rc == 1
    summary = json.loads((tmp_path / "out" / "T-r" / "summary.json").read_text(encoding="utf-8"))
    assert summary["collectors"][0]["status"] != "ok"


# ---- in-session review follow-ups ---------------------------------------------------------------------------------


def test_r057_a_failed_later_permissions_page_is_a_gap_not_complete_sharing() -> None:
    owner = {"id": "p0", "type": "user", "role": "owner", "emailAddress": "owner@example.com"}
    pages = {None: [{"permissions": [owner], "nextPageToken": "p2"}], "p2": [_HttpError(503)] * 10}

    class _Permissions:
        def list(self, **kwargs: Any) -> _Request:
            return _Request(pages[kwargs.get("pageToken")].pop(0))

    class _Files:
        def list(self, **_kwargs: Any) -> _Request:
            return _Request({"files": [{"id": "f1", "driveId": "d1"}]})

    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("drive", "v3")] = type("D", (), {"files": lambda self: _Files(), "permissions": lambda self: _Permissions()})()
    files = client.list_drive_files()
    assert files.permission_reads == 0
    assert [error["fileId"] for error in files.permission_errors or []] == ["f1"]
    assert files.permission_errors[0]["error_class"] == "google_transient"


def test_r011_r058_dropping_deleted_alerts_keeps_a_page_error() -> None:
    pages = {None: [{"alerts": [{"alertId": "a1", "deleted": True}, {"alertId": "a2"}], "nextPageToken": "p2"}],
             "p2": [_HttpError(503)] * 10}

    class _Alerts:
        def list(self, **kwargs: Any) -> _Request:
            return _Request(pages[kwargs.get("pageToken")].pop(0))

    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("alertcenter", "v1beta1")] = type("S", (), {"alerts": lambda self: _Alerts()})()
    alerts = client.list_alerts()
    assert [alert["alertId"] for alert in alerts] == ["a2"]
    assert getattr(alerts, "page_error", None) is not None and alerts.truncated is True


# ---- bot review wave 2, group I: read completion, DNS-only preflight, scope refusals and quota 403s ---------------


def _real_http_error(status: int, body: dict[str, Any]) -> Exception:
    import json

    from googleapiclient.errors import HttpError

    resp = type("Resp", (), {"status": status, "reason": "Forbidden"})()
    return HttpError(resp, json.dumps(body).encode("utf-8"), uri="https://admin.googleapis.com/admin/directory/v1/users")


def _quota_403(reason: str) -> Exception:
    return _real_http_error(403, {"error": {"code": 403, "message": "Quota exceeded.", "errors": [
        {"domain": "usageLimits", "reason": reason, "message": "Quota exceeded."}]}})


@pytest.mark.parametrize("reason", ["userRateLimitExceeded", "rateLimitExceeded"])
def test_w2_20_quota_403_is_retried_with_backoff(reason: str, _no_backoff_sleep: list[float]) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    factory = _paged({None: [_quota_403(reason), {"users": [{"id": "u1"}]}]})
    rows = client._collect_pages(factory, "users", limit=None)
    assert [row["id"] for row in rows] == ["u1"]
    assert len(_no_backoff_sleep) == 1
    assert google_client.classify_google_error(_quota_403(reason))[0] == "rate_limited"


def test_w2_20_a_permission_403_is_still_not_retried(_no_backoff_sleep: list[float]) -> None:
    denied = _real_http_error(403, {"error": {"code": 403, "message": "Not Authorized to access this resource/api",
                                              "errors": [{"domain": "global", "reason": "forbidden"}]}})
    client = GoogleWorkspaceClient(credentials=None)
    with pytest.raises(Exception, match="HttpError 403"):
        client._collect_pages(_paged({None: [denied]}), "users", limit=None)
    assert _no_backoff_sleep == []
    assert google_client.classify_google_error(denied)[0] == "insufficient_permissions"


def _refresh_error(error: str, description: str) -> Exception:
    from google.auth.exceptions import RefreshError

    return RefreshError(f"{error}: {description}", {"error": error, "error_description": description})


def test_w2_19_a_delegated_access_denied_token_exchange_is_a_scope_refusal() -> None:
    refused = _refresh_error("access_denied", "Requested client not authorized.")
    assert google_client.is_token_refusal(str(refused))
    assert google_client.classify_google_error(refused)[0] == "insufficient_permissions"


def test_w2_19_other_token_and_api_failures_are_not_scope_refusals() -> None:
    invalid_grant = _refresh_error("invalid_grant", "Invalid JWT Signature.")
    assert not google_client.is_token_refusal(str(invalid_grant))
    assert google_client.classify_google_error(invalid_grant)[0] == "client_error"
    api_denied = _real_http_error(403, {"error": {"code": 403, "message": "access_denied by policy"}})
    assert not google_client.is_token_refusal(str(api_denied))


def test_w2_19_per_scope_check_names_each_access_denied_scope() -> None:
    granted = {"https://www.googleapis.com/auth/a"}

    class _Credentials:
        def __init__(self, scopes: tuple[str, ...] = ()) -> None:
            self.scopes = scopes

        def with_scopes(self, scopes: list[str]) -> _Credentials:
            return _Credentials(tuple(scopes))

        def refresh(self, _request: Any) -> None:
            if not set(self.scopes) <= granted:
                raise _refresh_error("access_denied", "Requested client not authorized.")

    client = GoogleWorkspaceClient(credentials=_Credentials())
    original = google_client._token_request
    google_client._token_request = lambda: None  # type: ignore[assignment]
    try:
        missing = client.unauthorised_scopes(
            ("https://www.googleapis.com/auth/a", "https://www.googleapis.com/auth/b", "https://www.googleapis.com/auth/c")
        )
    finally:
        google_client._token_request = original  # type: ignore[assignment]
    assert missing == ["https://www.googleapis.com/auth/b", "https://www.googleapis.com/auth/c"]


def test_w2_21_an_empty_completed_read_proves_the_collector_token_scopes() -> None:
    from auditex.google_workspace.collectors import GoogleDevicesCollector
    from auditex.google_workspace.run import build_google_capability_rows

    class _Client:
        def list_devices(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            if resource == "chromeos":
                raise _HttpError(403)
            return []

    result = GoogleDevicesCollector().run({"client": _Client()})
    mobile = next(row for row in result.coverage if row["name"] == "mobileDevices")
    assert mobile["status"] == "ok" and mobile["item_count"] == 0
    row = build_google_capability_rows(
        ["google_devices"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=result.coverage,
    )[0]
    assert row["status"] == "partial"
    assert row["reason"] == "runtime_permission_block"
    assert row["missing_permissions"] == []


def test_w2_21_a_row_with_no_read_behind_it_proves_no_scope() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    coverage = [
        {"collector": "google_gmail_settings", "type": "google", "name": "mailboxSettingsSkipped", "status": "ok",
         "item_count": 0, "endpoint": "gmail.users.settings"},
        {"collector": "google_gmail_settings", "type": "google", "name": "mailboxSettings:a", "status": "failed",
         "item_count": 0, "error_class": "insufficient_permissions", "error": "HTTP 403"},
    ]
    row = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=coverage,
    )[0]
    assert row["status"] == "blocked_by_scope"


def test_w2_25_a_dns_only_preflight_never_marks_the_google_scope_exact() -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    preflight = build_google_preflight_rows(object(), ["google_dns_posture"], domain="example.com")
    assert [row.get("type") for row in preflight] == ["dns"]
    row = build_google_capability_rows(
        ["google_dns_posture"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=preflight,
    )[0]
    assert row["status"] != "supported_exact_scope"
    assert row["status"] == "supported"


def test_w2_25_a_completed_google_preflight_read_is_still_exact_scope() -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    class _Client:
        def list_alerts(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return []

    preflight = build_google_preflight_rows(_Client(), ["google_alert_center"], domain="example.com")
    row = build_google_capability_rows(
        ["google_alert_center"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=preflight,
    )[0]
    assert row["status"] == "supported_exact_scope"


def test_w2_21_a_permission_block_beside_proven_scopes_asks_for_a_role_not_scopes() -> None:
    from auditex.google_workspace.collectors import GoogleDevicesCollector
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_live_readiness,
    )

    class _Client:
        def list_devices(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            if resource == "chromeos":
                raise _HttpError(403)
            return []

    result = GoogleDevicesCollector().run({"client": _Client()})
    rows = build_google_capability_rows(
        ["google_devices"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=result.coverage,
    )
    row = rows[0]
    assert row["missing_permissions"] == []
    assert row["blocker_kind"] == "admin_role"
    assert "scope" not in row["next_step"].lower()
    readiness = build_google_live_readiness(["google_devices"], rows, coverage_rows=result.coverage)
    gate = readiness["evidence_gates"][0]
    assert gate["blocker_kind"] == "admin_role"
    assert readiness["blocker_summary"]["counts"].get("auth_scope") is None


def test_w2_21_a_refused_token_with_no_proven_scope_still_asks_for_scopes() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    coverage = [
        {"collector": "google_devices", "type": "google", "name": "mobileDevices", "status": "failed",
         "item_count": 0, "error_class": "insufficient_permissions", "error": "HTTP 403"},
    ]
    row = build_google_capability_rows(
        ["google_devices"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=coverage,
    )[0]
    assert row["status"] == "blocked_by_scope"
    assert row["blocker_kind"] == "auth_scope"


def test_w2_25_a_dns_only_probe_is_not_live_verified_or_exact_scope() -> None:
    from auditex.google_workspace.run import (
        _google_probe_summary_rows,
        build_google_capability_rows,
        build_google_live_readiness,
        build_google_preflight_rows,
    )
    from azure_tenant_audit.run import build_coverage_ledger

    selected = ["google_dns_posture"]
    preflight = build_google_preflight_rows(object(), selected, domain="example.com")
    capability = build_google_capability_rows(
        selected, auth_mode="domain-delegation", dependency_status={"available": True}, coverage_rows=preflight,
    )
    readiness = build_google_live_readiness(selected, capability, coverage_rows=preflight)
    assert readiness["trust_level"] != "live_verified"
    gate = readiness["evidence_gates"][0]
    assert gate["status"] == "unverified"
    assert "dns-only" in gate["reason"].replace("_", "-")
    ledger = build_coverage_ledger(
        capability_rows=capability,
        result_rows=_google_probe_summary_rows(selected, preflight),
        diagnostics=[],
    )
    assert ledger[0]["coverage_status"] != "complete_exact_scope"
    assert ledger[0]["coverage_status"] == "not_run"
    assert "dns-only" in ledger[0]["coverage_reason"].replace("_", "-")


def test_w2_25_a_completed_google_probe_read_is_still_live_verified() -> None:
    from auditex.google_workspace.run import (
        _google_probe_summary_rows,
        build_google_capability_rows,
        build_google_live_readiness,
        build_google_preflight_rows,
    )
    from azure_tenant_audit.run import build_coverage_ledger

    class _Client:
        def list_alerts(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return []

    selected = ["google_alert_center"]
    preflight = build_google_preflight_rows(_Client(), selected, domain="example.com")
    capability = build_google_capability_rows(
        selected, auth_mode="domain-delegation", dependency_status={"available": True}, coverage_rows=preflight,
    )
    readiness = build_google_live_readiness(selected, capability, coverage_rows=preflight)
    assert readiness["trust_level"] == "live_verified"
    ledger = build_coverage_ledger(
        capability_rows=capability, result_rows=_google_probe_summary_rows(selected, preflight), diagnostics=[],
    )
    assert ledger[0]["coverage_status"] == "complete_exact_scope"
