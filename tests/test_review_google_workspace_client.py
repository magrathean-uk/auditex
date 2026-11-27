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


# ---- LIVE-FIX-1: a user with no Gmail service is not applicable, never a failed mailbox -----------------------------


def _GmailHttpError(status: int, reason: str, message: str, *, top: str | None = None,
                    errors: list[tuple[str, str]] | None = None) -> Exception:
    """A real googleapiclient ``HttpError`` with Gmail's JSON error body: the top-level ``message`` and the
    structured ``errors`` (reason and message pairs)."""
    pairs = errors if errors is not None else [(reason, message)]
    return _real_http_error(status, {"error": {
        "code": status, "message": top if top is not None else message, "status": "FAILED_PRECONDITION",
        "errors": [{"message": text, "domain": "global", "reason": why} for why, text in pairs]}})


_NOT_ENABLED = _GmailHttpError(400, "failedPrecondition", "Mail service not enabled")


class _CountingSettings(_GmailSettings):
    def __init__(self, outcome: Any) -> None:
        super().__init__(outcome)
        self.calls: list[str] = []

    def __getattr__(self, name: str) -> Any:
        if name in {"outcome", "ok", "calls"}:
            raise AttributeError(name)
        self.calls.append(name)
        return super().__getattr__(name)


def _delegated_gmail_client(per_user: dict[str, Any]) -> GoogleWorkspaceClient:
    credentials = type("Credentials", (), {"with_subject": lambda self, _subject: self})()
    client = GoogleWorkspaceClient(credentials=credentials, delegated=True)
    assert client.per_user_delegation

    def subject_service(user_email: str, *_args: Any) -> Any:
        settings = per_user[user_email]
        users = type("Users", (), {"settings": lambda self: settings})()
        return type("Gmail", (), {"users": lambda self: users})()

    client._subject_service = subject_service  # type: ignore[method-assign]
    return client


def test_live_fix_1_mail_service_not_enabled_reads_nothing_more_and_is_not_applicable() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    unlicensed = _CountingSettings(_NOT_ENABLED)
    client = _delegated_gmail_client({"a@example.com": _GmailSettings({}), "b@example.com": unlicensed})
    assert client.get_gmail_settings_for_user("b@example.com") == {"userEmail": "b@example.com", "mailService": "not_enabled"}
    assert unlicensed.calls == ["getAutoForwarding"]

    users = [{"primaryEmail": "a@example.com"}, {"primaryEmail": "b@example.com"}]
    result = GoogleGmailSettingsCollector().run({"client": client, "users": users})
    assert result.status == "ok"
    rows = {row["name"]: row for row in result.coverage}
    assert rows["mailboxSettings:b@example.com"]["status"] == "ok"
    assert rows["mailboxSettings:b@example.com"]["item_count"] == 0
    assert rows["mailboxSettings:b@example.com"]["not_applicable"] == "mail_service_not_enabled"
    assert rows["mailboxSettings:a@example.com"]["status"] == "ok" and "not_applicable" not in rows["mailboxSettings:a@example.com"]

    snapshot = build_google_normalized_snapshot(
        tenant_name="T", run_id="r1", collector_payloads={"google_gmail_settings": result.payload},
        result_rows=[{"name": "google_gmail_settings", "status": result.status}], coverage_rows=result.coverage,
    )
    records = {row["user_email"]: row for row in snapshot["google_mailbox_settings"]["records"]}
    assert records["b@example.com"]["mail_service"] == "not_enabled"
    assert "auto_forwarding_error" not in records["b@example.com"]
    assert "mail_service" not in records["a@example.com"]


@pytest.mark.parametrize("error", [
    _GmailHttpError(400, "invalidArgument", "Mail service not enabled"),
    _GmailHttpError(400, "failedPrecondition", "Precondition check failed."),
    _GmailHttpError(403, "failedPrecondition", "Mail service not enabled"),
])
def test_live_fix_1_any_other_error_is_still_a_failed_mailbox(error: Exception) -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    settings = _CountingSettings(error)
    client = _delegated_gmail_client({"b@example.com": settings})
    result = GoogleGmailSettingsCollector().run({"client": client, "users": [{"primaryEmail": "b@example.com"}]})
    row = next(item for item in result.coverage if item["name"] == "mailboxSettings:b@example.com")
    assert (row["status"], result.status) == ("failed", "partial")
    assert "not_applicable" not in row
    assert len(settings.calls) > 1  # every other setting was still tried


@pytest.mark.parametrize("payload", [
    {"userEmail": "b@example.com", "mailService": "disabled"},
    {"userEmail": "b@example.com", "mailService": None},
    {"userEmail": "b@example.com", "mailService": ["not_enabled"]},
    {"userEmail": "b@example.com", "mailService": "not_enabled", "autoForwarding": {"enabled": True}},
    {"userEmail": "b@example.com", "mailService": "not_enabled", "imap_error": {"error_class": "client_error"}},
    {"mailService": "not_enabled"},
])
def test_live_fix_1_a_malformed_mail_service_marker_is_a_failed_read(payload: dict[str, Any]) -> None:
    from auditex.google_workspace.client import gmail_settings_status
    from auditex.google_workspace.normalize import _mailbox_record

    assert gmail_settings_status(payload) == (
        "failed", "malformed_response", "The Gmail settings row carries an unreadable mail service marker.")
    if "userEmail" in payload:
        assert _mailbox_record(payload)["mail_service"] == "unreadable"


def test_live_fix_1_an_offline_replay_keeps_the_unlicensed_mailbox_not_failed() -> None:
    from auditex.google_workspace.run import _replayed_mailbox_rows

    payload = {"mailboxSettings": {"value": [
        {"userEmail": "b@example.com", "mailService": "not_enabled"},
        {"userEmail": "c@example.com", "mailService": "off"},
    ]}}
    assert [(row["name"], row["status"]) for row in _replayed_mailbox_rows("google_gmail_settings", payload)] == [
        ("mailboxSettings:c@example.com", "failed")
    ]


# ---- LIVE-FIX-1 repair round 1 -------------------------------------------------------------------------------------


@pytest.mark.parametrize("error", [
    # B6: the reason and the text come from different structured errors, and the top-level message is another one.
    _GmailHttpError(400, "", "", top="Another precondition failed", errors=[
        ("failedPrecondition", "Another precondition failed"), ("invalidArgument", "Mail service not enabled")]),
    # The top-level message is the text, but the structured errors pair it with another reason.
    _GmailHttpError(400, "", "", top="Mail service not enabled", errors=[
        ("failedPrecondition", "Another precondition failed"), ("invalidArgument", "Mail service not enabled")]),
    # One matching pair beside an unrelated one: ambiguous.
    _GmailHttpError(400, "", "", top="Mail service not enabled", errors=[
        ("failedPrecondition", "Mail service not enabled"), ("invalidArgument", "Bad request")]),
    # The pair matches but the top-level message names another failure.
    _GmailHttpError(400, "failedPrecondition", "Mail service not enabled", top="Precondition check failed."),
    # No structured error at all.
    _GmailHttpError(400, "", "", top="Mail service not enabled", errors=[]),
])
def test_live_fix_1_r1_b6_mixed_gmail_error_fields_stay_a_failed_mailbox(error: Exception) -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    settings = _CountingSettings(error)
    client = _delegated_gmail_client({"b@example.com": settings})
    result = GoogleGmailSettingsCollector().run({"client": client, "users": [{"primaryEmail": "b@example.com"}]})
    row = next(item for item in result.coverage if item["name"] == "mailboxSettings:b@example.com")
    assert (row["status"], result.status) == ("failed", "partial")
    assert "not_applicable" not in row
    assert result.payload["mailboxSettings"]["value"][0].get("mailService") is None
    assert len(settings.calls) == 8  # every setting was still tried


def test_live_fix_1_r1_b6_a_non_json_body_is_never_the_not_enabled_marker() -> None:
    from googleapiclient.errors import HttpError

    from auditex.google_workspace.client import _gmail_not_enabled_error

    resp = type("Resp", (), {"status": 400, "reason": "Mail service not enabled"})()
    assert _gmail_not_enabled_error(HttpError(resp, b"Mail service not enabled", uri="https://gmail.googleapis.com/x")) is False
    assert _gmail_not_enabled_error(_NOT_ENABLED) is True


@pytest.mark.parametrize("user_email", [None, "", 7, ["b@example.com"], {"a": 1}, "b", "b@", "@example.com",
                                        "b@example", "b c@example.com", "a@b@example.com", True])
def test_live_fix_1_r1_b5_a_marker_without_a_mailbox_identifier_is_a_failed_read(user_email: Any) -> None:
    from auditex.google_workspace.client import (
        gmail_mail_service_not_enabled,
        gmail_settings_status,
    )

    payload = {"userEmail": user_email, "mailService": "not_enabled"}
    assert gmail_mail_service_not_enabled(payload) is False
    assert gmail_settings_status(payload) == (
        "failed", "malformed_response", "The Gmail settings row carries an unreadable mail service marker.")


@pytest.mark.parametrize("user_email", ["b@example.com", "me", "first.last+tag@sub.example.co.uk"])
def test_live_fix_1_r1_b5_a_mailbox_identifier_keeps_the_marker(user_email: str) -> None:
    from auditex.google_workspace.client import gmail_settings_status

    assert gmail_settings_status({"userEmail": user_email, "mailService": "not_enabled"}) == ("ok", None, None)


@pytest.mark.parametrize("row", [
    {"userEmail": None, "mailService": "not_enabled"},
    {"userEmail": "", "mailService": "not_enabled"},
    {"userEmail": 7, "mailService": "not_enabled"},
    {"userEmail": ["b@example.com"], "mailService": "not_enabled"},
    {"userEmail": "not an address", "mailService": "not_enabled"},
    {"userEmail": "b@example.com", "mailService": "not_enabled", "imap": {"enabled": True}},
])
def test_live_fix_1_r1_b5_a_malformed_marker_fails_the_replay_and_supplies_no_finding(tmp_path: Any, row: dict) -> None:
    import json

    from auditex.google_workspace.run import run_google_offline

    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"google_gmail_settings": {"mailboxSettings": {"value": [row]}}}), encoding="utf-8")
    rc = run_google_offline(sample_path=sample, out=tmp_path / "out", tenant_name="T", run_name="r",
                            domain="example.com", customer_id=None)
    run = tmp_path / "out" / "T-r"
    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    assert (rc, manifest["overall_status"]) == (1, "partial")
    findings = json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))
    rules = {item.get("rule_id") for item in (findings if isinstance(findings, list) else findings.get("findings", []))}
    assert "google.gmail_imap_enabled" not in rules
    path = run / "normalized" / "google_mailbox_settings.json"
    records = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    for record in records if isinstance(records, list) else records.get("records", []):
        if record.get("user_email") == "b@example.com":
            assert record == {**{key: record[key] for key in ("kind", "source", "id", "key")},
                              "user_email": "b@example.com", "mail_service": "unreadable"}


def test_live_fix_1_r1_m1_an_unlicensed_probe_mailbox_proves_no_read_and_no_exact_scope() -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    client = _delegated_gmail_client({"b@example.com": _CountingSettings(_NOT_ENABLED)})
    client.list_directory = lambda kind, top=1: [{"primaryEmail": "b@example.com"}]  # type: ignore[method-assign]
    preflight = build_google_preflight_rows(client, ["google_gmail_settings"], domain="example.com")
    (row,) = preflight
    assert (row["status"], row["item_count"], row["not_applicable"]) == ("ok", 0, "mail_service_not_enabled")
    assert not row.get("authenticated_read")
    capability = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=preflight,
    )[0]
    assert capability["status"] == "supported"


def test_live_fix_1_r1_m1_a_licensed_probe_mailbox_still_proves_the_scope() -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    client = _delegated_gmail_client({"a@example.com": _GmailSettings({})})
    client.list_directory = lambda kind, top=1: [{"primaryEmail": "a@example.com"}]  # type: ignore[method-assign]
    preflight = build_google_preflight_rows(client, ["google_gmail_settings"], domain="example.com")
    assert (preflight[0]["status"], preflight[0]["item_count"], "not_applicable" in preflight[0]) == ("ok", 1, False)
    capability = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=preflight,
    )[0]
    assert capability["status"] == "supported_exact_scope"


# ---- LIVE-FIX-1 round 2: B7 (mailbox identifiers) and M2 (an empty Gmail probe) -----------------------------------


@pytest.mark.parametrize("user_email,readable", [
    ("b@example.com", True), ("me", True), ("first.last+tag@sub.example.co.uk", True), ("o'neil@example.com", True),
    ("b@example.com/archive.txt", False), ("b@exa_mple.com", False), ("b@example.com,broken", False),
    ("/srv/synthetic/mailbox.txt", False), ("b@example.123", False), ("b@-example.com", False), ("b@example.com ", False),
    ("b/c@example.com", False), ("b@example..com", False),
])
def test_live_fix_1_r2_b7_one_mailbox_address_or_me(user_email: str, readable: bool) -> None:
    from auditex.google_workspace.client import (
        gmail_mail_service_not_enabled,
        gmail_settings_status,
    )
    from azure_tenant_audit.data_minimisation import (
        gmail_mailbox_identifier,
        minimise_gmail_settings,
    )

    assert gmail_mailbox_identifier(user_email) is readable
    marker = {"userEmail": user_email, "mailService": "not_enabled"}
    assert gmail_mail_service_not_enabled(marker) is readable
    kept = minimise_gmail_settings(marker)["userEmail"]
    assert kept == (user_email if readable else "redacted:mailbox")
    status = gmail_settings_status({"userEmail": user_email, "imap": {"enabled": False}})
    assert status == (("ok", None, None) if readable else
                      ("failed", "malformed_response", "The Gmail settings row names no readable mailbox."))


@pytest.mark.parametrize("row", [
    {"userEmail": "b@example.com/archive.txt", "mailService": "not_enabled"},
    {"userEmail": "b@example.com,broken", "mailService": "not_enabled"},
    {"userEmail": "/srv/synthetic/mailbox.txt", "mailService": "not_enabled"},
    {"userEmail": "/srv/synthetic/mailbox.txt", "imap": {"enabled": True}},
])
def test_live_fix_1_r2_b7_an_unreadable_identifier_fails_the_replay_and_never_reaches_the_bundle(
        tmp_path: Any, row: dict) -> None:
    import json

    from auditex.google_workspace.run import run_google_offline

    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"google_gmail_settings": {"mailboxSettings": {"value": [row]}}}), encoding="utf-8")
    rc = run_google_offline(sample_path=sample, out=tmp_path / "out", tenant_name="T", run_name="r",
                            domain="example.com", customer_id=None)
    run = tmp_path / "out" / "T-r"
    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    assert (rc, manifest["overall_status"]) == (1, "partial")
    text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in run.rglob("*") if path.is_file())
    assert row["userEmail"] not in text
    assert "archive.txt" not in text and "synthetic/mailbox" not in text and ",broken" not in text
    records = json.loads((run / "normalized" / "google_mailbox_settings.json").read_text(encoding="utf-8"))
    records = records if isinstance(records, list) else records["records"]
    assert [(record.get("user_email"), record.get("mail_service"), "imap" in record) for record in records
            if record.get("kind") == "google_mailbox_setting"] == [("redacted:mailbox", "unreadable", False)]
    findings = json.loads((run / "findings" / "findings.json").read_text(encoding="utf-8"))
    rules = {item.get("rule_id") for item in (findings if isinstance(findings, list) else findings.get("findings", []))}
    assert "google.gmail_imap_enabled" not in rules


@pytest.mark.parametrize("users", [[], [{"primaryEmail": ""}], [{"id": "u1"}]])
def test_live_fix_1_r2_m2_an_empty_gmail_probe_proves_no_read_and_no_exact_scope(users: list) -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    client = _delegated_gmail_client({})
    client.list_directory = lambda kind, top=1: users  # type: ignore[method-assign]
    preflight = build_google_preflight_rows(client, ["google_gmail_settings"], domain="example.com")
    (row,) = preflight
    assert (row["status"], row["item_count"], row.get("authenticated_read")) == ("ok", 0, False)
    capability = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=preflight,
    )[0]
    assert capability["status"] == "supported"


# ---- LIVE-FIX-1 final small fix ------------------------------------------------------------------------------------


def test_live_fix_1_final_b1_a_rejected_directory_address_never_reaches_coverage_or_the_bundle() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    bad = "/srv/synthetic/live-invalid-mailbox.txt"
    settings = _CountingSettings(_NOT_ENABLED)
    client = _delegated_gmail_client({"a@example.com": _GmailSettings({}), bad: settings})
    result = GoogleGmailSettingsCollector().run({"client": client, "users": [{"primaryEmail": "a@example.com"}, {"primaryEmail": bad}]})
    assert settings.calls == []  # never used as a delegated subject
    assert result.status == "partial"
    assert "live-invalid-mailbox" not in repr((result.payload, result.coverage))
    names = {row["name"]: row for row in result.coverage}
    assert names["mailboxSettings:unknown"]["status"] == "failed"
    assert names["mailboxSettings:a@example.com"]["status"] == "ok"
    assert {"userEmail": "redacted:mailbox"} in result.payload["mailboxSettings"]["value"]


def test_live_fix_1_final_b2_a_local_part_of_only_dots_is_no_mailbox() -> None:
    from auditex.google_workspace.client import (
        gmail_mail_service_not_enabled,
        gmail_settings_status,
    )

    for address in (".@example.com", "..@example.com"):
        payload = {"userEmail": address, "mailService": "not_enabled"}
        assert gmail_mail_service_not_enabled(payload) is False
        assert gmail_settings_status(payload)[0] == "failed"
    assert gmail_mail_service_not_enabled({"userEmail": "a.b@example.com", "mailService": "not_enabled"}) is True


def test_live_fix_1_final_b2_replay_of_a_dots_only_marker_is_partial_and_withheld(tmp_path: Any) -> None:
    import json

    from auditex.google_workspace.run import run_google_offline

    sample = tmp_path / "sample.json"
    row = {"userEmail": ".@example.com", "mailService": "not_enabled"}
    sample.write_text(json.dumps({"google_gmail_settings": {"mailboxSettings": {"value": [row]}}}), encoding="utf-8")
    rc = run_google_offline(sample_path=sample, out=tmp_path / "out", tenant_name="T", run_name="r",
                            domain="example.com", customer_id=None)
    run = tmp_path / "out" / "T-r"
    manifest = json.loads((run / "run-manifest.json").read_text(encoding="utf-8"))
    assert (rc, manifest["overall_status"]) == (1, "partial")
    assert ".@example.com" not in "".join(path.read_text(encoding="utf-8", errors="ignore")
                                        for path in run.rglob("*.json"))


@pytest.mark.parametrize("row", [None, {"userEmail": "b@example.com"}, {"userEmail": "b@example.com", "skippedSettings": []}])
def test_live_fix_1_final_m2_a_row_that_supplies_no_settings_is_never_a_complete_read(tmp_path: Any, row: Any) -> None:
    import json

    from auditex.google_workspace.client import gmail_settings_status
    from auditex.google_workspace.run import run_google_offline

    if isinstance(row, dict):
        assert gmail_settings_status(row)[0] == "failed"
    sample = tmp_path / "sample.json"
    sample.write_text(json.dumps({"google_gmail_settings": {"mailboxSettings": {"value": [row]}}}), encoding="utf-8")
    rc = run_google_offline(sample_path=sample, out=tmp_path / "out", tenant_name="T", run_name="r",
                            domain="example.com", customer_id=None)
    manifest = json.loads((tmp_path / "out" / "T-r" / "run-manifest.json").read_text(encoding="utf-8"))
    assert (rc, manifest["overall_status"]) == (1, "partial")


def test_live_fix_1_final_m2_a_row_with_one_read_setting_is_still_complete() -> None:
    from auditex.google_workspace.client import gmail_settings_status

    assert gmail_settings_status({"userEmail": "b@example.com", "imap": {"enabled": False}}) == ("ok", None, None)


# ---- LIVE-FIX-5 B1: a list row that cannot be read is never dropped silently ----------------------------------

_GOOD_USERS = [{"id": "u100", "primaryEmail": "ada@example.com"}, {"id": "u200", "primaryEmail": "bo@example.com"}]


@pytest.mark.parametrize("bad_row", [None, ["u300"], "u300", 300, True, 1.5])
def test_live_fix_5_b1_an_unreadable_user_row_makes_the_list_partial(bad_row: Any) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": [_GOOD_USERS[0], bad_row, _GOOD_USERS[1]]}]}),
                                 "users", limit=None)
    assert list(rows) == _GOOD_USERS
    assert isinstance(rows.page_error, google_client.PolicyReadError)
    assert rows.page_error.error_class == "malformed_response"


@pytest.mark.parametrize("bad_list", ["u300", "", 0, 7, False, True, {}, {"id": "u300"}])
def test_live_fix_5_b1_a_row_list_that_is_not_a_list_makes_the_list_partial(bad_list: Any) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": list(_GOOD_USERS), "nextPageToken": "p2"}],
                                         "p2": [{"users": bad_list}]}), "users", limit=None)
    assert list(rows) == _GOOD_USERS
    assert rows.page_error is not None and rows.page_error.error_class == "malformed_response"


@pytest.mark.parametrize("page", [{}, {"users": []}, {"users": None}, {"kind": "admin#directory#users"}])
def test_live_fix_5_b1_an_absent_or_empty_row_list_is_still_a_complete_read(page: dict[str, Any]) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": list(_GOOD_USERS), "nextPageToken": "p2"}], "p2": [page]}),
                                 "users", limit=None)
    assert list(rows) == _GOOD_USERS
    assert rows.page_error is None and rows.truncated is False


@pytest.mark.parametrize("values", [[{"orgUnitId": "id:root01"}, None], [{"orgUnitId": "id:root01"}, "x"],
                                    "id:root01", 5, {"orgUnitId": "id:root01"}])
def test_live_fix_5_b1_a_single_call_list_with_an_unreadable_row_is_partial(values: Any) -> None:
    rows = google_client._cut(values, None)
    assert rows.page_error is not None and rows.page_error.error_class == "malformed_response"


def test_live_fix_5_b1_reviewer_scenario_a_null_user_row_is_a_partial_users_read() -> None:
    """Five readable users and one null row: the users read is partial, so it proves no absence (CC.6.1)."""
    users = [{"id": f"u{n}00", "primaryEmail": f"user{n}@example.com", "isAdmin": n < 3} for n in range(1, 6)]

    class _Client:
        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            if resource == "users":
                client = GoogleWorkspaceClient(credentials=None)
                return client._collect_pages(_paged({None: [{"users": [*users[:3], None, *users[3:]]}]}),
                                             "users", limit=None)
            return []

    result = GoogleDirectoryCollector().run({"client": _Client()})
    users_row = next(row for row in result.coverage if row["name"] == "users")
    assert result.payload["users"]["value"] == users
    assert users_row["status"] == "partial"
    assert users_row["error_class"] == "malformed_response"
    assert users_row["collection_truncated"] is True
    assert result.status == "partial"


# ---- LIVE-FIX-6 B1b: only an absent or null cursor ends a list -------------------------------------------------

_CURSOR_TEXT = (
    "This Google list answer carried a continuation cursor that cannot be read (not a non-empty string); the rows "
    "read are kept, but the list is not complete."
)


@pytest.mark.parametrize("token", [0, 1, False, True, 1.5, [], ["p2"], {}, {"page": "p2"}, "", "   "])
def test_live_fix_6_b1b_a_cursor_of_the_wrong_type_makes_the_list_partial(token: Any) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": list(_GOOD_USERS), "nextPageToken": token}]}),
                                 "users", limit=None)
    assert list(rows) == _GOOD_USERS
    assert rows.truncated is True
    assert isinstance(rows.page_error, google_client.PolicyReadError)
    assert rows.page_error.error_class == "malformed_response"
    assert str(rows.page_error) == _CURSOR_TEXT


@pytest.mark.parametrize("token", [0, False, ["p2"], ""])
def test_live_fix_6_b1b_a_wrong_cursor_at_the_limit_is_still_partial(token: Any) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": list(_GOOD_USERS), "nextPageToken": token}]}),
                                 "users", limit=2)
    assert list(rows) == _GOOD_USERS
    assert rows.truncated is True
    assert rows.page_error is not None and rows.page_error.error_class == "malformed_response"


@pytest.mark.parametrize("page", [{"users": [_GOOD_USERS[1]]}, {"users": [_GOOD_USERS[1]], "nextPageToken": None}])
def test_live_fix_6_b1b_an_absent_or_null_cursor_ends_a_complete_list(page: dict[str, Any]) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": [_GOOD_USERS[0]], "nextPageToken": "p2"}], "p2": [page]}),
                                 "users", limit=None)
    assert list(rows) == _GOOD_USERS
    assert rows.page_error is None and rows.truncated is False


@pytest.mark.parametrize("page", [None, "page", 7, ["u300"]])
def test_live_fix_6_b1b_a_later_page_that_is_not_an_object_is_partial(page: Any) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    rows = client._collect_pages(_paged({None: [{"users": list(_GOOD_USERS), "nextPageToken": "p2"}], "p2": [page]}),
                                 "users", limit=None)
    assert list(rows) == _GOOD_USERS
    assert rows.truncated is True
    assert rows.page_error is not None and rows.page_error.error_class == "malformed_response"


@pytest.mark.parametrize("page", [None, "page", ["u300"]])
def test_live_fix_6_b1b_a_first_page_that_is_not_an_object_fails_the_read(page: Any) -> None:
    client = GoogleWorkspaceClient(credentials=None)
    with pytest.raises(google_client.PolicyReadError):
        client._collect_pages(_paged({None: [page]}), "users", limit=None)


def test_live_fix_6_b1b_reviewer_scenario_a_numeric_cursor_is_a_partial_users_read() -> None:
    """Five readable users and nextPageToken 0: the users read is partial, so it proves no absence (CC.6.1)."""
    users = [{"id": f"u{n}00", "primaryEmail": f"user{n}@example.com", "isAdmin": n < 3} for n in range(1, 6)]

    class _Client:
        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            if resource == "users":
                client = GoogleWorkspaceClient(credentials=None)
                return client._collect_pages(_paged({None: [{"users": list(users), "nextPageToken": 0}]}),
                                             "users", limit=None)
            return []

    result = GoogleDirectoryCollector().run({"client": _Client()})
    users_row = next(row for row in result.coverage if row["name"] == "users")
    assert result.payload["users"]["value"] == users
    assert users_row["status"] == "partial"
    assert users_row["error_class"] == "malformed_response"
    assert users_row["collection_truncated"] is True
    assert users_row["truncation_reason"] == "pagination_failed"
    assert result.status == "partial"


# ---- LIVE-FIX-6 B1c: a single-call list field of the wrong type is a malformed partial read ---------------------


def _directory_client(answer: Any) -> GoogleWorkspaceClient:
    """A client whose orgunits.list, users.aliases.list and tokens.list each answer ``answer``."""

    class _Lister:
        def list(self, **_kwargs: Any) -> _Request:
            return _Request(answer)

    class _Users:
        def aliases(self) -> _Lister:
            return _Lister()

    service = type("Dir", (), {
        "orgunits": lambda self: _Lister(), "users": lambda self: _Users(), "tokens": lambda self: _Lister(),
    })()
    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("admin", "directory_v1")] = service
    return client


_SINGLE_CALL_READS = [
    ("organizationUnits", lambda client: client.list_directory("orgUnits")),
    ("aliases", lambda client: client.list_user_aliases("ada@example.com")),
    ("items", lambda client: client.list_user_tokens("ada@example.com")),
]


@pytest.mark.parametrize(("field", "read"), _SINGLE_CALL_READS)
@pytest.mark.parametrize("value", [None, False, True, 0, 7, "", "row", {}, {"alias": "a@example.com"}])
def test_live_fix_6_b1c_a_present_list_field_that_is_not_a_list_is_partial(field: str, read: Any, value: Any) -> None:
    rows = read(_directory_client({"kind": "admin#directory#x", field: value}))
    assert list(rows) == []
    assert rows.page_error is not None
    assert rows.page_error.error_class == "malformed_response"
    assert str(rows.page_error) == (
        "Some rows of this Google list cannot be read (not an object, or a list that is not a list); the rows read "
        "are kept, but the list is not complete."
    )


@pytest.mark.parametrize(("field", "read"), _SINGLE_CALL_READS)
def test_live_fix_6_b1c_an_absent_list_field_is_a_clean_empty_list(field: str, read: Any) -> None:
    rows = read(_directory_client({"kind": "admin#directory#x", "etag": "e1"}))
    assert list(rows) == [] and rows.page_error is None


@pytest.mark.parametrize(("field", "read"), _SINGLE_CALL_READS)
def test_live_fix_6_b1c_an_empty_or_whole_list_is_a_clean_read(field: str, read: Any) -> None:
    assert read(_directory_client({field: []})).page_error is None
    rows = read(_directory_client({field: [{"id": "r1"}, {"id": "r2"}]}))
    assert list(rows) == [{"id": "r1"}, {"id": "r2"}] and rows.page_error is None


@pytest.mark.parametrize(("field", "read"), _SINGLE_CALL_READS)
@pytest.mark.parametrize(("token", "text"), [
    ("p2", "This Google list is read in one call, but its answer carried a continuation cursor; the rows read are "
           "kept, but the list is not complete."),
    (0, "This Google list answer carried a continuation cursor that cannot be read (not a non-empty string); the "
        "rows read are kept, but the list is not complete."),
    ("", "This Google list answer carried a continuation cursor that cannot be read (not a non-empty string); the "
         "rows read are kept, but the list is not complete."),
])
def test_live_fix_6_b1c_a_cursor_on_a_single_call_list_is_partial(field: str, read: Any, token: Any, text: str) -> None:
    rows = read(_directory_client({field: [{"id": "r1"}], "nextPageToken": token}))
    assert list(rows) == [{"id": "r1"}]
    assert rows.page_error is not None and rows.page_error.error_class == "malformed_response"
    assert str(rows.page_error) == text


@pytest.mark.parametrize(("field", "read"), _SINGLE_CALL_READS)
@pytest.mark.parametrize("answer", [None, "x", [{"id": "r1"}]])
def test_live_fix_6_b1c_an_answer_that_is_not_an_object_fails_the_read(field: str, read: Any, answer: Any) -> None:
    with pytest.raises(google_client.PolicyReadError):
        read(_directory_client(answer))


@pytest.mark.parametrize(("name", "answer"), [
    ("orgUnits", {"organizationUnits": False}),
    ("aliases:ada@example.com", {"aliases": {}}),
    ("oauthGrants:ada@example.com", {"items": 0}),
])
def test_live_fix_6_b1c_reviewer_scenario_the_collector_records_the_gap(name: str, answer: dict[str, Any]) -> None:
    good = {"organizationUnits": [{"orgUnitId": "id:root01", "orgUnitPath": "/"}],
            "aliases": [], "items": []}

    class _Lister:
        def __init__(self, field: str) -> None:
            self.field = field

        def list(self, **_kwargs: Any) -> _Request:
            wanted = {"orgUnits": "organizationUnits", "aliases": "aliases", "oauthGrants": "items"}[name.split(":")[0]]
            return _Request(answer if self.field == wanted else {self.field: good[self.field]})

    class _Users:
        def list(self, **_kwargs: Any) -> _Request:
            return _Request({"users": [{"id": "u100", "primaryEmail": "ada@example.com"}]})

        def aliases(self) -> _Lister:
            return _Lister("aliases")

    class _Empty:
        def list(self, **_kwargs: Any) -> _Request:
            return _Request({"items": [], "groups": [], "domains": [{"domainName": "example.com"}]})

    service = type("Dir", (), {
        "orgunits": lambda self: _Lister("organizationUnits"), "users": lambda self: _Users(),
        "tokens": lambda self: _Lister("items"), "groups": lambda self: _Empty(), "domains": lambda self: _Empty(),
        "roles": lambda self: _Empty(), "roleAssignments": lambda self: _Empty(),
    })()
    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("admin", "directory_v1")] = service
    result = GoogleDirectoryCollector().run({"client": client})
    row = next(row for row in result.coverage if row["name"] == name)
    assert (row["status"], row["error_class"], row["collection_truncated"]) == ("partial", "malformed_response", True)
    assert result.status == "partial"
    assert [r["name"] for r in result.coverage if r["status"] != "ok"] == [name]
