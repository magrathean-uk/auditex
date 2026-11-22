"""Deep-review regressions for the Google Workspace lane, repair round 1 (review blockers)."""
from __future__ import annotations

from typing import Any

import pytest

from auditex.google_workspace import client as google_client
from auditex.google_workspace.findings import build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot


class _HttpError(Exception):
    def __init__(self, status: int, message: str | None = None) -> None:
        super().__init__(message or f"HTTP {status}")
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


# ---- R011: a deleted alert replayed offline is not active ------------------------------------------------------


def test_r011_deleted_alert_replayed_offline_is_not_active() -> None:
    alert = {"alertId": "a-1", "type": "Suspicious login", "deleted": True,
             "metadata": {"severity": "HIGH", "status": "NOT_STARTED"}}
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="run-1", domain="example.com",
        collector_payloads={"google_alert_center": {"alerts": {"value": [alert]}}},
    )
    rule_ids = [str(item.get("rule_id")) for item in build_google_findings(snapshot)]
    assert "google.alert_active" not in rule_ids


# ---- R055: probe counts, partial mailbox rows and the delegation-only delegates read ----------------------------


class _Settings:
    """Gmail users.settings fake: each call answers ``outcome`` unless its name is in ``ok``; calls are recorded."""

    def __init__(self, outcome: Any, ok: tuple[str, ...] = ()) -> None:
        self.outcome = outcome
        self.ok = ok
        self.calls: list[str] = []

    def _answer(self, name: str) -> _Request:
        self.calls.append(name)
        return _Request({} if name in self.ok else self.outcome)

    def __getattr__(self, name: str) -> Any:
        if name in {"filters", "forwardingAddresses", "sendAs", "delegates"}:
            sub = type("Sub", (), {"list": lambda _self, **_k: self._answer(name)})()
            return lambda: sub
        return lambda **_k: self._answer(name)


def _gmail_client(settings: _Settings, *, delegated: bool = False) -> google_client.GoogleWorkspaceClient:
    users = type("Users", (), {"settings": lambda _self: settings})()
    client = google_client.GoogleWorkspaceClient(credentials=None, delegated=delegated)
    assert client._services is not None
    client._services[("gmail", "v1")] = type("Gmail", (), {"users": lambda _self: users})()
    return client


def test_r055_probe_counts_no_item_when_every_settings_read_fails() -> None:
    from auditex.google_workspace.run import build_google_preflight_rows

    client = _gmail_client(_Settings(_HttpError(403)))
    row = build_google_preflight_rows(client, ["google_gmail_settings"], domain="example.com")[0]
    assert row["status"] == "failed"
    assert row["item_count"] == 0


def test_r055_a_partial_mailbox_read_is_partial_not_blocked_by_scope() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    partial = {"collector": "google_gmail_settings", "name": "mailboxSettings", "status": "partial",
               "item_count": 1, "error_class": "insufficient_permissions", "error": "1 of 8 Gmail settings reads failed"}
    row = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=[partial],
    )[0]
    assert row["status"] == "partial"
    assert row["missing_permissions"] == []


def test_r055_oauth_mailbox_read_skips_the_delegation_only_delegates_list() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    # delegates.list answers 403 to anything but a delegated service account.
    settings = _Settings(_HttpError(403), ok=("getAutoForwarding", "filters", "forwardingAddresses", "sendAs",
                                              "getImap", "getPop", "getVacation"))
    client = _gmail_client(settings)
    result = GoogleGmailSettingsCollector().run({"client": client, "users": []})
    assert "delegates" not in settings.calls
    mailbox = next(row for row in result.coverage if row["name"] == "mailboxSettings:me")
    assert mailbox["status"] == "ok"
    assert "delegates_error" not in result.payload["mailboxSettings"]["value"][0]

    preflight = build_google_preflight_rows(client, ["google_gmail_settings"], domain="example.com")
    capability = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="oauth", dependency_status={"available": True}, coverage_rows=preflight
    )[0]
    assert capability["status"] != "blocked_by_scope"


def test_r055_delegated_mailbox_read_still_lists_delegates() -> None:
    settings = _Settings({}, ok=())
    client = _gmail_client(settings)
    client.delegated = True
    client.credentials = type("C", (), {"with_subject": lambda self, _s: self})()
    client._subject_services["me@example.com", "gmail", "v1"] = client._services["gmail", "v1"]  # type: ignore[index]
    client.get_gmail_settings_for_user("me@example.com")
    assert "delegates" in settings.calls


# ---- R056: a blocked collector names only the scope the delegation left out ---------------------------------------

_DRIVE_META = "https://www.googleapis.com/auth/drive.metadata.readonly"
_DRIVE_READ = "https://www.googleapis.com/auth/drive.readonly"
_TOKEN_REFUSED = "unauthorized_client: Client is unauthorized to retrieve access tokens using this method"


class _DelegatedCredentials:
    """Service-account credentials whose token exchange is refused when it asks for a scope not authorised."""

    def __init__(self, scopes: tuple[str, ...], authorised: frozenset[str]) -> None:
        self.scopes = scopes
        self.authorised = authorised

    def with_scopes(self, scopes: list[str]) -> _DelegatedCredentials:
        return _DelegatedCredentials(tuple(scopes), self.authorised)

    def with_subject(self, _subject: str) -> _DelegatedCredentials:
        return self

    def refresh(self, _request: Any) -> None:
        if not set(self.scopes) <= self.authorised:
            raise Exception(_TOKEN_REFUSED)


def test_r056_a_blocked_collector_names_only_the_missing_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    monkeypatch.setattr(google_client, "_token_request", lambda: None, raising=False)

    class _Client(google_client.GoogleWorkspaceClient):
        def _drive(self) -> list[dict[str, Any]]:
            self.credentials.refresh(None)
            return []

        def list_drive_files(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return self._drive()

        def list_shared_drives(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return self._drive()

    client = _Client(_DelegatedCredentials((_DRIVE_META, _DRIVE_READ), frozenset({_DRIVE_META})), delegated=True)
    preflight = build_google_preflight_rows(client, ["google_drive_posture"], domain=None)
    row = build_google_capability_rows(
        ["google_drive_posture"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=preflight,
    )[0]
    assert row["status"] == "blocked_by_scope"
    assert row["missing_permissions"] == [_DRIVE_READ]


# ---- R057 and R058: the probe reads unreadable Drive sharing and a failed later page as gaps ----------------------


def _probe_capability(client: Any, collector: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from auditex.google_workspace.run import build_google_capability_rows, build_google_preflight_rows

    preflight = build_google_preflight_rows(client, [collector], domain=None)
    capability = build_google_capability_rows(
        [collector], auth_mode="domain-delegation", dependency_status={"available": True}, coverage_rows=preflight
    )[0]
    return preflight, capability


def test_r057_probe_reports_unreadable_drive_sharing_as_a_gap() -> None:
    class _Client(google_client.GoogleWorkspaceClient):
        def list_drive_files(self, **_kwargs: Any) -> list[dict[str, Any]]:
            files = google_client.CollectedRows([{"id": "file-1", "driveId": "d1", "permissions": []}])
            files.permission_errors = [{"fileId": "file-1", "error_class": "insufficient_permissions", "error": "HTTP 403"}]
            return files

        def list_shared_drives(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return []

    preflight, capability = _probe_capability(_Client(credentials=None), "google_drive_posture")
    files_row = next(row for row in preflight if row["name"] == "driveFiles")
    assert files_row["status"] != "ok"
    assert files_row["error_class"] == "insufficient_permissions"
    assert capability["status"] != "supported_exact_scope"


def test_r057_drive_permission_gap_keeps_request_details_out_of_coverage() -> None:
    from auditex.google_workspace.collectors import GoogleDrivePostureCollector

    secret_id = "1AbCdEfGhIjKlMnOpQrStUvWxYz"
    request_error = (f"<HttpError 403 when requesting https://www.googleapis.com/drive/v3/files/{secret_id}/permissions"
                     "?supportsAllDrives=true returned \"forbidden\">")

    class _Client:
        def list_drive_files(self, **_kwargs: Any) -> list[dict[str, Any]]:
            files = google_client.CollectedRows([{"id": secret_id, "driveId": "d1", "permissions": []}])
            files.permission_errors = [{"fileId": secret_id, "error_class": "insufficient_permissions", "error": request_error}]
            return files

        def list_shared_drives(self, **_kwargs: Any) -> list[dict[str, Any]]:
            return []

    result = GoogleDrivePostureCollector().run({"client": _Client()})
    row = next(item for item in result.coverage if item["name"] == "drivePermissions")
    assert row["status"] == "failed"
    assert secret_id not in str(row)
    assert "googleapis.com" not in str(row)


def test_r058_probe_reports_a_failed_later_page_as_a_gap() -> None:
    class _Client(google_client.GoogleWorkspaceClient):
        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            return google_client.CollectedRows([{"id": "u1"}], truncated=True, page_error=_HttpError(503))

    preflight, capability = _probe_capability(_Client(credentials=None), "google_directory")
    assert preflight[0]["status"] == "partial"
    assert preflight[0]["error_class"] == "google_transient"
    assert capability["status"] != "supported_exact_scope"
