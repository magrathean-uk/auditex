"""Deep-review regressions for the Google Workspace lane, repair round 2 (review blockers R055, R058, X1)."""
from __future__ import annotations

import json
from typing import Any

import pytest

from auditex.google_workspace import client as google_client

_GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.settings.basic"
# What googleapiclient's HttpError prints: the full request URL, with the customer and the opaque page cursor.
_REQUEST_URL = (
    "https://admin.googleapis.com/admin/directory/v1/users?customer=C0secret42&maxResults=1"
    "&pageToken=CURSOR-opaque-77&alt=json"
)


class _HttpError(Exception):
    def __init__(self, status: int, message: str | None = None) -> None:
        super().__init__(message or f"HTTP {status}")
        self.resp = type("Resp", (), {"status": status})()


def _page_error() -> _HttpError:
    return _HttpError(503, f'<HttpError 503 when requesting {_REQUEST_URL} returned "Backend Error">')


class _Request:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    def execute(self) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class _Settings:
    """Gmail users.settings fake: every read answers ``{}``; calls are recorded."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def _answer(self, name: str) -> _Request:
        self.calls.append(name)
        return _Request({})

    def __getattr__(self, name: str) -> Any:
        if name in {"filters", "forwardingAddresses", "sendAs", "delegates"}:
            sub = type("Sub", (), {"list": lambda _self, **_k: self._answer(name)})()
            return lambda: sub
        return lambda **_k: self._answer(name)


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(google_client, "_sleep", lambda _delay: None, raising=False)


def _oauth_gmail_client() -> google_client.GoogleWorkspaceClient:
    settings = _Settings()
    users = type("Users", (), {"settings": lambda _self: settings})()
    client = google_client.GoogleWorkspaceClient(credentials=None, delegated=False)
    assert client._services is not None
    client._services[("gmail", "v1")] = type("Gmail", (), {"users": lambda _self: users})()
    return client


# ---- R055: unread delegates are a gap, and a working Gmail read proves its scope --------------------------------


def test_r055_oauth_probe_names_unread_delegates_as_a_gap_not_exact_scope() -> None:
    from auditex.google_workspace.run import (
        build_google_capability_rows,
        build_google_preflight_rows,
    )

    preflight = build_google_preflight_rows(_oauth_gmail_client(), ["google_gmail_settings"], domain="example.com")
    row = preflight[0]
    assert row["status"] == "partial"
    assert row["error_class"] == "subject_scope"
    assert "delegates" in str(row["error"])
    capability = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="oauth", dependency_status={"available": True}, coverage_rows=preflight
    )[0]
    assert capability["status"] != "supported_exact_scope"
    assert capability["missing_permissions"] == []


def test_r055_oauth_collector_mailbox_row_is_partial_when_delegates_are_unread() -> None:
    from auditex.google_workspace.collectors import GoogleGmailSettingsCollector

    result = GoogleGmailSettingsCollector().run({"client": _oauth_gmail_client(), "users": []})
    mailbox = next(row for row in result.coverage if row["name"] == "mailboxSettings:me")
    assert mailbox["status"] == "partial"
    assert mailbox["error_class"] == "subject_scope"
    assert result.status == "partial"


def test_r055_a_working_gmail_read_is_never_listed_as_a_missing_scope() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    # OAuth: a non-admin signed-in user is refused the Directory users list, but their own mailbox reads fine.
    coverage = [
        {"collector": "google_gmail_settings", "name": "users", "status": "failed", "item_count": 0,
         "endpoint": "admin.directory.users.list", "error_class": "insufficient_permissions", "error": "HTTP 403"},
        {"collector": "google_gmail_settings", "name": "mailboxSettings:me", "status": "ok", "item_count": 1,
         "endpoint": "gmail.users.settings"},
    ]
    row = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="oauth", dependency_status={"available": True}, coverage_rows=coverage
    )[0]
    assert _GMAIL_SCOPE not in row["missing_permissions"]
    assert row["status"] == "partial"


def test_r055_every_read_refused_is_still_a_scope_block() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    coverage = [
        {"collector": "google_gmail_settings", "name": "users", "status": "failed", "item_count": 0,
         "error_class": "insufficient_permissions", "error": "HTTP 403"},
    ]
    row = build_google_capability_rows(
        ["google_gmail_settings"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=coverage,
    )[0]
    assert row["status"] == "blocked_by_scope"
    assert _GMAIL_SCOPE in row["missing_permissions"]


# ---- R058: a failed later page never carries its request details into coverage -----------------------------------


class _PagedClient(google_client.GoogleWorkspaceClient):
    def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
        return google_client.CollectedRows([{"id": "u1"}], truncated=True, page_error=_page_error())

    def list_alerts(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return google_client.CollectedRows([{"alertId": "a1"}], truncated=True, page_error=_page_error())


def test_r058_probe_page_error_keeps_the_request_url_out_of_coverage() -> None:
    from auditex.google_workspace.run import build_google_preflight_rows

    row = build_google_preflight_rows(_PagedClient(credentials=None), ["google_directory"], domain=None)[0]
    assert row["status"] == "partial"
    assert row["error_class"] == "google_transient"
    text = json.dumps(row)
    assert "C0secret42" not in text
    assert "CURSOR-opaque-77" not in text
    assert "googleapis.com" not in text
    assert "503" in str(row["error"])


def test_r058_collector_page_error_keeps_the_request_url_out_of_coverage() -> None:
    from auditex.google_workspace.collectors import GoogleAlertCenterCollector

    result = GoogleAlertCenterCollector().run({"client": _PagedClient(credentials=None)})
    row = next(item for item in result.coverage if item["name"] == "alerts")
    assert row["status"] == "partial"
    text = json.dumps(result.coverage)
    assert "C0secret42" not in text
    assert "CURSOR-opaque-77" not in text
    assert "googleapis.com" not in text


# ---- X1: transport text outside a URL never carries the resolver's private path -----------------------------------


def _requests_error(url: str) -> Exception:
    import requests

    response = requests.Response()
    response.status_code = 503
    response.reason = "Service Unavailable at /profile-abc123"
    response.url = url
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        return exc
    raise AssertionError("raise_for_status did not raise")


def test_x1_resolver_error_drops_transport_text_that_repeats_the_private_path() -> None:
    from auditex.google_workspace.collectors import GoogleDnsPostureCollector
    from azure_tenant_audit.dns_lookup import DohError

    class _Resolver:
        endpoint = "https://dns.example.net/profile-abc123"

        def query_detailed(self, name: str, record_type: str) -> Any:
            exc = _requests_error(f"{self.endpoint}?name={name}&type={record_type}")
            raise DohError(f"DoH query failed for {record_type} {name}: {exc}")

        def query(self, name: str, record_type: str) -> list[str]:
            return self.query_detailed(name, record_type)

    result = GoogleDnsPostureCollector().run({"domain": "example.com", "dns_resolver": _Resolver()})
    row = next(item for item in result.coverage if item["name"] == "posture:example.com")
    assert row["status"] == "failed"
    assert "dns.example.net" in str(row["error"])
    assert "503" in str(row["error"])
    assert "profile-abc123" not in json.dumps(result.coverage)
    assert "profile-abc123" not in json.dumps(result.payload)


def test_x1_resolver_answer_errors_keep_their_wording() -> None:
    from auditex.google_workspace.collectors import GoogleDnsPostureCollector
    from azure_tenant_audit.dns_lookup import DohError

    class _Resolver:
        endpoint = "https://dns.example.net/profile-abc123"

        def query_detailed(self, name: str, record_type: str) -> Any:
            raise DohError(f"DoH resolver could not answer {record_type} {name}: SERVFAIL")

        def query(self, name: str, record_type: str) -> list[str]:
            return self.query_detailed(name, record_type)

    result = GoogleDnsPostureCollector().run({"domain": "example.com", "dns_resolver": _Resolver()})
    row = next(item for item in result.coverage if item["name"] == "posture:example.com")
    assert "SERVFAIL" in str(row["error"])


def test_r055_a_dns_lookup_never_proves_a_google_scope() -> None:
    from auditex.google_workspace.run import build_google_capability_rows

    # The domains list is refused, the --domain fallback is looked up over DNS without any Google token.
    coverage = [
        {"collector": "google_dns_posture", "type": "google", "name": "domains", "status": "failed", "item_count": 0,
         "endpoint": "admin.directory.domains.list", "error_class": "insufficient_permissions", "error": "HTTP 403"},
        {"collector": "google_dns_posture", "type": "dns", "name": "posture:example.com", "status": "ok",
         "item_count": 1, "endpoint": "doh://example.com"},
    ]
    row = build_google_capability_rows(
        ["google_dns_posture"], auth_mode="domain-delegation", dependency_status={"available": True},
        coverage_rows=coverage,
    )[0]
    assert row["status"] == "blocked_by_scope"
    assert row["missing_permissions"] == ["https://www.googleapis.com/auth/admin.directory.domain.readonly"]
