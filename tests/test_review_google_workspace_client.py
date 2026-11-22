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
