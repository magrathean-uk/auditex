"""Google Workspace lists are collected to their last row unless the operator limits them, and a list
that was cut short is a coverage gap that makes the run partial."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from auditex import cli as auditex_cli
from auditex.google_workspace import run as google_run
from auditex.google_workspace.client import CollectedRows, GoogleWorkspaceClient
from auditex.google_workspace.collectors import (
    STREAM_SAMPLE_LIMIT,
    GoogleDevicesCollector,
    GoogleDirectoryCollector,
    GoogleDrivePostureCollector,
    GoogleReportsCollector,
)
from auditex.google_workspace.normalize import build_google_normalized_snapshot
from auditex.google_workspace.run import GoogleRunConfig, run_google_live
from azure_tenant_audit.collection_gaps import list_truncations

USERS = 250
GROUPS = 130
DEVICES = 160
TOKENS = 120


class _Request:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def execute(self) -> dict[str, Any]:
        return self.payload


class _Endpoint:
    """A Google list endpoint that pages ``rows`` by ``maxResults`` and ``pageToken``."""

    def __init__(self, key: str, rows: list[dict[str, Any]], calls: list[dict[str, Any]]) -> None:
        self.key = key
        self.rows = rows
        self.calls = calls

    def list(self, **kwargs: Any) -> _Request:
        self.calls.append(kwargs)
        size = kwargs.get("maxResults") or kwargs.get("pageSize") or 100
        start = int(kwargs.get("pageToken") or 0)
        payload: dict[str, Any] = {self.key: self.rows[start:start + size]}
        if start + size < len(self.rows):
            payload["nextPageToken"] = str(start + size)
        return _Request(payload)


def _client(*, users: int = USERS, groups: int = GROUPS, devices: int = DEVICES, tokens: int = TOKENS) -> tuple[GoogleWorkspaceClient, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def rows(prefix: str, count: int) -> list[dict[str, Any]]:
        return [{"id": f"{prefix}-{i}", "primaryEmail": f"{prefix}{i}@example.com", "email": f"{prefix}{i}@example.com"} for i in range(count)]

    user_endpoint = _Endpoint("users", rows("u", users), calls)
    user_endpoint.aliases = lambda: SimpleNamespace(list=lambda **_k: _Request({"aliases": []}))  # type: ignore[attr-defined]
    directory = SimpleNamespace(
        users=lambda: user_endpoint,
        groups=lambda: _Endpoint("groups", rows("g", groups), calls),
        members=lambda: _Endpoint("members", rows("m", 3), calls),
        orgunits=lambda: SimpleNamespace(list=lambda **_k: _Request({"organizationUnits": []})),
        domains=lambda: SimpleNamespace(list=lambda **_k: _Request({"domains": []})),
        roles=lambda: _Endpoint("items", [], calls),
        roleAssignments=lambda: _Endpoint("items", [], calls),
        tokens=lambda: SimpleNamespace(list=lambda **_k: _Request({"items": [{"clientId": f"app-{i}"} for i in range(tokens)]})),
        mobiledevices=lambda: _Endpoint("mobiledevices", rows("mob", devices), calls),
        chromeosdevices=lambda: _Endpoint("chromeosdevices", rows("chr", devices), calls),
    )
    client = GoogleWorkspaceClient(credentials=None, customer_id="C1", page_size=100)
    assert client._services is not None
    client._services[("admin", "directory_v1")] = directory
    return client, calls


def _coverage(result: Any, name: str) -> dict[str, Any]:
    return next(row for row in result.coverage if row["name"] == name)


# ---- default: every list is paged to its last row ---------------------------------------------------


@pytest.mark.parametrize("context", [{}, {"top": None}, {"top": 0}])
def test_google_users_groups_tokens_and_devices_have_no_default_cap(context: dict[str, Any]) -> None:
    client, _calls = _client(users=USERS, groups=GROUPS, tokens=TOKENS)

    directory = GoogleDirectoryCollector().run({"client": client, "domain": None, **context})
    devices = GoogleDevicesCollector().run({"client": client, **context})

    assert len(directory.payload["users"]["value"]) == USERS
    assert len(directory.payload["groups"]["value"]) == GROUPS
    assert len(directory.payload["oauthGrants"]["value"]) == TOKENS * USERS
    assert len(devices.payload["mobileDevices"]["value"]) == DEVICES
    assert len(devices.payload["chromeosDevices"]["value"]) == DEVICES
    for result in (directory, devices):
        assert result.status == "ok"
        assert not [row for row in result.coverage if row.get("collection_truncated")]
        assert list_truncations(result.coverage) == []


def test_google_default_is_not_a_100_row_cap() -> None:
    assert GoogleRunConfig(tenant_name="x", out=Path(".")).top is None
    args = auditex_cli._build_google_parser().parse_args(["run"])
    assert args.top is None
    assert auditex_cli._google_config_from_args(args).top is None


# ---- an explicit limit is recorded as a coverage gap ------------------------------------------------


def test_google_explicit_limit_is_a_coverage_gap_for_each_cut_list() -> None:
    client, _calls = _client()

    directory = GoogleDirectoryCollector().run({"client": client, "top": 100, "domain": None})
    devices = GoogleDevicesCollector().run({"client": client, "top": 100})

    for result, names in ((directory, ("users", "groups", "oauthGrants:u0@example.com")), (devices, ("mobileDevices", "chromeosDevices"))):
        assert result.status == "partial"
        for name in names:
            row = _coverage(result, name)
            assert row["status"] == "partial", name
            assert row["item_count"] == 100
            assert row["collection_truncated"] is True
            assert row["truncation_reason"] == "operator_limit"
            assert row["result_limit"] == 100
            assert row["error_class"] == "collection_limit"
    assert {item["list"] for item in list_truncations(directory.coverage)} >= {"users", "groups", "oauthGrants:u0@example.com"}
    assert _coverage(directory, "roles")["collection_truncated"] is False


def test_google_limit_equal_to_the_list_length_is_not_a_gap() -> None:
    client, _calls = _client(users=100, groups=100, devices=100, tokens=100)

    directory = GoogleDirectoryCollector().run({"client": client, "top": 100, "domain": None})

    assert directory.status == "ok"
    assert list_truncations(directory.coverage) == []


def test_google_client_reports_whether_a_list_continued() -> None:
    client, _calls = _client()

    cut = client.list_directory("users", top=100)
    whole = client.list_directory("users", top=USERS)
    unlimited = client.list_directory("users")
    tokens = client.list_user_tokens("u0@example.com", top=50)

    assert (len(cut), cut.truncated, cut.result_limit) == (100, True, 100)
    assert (len(whole), whole.truncated) == (USERS, False)
    assert (len(unlimited), unlimited.truncated) == (USERS, False)
    assert (len(tokens), tokens.truncated) == (50, True)
    assert isinstance(cut, CollectedRows) and isinstance(cut, list)


def test_google_event_logs_and_file_crawls_are_a_bounded_sample_unless_limited() -> None:
    seen: list[int | None] = []

    class Client:
        def list_report_activities(self, application: str, *, top: int | None = None, **_k: Any) -> CollectedRows:
            seen.append(top)
            return CollectedRows([{"id": 1}] * (top or 0), truncated=True, result_limit=top)

        def list_drive_files(self, *, top: int | None = None) -> CollectedRows:
            seen.append(top)
            return CollectedRows([{"id": 1}] * (top or 0), truncated=True, result_limit=top)

        def list_shared_drives(self, *, top: int | None = None) -> CollectedRows:
            return CollectedRows([], result_limit=top)

    default = GoogleReportsCollector().run({"client": Client(), "top": None})
    files = GoogleDrivePostureCollector().run({"client": Client(), "top": None})

    assert seen.count(STREAM_SAMPLE_LIMIT) == len(GoogleReportsCollector.applications) + 1
    for result in (default, files):
        assert result.status == "ok"
        assert [row for row in result.coverage if row.get("bounded_sample")]
        assert list_truncations(result.coverage) == []

    limited = GoogleReportsCollector().run({"client": Client(), "top": 10})

    assert limited.status == "partial"
    assert all(row["collection_truncated"] for row in limited.coverage)


# ---- the gap reaches the normalized output, the manifest and the exit status ------------------------


def test_google_normalized_snapshot_records_cut_lists_not_busy_collectors() -> None:
    client, _calls = _client()
    result = GoogleDirectoryCollector().run({"client": client, "top": 100, "domain": None})

    normalized = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        collector_payloads={"google_directory": result.payload},
        coverage_rows=result.coverage,
        result_rows=[{"name": "google_directory", "status": result.status, "item_count": result.item_count}],
        top_limit=100,
    )

    snapshot = normalized["snapshot"]
    gaps = {row["source"]: row for row in normalized["collection_gaps"]["records"]}
    assert snapshot["top_limit"] == 100
    assert snapshot["sample_truncated"] is True
    assert "google_directory.users" in snapshot["truncated_sections"]
    assert snapshot["collection_gap_count"] == len(gaps)
    users = gaps["google_directory.users"]
    assert (users["rows_collected"], users["reason"], users["result_limit"]) == (100, "operator_limit", 100)


def test_a_collector_that_returns_many_rows_is_not_truncated_by_coincidence() -> None:
    # The old check flagged a collector whose total item count reached --top, however its lists ended.
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example",
        run_id="run1",
        collector_payloads={"google_directory": {"users": {"value": [{"id": "u-1", "primaryEmail": "a@example.com"}]}}},
        result_rows=[{"name": "google_directory", "status": "ok", "item_count": 500}],
        coverage_rows=[{"collector": "google_directory", "name": "users", "status": "ok", "item_count": 1, "collection_truncated": False}],
        top_limit=500,
    )["snapshot"]

    assert snapshot["top_limit"] == 500
    assert snapshot["sample_truncated"] is False
    assert snapshot["truncated_sections"] == []


def _live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, top: int | None) -> tuple[int, Path]:
    client, _calls = _client(users=30, groups=12, devices=25, tokens=4)
    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": GoogleDirectoryCollector(), "google_devices": GoogleDevicesCollector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_args, **_kwargs: client)
    rc = run_google_live(
        GoogleRunConfig(
            tenant_name="Example",
            out=tmp_path,
            run_name="gaps",
            domain=None,
            customer_id="C1",
            subject="admin@example.com",
            service_account_key=tmp_path / "service-account.json",
            collectors="google_directory,google_devices",
            top=top,
            page_size=10,
        )
    )
    return rc, tmp_path / "Example-gaps"


def test_a_google_run_without_a_limit_is_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, run_dir = _live(tmp_path, monkeypatch, None)

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert rc == 0
    assert manifest["overall_status"] == "ok"
    assert "top_limit" not in manifest
    assert manifest["coverage_gaps"] == []
    assert not (run_dir / "normalized" / "collection_gaps.json").exists()


def test_a_google_run_with_a_limit_is_partial_and_records_the_gap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, run_dir = _live(tmp_path, monkeypatch, 10)

    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    gaps = json.loads((run_dir / "normalized" / "collection_gaps.json").read_text(encoding="utf-8"))

    assert rc == 1
    assert manifest["overall_status"] == "partial"
    assert manifest["top_limit"] == 10
    assert manifest["sample_truncated"] is True
    assert validation["valid"] is True, validation["issues"]
    truncated = {
        (item["collector"], item["list"]): item
        for gap in manifest["coverage_gaps"]
        for item in gap.get("truncated_lists", [])
    }
    for key in (("google_directory", "users"), ("google_directory", "groups"), ("google_devices", "mobileDevices"), ("google_devices", "chromeosDevices")):
        assert truncated[key]["rows_collected"] == 10
        assert truncated[key]["reason"] == "operator_limit"
    assert {row["source"] for row in gaps["records"]} >= {f"{collector}.{name}" for collector, name in truncated}


def test_a_cut_google_list_raises_a_collector_issue_that_says_to_rerun_without_the_limit() -> None:
    from auditex.google_workspace.findings import build_google_findings

    client, _calls = _client()
    result = GoogleDirectoryCollector().run({"client": client, "top": 10, "domain": None})
    diagnostics = [row for row in result.coverage if row.get("status") != "ok"]

    findings = build_google_findings({"snapshot": {}}, diagnostics=diagnostics)

    users = next(item for item in findings if item["affected_objects"] == ["google_directory:users"])
    assert users["rule_id"] == "google.collector_issue"
    assert "--top" in users["remediation"]
    assert "operator row limit" in users["returned_value"]


def test_a_top_above_the_stream_sample_does_not_raise_it_on_google_or_microsoft_365() -> None:
    from auditex.google_workspace.collectors import _stream_limit

    assert [_stream_limit(top) for top in (None, 0, 2000, 500, 499, 100)] == [
        (STREAM_SAMPLE_LIMIT, True),
        (STREAM_SAMPLE_LIMIT, True),
        (STREAM_SAMPLE_LIMIT, True),
        (STREAM_SAMPLE_LIMIT, True),
        (499, False),
        (100, False),
    ]
    asked: list[int | None] = []

    class Client:
        def list_report_activities(self, application: str, *, top: int | None = None, **_k: Any) -> CollectedRows:
            asked.append(top)
            return CollectedRows([{"id": 1}] * (top or 0), truncated=True, result_limit=top)

    result = GoogleReportsCollector().run({"client": Client(), "top": 2000})

    assert set(asked) == {STREAM_SAMPLE_LIMIT}
    assert result.status == "ok"
    assert all(row["bounded_sample"] and not row["collection_truncated"] for row in result.coverage)
