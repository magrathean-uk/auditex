"""LIVE-FIX-6 B1a: a Google list read that failed, was cut or held rows it could not read is marked on its raw section.

A live run keeps the readable rows of such a read and records the gap on its coverage ledger. The raw section now
carries the same marker, so an offline replay of the saved raw sections, and compare and drift over that replay, see
the read as incomplete instead of reading the retained rows as the whole list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace import client as google_client
from auditex.google_workspace.client import CollectedRows, GoogleWorkspaceClient
from auditex.google_workspace.collectors import (
    COLLECTOR_SECTIONS,
    RAW_SECTION_READS,
    REGISTRY,
    GoogleDirectoryCollector,
    mark_incomplete_sections,
)

USERS = [
    {"id": f"u{n}00", "primaryEmail": f"user{n}@example.com", "lastLoginTime": "2026-11-01T00:00:00.000Z",
     "creationTime": "2020-01-01T00:00:00.000Z", "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True}
    for n in range(1, 6)
]
# Active, never signed in for years: google.stale_user in a complete read.
STALE = {"id": "u900", "primaryEmail": "stale@example.com", "lastLoginTime": "2021-01-01T00:00:00.000Z",
         "creationTime": "2020-01-01T00:00:00.000Z", "isEnrolledIn2Sv": True, "isEnforcedIn2Sv": True}
MARKED_USERS = {
    "status": "partial",
    "collection_truncated": True,
    "truncation_reason": "pagination_failed",
    "error_class": "malformed_response",
    "error": "users: a read of this list failed or could not be read in full (malformed_response).",
}


class _Request:
    def __init__(self, answer: Any) -> None:
        self.answer = answer

    def execute(self) -> Any:
        return self.answer


class _FakeDirectory:
    """Directory reads for the live run: the users list from the real paginator, everything else complete."""

    def __init__(self, users_page: dict[str, Any]) -> None:
        self.users_page = users_page

    def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
        if resource == "users":
            return GoogleWorkspaceClient(credentials=None)._collect_pages(
                lambda _token: _Request(self.users_page), "users", limit=None)
        if resource == "domains":
            return CollectedRows([{"domainName": "example.com", "isPrimary": True, "verified": True}])
        return CollectedRows([])


def _live_raw(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, users_page: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.run import GoogleRunConfig, run_google_live

    monkeypatch.setattr(google_run, "REGISTRY", {"google_directory": GoogleDirectoryCollector()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_args, **_kwargs: _FakeDirectory(users_page))
    out = tmp_path / "live"
    rc = run_google_live(
        GoogleRunConfig(
            tenant_name="Example", out=out, run_name="live", domain="example.com", customer_id="my_customer",
            subject="admin@example.com", service_account_key=tmp_path / "service-account.json",
            collectors="google_directory",
        ),
        command_line=["auditex", "google", "run", "--domain", "example.com"],
    )
    raw = json.loads((out / "Example-live" / "raw" / "google_directory.json").read_text(encoding="utf-8"))
    return rc, raw


def _replay(tmp_path: Path, name: str, directory: dict[str, Any]) -> tuple[int, Path]:
    from datetime import UTC, datetime

    from auditex.google_workspace.run import run_google_offline

    sample = tmp_path / f"{name}.json"
    sample.write_text(json.dumps({"google_directory": directory}), encoding="utf-8")
    out = tmp_path / name
    rc = run_google_offline(sample_path=sample, out=out, tenant_name="Example", run_name=name, domain="example.com",
                            customer_id=None, as_of=datetime(2026, 11, 27, tzinfo=UTC))
    return rc, out / f"Example-{name}"


def _coverage(run_dir: Path) -> list[dict[str, Any]]:
    payload = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    return payload if isinstance(payload, list) else payload.get("coverage", [])


def _finding_rules(run_dir: Path) -> set[str]:
    from auditex.run_bundle import RunBundle

    return {str(row.get("rule_id")) for row in RunBundle(run_dir).finding_rows()}


def test_live_fix_6_b1a_a_partial_users_read_is_marked_on_the_raw_section(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, raw = _live_raw(tmp_path, monkeypatch, {"users": [*USERS[:3], None, *USERS[3:]]})
    assert rc == 1
    assert raw["users"] == {"value": USERS, **MARKED_USERS}
    # The complete reads stay unmarked.
    assert raw["domains"] == {"value": [{"domainName": "example.com", "isPrimary": True, "verified": True}]}
    assert raw["groups"] == {"value": []}


@pytest.mark.parametrize("users_page", [
    {"users": [*USERS[:3], None, *USERS[3:]]},
    {"users": list(USERS), "nextPageToken": 0},
])
def test_live_fix_6_b1a_reviewer_scenario_replay_compare_and_drift_see_the_gap(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, users_page: dict[str, Any]) -> None:
    """The stale user is the row the live read could not read: the replay is partial and the finding is not resolved."""
    from auditex.compare import compare_run_directories
    from auditex.gate import gate_drift

    _, raw = _live_raw(tmp_path, monkeypatch, users_page)
    assert {key: raw["users"][key] for key in MARKED_USERS} == MARKED_USERS

    base_rc, baseline = _replay(tmp_path, "baseline", {
        "users": {"value": [*USERS, STALE]},
        "domains": {"value": [{"domainName": "example.com", "isPrimary": True, "verified": True}]},
    })
    assert base_rc == 0
    assert "google.stale_user" in _finding_rules(baseline)

    rc, current = _replay(tmp_path, "current", raw)
    assert rc == 1
    users_rows = [row for row in _coverage(current) if row.get("collector") == "google_directory"
                  and row.get("name") == "users"]
    assert [(row["status"], row["collection_truncated"], row["truncation_reason"], row["error_class"])
            for row in users_rows] == [("failed", True, "pagination_failed", "malformed_response")]
    assert "google.stale_user" not in _finding_rules(current)

    result = compare_run_directories([baseline, current])
    assert result["baseline_diff"]["status"] == "ok"
    delta = result["baseline_diff"]["finding_delta"]
    stale = [row for row in delta["not_reassessed"] if row["rule_id"] == "google.stale_user"]
    assert [row["reason"] for row in stale] == ["collector_partial_success"]
    assert [row for row in delta["resolved"] if row["rule_id"] == "google.stale_user"] == []

    strict = gate_drift(baseline_run_dir=str(baseline), current_run_dir=str(current), fail_on="low")
    assert strict["pass"] is False


@pytest.mark.parametrize(("row", "marker"), [
    ({"name": "users", "status": "partial", "error_class": "collection_limit", "collection_truncated": True,
      "truncation_reason": "operator_limit", "result_limit": 5},
     {"status": "partial", "collection_truncated": True, "truncation_reason": "operator_limit", "result_limit": 5}),
    ({"name": "users", "status": "failed", "error_class": "permission_denied", "error": "HTTP 403 for ada@example.com"},
     {"status": "partial", "error_class": "permission_denied",
      "error": "users: a read of this list failed or could not be read in full (permission_denied)."}),
    ({"name": "aliases:ada@example.com", "status": "failed", "error_class": "client_error"},
     {"status": "partial", "error_class": "client_error",
      "error": "aliases: a read of this list failed or could not be read in full (client_error)."}),
])
def test_live_fix_6_b1a_marker_literals(row: dict[str, Any], marker: dict[str, Any]) -> None:
    section = "aliases" if row["name"].startswith("aliases") else "users"
    payload = {"users": {"value": [{"id": "u1"}]}, "aliases": {"value": []}}
    marked = mark_incomplete_sections("google_directory", payload, [{"collector": "google_directory", **row}])
    assert marked[section] == {"value": payload[section]["value"], **marker}
    other = "users" if section == "aliases" else "aliases"
    assert marked[other] == payload[other]
    assert payload == {"users": {"value": [{"id": "u1"}]}, "aliases": {"value": []}}  # never changed in place


def test_live_fix_6_b1a_ok_reads_and_bounded_samples_leave_the_section_unmarked() -> None:
    payload = {"adminActivities": {"value": [{"id": {"uniqueQualifier": "1"}}]}}
    rows = [{"collector": "google_reports", "name": "adminActivities", "status": "ok", "bounded_sample": True,
             "collection_truncated": False}]
    assert mark_incomplete_sections("google_reports", payload, rows) == payload


@pytest.mark.parametrize(("collector", "row_name", "section"), [
    ("google_reports", "loginActivities", "loginActivities"),
    ("google_alert_center", "alerts", "alerts"),
    ("google_gmail_settings", "users", "mailboxSettings"),
    ("google_devices", "chromeosDevices", "chromeosDevices"),
    ("google_drive_posture", "driveFiles", "driveFiles"),
    ("google_drive_posture", "drivePermissions", "driveFiles"),
    ("google_drive_posture", "sharedDrives", "sharedDrives"),
    ("google_groups_settings", "groups", "groupSettings"),
    ("google_calendar_posture", "calendarAcls:room@example.com", "calendarAcls"),
    ("google_directory", "groupMembers:team@example.com", "groupMembers"),
    ("google_directory", "oauthGrants:ada@example.com", "oauthGrants"),
])
def test_live_fix_6_b1a_every_google_list_collector_marks_its_section(collector: str, row_name: str, section: str) -> None:
    payload = {section: {"value": [{"id": "r1"}]}}
    row = {"collector": collector, "name": row_name, "status": "partial", "error_class": "malformed_response",
           "collection_truncated": True, "truncation_reason": "pagination_failed"}
    marked = mark_incomplete_sections(collector, payload, [row])
    assert marked[section]["collection_truncated"] is True
    assert marked[section]["truncation_reason"] == "pagination_failed"
    assert marked[section]["error_class"] == "malformed_response"


def test_live_fix_6_b1a_every_google_collector_marks_its_raw_sections() -> None:
    """Each collector is listed here or writes its own markers (policies, SCuBA reads, DNS posture)."""
    self_marking = {"google_policies", "google_setting_events", "google_sso_assignments", "google_dns_posture"}
    assert set(REGISTRY) == set(RAW_SECTION_READS) | self_marking
    assert set(RAW_SECTION_READS) & self_marking == set()
    for collector, reads in RAW_SECTION_READS.items():
        planned = set(COLLECTOR_SECTIONS[collector])
        extra = {"aliases"} if collector == "google_directory" else set()
        if collector == "google_reports":  # every application's stream, not only the two the replay requires
            extra = {f"{app}Activities" for app in ("admin", "login", "token", "drive", "mobile", "groups", "chrome")}
        assert set(reads.values()) <= planned | extra, collector


def test_live_fix_6_b1a_a_partial_read_written_by_the_collector_reaches_the_section_marker() -> None:
    class _Client:
        def list_directory(self, resource: str, **_kwargs: Any) -> list[dict[str, Any]]:
            if resource == "users":
                rows = CollectedRows(list(USERS))
                rows.page_error = google_client.unreadable_rows_error()
                return rows
            return []

    result = GoogleDirectoryCollector().run({"client": _Client()})
    marked = mark_incomplete_sections("google_directory", result.payload, result.coverage)
    assert marked["users"] == {"value": USERS, **MARKED_USERS}
