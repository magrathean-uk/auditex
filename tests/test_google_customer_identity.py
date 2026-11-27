"""LIVE-FIX-3: the Reports API's ``ownerIdentity[].customerIdentity.id`` is an explicit customer id field.

Reports activities name the owning customer as ``resourceDetails[].ownerDetails.ownerIdentity[].customerIdentity.id``.
That ``id`` is learnt and withheld like ``customerId``: masking it does not count as changed evidence, so it does not
add a ``customer_id_withheld`` row or make the collector partial. Masking anything else still does.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.google_workspace.customer_id import WITHHELD, CustomerIds

CUSTOMER = "C00000000"


def _activity(identity: Any, **extra: Any) -> dict[str, Any]:
    return {
        "id": {"applicationName": "admin", "time": "2026-11-01T00:00:00Z", "uniqueQualifier": "1"},
        "events": [{"name": "CHANGE_APPLICATION_SETTING"}],
        "resourceDetails": [{
            "id": "r1", "title": "Setting", "type": "SETTING",
            "ownerDetails": {"ownerType": "CUSTOMER", "ownerIdentity": [identity]},
        }],
        **extra,
    }


def test_customer_identity_id_is_learnt_and_withheld_without_changing_evidence() -> None:
    ids = CustomerIds()
    rows = [_activity({"customerIdentity": {"id": CUSTOMER}})]
    ids.learn(rows)
    assert ids.values == {CUSTOMER}

    safe, changed = ids.evidence(rows)
    assert changed is False
    assert safe[0]["resourceDetails"][0]["ownerDetails"]["ownerIdentity"] == [{"customerIdentity": {"id": "<customer-id>"}}]
    assert safe[0]["resourceDetails"][0]["id"] == "r1"
    assert CUSTOMER not in json.dumps(safe)


def test_customer_identity_key_spelling_is_normalised() -> None:
    ids = CustomerIds()
    rows = [{"customer_identity": {"ID": CUSTOMER}}]
    ids.learn(rows)
    assert ids.values == {CUSTOMER}
    assert ids.evidence(rows) == ([{"customer_identity": {"ID": "<customer-id>"}}], False)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"nested": CUSTOMER}, "<customer-id>"),
        ([CUSTOMER], "<customer-id>"),
        (12345, "<customer-id>"),
        (True, "<customer-id>"),
        (None, None),
        ("", ""),
        ("my_customer", "my_customer"),
    ],
)
def test_malformed_customer_identity_id_is_withheld_whole_and_never_learnt(value: Any, expected: Any) -> None:
    ids = CustomerIds()
    rows = [{"customerIdentity": {"id": value}}]
    ids.learn(rows)
    assert ids.values == set()
    assert ids.evidence(rows) == ([{"customerIdentity": {"id": expected}}], False)


def test_other_members_of_a_customer_identity_are_ordinary_evidence() -> None:
    ids = CustomerIds(CUSTOMER)
    safe, changed = ids.evidence([{"customerIdentity": {"id": CUSTOMER, "label": f"owner {CUSTOMER}"}}])
    assert safe == [{"customerIdentity": {"id": "<customer-id>", "label": "owner <customer-id>"}}]
    assert changed is True


@pytest.mark.parametrize(
    "rows",
    [
        # An ``id`` that is not directly under customerIdentity is not an explicit customer id field.
        [{"ownerIdentity": [{"id": CUSTOMER}]}],
        [{"customerIdentity": {"user": {"id": CUSTOMER}}}],
        # A customerIdentity that is not an object is not read as one.
        [{"customerIdentity": CUSTOMER}],
        [{"customerIdentity": [{"id": CUSTOMER}]}],
        [{"identity": {"id": CUSTOMER}}],
    ],
)
def test_a_learnt_id_outside_the_explicit_field_still_changes_evidence(rows: list[dict[str, Any]]) -> None:
    ids = CustomerIds(CUSTOMER)
    safe, changed = ids.evidence(rows)
    assert changed is True
    assert CUSTOMER not in json.dumps(safe)
    assert WITHHELD in json.dumps(safe)


def test_an_id_outside_the_explicit_field_is_not_learnt() -> None:
    ids = CustomerIds()
    ids.learn([{"ownerIdentity": [{"id": CUSTOMER}]}, {"customerIdentity": CUSTOMER}, {"customerIdentity": [{"id": CUSTOMER}]}])
    assert ids.values == set()


def _live_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, activities: list[dict[str, Any]]) -> tuple[int, Path]:
    from auditex.google_workspace import run as google_run
    from auditex.google_workspace.run import GoogleRunConfig, run_google_live
    from azure_tenant_audit.collectors.base import CollectorResult

    class _FakeReports:
        name = "google_reports"
        required_scopes = ("scope://reports.readonly",)

        def run(self, _context: Any) -> CollectorResult:
            return CollectorResult(
                name=self.name, status="ok", item_count=len(activities),
                payload={"adminActivities": {"value": activities}},
                coverage=[{"collector": self.name, "name": "adminActivities", "type": "google", "status": "ok",
                           "item_count": len(activities), "authenticated_read": True}],
            )

    monkeypatch.setattr(google_run, "REGISTRY", {"google_reports": _FakeReports()})
    monkeypatch.setattr(google_run, "google_dependency_status", lambda: {"available": True, "missing": [], "install_hint": ""})
    monkeypatch.setattr(google_run, "build_google_credentials", lambda _config: object())
    monkeypatch.setattr(google_run, "GoogleWorkspaceClient", lambda *_args, **_kwargs: object())
    rc = run_google_live(
        GoogleRunConfig(
            tenant_name="Example", out=tmp_path, run_name="live", domain="example.com", customer_id="my_customer",
            subject="admin@example.com", service_account_key=tmp_path / "service-account.json",
            collectors="google_reports",
        ),
        command_line=["auditex", "google", "run", "--domain", "example.com"],
    )
    return rc, tmp_path / "Example-live"


def _withheld_rows(run_dir: Path) -> list[dict[str, Any]]:
    coverage = json.loads((run_dir / "coverage.json").read_text(encoding="utf-8"))
    rows = coverage if isinstance(coverage, list) else coverage.get("coverage", [])
    return [row for row in rows if row.get("name") == "customer_id_withheld"]


def test_live_run_with_customer_identity_rows_is_not_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rc, run_dir = _live_run(tmp_path, monkeypatch, [_activity({"customerIdentity": {"id": CUSTOMER}})])

    raw = json.loads((run_dir / "raw" / "google_reports.json").read_text(encoding="utf-8"))
    owner = raw["adminActivities"]["value"][0]["resourceDetails"][0]["ownerDetails"]["ownerIdentity"]
    assert owner == [{"customerIdentity": {"id": "<customer-id>"}}]
    assert _withheld_rows(run_dir) == []
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert [(row["name"], row["status"]) for row in summary["collectors"]] == [("google_reports", "ok")]
    assert [str(path.relative_to(run_dir)) for path in run_dir.rglob("*")
            if path.is_file() and CUSTOMER.encode() in path.read_bytes()] == []
    assert rc == 0


def test_live_run_with_the_id_elsewhere_in_evidence_stays_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    activity = _activity({"customerIdentity": {"id": CUSTOMER}})
    activity["events"] = [{"name": "CHANGE_APPLICATION_SETTING", "parameters": [{"name": "NOTE", "value": f"for {CUSTOMER}"}]}]
    rc, run_dir = _live_run(tmp_path, monkeypatch, [activity])

    rows = _withheld_rows(run_dir)
    assert [(row["collector"], row["status"], row["error_class"]) for row in rows] == [
        ("google_reports", "partial", "customer_id_withheld"),
    ]
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert [(row["name"], row["status"]) for row in summary["collectors"]] == [("google_reports", "partial")]
    assert rc == 1
