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
        # LIVE-FIX-5 B2: an identity whose id is not a string is not a customer identity, so it is withheld whole.
        ({"nested": CUSTOMER}, "<customer-id>"),
        ([CUSTOMER], "<customer-id>"),
        (12345, "<customer-id>"),
        (True, "<customer-id>"),
        (None, "<customer-id>"),
        ("", {"id": ""}),
        ("my_customer", {"id": "my_customer"}),
    ],
)
def test_malformed_customer_identity_id_is_withheld_whole_and_never_learnt(value: Any, expected: Any) -> None:
    ids = CustomerIds()
    rows = [{"customerIdentity": {"id": value}}]
    ids.learn(rows)
    assert ids.values == set()
    assert ids.evidence(rows) == ([{"customerIdentity": expected}], False)


def test_other_members_of_a_customer_identity_are_ordinary_evidence() -> None:
    ids = CustomerIds(CUSTOMER)
    safe, changed = ids.evidence([{"customerIdentity": {"id": CUSTOMER, "label": f"owner {CUSTOMER}"}}])
    assert safe == [{"customerIdentity": {"id": "<customer-id>", "label": "owner <customer-id>"}}]
    assert changed is True


@pytest.mark.parametrize(
    "rows",
    [
        # An ``id`` that is not directly under customerIdentity is not an explicit customer id field. (An ownerIdentity
        # entry with a member of its own is withheld whole since LIVE-FIX-6 B2a, so a user identity stands in here.)
        [{"ownerIdentity": [{"userIdentity": {"id": CUSTOMER}}]}],
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


# ---- LIVE-FIX-5 B2: a customer field of the wrong shape is withheld whole, before or after the id is learnt -------

WRONG_IDENTITY = [
    [{"id": CUSTOMER}],
    [CUSTOMER],
    CUSTOMER,
    f" {CUSTOMER} ",
    f"customers/{CUSTOMER}",
    9000000001,
    1.5,
    True,
    {"user": {"id": CUSTOMER}},
    {"id": None, "label": CUSTOMER},
    {"id": [CUSTOMER]},
    {"id": 7, "name": CUSTOMER},
    {"id": "x", "ID": [CUSTOMER]},
    {},
]


@pytest.mark.parametrize("learnt", [False, True])
@pytest.mark.parametrize("identity", WRONG_IDENTITY)
def test_live_fix_5_b2_a_wrong_typed_customer_identity_is_withheld_whole(identity: Any, learnt: bool) -> None:
    ids = CustomerIds(CUSTOMER) if learnt else CustomerIds()
    rows = [_activity({"customerIdentity": identity})]
    ids.learn(rows)
    assert ids.values == ({CUSTOMER} if learnt else set())
    safe, changed = ids.evidence(rows)
    assert safe[0]["resourceDetails"][0]["ownerDetails"]["ownerIdentity"] == [{"customerIdentity": "<customer-id>"}]
    assert changed is False
    assert CUSTOMER not in json.dumps(safe)
    assert CUSTOMER not in json.dumps(CustomerIds().scrub(rows))


@pytest.mark.parametrize("identity", [None, ""])
def test_live_fix_5_b2_an_empty_customer_identity_holds_nothing_to_withhold(identity: Any) -> None:
    rows = [{"customerIdentity": identity}]
    assert CustomerIds().evidence(rows) == ([{"customerIdentity": identity}], False)


@pytest.mark.parametrize("customer", [
    [f"customers/{CUSTOMER}"], {"name": f"customers/{CUSTOMER}"}, CUSTOMER, f" customers/{CUSTOMER}", 9000000001,
    True, {"id": CUSTOMER},
])
def test_live_fix_5_b2_a_wrong_typed_customer_field_is_withheld_whole(customer: Any) -> None:
    ids = CustomerIds()
    rows = [{"name": "policies/p1", "customer": customer}]
    ids.learn(rows)
    assert ids.values == set()
    assert ids.evidence(rows) == ([{"name": "policies/p1", "customer": "<customer-id>"}], False)
    assert CUSTOMER not in json.dumps(ids.scrub(rows))


@pytest.mark.parametrize("customer", [None, "", "my_customer"])
def test_live_fix_5_b2_an_empty_customer_field_is_kept(customer: Any) -> None:
    rows = [{"customer": customer}]
    assert CustomerIds().evidence(rows) == ([{"customer": customer}], False)


def test_live_fix_5_b2_a_customers_path_is_still_learnt_and_masked() -> None:
    ids = CustomerIds()
    rows = [{"customer": f"customers/{CUSTOMER}"}]
    ids.learn(rows)
    assert ids.values == {CUSTOMER}
    assert ids.evidence(rows) == ([{"customer": "customers/<customer-id>"}], False)


@pytest.mark.parametrize("row", [
    # Reports Activity.id.customerId and UsageReport.entity.customerId, well formed and in wrong-typed containers.
    {"id": {"applicationName": "admin", "customerId": CUSTOMER}},
    {"id": [{"customerId": CUSTOMER}]},
    {"id": {"customerId": [CUSTOMER]}},
    {"id": {"customerId": {"value": CUSTOMER}}},
    {"id": {"customerId": 9000000001}},
    {"entity": {"customerId": CUSTOMER, "type": "CUSTOMER"}},
    {"entity": [{"customerId": CUSTOMER}]},
    {"entity": {"customerId": [CUSTOMER]}},
    {"entity": {"customer_id": {"id": CUSTOMER}}},
    {"usageReports": [{"entity": [[{"customerId": CUSTOMER}]]}]},
])
def test_live_fix_5_b2_report_customer_id_paths_never_copy_the_id(row: dict[str, Any]) -> None:
    ids = CustomerIds()
    ids.learn([row])
    safe, changed = ids.evidence([row])
    assert changed is False
    assert CUSTOMER not in json.dumps(safe)
    assert "<customer-id>" in json.dumps(safe)


@pytest.mark.parametrize("identity", [[{"id": CUSTOMER}], CUSTOMER, 9000000001, {"user": {"id": CUSTOMER}}])
def test_live_fix_5_b2_reviewer_scenario_live_run_never_writes_the_id(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: Any) -> None:
    rc, run_dir = _live_run(tmp_path, monkeypatch, [_activity({"customerIdentity": identity})])

    raw = json.loads((run_dir / "raw" / "google_reports.json").read_text(encoding="utf-8"))
    owner = raw["adminActivities"]["value"][0]["resourceDetails"][0]["ownerDetails"]["ownerIdentity"]
    assert owner == [{"customerIdentity": "<customer-id>"}]
    needle = str(identity if not isinstance(identity, (list, dict)) else CUSTOMER).encode()
    assert [str(path.relative_to(run_dir)) for path in run_dir.rglob("*")
            if path.is_file() and needle in path.read_bytes()] == []
    assert rc == 0


# ---- LIVE-FIX-6 B2a: a Reports field on a customer id path with the wrong shape is withheld whole -----------------

_TIME = "2026-11-01T00:00:00Z"


def _with_id(activity_id: Any) -> dict[str, Any]:
    return {"kind": "admin#reports#activity", "id": activity_id, "events": [{"name": "CHANGE_APPLICATION_SETTING"}]}


WRONG_ACTIVITY_ID = [
    CUSTOMER,
    f"id {CUSTOMER}",
    [CUSTOMER],
    [{"customerId": CUSTOMER}],
    9000000001,
    True,
    {"time": _TIME, "cid": CUSTOMER},
    {"time": _TIME, "uniqueQualifier": [CUSTOMER]},
    {"applicationName": {"name": CUSTOMER}},
    {"time": _TIME, "uniqueQualifier": "1", "owner": {"id": CUSTOMER}},
]


@pytest.mark.parametrize("learnt", [False, True])
@pytest.mark.parametrize("activity_id", WRONG_ACTIVITY_ID)
def test_live_fix_6_b2a_an_activity_id_of_the_wrong_shape_is_withheld_whole(activity_id: Any, learnt: bool) -> None:
    ids = CustomerIds(CUSTOMER) if learnt else CustomerIds()
    rows = [_with_id(activity_id)]
    ids.learn(rows)
    safe, changed = ids.evidence(rows)
    assert safe == [{"kind": "admin#reports#activity", "id": "<customer-id>",
                     "events": [{"name": "CHANGE_APPLICATION_SETTING"}]}]
    assert changed is False
    assert CUSTOMER not in json.dumps(CustomerIds().scrub(rows))


@pytest.mark.parametrize("row", [
    # No kind, but members only an activity has.
    {"id": CUSTOMER, "actor": {"email": "ada@example.com"}},
    {"id": [CUSTOMER], "ipAddress": "192.0.2.1"},
    {"id": CUSTOMER, "resourceDetails": []},
])
def test_live_fix_6_b2a_an_activity_without_kind_is_still_an_activity(row: dict[str, Any]) -> None:
    safe, _ = CustomerIds().evidence([row])
    assert safe[0]["id"] == "<customer-id>"
    assert CUSTOMER not in json.dumps(safe)


@pytest.mark.parametrize("payload", [
    {"adminActivities": {"value": [{"id": CUSTOMER}]}},
    {"loginActivities": {"value": [{"id": [CUSTOMER]}], "status": "partial"}},
    {"tokenActivities": [{"id": CUSTOMER}]},
])
def test_live_fix_6_b2a_a_row_of_a_reports_stream_is_an_activity_whatever_it_holds(payload: dict[str, Any]) -> None:
    safe, changed = CustomerIds().evidence(payload)
    assert CUSTOMER not in json.dumps(safe)
    assert '"id": "<customer-id>"' in json.dumps(safe)
    assert changed is False


def test_live_fix_6_b2a_a_well_formed_activity_id_is_kept_with_its_customer_id_withheld() -> None:
    rows = [_with_id({"time": _TIME, "uniqueQualifier": "-12", "applicationName": "admin", "customerId": CUSTOMER})]
    ids = CustomerIds()
    ids.learn(rows)
    assert ids.values == {CUSTOMER}
    assert ids.evidence(rows) == ([_with_id({"time": _TIME, "uniqueQualifier": "-12", "applicationName": "admin",
                                             "customerId": "<customer-id>"})], False)
    numeric = [_with_id({"time": _TIME, "uniqueQualifier": 12})]
    assert CustomerIds().evidence(numeric) == (numeric, False)


@pytest.mark.parametrize("row", [
    # Objects that are not activities keep a scalar id: other kinds, and objects without an activity member.
    {"kind": "google_activity", "id": "u1", "events": [{"name": "x"}]},
    {"kind": "admin#directory#user", "id": "u1", "primaryEmail": "ada@example.com"},
    {"id": "file-1", "name": "Plan"},
    {"settingEvents": {"value": [{"id": {"time": _TIME}, "events": []}]}},
])
def test_live_fix_6_b2a_other_ids_are_ordinary_evidence(row: dict[str, Any]) -> None:
    assert CustomerIds().evidence([row]) == ([row], False)


WRONG_ENTITY = [CUSTOMER, [CUSTOMER], [{"customerId": CUSTOMER}], 7, {"type": "CUSTOMER", "owner": CUSTOMER},
                {"type": "CUSTOMER", "userEmail": [CUSTOMER]}, {"customer": {"id": CUSTOMER}}]


@pytest.mark.parametrize("learnt", [False, True])
@pytest.mark.parametrize("entity", WRONG_ENTITY)
def test_live_fix_6_b2a_a_usage_report_entity_of_the_wrong_shape_is_withheld_whole(entity: Any, learnt: bool) -> None:
    ids = CustomerIds(CUSTOMER) if learnt else CustomerIds()
    rows = [{"kind": "admin#reports#usageReport", "date": "2026-11-01", "entity": entity, "parameters": []}]
    ids.learn(rows)
    safe, changed = ids.evidence(rows)
    assert safe == [{"kind": "admin#reports#usageReport", "date": "2026-11-01", "entity": "<customer-id>",
                     "parameters": []}]
    assert changed is False
    assert CUSTOMER not in json.dumps(CustomerIds().scrub(rows))


def test_live_fix_6_b2a_a_well_formed_usage_entity_and_an_alert_entity_are_kept() -> None:
    usage = [{"kind": "admin#reports#usageReport", "date": "2026-11-01", "parameters": [],
              "entity": {"type": "CUSTOMER", "customerId": CUSTOMER}}]
    assert CustomerIds().evidence(usage)[0][0]["entity"] == {"type": "CUSTOMER", "customerId": "<customer-id>"}
    alert = [{"alertId": "a1", "data": {"entity": {"emailAddress": "ada@example.com", "displayName": "Ada"}}}]
    assert CustomerIds().evidence(alert) == (alert, False)
    assert CustomerIds().evidence([{"entity": CUSTOMER}])[0] == [{"entity": "<customer-id>"}]


WRONG_OWNER_DETAILS = [CUSTOMER, [CUSTOMER], 5, {"ownerType": "CUSTOMER", "owner": CUSTOMER},
                       {"ownerType": [CUSTOMER]}, {"ownerType": {"id": CUSTOMER}}]


@pytest.mark.parametrize("learnt", [False, True])
@pytest.mark.parametrize("details", WRONG_OWNER_DETAILS)
def test_live_fix_6_b2a_owner_details_of_the_wrong_shape_are_withheld_whole(details: Any, learnt: bool) -> None:
    ids = CustomerIds(CUSTOMER) if learnt else CustomerIds()
    rows = [{"kind": "admin#reports#activity", "id": {"time": _TIME},
             "resourceDetails": [{"id": "r1", "ownerDetails": details}]}]
    ids.learn(rows)
    safe, changed = ids.evidence(rows)
    assert safe[0]["resourceDetails"] == [{"id": "r1", "ownerDetails": "<customer-id>"}]
    assert changed is False
    assert CUSTOMER not in json.dumps(CustomerIds().scrub(rows))


WRONG_OWNER_IDENTITY = [
    [CUSTOMER],
    CUSTOMER,
    {"customerIdentity": {"id": CUSTOMER}},
    [{"id": CUSTOMER}],
    [{"customerIdentity": {"id": "C11111111"}}, CUSTOMER],
    [{"userIdentity": CUSTOMER}],
    [{"groupIdentity": [CUSTOMER]}],
    [{"customerIdentity": {"id": "C11111111"}, "owner": CUSTOMER}],
]


@pytest.mark.parametrize("learnt", [False, True])
@pytest.mark.parametrize("owner_identity", WRONG_OWNER_IDENTITY)
def test_live_fix_6_b2a_an_owner_identity_of_the_wrong_shape_is_withheld_whole(owner_identity: Any, learnt: bool) -> None:
    ids = CustomerIds(CUSTOMER) if learnt else CustomerIds()
    rows = [{"kind": "admin#reports#activity", "id": {"time": _TIME}, "resourceDetails": [
        {"id": "r1", "ownerDetails": {"ownerType": "CUSTOMER", "ownerIdentity": owner_identity}}]}]
    ids.learn(rows)
    safe, changed = ids.evidence(rows)
    assert safe[0]["resourceDetails"][0]["ownerDetails"] == {"ownerType": "CUSTOMER", "ownerIdentity": "<customer-id>"}
    assert changed is False
    assert CUSTOMER not in json.dumps(CustomerIds().scrub(rows))


def test_live_fix_6_b2a_well_formed_owner_identities_are_kept() -> None:
    identity = [{"customerIdentity": {"id": CUSTOMER}}, {"userIdentity": {"id": "u1", "userEmail": "ada@example.com"}},
                {"groupIdentity": {"id": "g1", "groupEmail": "team@example.com"}},
                {"sharedDriveIdentity": {"id": "d1", "sharedDriveName": "Shared"}}]
    safe, changed = CustomerIds().evidence([{"ownerDetails": {"ownerType": "CUSTOMER", "ownerIdentity": identity}}])
    assert safe == [{"ownerDetails": {"ownerType": "CUSTOMER", "ownerIdentity": [
        {"customerIdentity": {"id": "<customer-id>"}}, *identity[1:]]}}]
    assert changed is False


@pytest.mark.parametrize("activity", [
    _with_id(CUSTOMER),
    {"id": CUSTOMER},
    {"kind": "admin#reports#activity", "id": {"time": _TIME, "uniqueQualifier": "1"}, "resourceDetails": [
        {"id": "r1", "ownerDetails": {"ownerType": "CUSTOMER", "ownerIdentity": [CUSTOMER]}}]},
])
def test_live_fix_6_b2a_reviewer_scenario_live_run_never_writes_the_id(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, activity: dict[str, Any]) -> None:
    rc, run_dir = _live_run(tmp_path, monkeypatch, [activity])
    assert [str(path.relative_to(run_dir)) for path in run_dir.rglob("*")
            if path.is_file() and CUSTOMER.encode() in path.read_bytes()] == []
    raw = json.loads((run_dir / "raw" / "google_reports.json").read_text(encoding="utf-8"))
    assert "<customer-id>" in json.dumps(raw["adminActivities"]["value"][0])
    assert rc == 0


def test_live_fix_6_b2a_a_scalar_activity_id_never_names_the_normalised_record() -> None:
    from auditex.google_workspace.normalize import build_google_normalized_snapshot

    payloads = {"google_reports": {"adminActivities": {"value": [
        {"id": CUSTOMER, "events": [{"name": "x"}]},
        {"id": {"time": _TIME, "uniqueQualifier": "77"}, "events": [{"name": "y"}]},
    ]}}}
    snapshot = build_google_normalized_snapshot(tenant_name="Example", run_id="r1", collector_payloads=payloads)
    records = snapshot["google_activity_events"]["records"]
    assert [record["id"] for record in records] == ["adminActivities:0", "77"]
    assert CUSTOMER not in json.dumps(records)
