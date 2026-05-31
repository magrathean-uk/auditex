"""Regression: usage-report record_key uniqueness under M365 anonymization.

Live audit on 2026-05-09 against a tenant with ``ConcealedInfo=true``
(the secure-by-default Microsoft 365 setting) returned every usage-
report row with the all-zeros placeholder UUID, collapsing 87 rows
to one ``record_key`` and tripping the C3 duplicate_record_key
validator.

Fix: synthesize a stable per-row key from source_name + refresh_date
+ row index when the natural id is the anonymization placeholder.
"""
from __future__ import annotations

from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot(rows_by_source: dict[str, list[dict]]) -> dict:
    payloads = {
        "reports_usage": {
            source: {"value": rows} for source, rows in rows_by_source.items()
        }
    }
    return build_normalized_snapshot(
        tenant_name="example",
        run_id="run-test",
        collector_payloads=payloads,
    )


_ANON = "00000000-0000-0000-0000-000000000000"


def test_anonymized_usage_rows_get_distinct_record_keys() -> None:
    """All-zeros placeholder must not collapse 87 rows to one key."""
    rows = [
        {"User Principal Name": _ANON, "Report Refresh Date": "2026-05-08"}
        for _ in range(87)
    ]
    snapshot = _snapshot({"oneDriveUsageAccountDetail": rows})
    section = snapshot.get("usage_report_objects")
    assert section is not None
    record_keys = [r["key"] for r in section["records"]]
    assert len(record_keys) == 87
    assert len(set(record_keys)) == 87, "anonymized rows still collide"


def test_unanonymized_usage_rows_keep_natural_ids() -> None:
    """When the tenant exposes real principal names, the record_key
    uses them — preserves identity-aware reporting."""
    rows = [
        {"User Principal Name": "alice@example.com", "Report Refresh Date": "2026-05-08"},
        {"User Principal Name": "bob@example.com", "Report Refresh Date": "2026-05-08"},
    ]
    snapshot = _snapshot({"mailboxUsageDetail": rows})
    section = snapshot["usage_report_objects"]
    ids = [r["id"] for r in section["records"]]
    assert ids == ["alice@example.com", "bob@example.com"]


def test_anonymized_record_key_includes_refresh_date_for_traceability() -> None:
    """Operators investigating need to know WHICH report period each
    anonymized row came from. The synthesized key should encode it."""
    rows = [
        {"User Principal Name": _ANON, "Report Refresh Date": "2026-05-08"},
        {"User Principal Name": _ANON, "Report Refresh Date": "2026-05-09"},
    ]
    snapshot = _snapshot({"oneDriveUsageAccountDetail": rows})
    ids = [r["id"] for r in snapshot["usage_report_objects"]["records"]]
    assert any("2026-05-08" in i for i in ids)
    assert any("2026-05-09" in i for i in ids)


def test_anonymized_record_key_falls_back_to_index_when_date_missing() -> None:
    rows = [
        {"User Principal Name": _ANON},
        {"User Principal Name": _ANON},
    ]
    snapshot = _snapshot({"sharePointSiteUsageDetail": rows})
    ids = [r["id"] for r in snapshot["usage_report_objects"]["records"]]
    assert len(set(ids)) == 2


def test_empty_principal_name_treated_as_anonymized() -> None:
    """An empty / whitespace User Principal Name should be treated the
    same as the all-zeros placeholder — both indicate anonymization."""
    rows = [
        {"User Principal Name": "", "Report Refresh Date": "2026-05-08"},
        {"User Principal Name": "   ", "Report Refresh Date": "2026-05-08"},
    ]
    snapshot = _snapshot({"oneDriveUsageAccountDetail": rows})
    ids = [r["id"] for r in snapshot["usage_report_objects"]["records"]]
    assert len(set(ids)) == 2
