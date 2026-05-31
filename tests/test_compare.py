from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from auditex.compare import compare_run_directories, compare_runs
from auditex.evidence_db import build_run_evidence_index


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_run(
    root: Path,
    *,
    tenant_name: str,
    run_id: str,
    created_utc: str,
    status: str,
    collector_name: str,
    normalized_name: str,
    records: list[dict],
) -> Path:
    run_dir = root / run_id
    _write_json(
        run_dir / "run-manifest.json",
        {
            "tenant_name": tenant_name,
            "run_id": run_id,
            "created_utc": created_utc,
            "overall_status": status,
        },
    )
    _write_json(
        run_dir / "summary.json",
        {
            "collectors": [
                {
                    "name": collector_name,
                    "status": status,
                    "item_count": len(records),
                    "message": f"{collector_name} done",
                }
            ]
        },
    )
    _write_json(run_dir / "normalized" / f"{normalized_name}.json", {"kind": normalized_name, "records": records})
    return run_dir


def test_compare_run_directories_builds_multi_run_aggregation(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[
            {"key": "user:1", "display_name": "Alice", "department": "Sales"},
            {"key": "user:2", "display_name": "Bob", "department": "IT"},
        ],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-b",
        created_utc="2026-04-02T00:00:00Z",
        status="partial",
        collector_name="users",
        normalized_name="users",
        records=[
            {"key": "user:1", "display_name": "Alice", "department": "Finance"},
            {"key": "user:3", "display_name": "Charlie", "department": "IT"},
        ],
    )
    run_c = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-c",
        created_utc="2026-04-03T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[
            {"key": "user:1", "display_name": "Alice", "department": "Finance"},
            {"key": "user:3", "display_name": "Charlie", "department": "Operations"},
        ],
    )

    result = compare_run_directories([run_a, run_b, run_c])

    assert [item["run_id"] for item in result["runs"]] == ["run-a", "run-b", "run-c"]
    assert [item["run_id"] for item in result["timeline"]] == ["run-a", "run-b", "run-c"]
    assert result["compare_context"]["same_tenant"] is True
    assert len(result["adjacent_diffs"]) == 2
    assert result["adjacent_diffs"][0]["left_run"]["run_id"] == "run-a"
    assert result["adjacent_diffs"][0]["right_run"]["run_id"] == "run-b"
    assert result["adjacent_diffs"][0]["compare_context"]["same_tenant"] is True
    assert result["baseline_diff"]["left_run"]["run_id"] == "run-a"
    assert result["baseline_diff"]["right_run"]["run_id"] == "run-c"
    assert result["baseline_diff"]["summary"]["changed"] == 1
    assert result["adjacent_diffs"][0]["summary"]["added"] == 1
    assert result["adjacent_diffs"][0]["summary"]["removed"] == 1
    assert result["adjacent_diffs"][0]["summary"]["changed"] == 1


def test_compare_run_directories_blocks_cross_tenant_compare(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="other",
        run_id="run-b",
        created_utc="2026-04-02T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )

    result = compare_run_directories([run_a, run_b])

    assert result["compare_context"]["same_tenant"] is False
    assert result["baseline_diff"]["status"] == "blocked"
    assert result["baseline_diff"]["reason"] == "same_tenant_required"
    assert result["adjacent_diffs"][0]["status"] == "blocked"
    assert result["adjacent_diffs"][0]["reason"] == "same_tenant_required"


def test_compare_runs_can_allow_cross_tenant(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="other",
        run_id="run-b",
        created_utc="2026-04-02T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )

    result = compare_runs([str(run_a), str(run_b)], allow_cross_tenant=True)

    assert result["compare_context"]["same_tenant"] is False
    assert result["baseline_diff"]["status"] == "ok"


def test_compare_runs_result_is_json_serializable(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-b",
        created_utc="2026-04-02T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )

    payload = compare_runs([str(run_a), str(run_b)])

    json.dumps(payload)


def test_compare_runs_can_use_classic_mode_for_raw_timestamp_churn(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="devices",
        normalized_name="devices",
        records=[{"key": "device:1", "platform": "Windows", "last_sync": "2026-05-01T00:00:00Z"}],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-b",
        created_utc="2026-04-02T00:00:00Z",
        status="ok",
        collector_name="devices",
        normalized_name="devices",
        records=[{"key": "device:1", "platform": "Windows", "last_sync": "2026-05-02T00:00:00Z"}],
    )

    suppressed = compare_runs([str(run_a), str(run_b)])
    classic = compare_runs([str(run_a), str(run_b)], classic=True)

    assert suppressed["classic"] is False
    assert suppressed["baseline_diff"]["summary"]["changed"] == 0
    assert suppressed["baseline_diff"]["noise_suppression"]["suppressed_changed"] == 1
    assert suppressed["baseline_diff"]["noise_suppression"]["suppressed_path_counts"] == {"last_sync": 1}
    assert classic["classic"] is True
    assert classic["baseline_diff"]["summary"]["changed"] == 1
    assert classic["baseline_diff"]["noise_suppression"]["enabled"] is False


def test_compare_runs_exposes_usage_refresh_noise_summary(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="usage_report_objects",
        normalized_name="usage_report_objects",
        records=[{"key": "usage:users", "source_name": "office365ActiveUserCounts", "report_refresh_date": "2026-05-01"}],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-b",
        created_utc="2026-04-02T00:00:00Z",
        status="ok",
        collector_name="usage_report_objects",
        normalized_name="usage_report_objects",
        records=[{"key": "usage:users", "source_name": "office365ActiveUserCounts", "report_refresh_date": "2026-05-02"}],
    )

    result = compare_runs([str(run_a), str(run_b)])

    assert result["baseline_diff"]["summary"]["changed"] == 0
    assert result["baseline_diff"]["noise_suppression"]["suppressed_changed"] == 1
    assert result["baseline_diff"]["noise_suppression"]["suppressed_path_counts"] == {"report_refresh_date": 1}


def test_compare_run_directories_falls_back_to_manifest_when_index_metadata_is_sparse(tmp_path: Path) -> None:
    run_a = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="20260401_000000",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )
    run_b = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-b",
        created_utc="20260402_000000",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[{"key": "user:1", "display_name": "Alice"}],
    )
    db_a = build_run_evidence_index(run_a)
    db_b = build_run_evidence_index(run_b)

    for db_path in (db_a, db_b):
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DELETE FROM run_meta WHERE key NOT IN ('run_dir', 'summary')")
            conn.commit()
        finally:
            conn.close()

    result = compare_run_directories([run_a, run_b])

    assert result["compare_context"]["same_tenant"] is True
    assert result["runs"][0]["tenant_name"] == "acme"
    assert result["runs"][0]["run_id"] == "run-a"
    assert result["runs"][0]["created_utc"] == "20260401_000000"


def test_build_run_evidence_index_creates_tables_from_run_dir(tmp_path: Path) -> None:
    run_dir = _write_run(
        tmp_path,
        tenant_name="acme",
        run_id="run-a",
        created_utc="2026-04-01T00:00:00Z",
        status="ok",
        collector_name="users",
        normalized_name="users",
        records=[
            {"key": "user:1", "display_name": "Alice", "department": "Sales"},
            {"key": "user:2", "display_name": "Bob", "department": "IT"},
        ],
    )

    db_path = build_run_evidence_index(run_dir)
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute("select name from sqlite_master where type='table' order by name")
        }
        assert {"normalized_records", "run_meta", "section_stats"} <= tables

        run_meta = dict(conn.execute("select key, value from run_meta").fetchall())
        assert run_meta["run_id"] == "run-a"
        assert run_meta["tenant_name"] == "acme"

        section_stats = conn.execute(
            "select section_name, item_count, source_path from section_stats order by section_name"
        ).fetchall()
        assert section_stats == [("users", 2, "normalized/users.json")]

        normalized_records = conn.execute(
            "select section_name, record_key, record_json from normalized_records order by record_key"
        ).fetchall()
        assert normalized_records[0][0] == "users"
        assert normalized_records[0][1] == "user:1"
        assert json.loads(normalized_records[0][2])["display_name"] == "Alice"
    finally:
        conn.close()


def test_load_run_index_summary_ignores_legacy_or_sparse_sqlite(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-a"
    (run_dir / "index").mkdir(parents=True)
    conn = sqlite3.connect(run_dir / "index" / "evidence.sqlite")
    try:
        conn.execute("create table legacy (value text)")
        conn.execute("insert into legacy(value) values ('old')")
        conn.commit()
    finally:
        conn.close()

    from auditex.evidence_db import load_run_index_summary

    assert load_run_index_summary(run_dir) == {}
