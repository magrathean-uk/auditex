"""C2: evidence DB schema migration / forward-compat.

``build_run_evidence_index`` rebuilds ``index/evidence.sqlite`` on every
finalize via ``DROP TABLE IF EXISTS`` + ``CREATE TABLE`` for the three
canonical tables (run_meta, section_stats, normalized_records). The
canonical contract is therefore:

1. A bundle from a prior auditex release (with a different / older
   schema in evidence.sqlite) must NOT crash the rebuild.
2. After rebuild, the DB must have exactly the current schema with
   columns matching ``_SCHEMA`` in ``src/azure_tenant_audit/evidence_db.py``.
3. All normalized records from the bundle's ``normalized/*.json`` files
   must be re-indexed; nothing leaks from the prior schema.

The test below plants a deliberately-foreign DB at the target path
(extra table, different columns, foreign indexes) and asserts the
rebuild emits the canonical schema with the expected data populated.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

# Re-use the bundle prep from C1 — same shape, same offline sample, no
# duplicated boilerplate.
from test_finalize_idempotent import _prepare_bundle_for_finalize

from azure_tenant_audit.evidence_db import build_run_evidence_index
from azure_tenant_audit.finalize import finalize_bundle_contract

# Tables the rebuild must produce, paired with the columns those tables
# must have (column NAME only — types/constraints are exercised by the
# normal contract-smoke run already).
_EXPECTED_TABLES: dict[str, set[str]] = {
    "run_meta": {"key", "value"},
    "section_stats": {"section_name", "item_count", "source_path"},
    "normalized_records": {
        "run_id",
        "tenant_name",
        "section_name",
        "record_index",
        "record_key",
        "display_name",
        "source_name",
        "collector",
        "severity",
        "record_json",
        "source_path",
    },
}


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _all_tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        if not row[0].startswith("sqlite_")
    }


def _plant_legacy_db(target: Path) -> None:
    """Write a DB at the canonical evidence.sqlite path that uses a
    foreign schema — emulates an older auditex release or third-party
    inspection tool that touched the file."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    with sqlite3.connect(target) as conn:
        conn.executescript(
            """
            CREATE TABLE legacy_run_meta (run_id TEXT, info TEXT);
            CREATE TABLE legacy_findings (
                rule_id TEXT,
                severity TEXT,
                old_column_only_in_legacy TEXT
            );
            CREATE INDEX idx_legacy_findings_rule ON legacy_findings(rule_id);
            INSERT INTO legacy_run_meta VALUES ('old-run-id', 'should-be-wiped');
            INSERT INTO legacy_findings VALUES ('old.rule', 'high', 'leaked');
            """
        )
        conn.commit()


def test_legacy_evidence_db_is_replaced_with_canonical_schema(tmp_path: Path) -> None:
    """Plant a foreign-schema DB; rebuild; assert exactly the canonical
    tables emerge with the right columns and the legacy artefacts are
    gone."""
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)

    legacy_db = writer.run_dir / "index" / "evidence.sqlite"
    _plant_legacy_db(legacy_db)

    rebuilt_path = build_run_evidence_index(writer.run_dir)
    assert rebuilt_path == legacy_db

    with sqlite3.connect(rebuilt_path) as conn:
        tables = _all_tables(conn)
        assert tables == set(_EXPECTED_TABLES), (
            f"rebuilt DB tables drifted from canonical contract: got {sorted(tables)}, "
            f"expected {sorted(_EXPECTED_TABLES)}"
        )
        for table, expected_columns in _EXPECTED_TABLES.items():
            actual = _table_columns(conn, table)
            missing = expected_columns - actual
            extra = actual - expected_columns
            assert not missing, f"{table}: missing columns {missing}"
            assert not extra, f"{table}: unexpected extra columns {extra}"
        # Legacy rows must not survive the rebuild.
        for legacy_value in conn.execute("SELECT key, value FROM run_meta"):
            assert legacy_value[1] != "should-be-wiped"


def test_rebuild_populates_normalized_records_after_legacy_overwrite(
    tmp_path: Path,
) -> None:
    """The rebuild must source data from the bundle's normalized/*.json
    files, not from the previous DB. Plant a legacy DB, rebuild, and
    confirm the normalized records appear."""
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)

    legacy_db = writer.run_dir / "index" / "evidence.sqlite"
    _plant_legacy_db(legacy_db)

    build_run_evidence_index(writer.run_dir)

    with sqlite3.connect(legacy_db) as conn:
        record_count = conn.execute(
            "SELECT COUNT(*) FROM normalized_records"
        ).fetchone()[0]
        section_count = conn.execute(
            "SELECT COUNT(*) FROM section_stats"
        ).fetchone()[0]
        meta_count = conn.execute("SELECT COUNT(*) FROM run_meta").fetchone()[0]

    assert record_count > 0, (
        "rebuild did not re-populate normalized_records from normalized/*.json"
    )
    assert section_count > 0, "rebuild did not re-populate section_stats"
    assert meta_count > 0, "rebuild did not re-populate run_meta"


def test_rebuild_is_safe_when_target_db_does_not_exist(tmp_path: Path) -> None:
    """Cold path: no legacy DB, no prior finalize — rebuild must still
    produce a valid canonical DB so an external script can run
    build_run_evidence_index against an existing bundle without
    re-finalising."""
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)

    db_path = writer.run_dir / "index" / "evidence.sqlite"
    db_path.unlink()  # remove the DB the finalize call just produced

    build_run_evidence_index(writer.run_dir)

    with sqlite3.connect(db_path) as conn:
        assert _all_tables(conn) == set(_EXPECTED_TABLES)
        assert (
            conn.execute("SELECT COUNT(*) FROM normalized_records").fetchone()[0] > 0
        )


def test_rebuild_drops_foreign_indexes(tmp_path: Path) -> None:
    """Foreign indexes from the legacy DB must not survive the rebuild
    — an external SQLite tool inspecting the rebuilt file should see
    only the indexes defined in ``_INDEXES``."""
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)

    legacy_db = writer.run_dir / "index" / "evidence.sqlite"
    _plant_legacy_db(legacy_db)

    build_run_evidence_index(writer.run_dir)

    with sqlite3.connect(legacy_db) as conn:
        index_names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
            if not row[0].startswith("sqlite_")
        }
    # The rebuild creates exactly the three canonical indexes; the
    # legacy ``idx_legacy_findings_rule`` was wiped along with its
    # underlying table.
    expected = {
        "idx_normalized_records_key",
        "idx_normalized_records_collector",
        "idx_normalized_records_section",
    }
    assert index_names == expected, (
        f"index drift: got {sorted(index_names)}, expected {sorted(expected)}"
    )
