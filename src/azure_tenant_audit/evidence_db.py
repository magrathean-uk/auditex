from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .perf_runtime import sqlite_bulk_pragmas
from .tenant_identity import decode_identity_metadata


_SCHEMA = (
    "DROP TABLE IF EXISTS run_meta",
    "DROP TABLE IF EXISTS section_stats",
    "DROP TABLE IF EXISTS normalized_records",
    "CREATE TABLE run_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE section_stats (section_name TEXT PRIMARY KEY, item_count INTEGER NOT NULL, source_path TEXT NOT NULL)",
    """
    CREATE TABLE normalized_records (
        run_id TEXT NOT NULL,
        tenant_name TEXT NOT NULL,
        section_name TEXT NOT NULL,
        record_index INTEGER NOT NULL,
        record_key TEXT NOT NULL,
        display_name TEXT NOT NULL,
        source_name TEXT NOT NULL,
        collector TEXT NOT NULL,
        severity TEXT NOT NULL,
        record_json TEXT NOT NULL,
        source_path TEXT NOT NULL,
        PRIMARY KEY (section_name, record_index)
    )
    """,
)
_INDEXES = (
    "CREATE INDEX idx_normalized_records_key ON normalized_records(record_key)",
    "CREATE INDEX idx_normalized_records_collector ON normalized_records(collector)",
    "CREATE INDEX idx_normalized_records_section ON normalized_records(section_name)",
)


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return fallback


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _record_key(record: Mapping[str, Any], section_name: str, index: int) -> str:
    for key in ("key", "id", "display_name", "name", "collector", "surface"):
        value = record.get(key)
        if value is not None and str(value).strip():
            return f"{section_name}:{value}" if key != "key" else str(value)
    return f"{section_name}:{index}"


def _normalized_payloads(run_path: Path) -> Iterable[tuple[str, Path, list[dict[str, Any]]]]:
    normalized_dir = run_path / "normalized"
    if not normalized_dir.is_dir():
        return []

    rows: list[tuple[str, Path, list[dict[str, Any]]]] = []
    for path in sorted(normalized_dir.glob("*.json"), key=lambda item: item.name):
        payload = _read_json(path, {})
        if not isinstance(payload, Mapping):
            continue
        section_name = str(payload.get("kind") or path.stem)
        records = payload.get("records")
        clean_records = [dict(item) for item in records if isinstance(item, Mapping)] if isinstance(records, list) else []
        rows.append((section_name, path, clean_records))
    return rows


def _create_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def _create_indexes(conn: sqlite3.Connection) -> None:
    for statement in _INDEXES:
        conn.execute(statement)


def _insert_meta(conn: sqlite3.Connection, run_path: Path, manifest: Mapping[str, Any], summary: Mapping[str, Any]) -> None:
    rows = {"run_dir": str(run_path), "summary": _scalar(summary)}
    rows.update({str(key): _scalar(value) for key, value in manifest.items()})
    conn.executemany("INSERT INTO run_meta (key, value) VALUES (?, ?)", sorted(rows.items()))


def _insert_records(
    conn: sqlite3.Connection,
    run_path: Path,
    section_name: str,
    source_path: Path,
    records: list[dict[str, Any]],
    *,
    run_id: str,
    tenant_name: str,
) -> None:
    relative_source = _relative(source_path, run_path)
    conn.execute(
        "INSERT INTO section_stats (section_name, item_count, source_path) VALUES (?, ?, ?)",
        (section_name, len(records), relative_source),
    )
    insert_rows = [
        (
            run_id,
            tenant_name,
            section_name,
            index,
            _record_key(record, section_name, index),
            _scalar(record.get("display_name") or record.get("name")),
            _scalar(record.get("source_name")),
            _scalar(record.get("collector")),
            _scalar(record.get("severity")),
            json.dumps(record, sort_keys=True, ensure_ascii=False, default=str),
            relative_source,
        )
        for index, record in enumerate(records)
    ]
    conn.executemany(
        """
        INSERT INTO normalized_records (
            run_id, tenant_name, section_name, record_index, record_key,
            display_name, source_name, collector, severity, record_json, source_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        insert_rows,
    )


def build_run_evidence_index(run_dir: str | Path, db_path: str | Path | None = None) -> Path:
    run_path = Path(run_dir)
    target = Path(db_path) if db_path is not None else run_path / "index" / "evidence.sqlite"
    target.parent.mkdir(parents=True, exist_ok=True)

    # Hard-reset the file (and any WAL/SHM/journal sidecars) before rebuilding.
    # The DROP TABLE IF EXISTS chain in _SCHEMA only knows about the canonical
    # tables, so a renamed or added table from a newer/older auditex release
    # — or a foreign DB planted by a third-party inspection tool — would leak
    # into the rebuilt DB and break the contract that index/evidence.sqlite
    # contains exactly the canonical tables and indexes.
    for suffix in ("", "-wal", "-shm", "-journal"):
        sidecar = target.with_name(target.name + suffix)
        sidecar.unlink(missing_ok=True)

    manifest = _read_json(run_path / "run-manifest.json", {})
    summary = _read_json(run_path / "summary.json", {})
    manifest = manifest if isinstance(manifest, Mapping) else {}
    summary = summary if isinstance(summary, Mapping) else {}

    with sqlite3.connect(target) as conn:
        for pragma in sqlite_bulk_pragmas():
            conn.execute(pragma)
        _create_schema(conn)
        _insert_meta(conn, run_path, manifest, summary)
        run_id = _scalar(manifest.get("run_id"))
        tenant_name = _scalar(manifest.get("tenant_name"))
        for section_name, path, records in _normalized_payloads(run_path):
            _insert_records(conn, run_path, section_name, path, records, run_id=run_id, tenant_name=tenant_name)
        _create_indexes(conn)
        conn.commit()

    return target


def load_run_index_summary(run_dir: str | Path) -> dict[str, Any]:
    db_path = Path(run_dir) / "index" / "evidence.sqlite"
    if not db_path.exists():
        return {}

    try:
        with sqlite3.connect(db_path) as conn:
            meta = dict(conn.execute("SELECT key, value FROM run_meta").fetchall())
            stats = [
                {"name": row[0], "item_count": row[1], "source_path": row[2]}
                for row in conn.execute(
                    "SELECT section_name, item_count, source_path FROM section_stats ORDER BY section_name"
                ).fetchall()
            ]
    except sqlite3.DatabaseError:
        return {}

    return {
        "run_id": meta.get("run_id"),
        "tenant_name": meta.get("tenant_name"),
        "tenant_id": meta.get("tenant_id"),
        **decode_identity_metadata(meta),
        "created_utc": meta.get("created_utc"),
        "overall_status": meta.get("overall_status"),
        "auditor_profile": meta.get("auditor_profile"),
        "section_stats": stats,
        "item_count": sum(int(row["item_count"]) for row in stats),
    }
