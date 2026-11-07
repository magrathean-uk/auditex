from __future__ import annotations

import json
import os
import plistlib
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import ExitStack, closing, contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .bundle_integrity import evidence_index_is_hashed, evidence_sidecars
from .guarded_io import current_context, guarded_operation
from .perf_runtime import sqlite_bulk_pragmas
from .run_files import UnsafeRunFileError, open_run_file
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
        from .run_files import read_run_file
        return json.loads(read_run_file(path.parent, path.name).decode("utf-8"))
    except UnsafeRunFileError:
        raise
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
            _scalar((record.get("name") or record.get("id"))
                    if section_name == "power_platform_environment_objects"
                    else (record.get("display_name") or record.get("name"))),
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


@guarded_operation
def build_run_evidence_index(run_dir: str | Path, db_path: str | Path | None = None) -> Path:
    run_path = Path(run_dir)
    if os.path.lexists(run_path / "run-manifest.json") or os.path.lexists(run_path / "operator-inputs"):
        current_context().bind_run(run_path)
    target = Path(db_path) if db_path is not None else run_path / "index" / "evidence.sqlite"
    from .private_io import make_private_dirs, _write_all
    make_private_dirs(target.parent)

    # Construct a fresh database so tables from an older, newer or foreign
    # index cannot survive the rebuild.
    from .guarded_io import guard_session, open_private_output, remove_guarded_output
    manifest = _read_json(run_path / "run-manifest.json", {})
    summary = _read_json(run_path / "summary.json", {})
    manifest = manifest if isinstance(manifest, Mapping) else {}
    summary = summary if isinstance(summary, Mapping) else {}

    # SQLite writes only inside a protected snapshot directory. Publish the
    # completed database through an admitted destination descriptor.
    from .guarded_io import open_guarded_file
    failed = False
    try:
        temporary_root = Path(os.environ.get("TMPDIR") or tempfile.gettempdir()).resolve()
        if not _encrypted_internal_storage(temporary_root):
            raise UnsafeRunFileError("evidence index")
        with tempfile.TemporaryDirectory(prefix="auditex-index-build-", dir=temporary_root) as directory:
            os.chmod(directory, 0o700)
            snapshot = Path(directory) / "evidence.sqlite"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(snapshot, flags, 0o600)
            os.close(descriptor)
            with closing(sqlite3.connect(snapshot)) as conn:
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
            with guard_session() as context, open_guarded_file(snapshot, field="index", context=context) as source:
                with open_private_output(target, field="index", context=context, append=True) as destination:
                    for suffix in ("-wal", "-shm", "-journal"):
                        remove_guarded_output(target.with_name(target.name + suffix))
                    os.ftruncate(destination, 0)
                    while data := os.read(source, 1024 * 1024):
                        _write_all(destination, data)
    except (OSError, sqlite3.DatabaseError, ValueError):
        failed = True
    if failed:
        raise UnsafeRunFileError("evidence index") from None

    return target


def _read_only_uri(db_path: str | Path, *, immutable: bool) -> str:
    return f"file:{quote(str(Path(db_path).absolute()), safe='/')}?mode=ro" + ("&immutable=1" if immutable else "")


def open_index_read_only(db_path: str | Path, *, immutable: bool = True) -> sqlite3.Connection:
    """Open an evidence index without being able to change it.

    ``immutable`` (the default) makes SQLite read the main file as it is: it takes no lock, writes nothing,
    never creates ``-wal`` or ``-shm`` (so an index on read-only media opens) and ignores a ``-wal`` file
    that sits beside it. A plain connection to a WAL-mode index replays such a file over the main file and,
    when it closes, checkpoints it into the main file. Pass ``immutable=False`` only for a legacy index
    whose data may still sit in its ``-wal`` file.
    """
    return sqlite3.connect(_read_only_uri(db_path, immutable=immutable), uri=True)


class _MissingIndex(Exception):
    pass


@contextmanager
def open_private_run_index(run_dir: str | Path, *, include_sidecars: bool):
    """Inspect only a private, coherent snapshot of admitted index descriptors."""
    root = Path(run_dir)
    relative = "index/evidence.sqlite"
    suffixes = ("", "-wal", "-shm", "-journal")
    failed = False
    missing = False
    with ExitStack() as stack:
        try:
            sources: dict[str, tuple[int, tuple[int, int, int, int, int]]] = {}
            absent: list[str] = []
            for suffix in suffixes:
                try:
                    descriptor = stack.enter_context(open_run_file(root, relative + suffix, max_bytes=None))
                except FileNotFoundError:
                    if not suffix:
                        raise _MissingIndex
                    absent.append(suffix)
                    continue
                if suffix and not include_sidecars:
                    raise UnsafeRunFileError("evidence index")
                sources[suffix] = (descriptor, _file_state(os.fstat(descriptor)))
            temporary_root = Path(os.environ.get("TMPDIR") or tempfile.gettempdir()).resolve()
            if not _encrypted_internal_storage(temporary_root):
                raise UnsafeRunFileError("evidence index")
            if include_sidecars and temporary_root.is_relative_to(root.resolve().parent):
                raise UnsafeRunFileError("evidence index")
            temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="auditex-index-", dir=temporary_root)))
            os.chmod(temporary, 0o700)
            copied = temporary / "evidence.sqlite"
            for suffix, (descriptor, _) in sources.items():
                _copy_index_descriptor(descriptor, copied.with_name(copied.name + suffix))
            for descriptor, before in sources.values():
                if _file_state(os.fstat(descriptor)) != before:
                    raise UnsafeRunFileError("evidence index")
            for suffix in absent:
                try:
                    with open_run_file(root, relative + suffix, max_bytes=None):
                        raise UnsafeRunFileError("evidence index")
                except FileNotFoundError:
                    pass
        except _MissingIndex:
            missing = True
        except (OSError, RuntimeError, ValueError):
            failed = True
        if missing:
            raise FileNotFoundError("Evidence index is absent.") from None
        if failed:
            raise UnsafeRunFileError("evidence index") from None
        with closing(open_index_read_only(copied, immutable=not include_sidecars)) as conn:
            yield conn


def _file_state(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _copy_index_descriptor(descriptor: int, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    output = os.open(destination, flags, 0o600)
    try:
        os.fchmod(output, 0o600)
        while data := os.read(descriptor, 1024 * 1024):
            view = memoryview(data)
            while view:
                count = os.write(output, view)
                if count <= 0:
                    raise OSError("short write")
                view = view[count:]
    finally:
        os.close(output)


def _encrypted_internal_storage(path: Path) -> bool:
    """Prove the temporary directory is on an encrypted internal macOS data volume."""
    if sys.platform != "darwin":
        return False
    try:
        data_volume = Path("/System/Volumes/Data")
        if os.stat(path).st_dev != os.stat(data_volume).st_dev:
            return False
        info = plistlib.loads(subprocess.run(
            ["/usr/sbin/diskutil", "info", "-plist", str(data_volume)], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        ).stdout)
        if info.get("Internal") is not True or not isinstance(info.get("DeviceIdentifier"), str):
            return False
        volume_id = info["DeviceIdentifier"]
        apfs = plistlib.loads(subprocess.run(
            ["/usr/sbin/diskutil", "apfs", "list", "-plist"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        ).stdout)
        return any(volume.get("DeviceIdentifier") == volume_id and volume.get("Encryption") is True
                   for container in apfs.get("Containers", []) for volume in container.get("Volumes", []))
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


def load_run_index_summary(run_dir: str | Path) -> dict[str, Any]:
    """The run metadata held in ``index/evidence.sqlite``, or ``{}`` when it cannot be trusted or read.

    Indices use a private temporary copy. When ``bundle-hashes.json`` lists the
    index, a sidecar beside it makes this return ``{}``: the sidecar is not
    covered by the hash, so whatever it holds was not part of the run as finalized, and callers fall back to
    the manifest. Only an index no hash manifest covers (a bundle from before it existed) is read together
    with a sidecar, because its data may still sit there.
    """
    sidecars = evidence_sidecars(run_dir)
    if sidecars and evidence_index_is_hashed(run_dir):
        return {}

    def inspect(conn: sqlite3.Connection) -> tuple[dict[str, str], list[dict[str, Any]]]:
        meta = dict(conn.execute("SELECT key, value FROM run_meta").fetchall())
        stats = [
            {"name": row[0], "item_count": row[1], "source_path": row[2]}
            for row in conn.execute(
                "SELECT section_name, item_count, source_path FROM section_stats ORDER BY section_name"
            ).fetchall()
        ]
        return meta, stats

    try:
        with open_private_run_index(run_dir, include_sidecars=bool(sidecars)) as conn:
            meta, stats = inspect(conn)
    except UnsafeRunFileError:
        raise
    except (OSError, sqlite3.DatabaseError):
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
