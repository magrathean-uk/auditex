"""What an offline replay can say about a sample's collectors.

A live run records, per list, whether the read failed or the list was cut short, and a collector that
did either is ``partial``. A sample that was captured from such a run carries the same markers on its
sections (``error``, ``error_class``, ``collection_truncated``), so replaying it has to carry them to the
collector status and to coverage rows. Otherwise the replay reads every collector as complete and a rule
that depends on a blocked or cut list reads ``pass`` in a bundle that validates. A section with no marker
needs no row: a clean sample stays ``ok`` exactly as before.

A replay also records what it was replayed from (``replay_source`` in ``run-manifest.json``: the sample's file
name and SHA-256), so that a report can say "replayed from <file>, no tenant contact" instead of presenting
the replay's flags as something observed on a tenant.

Nothing here reads a tenant. The helper is shared by the Microsoft 365 and Google Workspace replays.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .collection_gaps import REASON_OPERATOR_LIMIT, REASON_UNKNOWN, TRUNCATION_ERROR_CLASS, section_was_cut

OFFLINE_ROW_TYPE = "offline_sample"


def replay_source(sample_path: str | Path) -> dict[str, Any]:
    """What a replay was run from: the sample's file name (never its directory) and the SHA-256 of its bytes."""
    path = Path(sample_path)
    try:
        digest: str | None = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        digest = None
    return {"file": path.name, "sha256": digest}


def _row_count(section: Mapping[str, Any]) -> int:
    count = section.get("item_count")
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        return count
    value = section.get("value")
    return len(value) if isinstance(value, list) else 0


def _positive_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def replay_coverage_rows(collector: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Coverage rows for the sections of one replayed collector that carry an error or a cut-list marker."""
    rows: list[dict[str, Any]] = []
    for name, section in sorted(payload.items()):
        if not isinstance(section, Mapping):
            continue
        error = section.get("error")
        error_class = section.get("error_class")
        failed = bool(error or error_class)
        cut = section_was_cut(section)
        if not failed and not cut:
            continue
        limit = _positive_int(section.get("result_limit"))
        row: dict[str, Any] = {
            "collector": collector,
            "type": OFFLINE_ROW_TYPE,
            "name": str(name),
            "status": "failed" if failed else "partial",
            "item_count": _row_count(section),
            "result_limit": limit,
            "collection_truncated": bool(cut),
            "error_class": str(error_class or "unknown") if failed else TRUNCATION_ERROR_CLASS,
            "error": str(error or error_class) if failed else None,
            "message": "Replayed from an offline sample that recorded this read as failed or cut short.",
        }
        if cut:
            reason = str(section.get("truncation_reason") or (REASON_OPERATOR_LIMIT if limit else REASON_UNKNOWN))
            row["truncation_reason"] = reason
            if not failed:
                row["error"] = (
                    f"{name}: the offline sample records this list as cut short after {row['item_count']} rows; "
                    "the list is incomplete."
                )
        rows.append(row)
    return rows


def replay_collector_status(coverage_rows: list[dict[str, Any]]) -> str:
    """``ok`` for a collector whose sections carry no marker, else ``partial``."""
    return "partial" if coverage_rows else "ok"
