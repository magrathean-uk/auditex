"""What an offline replay can say about a sample's collectors.

A live run records, per list, whether the read failed or the list was cut short, and a collector that
did either is ``partial``. A sample that was captured from such a run carries the same markers on its
sections (``error``, ``error_class``, ``collection_truncated``), so replaying it has to carry them to the
collector status and to coverage rows. Otherwise the replay reads every collector as complete and a rule
that depends on a blocked or cut list reads ``pass`` in a bundle that validates. A section with no marker
needs no row: a clean sample stays ``ok`` exactly as before.

A collector that is in the sample but holds nothing (an empty object, ``null``, a list) has no evidence at all, and
used to replay ``ok``: every section its live run records is written as a failed ``section_absent`` row, and a domain
posture record that carries a ``resolver_error`` as a failed ``dns_resolver_error`` row, the same rows a live run
records. The sections of a collector come from ``configs/collector-definitions.json`` (``query_plan``). A collector
that holds any key is not second-guessed section by section (minimal fixtures omit sections on purpose and the plan is
not a schema), and a collector the definitions do not know is left alone.

A replay also records what it was replayed from (``replay_source`` in ``run-manifest.json``: the sample's file
name and SHA-256), so that a report can say "replayed from <file>, no tenant contact" instead of presenting
the replay's flags as something observed on a tenant.

Nothing here reads a tenant. The helper is shared by the Microsoft 365 and Google Workspace replays.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from .collection_gaps import REASON_OPERATOR_LIMIT, REASON_UNKNOWN, TRUNCATION_ERROR_CLASS, section_was_cut
from .resources import resolve_resource_path

OFFLINE_ROW_TYPE = "offline_sample"
SECTION_ABSENT_ERROR_CLASS = "section_absent"
DNS_RESOLVER_ERROR_CLASS = "dns_resolver_error"
_COLLECTOR_DEFINITIONS_PATH = Path("configs/collector-definitions.json")


@lru_cache(maxsize=1)
def _collector_sections() -> dict[str, tuple[str, ...]]:
    """``collector -> sections its live run records``, from the shipped collector definitions."""
    try:
        payload = json.loads(resolve_resource_path(_COLLECTOR_DEFINITIONS_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    collectors = payload.get("collectors") if isinstance(payload, Mapping) else None
    if not isinstance(collectors, Mapping):
        return {}
    return {
        str(name): tuple(str(item) for item in definition.get("query_plan") or [] if str(item))
        for name, definition in collectors.items()
        if isinstance(definition, Mapping)
    }


def planned_sections(collector: str) -> tuple[str, ...]:
    """The sections a Microsoft 365 collector's live run records (empty for a collector the definitions do not know)."""
    return _collector_sections().get(collector, ())


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


def absent_section_rows(collector: str, value: Any, planned: Sequence[str]) -> list[dict[str, Any]]:
    """Failed ``section_absent`` rows for a replayed collector that delivered none of its planned sections.

    ``value`` is what the sample holds under the collector's name. Any mapping with at least one key is a delivery
    (a section that is empty or failed is a section, and the older flat shape holds a collector-level ``value`` list):
    the sections it leaves out are not second-guessed, because minimal fixtures omit sections on purpose and the
    collector definitions are the plan of a live run, not a schema of what a sample may contain. Only a collector that
    holds nothing (``{}``, ``null``, a list, a string) has no evidence at all.
    """
    if not planned:
        return []
    if isinstance(value, Mapping) and value:
        return []
    return [
        {
            "collector": collector,
            "type": OFFLINE_ROW_TYPE,
            "name": str(name),
            "status": "failed",
            "item_count": 0,
            "error_class": SECTION_ABSENT_ERROR_CLASS,
            "error": f"{collector}.{name}: the offline sample carries no such section, so nothing was read.",
            "message": "Replayed from an offline sample that holds none of this collector's sections.",
        }
        for name in planned
    ]


def resolver_error_rows(collector: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Failed rows for domain posture records whose DNS resolver did not answer (a live run writes the same rows)."""
    section = payload.get("domainPosture")
    records = section.get("value") if isinstance(section, Mapping) else None
    rows: list[dict[str, Any]] = []
    for record in records if isinstance(records, list) else []:
        if isinstance(record, Mapping) and record.get("resolver_error"):
            domain = str(record.get("domain") or record.get("id") or "")
            rows.append(
                {
                    "collector": collector,
                    "type": OFFLINE_ROW_TYPE,
                    "name": f"posture:{domain}" if domain else "posture",
                    "status": "failed",
                    "item_count": 1,
                    "error_class": DNS_RESOLVER_ERROR_CLASS,
                    "error": str(record["resolver_error"]),
                    "message": "Replayed from an offline sample whose DNS resolver did not answer for this domain.",
                }
            )
    return rows


def replay_coverage_rows(collector: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Coverage rows for the sections of one replayed collector that carry an error or a cut-list marker.

    A domain posture record with a ``resolver_error`` is a failed read too (see :func:`resolver_error_rows`).
    """
    rows: list[dict[str, Any]] = resolver_error_rows(collector, payload)
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
