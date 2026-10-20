"""Lists that were cut short are coverage gaps, never silent passes.

A collector that stops before the last row of a list (an explicit ``--top`` limit, a failed
page, a refused next-page link) records the cut on that list's coverage row. The row is
``partial``, so the collector is not complete and baseline rules that read the list report
``not_assessed`` instead of ``pass``. The same facts reach the normalized ``collection_gaps``
records and the ``truncated_lists`` of the manifest's ``coverage_gaps``.

Without ``--top`` every list is paged to its last row, so a cut only happens when an
operator asks for one or a page cannot be read.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

# Error class of the coverage row for a list cut at the operator's row limit.
TRUNCATION_ERROR_CLASS = "collection_limit"

# Why a list stopped before its last row. These strings are part of the output contract.
REASON_OPERATOR_LIMIT = "operator_limit"
REASON_PAGINATION_FAILED = "pagination_failed"
REASON_NEXT_LINK_REFUSED = "next_link_refused"
# A collector bounds how many objects it expands (members, owners, relationships); it hit that bound.
REASON_FANOUT_LIMIT = "fanout_limit"
# A derived result was built from a list that was itself cut short.
REASON_INPUT_LIMITED = "input_limited"
REASON_UNKNOWN = "unknown"
TRUNCATION_REASONS = (
    REASON_OPERATOR_LIMIT,
    REASON_PAGINATION_FAILED,
    REASON_NEXT_LINK_REFUSED,
    REASON_FANOUT_LIMIT,
    REASON_INPUT_LIMITED,
    REASON_UNKNOWN,
)

COLLECTION_GAP_SECTION = "collection_gaps"

_SAMPLE_ONLY: ContextVar[bool] = ContextVar("auditex_sample_only", default=False)


@contextmanager
def sample_only() -> Iterator[None]:
    """Mark row limits as an intentional sample while capability probes and preflights run.

    A probe asks whether a list can be read, not whether it is complete, so a limit hit inside
    this block is not a coverage gap.
    """
    token = _SAMPLE_ONLY.set(True)
    try:
        yield
    finally:
        _SAMPLE_ONLY.reset(token)


def sampling() -> bool:
    return _SAMPLE_ONLY.get()


def truncation_message(list_name: str, rows: int, reason: str, limit: int | None) -> str:
    if reason == REASON_OPERATOR_LIMIT:
        suffix = f" ({limit})" if limit else ""
        return (
            f"{list_name}: collection stopped at {rows} rows because of the operator row limit{suffix}; "
            "the list is incomplete."
        )
    if reason == REASON_NEXT_LINK_REFUSED:
        return f"{list_name}: paging stopped after {rows} rows because the next-page link was refused; the list is incomplete."
    if reason == REASON_PAGINATION_FAILED:
        return f"{list_name}: paging stopped after {rows} rows because a later page could not be read; the list is incomplete."
    return f"{list_name}: collection stopped after {rows} rows; the list is incomplete."


# Per-object reads (site permissions, policy assignments, team channels, service principal links)
# expand only this many objects; the rest are a fan-out gap, not a sample the run may call complete.
FANOUT_OBJECT_LIMIT = 10


def fanout_gap_row(
    collector: str,
    name: str,
    *,
    total: int,
    expanded: int,
    limit: int = FANOUT_OBJECT_LIMIT,
    scope: str,
) -> dict[str, Any]:
    """A derived coverage row for a per-object fan-out that expanded only the first ``limit`` objects."""
    return {
        "collector": collector,
        "type": "derived",
        "name": name,
        "status": "partial",
        "item_count": 0,
        "rows_collected": expanded,
        "error_class": TRUNCATION_ERROR_CLASS,
        "error": f"{scope}: only the first {expanded} of {total} were expanded (fan-out limit {limit}); the rest were not read.",
        "collection_truncated": True,
        "truncation_reason": REASON_FANOUT_LIMIT,
        "fanout_limit": limit,
        "fanout_total": total,
    }


def section_was_cut(section: Any) -> bool:
    """Whether a raw section's list was cut short.

    ``collection_truncated`` is exact: the collector knew whether the list continued. Sections
    that only say a limit was reached (older bundles) may have ended exactly there, and still count.
    """
    if not isinstance(section, Mapping):
        return False
    truncated = section.get("collection_truncated")
    if isinstance(truncated, bool):
        return truncated
    return bool(section.get("collection_limit_reached"))


def latest_coverage(rows: Iterable[Any]) -> list[dict[str, Any]]:
    """A resumed endpoint replaces its earlier observation."""
    latest: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, Mapping):
            key = (
                str(row.get("collector") or ""),
                str(row.get("name") or ""),
                str(row.get("endpoint") or row.get("command") or ""),
            )
            latest[key] = dict(row)
    return list(latest.values())


def _row_count(row: Mapping[str, Any]) -> int:
    # A derived fan-out row has no rows of its own; it states how many objects were expanded.
    for key in ("rows_collected", "item_count"):
        count = row.get(key)
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
            return count
    return 0


def _limit(row: Mapping[str, Any]) -> int | None:
    limit = row.get("result_limit")
    return limit if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0 else None


def list_truncations(coverage_rows: Iterable[Any], *, require_reason: bool = False) -> list[dict[str, Any]]:
    """One record per list that was cut short: the list, the rows collected and the reason.

    ``require_reason`` keeps only rows that name why they were cut. Bundles from before gaps were
    recorded flagged ``collection_truncated`` on an ``ok`` row with no reason; they stay valid.
    """
    records: list[dict[str, Any]] = []
    for row in latest_coverage(coverage_rows):
        if row.get("collection_truncated") is not True:
            continue
        if require_reason and not row.get("truncation_reason"):
            continue
        limit = _limit(row)
        reason = str(row.get("truncation_reason") or (REASON_OPERATOR_LIMIT if limit else REASON_UNKNOWN))
        record: dict[str, Any] = {
            "collector": str(row.get("collector") or ""),
            "list": str(row.get("name") or ""),
            "rows_collected": _row_count(row),
            "reason": reason,
        }
        if row.get("endpoint"):
            record["endpoint"] = str(row["endpoint"])
        if limit is not None:
            record["result_limit"] = limit
        records.append(record)
    return sorted(records, key=lambda item: (item["collector"], item["list"], item.get("endpoint", "")))


def truncations_from_payloads(
    collector_payloads: Mapping[str, Any],
    known: Iterable[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """Truncations flagged on raw sections that no coverage row accounted for (offline and resumed runs)."""
    seen = {(item["collector"], item["list"]) for item in known}
    records: list[dict[str, Any]] = []
    for collector, payload in sorted(collector_payloads.items()):
        if not isinstance(payload, Mapping):
            continue
        for name, section in sorted(payload.items()):
            if not isinstance(section, Mapping) or section.get("collection_truncated") is not True:
                continue
            # A fan-out wrapper restates its own coverage row (privilegedGroupFanout and the like).
            if isinstance(section.get("fanout"), Mapping) or (str(collector), str(name)) in seen:
                continue
            value = section.get("value")
            count = section.get("item_count")
            rows = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else (
                len(value) if isinstance(value, list) else 0
            )
            limit = section.get("result_limit")
            record: dict[str, Any] = {
                "collector": str(collector),
                "list": str(name),
                "rows_collected": rows,
                "reason": str(section.get("truncation_reason") or REASON_UNKNOWN),
            }
            if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
                record["result_limit"] = limit
            records.append(record)
    return records


def collection_gap_records(truncations: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalized ``collection_gaps`` records, keyed by ``collector.list``."""
    records: list[dict[str, Any]] = []
    for item in truncations:
        source = f"{item['collector']}.{item['list']}"
        record = {
            "kind": "collection_gap",
            "source": source,
            "id": source,
            "key": f"collection_gap:{source}",
            **{key: value for key, value in item.items() if value not in (None, "")},
        }
        records.append(record)
    return records


def truncation_summary(truncations: Iterable[Mapping[str, Any]]) -> str:
    parts = [
        f"{item['collector']}.{item['list']} ({item['rows_collected']} rows, {item['reason']})"
        for item in truncations
    ]
    return ", ".join(parts)
