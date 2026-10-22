"""Per-object Graph reads shared by the Intune collectors: policy assignments and Defender state.

Two reads need one request per object: the assignments of a policy and the ``windowsProtectionState`` of a
managed device. Both read the object ids from a list the collector already read (from its chunk files when
the list was streamed to disk), expand at most ``limit`` of them, and say plainly when they stopped short:

* the section carries ``collection_truncated`` and a ``fanout`` summary, so normalization treats the
  evidence as a limited read and never as a complete one, and lists the cut under ``collection_gaps``;
* the coverage rows (a ``<name>`` row for the reads and a derived ``<name>Fanout`` row for the cut) are marked
  ``section_scoped``: the gap belongs to this section alone. The collector's own status comes from its base
  reads (:func:`collector_partial`), so a cut Defender read or one failed assignment read does not make every
  rule of the collector ``not_assessed``. The rules that read the section report the gap themselves
  (``defender_state_truncated``, ``policy_assignments_not_read_for_every_policy``) and never pass on it.

Every request is a GET; v1.0 reads go through ``$batch`` (GET-only inner requests) when the client has it.
Beta endpoints are read one at a time because ``$batch`` here targets v1.0.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..chunk_reader import iter_endpoint_records
from ..collection_gaps import REASON_FANOUT_LIMIT, REASON_INPUT_LIMITED, TRUNCATION_ERROR_CLASS, section_was_cut
from ..endpoint_posture import PROTECTION_FIELDS, READ_FAILED, READ_NOT_REPORTED, READ_OK, project
from ..graph import GraphError, graph_url
from .base import _classify_graph_error

# Policies and profiles are few; the windows devices of a small tenant fit in one go. Beyond these bounds the
# collector records a fan-out gap instead of reading on without limit.
ASSIGNMENT_FANOUT_LIMIT = 100
DEFENDER_FANOUT_LIMIT = 100

STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_FAILED = "failed"
SECTION_SCOPED = "section_scoped"


def mark_section_scoped(rows: Sequence[dict[str, Any]]) -> None:
    """Mark coverage rows whose gap is confined to their own section."""
    for row in rows:
        row[SECTION_SCOPED] = True


def collector_partial(coverage: Sequence[Mapping[str, Any]]) -> bool:
    """Whether a base read of the collector failed or was cut: section-scoped rows are left out."""
    return any(row.get("status") != "ok" for row in coverage if not row.get(SECTION_SCOPED))


def scoped_gap_message(label: str, coverage: Sequence[Mapping[str, Any]]) -> str:
    """The collector message when only section-scoped reads are incomplete (empty when none is)."""
    names = sorted({str(row.get("name")) for row in coverage if row.get(SECTION_SCOPED) and row.get("status") != "ok"})
    return f"{label} read in full; incomplete section-scoped reads (see coverage): {', '.join(names)}" if names else ""


@dataclass
class ObjectRead:
    """The outcome of one GET: ``status`` is ``ok``, ``not_found`` (HTTP 404) or ``failed``."""

    status: str
    body: Any = None
    rows: list[dict[str, Any]] | None = None
    error_class: str | None = None
    error: str | None = None


def _failure(status: Any, message: Any, error_code: Any, request: str) -> ObjectRead:
    exc = GraphError(
        str(message or "Graph request failed."),
        status=status if isinstance(status, int) else None,
        request=request,
        error_code=error_code if isinstance(error_code, str) else None,
    )
    error_class, error = _classify_graph_error(exc)
    return ObjectRead(STATUS_NOT_FOUND if status == 404 else STATUS_FAILED, error_class=error_class, error=error)


def _from_batch(result: Any, endpoint: str, *, rows: bool) -> ObjectRead:
    status = result.get("status") if isinstance(result, dict) else None
    body = result.get("body") if isinstance(result, dict) else None
    if status == 200 and isinstance(body, dict):
        return ObjectRead(STATUS_OK, body=body, rows=[row for row in body.get("value", []) if isinstance(row, dict)] if rows else None)
    error_code = result.get("error_code") if isinstance(result, dict) else None
    message = result.get("error") if isinstance(result, dict) else None
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            error_code = error_code or error.get("code")
            message = message or error.get("message")
        elif isinstance(error, str):
            message = message or error
    return _failure(status, message, error_code, endpoint)


def _read_one(client: Any, endpoint: str, *, api_version: str, rows: bool) -> ObjectRead:
    try:
        if rows:
            target = graph_url(endpoint, api_version) if api_version != "v1.0" else endpoint
            values = client.get_all(target, params={"$top": "50"})
            return ObjectRead(STATUS_OK, rows=[row for row in values if isinstance(row, dict)] if isinstance(values, list) else [])
        if api_version != "v1.0":
            return ObjectRead(STATUS_OK, body=client.get_json(graph_url(endpoint, api_version), full_url=True))
        return ObjectRead(STATUS_OK, body=client.get_json(endpoint))
    except Exception as exc:  # noqa: BLE001
        error_class, error = _classify_graph_error(exc)
        return ObjectRead(STATUS_NOT_FOUND if getattr(exc, "status", None) == 404 else STATUS_FAILED, error_class=error_class, error=error)


def read_endpoints(client: Any, endpoints: Sequence[str], *, rows: bool, api_version: str = "v1.0") -> list[ObjectRead]:
    """GET every endpoint in order. ``rows`` reads a collection (following a next-page link); otherwise one object."""
    if not endpoints:
        return []
    results: list[ObjectRead] | None = None
    if api_version == "v1.0" and hasattr(client, "get_batch"):
        try:
            batch = client.get_batch([{"path": endpoint, "params": {"$top": "50"} if rows else {}} for endpoint in endpoints])
        except Exception:  # noqa: BLE001
            batch = None
        if isinstance(batch, list) and len(batch) == len(endpoints):
            results = [_from_batch(item, endpoint, rows=rows) for item, endpoint in zip(batch, endpoints)]
            if rows:
                for result in results:
                    link = result.body.get("@odata.nextLink") if isinstance(result.body, dict) else None
                    if result.status == STATUS_OK and isinstance(link, str) and link and hasattr(client, "iter_items"):
                        try:
                            result.rows = (result.rows or []) + [row for row in client.iter_items(link) if isinstance(row, dict)]
                        except Exception as exc:  # noqa: BLE001
                            result.status = STATUS_FAILED
                            result.error_class, result.error = _classify_graph_error(exc)
    if results is None:
        results = [_read_one(client, endpoint, api_version=api_version, rows=rows) for endpoint in endpoints]
    return results


def input_rows(source: Any, run_dir: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool, bool]:
    """``(rows, issues, failed, cut)`` of a list the collector already read, chunk files included."""
    section = source if isinstance(source, Mapping) else {}
    issues: list[dict[str, Any]] = []
    rows = list(iter_endpoint_records(section, run_dir, issues=issues)) if section else []
    return rows, issues, (not section) or bool(section.get("error")), section_was_cut(section)


def _fanout_summary(
    *, scope: str, limit: int, input_count: int, selected: int, expanded: int, issues: list, failed_input: bool, cut: bool, failed_reads: int
) -> dict[str, Any]:
    omitted = max(selected - expanded, 0)
    limited = bool(omitted or cut)
    incomplete = bool(issues or failed_input or failed_reads)
    return {
        "fanout_scope": scope,
        "fanout_limit": limit,
        "input_record_count": input_count,
        "input_complete": not (issues or failed_input or cut),
        "input_unreadable": bool(issues or failed_input),
        "input_issues": issues,
        "input_collection_limited": cut,
        "fanout_total": selected,
        "fanout_target_count": expanded,
        "fanout_omitted_count": omitted,
        "failed_operation_count": failed_reads,
        "collection_truncated": limited,
        "fanout_complete": not (limited or incomplete),
        # A normalization gap record is written for this section itself: no coverage row restates it.
        "scoped_gap": True,
    }


def _derived_row(collector: str, name: str, summary: dict[str, Any], *, omitted: int) -> dict[str, Any]:
    limited = summary["collection_truncated"]
    incomplete = bool(summary["input_unreadable"] or summary["failed_operation_count"])
    # ``collection_truncated`` stays off the row: a row that flags it makes the run ``partial`` and must be named
    # in the manifest's coverage gaps, which would make the whole collector incomplete. The section carries it.
    fields = {key: value for key, value in summary.items() if key != "collection_truncated"}
    return {
        SECTION_SCOPED: True,
        "collector": collector,
        "type": "derived",
        "name": f"{name}Fanout",
        "status": "partial" if limited or incomplete else "ok",
        "item_count": 0,
        "rows_collected": summary["fanout_target_count"],
        "error_class": "incomplete_evidence" if incomplete else TRUNCATION_ERROR_CLASS if limited else None,
        "error": (
            f"{name}: some inputs or per-object reads failed."
            if incomplete
            else f"{name}: only {summary['fanout_target_count']} objects were expanded (limit {summary['fanout_limit']}); the rest were not read."
            if limited
            else None
        ),
        "truncation_reason": (REASON_FANOUT_LIMIT if omitted else REASON_INPUT_LIMITED) if limited else None,
        **fields,
    }


def _aggregate_row(
    collector: str,
    name: str,
    endpoint: str,
    api_version: str,
    results: Sequence[ObjectRead],
    started: float,
    *,
    item_count: int,
    failures: Sequence[ObjectRead],
) -> dict[str, Any]:
    status = STATUS_OK
    if failures:
        status = "failed" if len(failures) == len(results) else "partial"
    first = failures[0] if failures else None
    return {
        SECTION_SCOPED: True,
        "collector": collector,
        "type": "graph",
        "name": name,
        "endpoint": endpoint,
        "api_version": api_version,
        "status": status,
        "item_count": item_count,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "error_class": first.error_class if first else None,
        "error": first.error if first else None,
    }


def assignment_fanout(
    *,
    collector: str,
    client: Any,
    name: str,
    source: Any,
    run_dir: Any,
    endpoint_for: Callable[[str], str],
    endpoint_template: str,
    scope: str,
    api_version: str = "v1.0",
    rows_filter: Callable[[dict[str, Any]], bool] | None = None,
    limit: int = ASSIGNMENT_FANOUT_LIMIT,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read ``.../assignments`` for each selected row of ``source``; return the section and its coverage rows."""
    started = time.perf_counter()
    rows, issues, failed_input, cut = input_rows(source, run_dir)
    selected = [row for row in rows if isinstance(row.get("id"), str) and row["id"] and (rows_filter is None or rows_filter(row))]
    targets = [] if (issues or failed_input) else selected[:limit]
    results = read_endpoints(client, [endpoint_for(str(row["id"])) for row in targets], rows=True, api_version=api_version)
    values: list[dict[str, Any]] = []
    failures: list[ObjectRead] = []
    total = 0
    for row, result in zip(targets, results):
        if result.status == STATUS_OK and result.rows is not None:
            values.append({"policyId": row["id"], "displayName": row.get("displayName"), "assignments": result.rows})
            total += len(result.rows)
        else:
            failures.append(result)
    summary = _fanout_summary(
        scope=scope, limit=limit, input_count=len(selected), selected=len(selected), expanded=len(targets),
        issues=issues, failed_input=failed_input, cut=cut, failed_reads=len(failures),
    )
    omitted = summary["fanout_omitted_count"]
    if failed_input or issues:
        # An unreadable input list must not look like "nothing is assigned".
        section: dict[str, Any] = {"error": f"{scope}: the list to expand could not be read in full.", "error_class": "incomplete_evidence"}
    else:
        section = {"value": values, "fanout": summary, "collection_truncated": summary["collection_truncated"]}
        if summary["collection_truncated"]:
            section["truncation_reason"] = REASON_FANOUT_LIMIT if omitted else REASON_INPUT_LIMITED
    coverage = []
    if targets:
        coverage.append(_aggregate_row(collector, name, endpoint_template, api_version, results, started, item_count=total, failures=failures))
    coverage.append(_derived_row(collector, name, summary, omitted=omitted))
    return section, coverage


def protection_state_fanout(
    *,
    collector: str,
    client: Any,
    name: str,
    source: Any,
    run_dir: Any,
    endpoint_template: str,
    windows_only: Callable[[dict[str, Any]], bool],
    limit: int = DEFENDER_FANOUT_LIMIT,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read ``windowsProtectionState`` for the Windows managed devices in ``source``.

    A device Intune has no state for (HTTP 404) is recorded as ``not_reported``, not as a failed read: it is
    a fact about the device. Any other error is ``failed``. Only a fixed list of state fields is kept.
    """
    started = time.perf_counter()
    rows, issues, failed_input, cut = input_rows(source, run_dir)
    selected = [row for row in rows if isinstance(row.get("id"), str) and row["id"] and windows_only(row)]
    if failed_input or issues:
        # The device list itself is unreadable, so an empty result here would read as "no Windows devices".
        return (
            {"error": "The managed device list could not be read in full, so Defender state was not requested.", "error_class": "incomplete_evidence"},
            [],
        )
    targets = selected[:limit]
    results = read_endpoints(
        client, [f"/deviceManagement/managedDevices/{row['id']}/windowsProtectionState" for row in targets], rows=False
    )
    values: list[dict[str, Any]] = []
    failures: list[ObjectRead] = []
    ok = 0
    for row, result in zip(targets, results):
        base = {"deviceId": row["id"], "deviceName": row.get("deviceName")}
        if result.status == STATUS_OK and isinstance(result.body, Mapping):
            values.append({**base, "read_status": READ_OK, **project(result.body, PROTECTION_FIELDS)})
            ok += 1
        elif result.status == STATUS_NOT_FOUND:
            values.append({**base, "read_status": READ_NOT_REPORTED, "error_class": result.error_class})
        else:
            values.append({**base, "read_status": READ_FAILED, "error_class": result.error_class})
            failures.append(result)
    summary = _fanout_summary(
        scope="windows_managed_devices", limit=limit, input_count=len(selected), selected=len(selected), expanded=len(targets),
        issues=issues, failed_input=failed_input, cut=cut, failed_reads=len(failures),
    )
    section: dict[str, Any] = {"value": values, "fanout": summary, "collection_truncated": summary["collection_truncated"]}
    omitted = summary["fanout_omitted_count"]
    if summary["collection_truncated"]:
        section["truncation_reason"] = REASON_FANOUT_LIMIT if omitted else REASON_INPUT_LIMITED
    coverage = []
    if targets:
        coverage.append(_aggregate_row(collector, name, endpoint_template, "v1.0", results, started, item_count=ok, failures=failures))
    coverage.append(_derived_row(collector, name, summary, omitted=omitted))
    return section, coverage
