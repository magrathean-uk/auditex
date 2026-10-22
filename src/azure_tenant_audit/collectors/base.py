from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

from ..collection_gaps import (
    REASON_NEXT_LINK_REFUSED,
    REASON_OPERATOR_LIMIT,
    REASON_PAGINATION_FAILED,
    REASON_PAGINATION_NOT_FOLLOWED,
    TRUNCATION_ERROR_CLASS,
    sampling,
    truncation_message,
)
from ..perf_runtime import EndpointAccumulator, PageWindow
from ..graph import GraphClient, GraphError, NEXT_LINK_REFUSED, graph_url

if TYPE_CHECKING:
    from ..collector_runner import CollectorRunContext


def _classify_graph_error(exc: Exception) -> tuple[str, str]:
    message = str(exc)
    if isinstance(exc, GraphError):
        if exc.error_code == "PermissionStop":
            return "permission_stop", message
        if exc.error_code == NEXT_LINK_REFUSED:
            return "next_link_refused", message
        status = exc.status
        lower = message.lower()
        if status in {400, 401, 403} and any(
            phrase in lower
            for phrase in (
                "premium license",
                "spo license",
                "not licensed",
                "does not have a license",
                "license is required",
                "needs to have microsoft entra id p2",
                "governance license",
            )
        ):
            return "license_required", message
        if status in {401, 403} and "account is not provisioned" in lower:
            # Defender XDR answers this way when the tenant has no Defender workload provisioned.
            return "service_not_available", message
        if status == 401:
            # Intune answers 401 with ErrorCode "Forbidden" when the token lacks DeviceManagement scopes.
            if '"errorcode":"forbidden"' in lower.replace(" ", ""):
                return "insufficient_permissions", message
            return "unauthenticated", message
        if status == 403:
            return "insufficient_permissions", message
        if status == 404:
            return "resource_not_found", message
        if status == 400:
            if "no reply address is registered" in lower:
                return "app_missing_reply_url", message
            if "minimum page size" in lower:
                return "query_page_minimum", message
            if "unsupported" in lower and "query" in lower:
                return "unsupported_query", message
            return "bad_request", message
        if status and status >= 500:
            return "graph_transient", message
        return f"graph_http_{status}", message
    if "No reply address is registered" in message:
        return "app_missing_reply_url", message
    return "client_error", message


def _normalize_top(
    params: dict[str, Any] | None,
    top: int | None,
    *,
    min_top: int | None = None,
) -> dict[str, Any]:
    query: dict[str, Any] = dict(params) if params else {}
    if top is None:
        return query
    normalized_top = top
    if min_top is not None:
        normalized_top = max(top, min_top)
    query_top = query.get("$top")
    if query_top is None:
        query["$top"] = str(normalized_top)
        return query
    try:
        int(query_top)
    except (TypeError, ValueError):
        query["$top"] = str(normalized_top)
    return query


def normalize_collection_limit(value: Any, *, default: int | None) -> int | None:
    if value is None:
        return default
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return default
    if limit <= 0:
        return None
    return limit


def context_limit(context: Mapping[str, Any], *, default: int | None = None) -> int | None:
    """The operator's row limit from a collector context.

    ``top`` absent means the caller expressed no preference, so ``default`` applies. ``top`` set
    to ``None``, 0 or a negative number means no limit: lists are paged to their last row.
    """
    if "top" not in context:
        return default
    return normalize_collection_limit(context.get("top"), default=None)


def apply_collection_limit(rows: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    return list(rows) if limit is None else rows[:limit]


def limit_rows(rows: list[Any], limit: int | None) -> tuple[list[Any], bool]:
    """Rows cut to ``limit`` and whether any were cut."""
    if limit is None or len(rows) <= limit:
        return list(rows), False
    return rows[:limit], True


def record_truncation(
    row: dict[str, Any],
    *,
    list_name: str,
    rows: int,
    limit: int | None,
    reason: str = REASON_OPERATOR_LIMIT,
) -> None:
    """Mark a coverage row as a list that was cut short, which makes it a coverage gap.

    A limit hit makes the row ``partial`` with the ``collection_limit`` error class. A page that
    failed or was refused keeps the failed status and error the read already carries.
    """
    row["collection_truncated"] = True
    row["truncation_reason"] = reason
    if reason in {REASON_OPERATOR_LIMIT, REASON_PAGINATION_NOT_FOLLOWED}:
        row["status"] = "partial"
        row["error_class"] = TRUNCATION_ERROR_CLASS
        row["error"] = truncation_message(list_name, rows, reason, limit)


def run_graph_endpoints(
    collector: str,
    client: GraphClient,
    endpoint_specs: dict[str, dict[str, Any]],
    top: int | None,
    *,
    page_size: int | None = None,
    chunk_writer: Optional[Callable[[str, str, int, list[dict[str, Any]], Optional[dict[str, Any]]], str | None]] = None,
    log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute a set of Graph endpoints for one collector.

    Returns both the raw payload per section and per-endpoint coverage entries.

    ``top`` is the operator's explicit row limit; ``None`` (or 0) pages every list to its last
    row. A list cut short for any reason (the limit, a failed page, a refused next link) is
    recorded on its coverage row and raw section as ``collection_truncated`` with a
    ``truncation_reason``. Limit hits make the row ``partial``, so the collector is not
    complete. A spec may carry ``sample_limit`` for a list that is a sample by design; hitting
    that bound is not a gap.
    """
    payload: dict[str, Any] = {}
    coverage: list[dict[str, Any]] = []

    for key, spec in endpoint_specs.items():
        api_version = str(spec.get("api_version") or "v1.0")
        endpoint = spec["endpoint"]
        if api_version != "v1.0":
            # Beta (or other non-default) endpoints are called by full URL so the
            # client does not prefix them with the v1.0 root.
            endpoint = graph_url(endpoint, api_version)
        page = spec.get("page", True)
        apply_top = spec.get("apply_top", True)
        operator_limit = normalize_collection_limit(top, default=None)
        collection_limit = operator_limit
        sample_limit = spec.get("sample_limit")
        limit_is_sample = False
        if isinstance(sample_limit, int) and sample_limit > 0 and (operator_limit is None or sample_limit <= operator_limit):
            collection_limit = sample_limit
            limit_is_sample = True
        effective_top = page_size if page_size is not None else collection_limit
        if not page or not apply_top:
            # Non-collection calls often do not accept $top.
            effective_top = None
        max_top = spec.get("max_top")
        if effective_top is not None and isinstance(max_top, int) and effective_top > max_top:
            effective_top = max_top
        query = _normalize_top(spec.get("params"), effective_top, min_top=spec.get("min_top"))
        if log_event:
            log_event(
                "collector.endpoint.started",
                "Collector endpoint request started",
                {"collector": collector, "endpoint_name": key, "endpoint": endpoint, "top": query.get("$top")},
            )

        start = time.perf_counter()
        item_count = 0
        error_class: str | None = None
        error: str | None = None
        status = "ok"
        accumulator: EndpointAccumulator | None = None
        streamed_rows: list[Any] = []
        collection_truncated = False
        truncation_reason: str | None = None

        try:
            if page:
                if chunk_writer is not None and hasattr(client, "iter_pages") and not spec.get("inline"):
                    accumulator = EndpointAccumulator(sample_limit=20)
                    window = PageWindow.from_limit(collection_limit)
                    for page_number, page_payload in enumerate(client.iter_pages(endpoint, params=query), start=1):
                        values = page_payload.get("value", [])
                        if not isinstance(values, list):
                            raise GraphError(f"Non-list response from {endpoint}", request=endpoint)
                        if window.exhausted:
                            break
                        page_values = [item for item in values if isinstance(item, dict)]
                        limited_values, window = window.take(page_values)
                        if limited_values:
                            chunk_path = chunk_writer(
                                collector,
                                key,
                                page_number,
                                limited_values,
                                {"endpoint": endpoint, "page_number": page_number},
                            )
                            accumulator.add_page(limited_values, chunk_file=chunk_path)
                        else:
                            accumulator.add_page(limited_values)
                        if window.exhausted:
                            collection_truncated = len(limited_values) < len(page_values) or bool(page_payload.get("@odata.nextLink"))
                            break
                    item_count = accumulator.item_count
                    payload[key] = accumulator.payload()
                else:
                    if hasattr(client, "iter_items"):
                        # One row past the limit proves the list continues without paging further.
                        probe = None if collection_limit is None else collection_limit + 1
                        # Collected one by one so the rows read before a failed later page are kept.
                        for streamed in client.iter_items(endpoint, params=query, result_limit=probe):
                            streamed_rows.append(streamed)
                        rows = streamed_rows
                    else:
                        rows = client.get_all(endpoint, params=query)
                    if isinstance(rows, list):
                        rows, collection_truncated = limit_rows(rows, collection_limit)
                        item_count = len(rows)
                        payload[key] = {"value": rows}
                    elif isinstance(rows, dict):
                        payload[key] = rows
                        item_count = len(rows.get("value", [])) if isinstance(rows.get("value"), list) else 0
                    else:
                        payload[key] = {"value": rows}
                if collection_truncated:
                    truncation_reason = REASON_OPERATOR_LIMIT
            else:
                page_result = (
                    client.get_json(endpoint, params=query, full_url=True)
                    if endpoint.startswith("http")
                    else client.get_json(endpoint, params=query)
                )
                values = page_result.get("value") if isinstance(page_result, dict) else page_result
                payload[key] = page_result if isinstance(page_result, dict) else {"value": page_result}
                if isinstance(values, list):
                    item_count = len(values)
                    payload[key] = {"value": values}
                    if isinstance(page_result, dict) and page_result.get("@odata.nextLink"):
                        # A list read that is not paged must never drop the next-page link silently: the rows after
                        # this page were not read, so the list is a coverage gap, not a clean read.
                        collection_truncated = True
                        truncation_reason = REASON_PAGINATION_NOT_FOLLOWED
            status = "ok"
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error_class, error = _classify_graph_error(exc)
            # Successfully written pages remain evidence when a later page
            # fails. Keep their manifest and bounded sample on partial runs.
            if accumulator is not None:
                item_count = accumulator.item_count
                payload[key] = accumulator.payload()
            elif streamed_rows:
                kept, _cut = limit_rows(streamed_rows, collection_limit)
                item_count = len(kept)
                payload[key] = {"value": kept}
            else:
                payload[key] = {}
            payload[key].update({"error": error, "error_class": error_class})
            if page and item_count > 0:
                # Rows were read before the list stopped: the evidence is a prefix, not a blocked read.
                collection_truncated = True
                truncation_reason = (
                    REASON_NEXT_LINK_REFUSED if error_class == "next_link_refused" else REASON_PAGINATION_FAILED
                )
        # A cut at a bound the collector chose (a sample, or a probe) is not a gap; any other cut is.
        bounded_sample = bool(
            page and collection_truncated and truncation_reason == REASON_OPERATOR_LIMIT and (limit_is_sample or sampling())
        )
        is_gap = bool(collection_truncated and not bounded_sample)
        if not page and is_gap and isinstance(payload.get(key), dict):
            payload[key].update({"collection_truncated": True, "truncation_reason": truncation_reason})
        if page and isinstance(payload.get(key), dict):
            payload[key].update(
                {
                    "result_limit": collection_limit,
                    "collection_limit_reached": collection_limit is not None and item_count >= collection_limit,
                    "collection_truncated": is_gap,
                }
            )
            if is_gap and truncation_reason:
                payload[key]["truncation_reason"] = truncation_reason
            if bounded_sample:
                # The raw section says it too, so replay and resumed runs (which have no coverage row) see the bound.
                payload[key]["bounded_sample"] = True
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        coverage_row: dict[str, Any] = {
            "collector": collector,
            "type": "graph",
            "name": key,
            "endpoint": endpoint,
            "api_version": api_version,
            "status": status,
            "top": query.get("$top"),
            "result_limit": collection_limit if page else None,
            "page": page,
            "item_count": item_count,
            "page_count": payload.get(key, {}).get("page_count") if isinstance(payload.get(key), dict) else None,
            "chunk_count": payload.get(key, {}).get("chunk_count") if isinstance(payload.get(key), dict) else None,
            "sample_truncated": payload.get(key, {}).get("sample_truncated") if isinstance(payload.get(key), dict) else None,
            "collection_limit_reached": payload.get(key, {}).get("collection_limit_reached") if page else None,
            "collection_truncated": (is_gap if page else (True if is_gap else None)),
            "duration_ms": duration_ms,
            "error_class": error_class,
            "error": error,
        }
        if bounded_sample:
            coverage_row["bounded_sample"] = True
        if is_gap:
            record_truncation(
                coverage_row,
                list_name=key,
                rows=item_count,
                limit=collection_limit,
                reason=truncation_reason or REASON_OPERATOR_LIMIT,
            )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": collector,
                    "endpoint_name": key,
                    "status": coverage_row["status"],
                    "item_count": item_count,
                    "duration_ms": duration_ms,
                    "error_class": coverage_row["error_class"],
                    "collection_truncated": is_gap,
                },
            )
        coverage.append(coverage_row)

    return payload, coverage

@dataclass
class CollectorResult:
    name: str
    status: str
    payload: dict[str, Any]
    item_count: int
    message: str = ""
    error: Optional[str] = None
    coverage: list[dict[str, Any]] | None = None


class Collector:
    name: str = "base"
    description: str = ""
    required_permissions: list[str] = []
    command_collectors: list[dict[str, str]] | None = None

    def run(self, context: "CollectorRunContext | dict[str, Any]") -> CollectorResult:
        raise NotImplementedError

    @staticmethod
    def _safe_count(payload: dict[str, Any]) -> int:
        value = payload.get("value")
        if isinstance(value, list):
            return len(value)
        if isinstance(payload, dict):
            return len(payload)
        return 0
