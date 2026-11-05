from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Iterator, Optional

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
from ..graph import GraphClient, GraphError, INCOMPLETE_EVIDENCE, NEXT_LINK_REFUSED, graph_url

if TYPE_CHECKING:
    from ..collector_runner import CollectorRunContext


class _InvalidCollectionPage(ValueError):
    pass


STRICT_MAX_PAGES = 5000


def _validated_collection(client: GraphClient, endpoint: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate envelopes before flattening; never keep a prefix from a malformed list."""
    rows: list[dict[str, Any]] = []
    # Lightweight replay clients may expose only get_all. The real client must
    # use iter_pages: iter_items/get_all silently accept a missing value key.
    pages = client.iter_pages(endpoint, params=params) if hasattr(client, "iter_pages") else (
        {"value": client.get_all(endpoint, params=params)},
    )
    try:
        for page_number, page in enumerate(pages, 1):
            if page_number > STRICT_MAX_PAGES:
                raise _InvalidCollectionPage("Graph page-count limit reached; evidence withheld because the list is incomplete.")
            values = page.get("value") if isinstance(page, dict) else None
            if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
                raise _InvalidCollectionPage("Invalid collection page; evidence withheld.")
            next_link = page.get("@odata.nextLink")
            # GraphClient treats null like an absent link: the list has ended.
            # Leave URL safety checks to iter_pages so named refusals survive.
            if next_link is not None and (not isinstance(next_link, str) or not next_link):
                raise _InvalidCollectionPage("Invalid collection next link; evidence withheld.")
            rows.extend(values)
    except GraphError as exc:
        # iter_pages rejects non-dict envelopes itself. Preserve HTTP failures
        # and named client refusals, including unsafe next links.
        if exc.status is None and exc.error_code is None and str(exc).startswith("Non-dict response from "):
            raise _InvalidCollectionPage("Invalid collection page; evidence withheld.") from exc
        raise
    return rows


def _classify_graph_error(exc: Exception) -> tuple[str, str]:
    message = str(exc)
    if isinstance(exc, _InvalidCollectionPage):
        return "incomplete_evidence", message
    if isinstance(exc, GraphError):
        if exc.error_code == INCOMPLETE_EVIDENCE:
            return "incomplete_evidence", message
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


def _bounded_pages(
    client: GraphClient,
    endpoint: str,
    query: dict[str, Any],
    *,
    collection_limit: int | None,
    max_rows: int | None,
    max_empty_pages: int | None,
) -> Iterator[tuple[int, list[dict[str, Any]], bool, str | None, bool]]:
    """Read bounded pages and report whether the current page ends the read."""
    window = PageWindow.from_limit(collection_limit)
    rows_so_far = 0
    empty_pages = 0
    for page_number, page_payload in enumerate(client.iter_pages(endpoint, params=query), start=1):
        values = page_payload.get("value", [])
        if not isinstance(values, list):
            raise GraphError(f"Non-list response from {endpoint}", request=endpoint)
        page_values = [item for item in values if isinstance(item, dict)]
        limited_values, window = window.take(page_values)
        remaining = max(max_rows - rows_so_far, 0) if max_rows is not None else len(limited_values)
        selected = limited_values[:remaining]
        rows_so_far += len(selected)
        empty_pages = empty_pages + 1 if not page_values else 0
        next_link = bool(page_payload.get("@odata.nextLink"))
        if window.exhausted:
            truncated = len(limited_values) < len(page_values) or next_link
            reason = REASON_OPERATOR_LIMIT if truncated else None
            stop = True
        elif max_rows is not None and (len(selected) < len(limited_values) or rows_so_far >= max_rows):
            truncated = len(selected) < len(limited_values) or next_link
            reason = REASON_PAGINATION_NOT_FOLLOWED if truncated else None
            stop = True
        elif max_empty_pages is not None and empty_pages >= max_empty_pages and next_link:
            truncated, reason, stop = True, REASON_PAGINATION_NOT_FOLLOWED, True
        else:
            truncated, reason, stop = False, None, False
        yield page_number, selected, truncated, reason, stop
        if stop:
            break


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

    ``top`` is the operator's explicit row limit; ``None`` (or 0) pages lists to their last
    row unless a collector safety ceiling is reached. A list cut short for any reason is
    recorded on its coverage row and raw section as ``collection_truncated`` with a
    ``truncation_reason``. Limit hits make the row ``partial``, so the collector is not
    complete. A spec may carry ``sample_limit`` for a list that is a sample by design; hitting
    that bound is not a gap. ``max_rows`` is a safety ceiling; a remaining next link is an
    explicit ``pagination_not_followed`` gap. ``max_empty_pages`` stops empty-page loops.
    ``validate_collection`` opts a new list into atomic envelope validation;
    ``validate_object`` requires a non-empty object, optionally with ``required_key``.
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
        default_page_size = spec.get("default_page_size")
        if page_size is None and isinstance(default_page_size, int) and default_page_size > 0:
            effective_top = min(effective_top, default_page_size) if effective_top is not None else default_page_size
        if not page or not apply_top:
            # Non-collection calls often do not accept $top.
            effective_top = None
        max_top = spec.get("max_top")
        if effective_top is not None and isinstance(max_top, int) and effective_top > max_top:
            effective_top = max_top
        query = _normalize_top(
            spec.get("params"), effective_top,
            min_top=spec.get("min_top") if operator_limit is None else None,
        )
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
        max_rows = spec.get("max_rows")

        try:
            if page and spec.get("validate_collection"):
                # Opt-in policy reads validate every original page before publishing any rows.
                rows = _validated_collection(client, endpoint, query)
                rows, collection_truncated = limit_rows(rows, collection_limit)
                item_count = len(rows)
                payload[key] = {"value": rows}
                if collection_truncated:
                    truncation_reason = REASON_OPERATOR_LIMIT
            elif page:
                if chunk_writer is not None and hasattr(client, "iter_pages") and not spec.get("inline"):
                    accumulator = EndpointAccumulator(sample_limit=20)
                    pages = _bounded_pages(
                        client, endpoint, query, collection_limit=collection_limit,
                        max_rows=max_rows, max_empty_pages=spec.get("max_empty_pages") if max_rows is not None else None,
                    )
                    for page_number, limited_values, cut, reason, stop in pages:
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
                        if stop:
                            collection_truncated = cut
                            truncation_reason = reason
                            break
                    item_count = accumulator.item_count
                    payload[key] = accumulator.payload()
                else:
                    if max_rows is not None:
                        if not hasattr(client, "iter_pages"):
                            raise GraphError(f"Paged client required for bounded {endpoint}", request=endpoint)
                        for _page_number, limited_values, cut, reason, stop in _bounded_pages(
                            client, endpoint, query, collection_limit=collection_limit,
                            max_rows=max_rows, max_empty_pages=spec.get("max_empty_pages", 50),
                        ):
                            streamed_rows.extend(limited_values)
                            if stop:
                                collection_truncated = cut
                                truncation_reason = reason
                                break
                        rows = streamed_rows
                    elif hasattr(client, "iter_items"):
                        # One row past the limit proves the list continues without paging further.
                        probe = None if collection_limit is None else collection_limit + 1
                        # Collected one by one so the rows read before a failed later page are kept.
                        for streamed in client.iter_items(endpoint, params=query, result_limit=probe):
                            streamed_rows.append(streamed)
                        rows = streamed_rows
                    else:
                        rows = client.get_all(endpoint, params=query)
                    if isinstance(rows, list):
                        rows, cut_at_limit = limit_rows(rows, collection_limit)
                        collection_truncated |= cut_at_limit
                        item_count = len(rows)
                        payload[key] = {"value": rows}
                    elif isinstance(rows, dict):
                        payload[key] = rows
                        item_count = len(rows.get("value", [])) if isinstance(rows.get("value"), list) else 0
                    else:
                        payload[key] = {"value": rows}
                if collection_truncated and truncation_reason is None:
                    truncation_reason = REASON_OPERATOR_LIMIT
            else:
                page_result = (
                    client.get_json(endpoint, params=query, full_url=True)
                    if endpoint.startswith("http")
                    else client.get_json(endpoint, params=query)
                )
                if spec.get("validate_object"):
                    required_key = spec.get("required_key")
                    if (not isinstance(page_result, dict) or not page_result
                            or (required_key is not None and (
                                not isinstance(page_result.get(required_key), str) or not page_result[required_key]
                            ))):
                        raise _InvalidCollectionPage("Invalid policy object; evidence withheld.")
                values = page_result.get("value") if isinstance(page_result, dict) else page_result
                payload[key] = page_result if isinstance(page_result, dict) else {"value": page_result}
                if isinstance(values, list) and not spec.get("validate_object"):
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
            # Ordinary later-page failures retain the prefix. Safety stops and
            # strict validation failures withhold it, including stored chunks.
            if spec.get("validate_collection") or error_class == "incomplete_evidence":
                # A safety stop or strict validation failure withholds the entire section.
                discard = getattr(chunk_writer, "discard", None)
                if accumulator is not None and discard is not None:
                    discard(accumulator.chunk_files)
                item_count = 0
                payload[key] = {}
            elif accumulator is not None:
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
                limit=(max_rows if truncation_reason == REASON_PAGINATION_NOT_FOLLOWED
                       and max_rows is not None and item_count >= max_rows else
                       None if truncation_reason == REASON_PAGINATION_NOT_FOLLOWED else collection_limit),
                reason=truncation_reason or REASON_OPERATOR_LIMIT,
            )
            if (page and truncation_reason == REASON_PAGINATION_NOT_FOLLOWED and max_rows is not None
                    and item_count < max_rows and spec.get("max_empty_pages", 50) is not None):
                # Below the row cap a bounded paged read can only have been stopped by the empty-page backstop.
                coverage_row["error"] = (
                    f"{key}: stopped after {spec.get('max_empty_pages', 50)} consecutive empty pages that still "
                    f"carried a next-page link, after {item_count} rows; the list is incomplete."
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
        if spec.get("validate_collection") and status == "failed":
            # Keep the named refusal/HTTP cause above, and expose the withheld
            # section as an incomplete-evidence gap even when no rows were read.
            coverage.append({
                "collector": collector, "type": "derived", "name": key,
                "status": "failed", "item_count": 0, "duration_ms": 0,
                "error_class": "incomplete_evidence",
                "error": "Policy collection is incomplete; section withheld.",
            })

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
    # True for a collector that reads events between ``--since`` and ``--until``. Its checkpoint records the window,
    # and a resumed run under another window re-runs it instead of carrying evidence of a different one.
    time_windowed: bool = False

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
