"""Shared helpers for capability-gated collectors.

A capability-gated collector uses Microsoft Graph (or another auth context)
to probe optional services such as Sentinel XDR, Defender for Cloud Apps, or
Copilot governance. When the tenant lacks the underlying license or the
service is not provisioned, the collector translates the upstream error into
a structured diagnostic instead of crashing the run.
"""
from __future__ import annotations

import csv
import time
from io import StringIO
from typing import Any, Callable, Iterable, Optional

from ..graph import GraphError
from .base import Collector, CollectorResult, _classify_graph_error


def _coverage_row(
    collector: str,
    name: str,
    endpoint: str,
    status: str,
    item_count: int,
    duration_ms: float,
    *,
    error_class: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "collector": collector,
        "type": "graph",
        "name": name,
        "endpoint": endpoint,
        "status": status,
        "item_count": item_count,
        "duration_ms": duration_ms,
        "error_class": error_class,
        "error": error,
    }


def _parse_csv(content: str) -> list[dict[str, str]]:
    if not content or not content.strip():
        return []
    return [dict(row) for row in csv.DictReader(StringIO(content.lstrip("\ufeff")))]


def run_capability_gated_endpoints(
    collector_name: str,
    client: Any,
    endpoints: Iterable[tuple[str, str]],
    *,
    log_event: Optional[Callable[[str, str, Optional[dict[str, Any]]], None]] = None,
    skip_reason: str = "no Graph client available; service likely unlicensed in this tenant",
    csv_rows: Optional[dict[str, Callable[[list[dict[str, str]]], list[dict[str, Any]]]]] = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run each endpoint once; ``csv_rows`` maps endpoint names that return CSV reports to a row mapper."""
    payload: dict[str, Any] = {}
    coverage: list[dict[str, Any]] = []

    if client is None or not hasattr(client, "get_json"):
        for name, endpoint in endpoints:
            payload[name] = {"value": []}
            coverage.append(
                _coverage_row(
                    collector_name,
                    name,
                    endpoint,
                    "skipped",
                    0,
                    0.0,
                    error_class="service_not_available",
                    error=skip_reason,
                )
            )
        return payload, coverage

    for name, endpoint in endpoints:
        start = time.perf_counter()
        rows: list[dict[str, Any]] = []
        status = "ok"
        error_class: str | None = None
        error: str | None = None
        try:
            if csv_rows and name in csv_rows:
                rows = csv_rows[name](_parse_csv(client.get_content(endpoint)))
                response = None
            else:
                response = client.get_json(endpoint)
            if isinstance(response, dict):
                values = response.get("value") if "value" in response else response
                if isinstance(values, list):
                    rows = [item for item in values if isinstance(item, dict)]
                elif isinstance(values, dict):
                    rows = [values]
                elif response:
                    rows = [response]
        except GraphError as exc:
            status = "failed"
            error_class, error = _classify_graph_error(exc)
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            error_class, error = _classify_graph_error(exc)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        payload[name] = {"value": rows}
        coverage.append(
            _coverage_row(
                collector_name,
                name,
                endpoint,
                status,
                len(rows),
                duration_ms,
                error_class=error_class,
                error=error,
            )
        )
        if log_event:
            log_event(
                "collector.endpoint.finished",
                "Collector endpoint request completed",
                {
                    "collector": collector_name,
                    "endpoint_name": name,
                    "status": status,
                    "item_count": len(rows),
                    "duration_ms": duration_ms,
                    "error_class": error_class,
                },
            )
    return payload, coverage


def build_collector_result(
    collector: Collector,
    payload: dict[str, Any],
    coverage: list[dict[str, Any]],
    *,
    partial_message: str,
) -> CollectorResult:
    partial = any(row.get("status") not in {"ok"} for row in coverage)
    return CollectorResult(
        name=collector.name,
        status="partial" if partial else "ok",
        payload=payload,
        item_count=sum(int(row.get("item_count") or 0) for row in coverage),
        message=partial_message if partial else "",
        coverage=coverage,
    )
