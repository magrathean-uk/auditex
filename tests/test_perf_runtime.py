from __future__ import annotations

from azure_tenant_audit.perf_runtime import (
    EndpointAccumulator,
    PageWindow,
    json_size_bytes,
    sqlite_bulk_pragmas,
)


def test_endpoint_accumulator_keeps_bounded_sample_and_counts_chunks() -> None:
    acc = EndpointAccumulator(sample_limit=3)
    acc.add_page(({"id": i} for i in range(5)), chunk_file="chunks/users-00001.jsonl")
    acc.add_page(({"id": i} for i in range(5, 9)), chunk_file="chunks/users-00002.jsonl")
    payload = acc.payload()
    assert acc.item_count == 9
    assert acc.page_count == 2
    assert acc.chunk_count == 2
    assert payload["sample_truncated"] is True
    assert [row["id"] for row in payload["value"]] == [0, 1, 2]
    assert payload["chunk_files"] == ["chunks/users-00001.jsonl", "chunks/users-00002.jsonl"]


def test_page_window_enforces_global_result_limit() -> None:
    window = PageWindow.from_limit(5)
    first, window = window.take([{"id": i} for i in range(3)])
    second, window = window.take([{"id": i} for i in range(3, 10)])
    assert len(first) == 3
    assert len(second) == 2
    assert window.exhausted


def test_perf_helpers_are_deterministic() -> None:
    assert "PRAGMA synchronous=NORMAL" in sqlite_bulk_pragmas()
    assert json_size_bytes({"x": "£"}) > 0
