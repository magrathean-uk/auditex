from __future__ import annotations

import pytest

from azure_tenant_audit.chunk_reader import iter_endpoint_records
from azure_tenant_audit.collector_runner import AuditWriterCollectorAdapter
from azure_tenant_audit.collectors.base import (
    _classify_graph_error,
    run_graph_endpoints,
)
from azure_tenant_audit.config import AuthConfig
from azure_tenant_audit.graph import (
    GRAPH_ROOT,
    INCOMPLETE_EVIDENCE,
    GraphClient,
    GraphError,
)
from azure_tenant_audit.output import AuditWriter


def _client() -> GraphClient:
    return GraphClient(
        AuthConfig(
            tenant_id="tenant-1",
            client_id="client-1",
            auth_mode="access_token",
            access_token="token",
        )
    )


def test_iter_pages_follows_next_link(monkeypatch) -> None:
    client = _client()
    next_link = f"{GRAPH_ROOT}/users?$skiptoken=abc"
    payloads = {
        f"{GRAPH_ROOT}/users": {
            "value": [{"id": "user-1"}],
            "@odata.nextLink": next_link,
        },
        next_link: {
            "value": [{"id": "user-2"}],
        },
    }

    def _fake_get_json(path, params=None, full_url=False):  # noqa: ANN001, ARG001
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        return payloads[url]

    monkeypatch.setattr(client, "get_json", _fake_get_json)

    pages = list(client.iter_pages("/users", params={"$top": "1"}))
    assert len(pages) == 2
    assert pages[0]["value"][0]["id"] == "user-1"
    assert pages[1]["value"][0]["id"] == "user-2"


def test_iter_items_honors_global_result_limit(monkeypatch) -> None:
    client = _client()
    next_link = f"{GRAPH_ROOT}/users?$skiptoken=abc"
    payloads = {
        f"{GRAPH_ROOT}/users": {
            "value": [{"id": "user-1"}, {"id": "user-2"}],
            "@odata.nextLink": next_link,
        },
        next_link: {
            "value": [{"id": "user-3"}, {"id": "user-4"}],
        },
    }

    def _fake_get_json(path, params=None, full_url=False):  # noqa: ANN001, ARG001
        url = path if full_url else f"{GRAPH_ROOT}{path}"
        return payloads[url]

    monkeypatch.setattr(client, "get_json", _fake_get_json)

    rows = list(client.iter_items("/users", params={"$top": "2"}, result_limit=3))
    assert [row["id"] for row in rows] == ["user-1", "user-2", "user-3"]


# Constructed paging responses only; no tenant or held-out vector data.
@pytest.mark.parametrize("rows", [[], [{"id": "constructed-row"}]])
@pytest.mark.parametrize("entrypoint", ["iter_pages", "iter_items", "get_all"])
@pytest.mark.parametrize("two_page", [False, True])
def test_paging_backstop_stops_cycles_before_refetch(monkeypatch, rows, entrypoint, two_page):
    client = _client()
    first = f"{GRAPH_ROOT}/users"
    second = f"{GRAPH_ROOT}/users?$skiptoken=constructed"
    calls = []

    def get_json(path, params=None, full_url=False):
        calls.append((path, params, full_url))
        assert len(calls) <= 2, "cycle backstop must fire before a repeated request"
        return {"value": rows, "@odata.nextLink": second if two_page and path == first else first}

    monkeypatch.setattr(client, "get_json", get_json)
    with pytest.raises(GraphError, match="Repeated Graph page link") as stopped:
        list(getattr(client, entrypoint)("/users"))
    assert stopped.value.error_code == INCOMPLETE_EVIDENCE
    assert _classify_graph_error(stopped.value)[0] == "incomplete_evidence"
    assert len(calls) == (2 if two_page else 1)


@pytest.mark.parametrize("rows", [[], [{"id": "constructed-row"}]])
@pytest.mark.parametrize("terminal", [False, True])
def test_paging_bound_is_configurable_and_allows_exact_terminal_page(monkeypatch, rows, terminal):
    client = _client()
    client.max_pages = 2
    calls = []

    def get_json(path, params=None, full_url=False):
        calls.append(path)
        return {"value": rows, **({} if terminal and len(calls) == 2 else {
            "@odata.nextLink": f"{GRAPH_ROOT}/users?$skiptoken=constructed-{len(calls)}"})}

    monkeypatch.setattr(client, "get_json", get_json)
    if terminal:
        assert client.get_all("/users") == rows * 2
    else:
        with pytest.raises(GraphError, match="page-count limit") as stopped:
            client.get_all("/users")
        assert stopped.value.error_code == INCOMPLETE_EVIDENCE
    assert len(calls) == 2


@pytest.mark.parametrize("max_pages", [0, -1, True, 1.5, "2"])
def test_paging_bound_rejects_invalid_explicit_limits(monkeypatch, max_pages):
    client = _client()
    client.max_pages = max_pages
    monkeypatch.setattr(client, "get_json", lambda *args, **kwargs: pytest.fail("invalid bound must not request a page"))
    with pytest.raises(ValueError, match="positive integer"):
        client.get_all("/users")


@pytest.mark.parametrize("chunked", [False, True])
@pytest.mark.parametrize("rows", [[], [{"id": "constructed-row"}]])
@pytest.mark.parametrize("bounded", [False, True])
def test_shared_endpoint_withholds_cycle_or_page_limit_prefix(monkeypatch, chunked, rows, bounded):
    client = _client()
    client.max_pages = 2
    calls = []
    written = []

    def get_json(path, params=None, full_url=False):
        calls.append(path)
        return {"value": rows, "@odata.nextLink": f"{GRAPH_ROOT}/users?next={len(calls) if bounded else 'cycle'}"}

    monkeypatch.setattr(client, "get_json", get_json)
    payload, coverage = run_graph_endpoints(
        "constructed", client, {"users": {"endpoint": "/users"}}, top=None,
        chunk_writer=(lambda *args: written.append(args) or "constructed-chunk.jsonl") if chunked else None,
    )
    assert len(calls) == 2
    assert coverage[0]["status"] == "failed" and coverage[0]["error_class"] == "incomplete_evidence"
    assert coverage[0]["item_count"] == 0
    assert "value" not in payload["users"] and "sample" not in payload["users"]
    assert "chunk_files" not in payload["users"]
    assert payload["users"]["error_class"] == "incomplete_evidence"
    # A custom callback without discard cannot roll back its external storage.
    assert len(written) == (2 if chunked and rows else 0)


# Fixture meta: constructed rows and pack train and validation rows from v3.9.1;
# held-out test and pilot rows excluded. These responses are wholly constructed.
@pytest.mark.parametrize("chunked", [False, True])
def test_plain_list_beyond_old_page_bound_is_complete(monkeypatch, chunked):
    client = _client()
    assert client.max_pages is None
    expected = [{"id": f"constructed-{index}"} for index in range(5001)]
    calls = []
    chunks = {}

    def get_json(path, params=None, full_url=False):
        index = len(calls)
        calls.append(path)
        return {"value": [expected[index]], **({
            "@odata.nextLink": f"{GRAPH_ROOT}/users?next={index + 1}",
        } if index < 5000 else {})}

    def write_chunk(collector, name, page_number, rows, metadata):
        path = f"chunks/{collector}/{name}-{page_number:05d}.jsonl"
        chunks[path] = list(rows)
        return path

    monkeypatch.setattr(client, "get_json", get_json)
    payload, coverage = run_graph_endpoints(
        "constructed", client, {"users": {"endpoint": "/users"}}, top=None,
        chunk_writer=write_chunk if chunked else None,
    )
    assert len(calls) == 5001 and len(set(calls)) == 5001
    assert coverage[0]["status"] == "ok" and coverage[0]["item_count"] == 5001
    assert not coverage[0]["collection_truncated"]
    section = payload["users"]
    rows = ([row for path in section["chunk_files"] for row in chunks[path]] if chunked else section["value"])
    assert rows == expected
    if chunked:
        assert section["chunk_count"] == 5001 and section["page_count"] == 5001


@pytest.mark.parametrize("terminal", [False, True])
def test_strict_list_retains_its_own_page_bound(monkeypatch, terminal):
    from azure_tenant_audit.collectors import base

    monkeypatch.setattr(base, "STRICT_MAX_PAGES", 2)
    client = _client()
    calls = []

    def get_json(path, params=None, full_url=False):
        calls.append(path)
        return {"value": [{"id": f"constructed-{len(calls)}"}], **({} if terminal and len(calls) == 2 else {
            "@odata.nextLink": f"{GRAPH_ROOT}/policies?next={len(calls)}"})}

    monkeypatch.setattr(client, "get_json", get_json)
    payload, coverage = run_graph_endpoints(
        "constructed", client, {"policies": {"endpoint": "/policies", "validate_collection": True}}, top=None,
    )
    assert client.max_pages is None
    if terminal:
        assert len(calls) == 2
        assert coverage[0]["status"] == "ok" and coverage[0]["item_count"] == 2
        assert len(payload["policies"]["value"]) == 2
    else:
        assert len(calls) == 3
        assert coverage[0]["error_class"] == "incomplete_evidence"
        assert coverage[0]["item_count"] == 0 and "value" not in payload["policies"]


@pytest.mark.parametrize("bounded", [False, True])
@pytest.mark.parametrize("two_page", [False, True])
def test_withheld_endpoint_removes_only_its_chunks_and_artifacts(monkeypatch, tmp_path, bounded, two_page):
    from azure_tenant_audit.ai_context import _artifact_map

    client = _client()
    if bounded:
        client.max_pages = 2
    writer = AuditWriter(tmp_path, tenant_name="constructed", run_name="rollback")
    chunk_writer = AuditWriterCollectorAdapter(writer).hooks().chunk_writer
    first = f"{GRAPH_ROOT}/users"
    second = f"{GRAPH_ROOT}/users?next=second"
    calls = []

    def get_json(path, params=None, full_url=False):
        calls.append(path)
        if path.endswith("/groups"):
            return {"value": [{"id": "constructed-group"}]}
        next_link = (f"{GRAPH_ROOT}/users?next={len(calls)}" if bounded else
                     second if two_page and path == first else first)
        return {"value": [{"id": "constructed-user"}], "@odata.nextLink": next_link}

    monkeypatch.setattr(client, "get_json", get_json)
    payload, coverage = run_graph_endpoints(
        "constructed", client, {"groups": {"endpoint": "/groups"}, "users": {"endpoint": "/users"}},
        top=None, chunk_writer=chunk_writer,
    )
    assert coverage[1]["error_class"] == "incomplete_evidence" and coverage[1]["item_count"] == 0
    assert "chunk_files" not in payload["users"] and "value" not in payload["users"]
    assert not list(writer.chunks_dir.glob("constructed/users-*"))
    assert not any("users-" in path for path in writer.artifact_paths())
    assert not any("users-" in path for paths in _artifact_map(writer.run_dir).values() for path in paths)
    assert list(iter_endpoint_records(payload["groups"], writer.run_dir)) == [{"id": "constructed-group"}]
    assert "chunks/constructed/groups-00001.jsonl" in writer.artifact_paths()
    assert "chunks/constructed/groups-00001.meta.json" in writer.artifact_paths()
