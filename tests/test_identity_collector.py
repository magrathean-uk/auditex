from __future__ import annotations

import pytest

from azure_tenant_audit.collectors.base import run_graph_endpoints
from azure_tenant_audit.collectors.identity import IdentityCollector


class _FakeClient:
    def iter_pages(self, path, params=None):  # noqa: ANN001
        yield {"value": self.get_all(path, params)}

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001
        if path == "/organization":
            assert params == {"$select": "id,displayName,tenantType,city,country"}
            return {"value": [{"id": "org-1"}]}
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path, params=None):  # noqa: ANN001
        if path == "/domains":
            # A list read: paged through the shared path, without $top.
            assert params == {"$select": "id,authenticationType,isDefault,isVerified,isRoot"}
            return [{"id": "domain-1"}, {"id": "domain-2"}]
        if path == "/users":
            assert params["$top"] == "500"
            return [{"id": "user-1"}]
        if path == "/groups":
            assert params["$top"] == "500"
            return [{"id": "group-1"}]
        if path == "/applications":
            assert params["$top"] == "500"
            return [{"id": "app-1"}]
        if path == "/servicePrincipals":
            assert params["$top"] == "500"
            return [{"id": "sp-1"}]
        if path == "/roleManagement/directory/roleDefinitions":
            assert "$top" not in params
            return [{"id": "rd-1"}]
        if path == "/roleManagement/directory/roleAssignments":
            assert params["$top"] == "500"
            return [{"id": "ra-1"}]
        raise AssertionError(f"unexpected path: {path}")


def test_identity_collector_skips_top_for_role_definitions() -> None:
    collector = IdentityCollector()
    result = collector.run({"client": _FakeClient(), "top": 500, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["roleDefinitions"]["value"][0]["id"] == "rd-1"
    assert result.payload["users"]["value"][0]["id"] == "user-1"


def test_graph_endpoint_top_zero_means_unbounded_collection() -> None:
    class _StreamingClient:
        def __init__(self) -> None:
            self.calls = []

        def iter_items(self, endpoint, params=None, result_limit=None):  # noqa: ANN001
            self.calls.append((endpoint, params, result_limit))
            return iter([{"id": "1"}, {"id": "2"}])

    client = _StreamingClient()
    payload, coverage = run_graph_endpoints(
        "identity",
        client,
        {"users": {"endpoint": "/users", "params": {"$select": "id"}}},
        top=0,
        page_size=50,
    )

    assert payload["users"]["value"] == [{"id": "1"}, {"id": "2"}]
    assert coverage[0]["item_count"] == 2
    assert client.calls == [("/users", {"$select": "id", "$top": "50"}, None)]


@pytest.mark.parametrize("chunked", [False, True])
def test_graph_endpoint_row_ceiling_is_an_explicit_gap(chunked: bool) -> None:
    class _PagedClient:
        def __init__(self) -> None:
            self.pages_read = 0

        def iter_pages(self, endpoint, params=None):  # noqa: ANN001
            assert endpoint == "/users" and params["$top"] == "2"
            for number in range(3):
                self.pages_read += 1
                yield {"value": [{"id": f"{number}-1"}, {"id": f"{number}-2"}],
                       "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?next=mocktenant"}

    client = _PagedClient()
    payload, coverage = run_graph_endpoints(
        "identity", client,
        {"users": {"endpoint": "/users", "default_page_size": 2, "max_top": 2, "max_rows": 4}},
        top=None,
        chunk_writer=(lambda *args: "mocktenant-chunk.jsonl") if chunked else None,
    )
    assert client.pages_read == 2
    assert payload["users"]["collection_truncated"] is True
    assert payload["users"]["truncation_reason"] == "pagination_not_followed"
    assert coverage[0]["status"] == "partial"
    assert coverage[0]["error_class"] == "collection_limit"
    assert coverage[0]["item_count"] == 4
    assert "safety cap of 4 rows was hit" in coverage[0]["error"]


def test_bounded_endpoint_stops_at_operator_limit_before_row_ceiling() -> None:
    class _PagedClient:
        def __init__(self) -> None:
            self.pages_read = 0

        def iter_pages(self, endpoint, params=None):  # noqa: ANN001
            assert params["$top"] == "2"
            for number in range(3):
                self.pages_read += 1
                yield {"value": [{"id": f"{number}-1"}, {"id": f"{number}-2"}],
                       "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?next=mocktenant"}

    client = _PagedClient()
    payload, coverage = run_graph_endpoints(
        "identity", client,
        {"users": {"endpoint": "/users", "default_page_size": 2, "max_top": 2, "max_rows": 4}},
        top=2,
    )
    assert client.pages_read == 1
    assert len(payload["users"]["value"]) == 2
    assert coverage[0]["truncation_reason"] == "operator_limit"


@pytest.mark.parametrize("chunked", [False, True])
def test_empty_page_next_link_loop_has_a_backstop(chunked: bool) -> None:
    class _PagedClient:
        def __init__(self) -> None:
            self.pages_read = 0

        def iter_pages(self, endpoint, params=None):  # noqa: ANN001
            while True:
                self.pages_read += 1
                yield {"value": [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?next=repeat"}

    client = _PagedClient()
    payload, coverage = run_graph_endpoints(
        "identity", client,
        {"users": {"endpoint": "/users", "max_rows": 250_000, "max_empty_pages": 3}},
        top=None, chunk_writer=(lambda *args: "mocktenant-chunk.jsonl") if chunked else None,
    )
    assert client.pages_read == 3
    assert payload["users"]["truncation_reason"] == "pagination_not_followed"
    assert coverage[0]["status"] == "partial"
    assert "stopped after 3 consecutive empty pages" in coverage[0]["error"]
    assert "safety cap" not in coverage[0]["error"]


def test_user_inventory_caps_at_250000_not_at_page_count() -> None:
    class _PagedClient:
        def __init__(self) -> None:
            self.pages_read = 0

        def iter_pages(self, endpoint, params=None):  # noqa: ANN001
            if endpoint != "/users" or params["$select"] == "id,signInActivity":
                yield {"value": []}
                return
            assert params["$top"] == "500"
            for start in range(0, 250_001, 500):
                self.pages_read += 1
                yield {"value": [{"id": str(i)} for i in range(start, min(start + 500, 250_001))],
                       **({"@odata.nextLink": "https://graph.microsoft.com/v1.0/users?next=mocktenant"}
                          if start + 500 < 250_001 else {})}

        def get_json(self, endpoint, params=None, full_url=False):  # noqa: ANN001
            return {"value": []}

    client = _PagedClient()
    result = IdentityCollector().run({"client": client, "top": None,
                                      "chunk_writer": lambda *args: "mocktenant-chunk.jsonl"})
    assert result.status == "partial"
    assert client.pages_read == 500
    assert result.payload["users"]["item_count"] == 250_000
    assert result.payload["users"]["truncation_reason"] == "pagination_not_followed"
    user_row = next(row for row in result.coverage if row["name"] == "users")
    assert "safety cap of 250000 rows was hit" in user_row["error"]
