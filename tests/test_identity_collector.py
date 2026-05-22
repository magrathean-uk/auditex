from __future__ import annotations

from azure_tenant_audit.collectors.base import run_graph_endpoints
from azure_tenant_audit.collectors.identity import IdentityCollector


class _FakeClient:
    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001
        if path == "/organization":
            assert params == {"$select": "id,displayName,tenantType,city,country"}
            return {"value": [{"id": "org-1"}]}
        if path == "/domains":
            assert params == {"$select": "id,authenticationType,isDefault,isVerified,isRoot"}
            return {"value": [{"id": "domain-1"}, {"id": "domain-2"}]}
        raise AssertionError(f"unexpected path: {path}")

    def get_all(self, path, params=None):  # noqa: ANN001
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
