from __future__ import annotations

from uuid import UUID

from azure_tenant_audit.attack_graph import analyze_attack_graph, build_attack_graph
from azure_tenant_audit.catalog import load_catalog
from azure_tenant_audit.collectors.directory_relationships import DirectoryRelationshipsCollector
from azure_tenant_audit.directory_relationships import normalize_directory_relationships
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.scope_catalog import load_m365_scope_catalog


def uid(number):
    return str(UUID(int=number))


class Client:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def iter_items(self, path, params=None):
        self.calls.append((path, params))
        rows = self.pages[path]
        if isinstance(rows, Exception):
            raise rows
        yield from rows


def pages():
    return {
        "/groups": [{"id": uid(1), "displayName": "Outer"}, {"id": uid(2), "displayName": "Inner"}],
        "/applications": [{"id": uid(3), "appId": uid(4), "displayName": "Owned app"}],
        f"/groups/{uid(1)}/members": [{"id": uid(2), "@odata.type": "#microsoft.graph.group"}],
        f"/groups/{uid(1)}/owners": [],
        f"/groups/{uid(2)}/members": [{"id": uid(5), "@odata.type": "#microsoft.graph.user"}],
        f"/groups/{uid(2)}/owners": [],
        f"/applications/{uid(3)}/owners": [{"id": uid(5), "@odata.type": "#microsoft.graph.user"}],
    }


def test_relationships_reach_graph_with_exact_references_and_distinct_app_owner_target():
    client = Client(pages())
    result = DirectoryRelationshipsCollector().run({"client": client, "top": 500})
    assert result.status == "ok" and result.item_count == 3
    assert len(result.coverage) == 7
    snapshot = normalize_directory_relationships(result.payload)
    snapshot["users"] = {"records": [{"id": uid(5), "enabled": False}]}
    snapshot["service_principals"] = {"records": [{"id": uid(6), "app_id": uid(4), "enabled": False}]}
    graph = build_attack_graph(snapshot)
    assert {(edge.source, edge.target, edge.edge) for edge in graph.edges} == {
        (f"user:{uid(5)}", f"group:{uid(2)}", "member_of"),
        (f"group:{uid(2)}", f"group:{uid(1)}", "member_of"),
        (f"user:{uid(5)}", f"app:{uid(3)}", "owns"),
        (f"app:{uid(3)}", f"sp:{uid(6)}", "authenticates_as"),
    }
    assert all(edge.evidence_ref["artifact_path"] == "normalized/directory_relationship_objects.json" for edge in graph.edges)
    assert analyze_attack_graph(snapshot)["summary"]["footholds"] == 0
    assert all(path.startswith(("/groups", "/applications")) for path, _ in client.calls)


def test_more_than_twenty_members_are_retained_and_limit_is_a_gap():
    data = pages()
    data[f"/groups/{uid(2)}/members"] = [{"id": uid(100 + i)} for i in range(31)]
    complete = DirectoryRelationshipsCollector().run({"client": Client(data), "top": 100})
    assert complete.status == "ok" and complete.item_count == 33
    assert len(normalize_directory_relationships(complete.payload)["directory_relationship_objects"]["records"]) == 33
    limited = DirectoryRelationshipsCollector().run({"client": Client(data), "top": 25})
    assert limited.status == "partial"
    row = next(row for row in limited.coverage if row["endpoint"] == f"/groups/{uid(2)}/members")
    assert row["collection_truncated"] and row["error_class"] == "collection_limit"
    assert row["item_count"] == 25


def test_unreadable_owner_list_is_unknown_and_not_zero():
    data = pages()
    data[f"/applications/{uid(3)}/owners"] = GraphError("denied", status=403)
    result = DirectoryRelationshipsCollector().run({"client": Client(data), "top": 100})
    assert result.status == "partial"
    record = next(row for row in normalize_directory_relationships(result.payload)["directory_relationship_coverage"]["records"] if row["parent_type"] == "application")
    assert record["status"] == "failed" and record["count"] is None


def test_invalid_parent_id_is_not_interpolated_into_a_request():
    data = {"/groups": [{"id": "../../users", "displayName": "untrusted"}], "/applications": []}
    client = Client(data)
    result = DirectoryRelationshipsCollector().run({"client": client, "top": 100})
    assert result.status == "partial"
    assert [path for path, _ in client.calls] == ["/groups", "/applications"]


def test_unbounded_top_still_caps_parent_fanout_at_one_hundred():
    data = {"/groups": [{"id": uid(index + 1)} for index in range(101)], "/applications": []}
    for index in range(100):
        for relation in ("members", "owners"):
            data[f"/groups/{uid(index + 1)}/{relation}"] = []
    client = Client(data)
    result = DirectoryRelationshipsCollector().run({"client": client, "top": 0})
    assert result.status == "partial"
    assert len(client.calls) == 202
    assert result.coverage[0]["result_limit"] == 100
    assert result.coverage[0]["collection_truncated"] is True
    assert all(uid(101) not in path for path, _ in client.calls)


def test_disabled_service_principal_does_not_form_a_traversable_route():
    result = DirectoryRelationshipsCollector().run({"client": Client(pages()), "top": 100})
    snapshot = normalize_directory_relationships(result.payload)
    snapshot["users"] = {"records": [{"id": uid(5), "enabled": True}]}
    snapshot["service_principals"] = {"records": [{"id": uid(6), "app_id": uid(4), "enabled": False}]}
    snapshot["role_assignments"] = {"records": [{"id": uid(7), "principal_id": uid(6), "role_definition_id": "62e90394-69f5-4237-9190-012177145e10"}]}
    assert analyze_attack_graph(snapshot)["paths"] == []
    snapshot["service_principals"]["records"][0]["enabled"] = True
    assert any("owns" in path["chain"] for path in analyze_attack_graph(snapshot)["paths"])


def test_scope_catalog_includes_only_read_permissions_and_explicit_bounds():
    assert load_catalog().validate() == []
    row = load_m365_scope_catalog()["directory_relationships"]
    assert row["required_permissions"] == ["Directory.Read.All", "Group.Read.All", "Application.Read.All"]
    assert "100" in row["notes"] and "5000" in row["notes"]
