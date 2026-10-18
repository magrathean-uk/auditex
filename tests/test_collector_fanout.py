from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.attack_graph import analyze_attack_graph, build_attack_graph
from azure_tenant_audit.collector_runner import AuditWriterCollectorAdapter, CollectorRunContext, CollectorRunHooks, CollectorRunner
from azure_tenant_audit.collectors.app_consent import AppConsentCollector
from azure_tenant_audit.collectors.identity import IdentityCollector
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.output import AuditWriter


GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
ROLE_MANAGEMENT = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"


class _IdentityClient:
    def __init__(self, groups: list[dict[str, Any]], assignments: list[dict[str, Any]]) -> None:
        self.groups = groups
        self.assignments = assignments
        self.relationship_calls: list[str] = []
        self.relationships: dict[str, list[dict[str, Any]]] = {}

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
        assert path in {"/organization", "/domains"}
        return {"value": []}

    def iter_pages(self, path: str, params: Any = None):
        if path == "/applications":
            assert "appId" in params["$select"].split(",")
        if path == "/servicePrincipals":
            assert "accountEnabled" in params["$select"].split(",")
        rows = self.groups if path == "/groups" else self.assignments if path == "/roleManagement/directory/roleAssignments" else []
        for start in range(0, len(rows), 17):
            page: dict[str, Any] = {"value": rows[start:start + 17]}
            if start + 17 < len(rows):
                page["@odata.nextLink"] = "synthetic-next-page"
            yield page

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        assert path.startswith("/groups/") and path.endswith(("/members", "/owners"))
        self.relationship_calls.append(path)
        return self.relationships.get(path, [])


class _AppConsentClient:
    def __init__(self, count: int = 367, graph_index: int | None = 366) -> None:
        self.principals = [
            {"id": f"sp-{i}", "appId": GRAPH_APP_ID if i == graph_index else f"app-{i}",
             "displayName": f"Service {i}", "accountEnabled": i != 0}
            for i in range(count)
        ]
        self.graph_index = graph_index
        self.relationship_calls: list[str] = []

    def iter_pages(self, path: str, params: Any = None):
        assert path in {"/servicePrincipals", "/oauth2PermissionGrants"}
        if path == "/oauth2PermissionGrants":
            return
        assert "accountEnabled" in params["$select"].split(",")
        for start in range(0, len(self.principals), 17):
            page: dict[str, Any] = {"value": self.principals[start:start + 17]}
            if start + 17 < len(self.principals):
                page["@odata.nextLink"] = "synthetic-next-page"
            yield page

    def get_batch(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        responses = []
        for request in requests:
            path = request["path"]
            self.relationship_calls.append(path)
            rows = []
            if path == "/servicePrincipals/sp-0/owners":
                rows = [{"id": "owner-1", "displayName": "Synthetic owner", "@odata.type": "#microsoft.graph.user"}]
            if path == f"/servicePrincipals/sp-{self.graph_index}/appRoleAssignedTo":
                rows = [{"id": "assignment-1", "appRoleId": ROLE_MANAGEMENT, "principalId": "sp-0",
                         "principalType": "ServicePrincipal", "resourceId": f"sp-{self.graph_index}"}]
            responses.append({"status": 200, "body": {"value": rows}})
        return responses


def _run(tmp_path: Path, collector: Any, client: Any, *, top: int = 1000, damage: str | None = None):
    writer = AuditWriter(tmp_path, tenant_name="synthetic", run_name="fanout")
    adapter = AuditWriterCollectorAdapter(writer)
    hooks = adapter.hooks()
    assert hooks.run_dir == writer.run_dir
    if damage:
        original_writer = hooks.chunk_writer

        def chunk_writer(name: str, endpoint: str, page: int, rows: list[dict[str, Any]], metadata: Any = None):
            relative = original_writer(name, endpoint, page, rows, metadata)
            if endpoint not in {"groups", "servicePrincipals"} or page != 2:
                return relative
            if damage == "missing":
                (writer.run_dir / relative).unlink()
            elif damage == "corrupt":
                (writer.run_dir / relative).write_text('{"incomplete":\n')
            elif damage == "outside":
                return "../outside.jsonl"
            return relative

        hooks = replace(hooks, chunk_writer=chunk_writer)
    context = CollectorRunContext(client=client, top=top, page_size=17, hooks=hooks)
    output = CollectorRunner(adapter).run(collector, context)
    return output, writer


def _coverage(output: Any, name: str) -> dict[str, Any]:
    return next(row for row in output.coverage_rows if row["name"] == name)


def test_hook_exposes_run_dir_and_keeps_legacy_context_overrides(tmp_path: Path) -> None:
    assert CollectorRunContext(client=None, top=0).to_legacy_dict()["run_dir"] is None
    context = CollectorRunContext(client=None, top=0, hooks=CollectorRunHooks(run_dir=tmp_path))
    assert context.to_legacy_dict()["run_dir"] == tmp_path
    assert replace(context, extra={"run_dir": "explicit-run"}).to_legacy_dict()["run_dir"] == "explicit-run"


def test_identity_uses_beyond_sample_groups_and_role_assignments(tmp_path: Path) -> None:
    groups = [{"id": f"g-{i}", "displayName": f"Group {i}", "isAssignableToRole": i == 35} for i in range(40)]
    assignments = [{"id": f"ra-{i}", "principalId": f"user-{i}"} for i in range(34)]
    assignments.append({"id": "ra-34", "principalId": "g-34"})
    client = _IdentityClient(groups, assignments)
    client.relationships["/groups/g-34/members"] = [{"id": "g-nested", "@odata.type": "#microsoft.graph.group"}]
    client.relationships["/groups/g-nested/members"] = [{"id": "g-34", "@odata.type": "#microsoft.graph.group"}]
    output, writer = _run(tmp_path, IdentityCollector(), client)

    assert output.crashed is False and output.result.status == "ok"
    assert set(client.relationship_calls) == {
        f"/groups/{group}/{relation}" for group in ("g-34", "g-35", "g-nested") for relation in ("members", "owners")
    }
    assert len(client.relationship_calls) == 6
    assert len(output.result.payload["groups"]["value"]) == 20
    assert len(output.result.payload["roleAssignments"]["value"]) == 20
    fanout = _coverage(output, "privilegedGroupFanout")
    assert fanout["input_record_counts"] == {"groups": 40, "roleAssignments": 35}
    assert fanout["candidate_group_count"] == 2
    assert fanout["expanded_group_count"] == 3
    assert fanout["unexpanded_group_count"] == 0
    assert fanout["fanout_complete"] is True
    persisted = json.loads((writer.raw_dir / "identity.json").read_text())
    assert len(persisted["groups"]["value"]) == 20
    assert persisted["roleAssignableGroupMembers"]["fanout"] == output.result.payload["roleAssignableGroupMembers"]["fanout"]


@pytest.mark.parametrize("count,remaining", [(50, 0), (55, 5)])
def test_identity_preserves_fifty_group_bound_and_exposes_remaining_work(tmp_path: Path, count: int, remaining: int) -> None:
    client = _IdentityClient([{"id": f"g-{i}", "isAssignableToRole": True} for i in range(count)], [])
    client.relationships["/groups/g-0/members"] = [{"id": "g-1", "@odata.type": "#microsoft.graph.group"}]
    client.relationships["/groups/g-1/members"] = [{"id": "g-0", "@odata.type": "#microsoft.graph.group"}]
    output, _writer = _run(tmp_path, IdentityCollector(), client)
    assert len(client.relationship_calls) == 100
    fanout = _coverage(output, "privilegedGroupFanout")
    assert fanout["expanded_group_count"] == 50
    assert fanout["unexpanded_group_count"] == remaining
    assert fanout["collection_truncated"] is bool(remaining)
    assert fanout["status"] == ("partial" if remaining else "ok")
    assert output.result.status == ("partial" if remaining else "ok")


def test_identity_collection_cap_is_a_gap_even_when_every_collected_group_is_expanded(tmp_path: Path) -> None:
    client = _IdentityClient([{"id": f"g-{i}", "isAssignableToRole": True} for i in range(40)], [])
    output, _writer = _run(tmp_path, IdentityCollector(), client, top=25)
    fanout = _coverage(output, "privilegedGroupFanout")
    assert fanout["expanded_group_count"] == 25
    assert fanout["unexpanded_group_count"] == 0
    assert fanout["input_complete"] is False
    assert fanout["input_limited_sections"] == ["groups"]
    assert fanout["error_class"] == "collection_limit"
    assert output.result.status == "partial"


def test_consent_finds_tail_microsoft_graph_and_keeps_first_ten_bound(tmp_path: Path) -> None:
    client = _AppConsentClient()
    output, writer = _run(tmp_path, AppConsentCollector(), client)
    assert output.crashed is False
    assert set(client.relationship_calls) == {
        f"/servicePrincipals/sp-{i}/{relation}" for i in (*range(10), 366) for relation in ("owners", "appRoleAssignedTo")
    }
    assert len(client.relationship_calls) == 22
    assert len(output.result.payload["servicePrincipals"]["value"]) == 20
    fanout = _coverage(output, "servicePrincipalFanout")
    assert fanout["input_record_count"] == 367
    assert fanout["input_complete"] is True
    assert fanout["fanout_target_count"] == 11
    assert fanout["fanout_omitted_count"] == 356
    assert fanout["microsoft_graph_found"] is True
    assert fanout["fanout_scope"] == "first_10_service_principals_plus_microsoft_graph"
    assert fanout["status"] == "partial" and fanout["error_class"] == "collection_limit"

    snapshot = build_normalized_snapshot(tenant_name="synthetic", run_id="test",
                                         collector_payloads={"app_consent": output.result.payload}, run_dir=writer.run_dir)
    assert len(snapshot["service_principals"]["records"]) == 367
    graph = build_attack_graph(snapshot)
    assert graph.nodes["sp:sp-0"]["enabled"] is False
    assert any(edge.edge == "has_app_role" for edge in graph.edges)
    # Supply a known enabled owner to isolate SP disablement from the graph's
    # separate requirement for user-inventory evidence at the foothold.
    snapshot["users"] = {"records": [{"id": "owner-1", "enabled": True, "user_type": "Member"}]}
    assert analyze_attack_graph(snapshot)["paths"] == []
    enabled = deepcopy(snapshot)
    next(row for row in enabled["service_principals"]["records"] if row["id"] == "sp-0")["enabled"] = True
    assert any("owns" in path["chain"] for path in analyze_attack_graph(enabled)["paths"])


def test_consent_does_not_query_graph_twice_when_it_is_already_in_first_ten(tmp_path: Path) -> None:
    client = _AppConsentClient(count=31, graph_index=0)
    output, _writer = _run(tmp_path, AppConsentCollector(), client)
    assert len(client.relationship_calls) == len(set(client.relationship_calls)) == 20
    assert _coverage(output, "servicePrincipalFanout")["fanout_target_count"] == 10


def test_fanout_coverage_is_not_recorded_as_an_api_call(tmp_path: Path) -> None:
    from azure_tenant_audit.api_inventory import ApiInventoryRecorder

    output, _writer = _run(tmp_path, AppConsentCollector(), _AppConsentClient(count=31, graph_index=30))
    recorder = ApiInventoryRecorder(platform="m365", capability_rows=[])
    recorder.record_many(output.coverage_rows)
    assert len(recorder.observed_calls()) == 24
    assert all(call["endpoint"] for call in recorder.observed_calls())


def test_consent_reports_unlocated_graph_when_inventory_is_collection_limited(tmp_path: Path) -> None:
    client = _AppConsentClient()
    output, _writer = _run(tmp_path, AppConsentCollector(), client, top=25)
    fanout = _coverage(output, "servicePrincipalFanout")
    assert fanout["input_record_count"] == 25
    assert fanout["input_complete"] is False
    assert fanout["input_collection_limited"] is True
    assert fanout["microsoft_graph_found"] is False
    assert fanout["fanout_target_count"] == 10


@pytest.mark.parametrize("kind", ["identity", "app_consent"])
@pytest.mark.parametrize("damage,code", [("missing", "missing_chunk"), ("corrupt", "invalid_chunk_json"), ("outside", "unsafe_chunk_path")])
def test_bad_chunk_inputs_retain_raw_evidence_and_produce_coverage_gap(tmp_path: Path, kind: str, damage: str, code: str) -> None:
    if kind == "identity":
        collector = IdentityCollector()
        client = _IdentityClient([{"id": f"g-{i}", "isAssignableToRole": True} for i in range(31)], [])
        section_name, fanout_name = "groups", "privilegedGroupFanout"
    else:
        collector = AppConsentCollector()
        client = _AppConsentClient(count=31, graph_index=30)
        section_name, fanout_name = "servicePrincipals", "servicePrincipalFanout"
    output, writer = _run(tmp_path, collector, client, damage=damage)
    assert output.crashed is False
    assert output.result.status == "partial"
    assert client.relationship_calls == []
    section = output.result.payload[section_name]
    assert section["item_count"] == 31
    assert len(section["value"]) == 20
    assert len(section["chunk_files"]) == 2
    assert json.loads((writer.raw_dir / f"{kind}.json").read_text())[section_name] == section
    fanout = _coverage(output, fanout_name)
    assert fanout["error_class"] == "incomplete_evidence"
    assert fanout["input_complete"] is False
    assert code in {issue["code"] for issue in fanout["input_issues"]}


@pytest.mark.parametrize("identity_enabled,consent_enabled,expected", [(False, True, False), (True, False, True), (None, False, False)])
def test_consent_service_principal_merge_preserves_identity_enabled_state(identity_enabled: Any, consent_enabled: bool, expected: bool) -> None:
    identity = {"id": "shared", "displayName": "Identity name"}
    if identity_enabled is not None:
        identity["accountEnabled"] = identity_enabled
    payloads = {
        "identity": {"servicePrincipals": {"value": [identity]}},
        "app_consent": {"servicePrincipals": {"value": [
            {"id": "shared", "displayName": "Consent name", "appId": "app-shared", "accountEnabled": consent_enabled},
            {"id": "consent-only", "accountEnabled": False},
        ]}},
    }
    original = deepcopy(payloads)
    snapshot = build_normalized_snapshot(tenant_name="synthetic", run_id="test", collector_payloads=payloads)
    records = {row["id"]: row for row in snapshot["service_principals"]["records"]}
    assert len(records) == 2
    assert records["shared"]["enabled"] is expected
    assert records["shared"]["source"] == "identity.servicePrincipals"
    assert records["shared"]["display_name"] == "Identity name"
    assert records["shared"]["app_id"] == "app-shared"
    assert records["consent-only"]["source"] == "app_consent.servicePrincipals"
    assert records["consent-only"]["enabled"] is False
    assert payloads == original
