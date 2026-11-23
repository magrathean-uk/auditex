"""App-consent evidence: owner counts are exact only from complete owner reads, and two cut fan-out reads of the
same list stay two distinct collection gaps."""
from __future__ import annotations

from typing import Any

from graph_fakes import FakeGraph

from azure_tenant_audit.collectors.app_consent import AppConsentCollector
from azure_tenant_audit.graph import GRAPH_ROOT, GraphError
from azure_tenant_audit.normalize import build_normalized_snapshot

SPS = [
    {"id": "sp-1", "appId": "app-1", "displayName": "One", "accountEnabled": True},
    {"id": "sp-2", "appId": "app-2", "displayName": "Two", "accountEnabled": True},
]
GRANTS = [
    {"id": "g-1", "clientId": "sp-1", "resourceId": "sp-1", "scope": "User.Read"},
    {"id": "g-2", "clientId": "sp-2", "resourceId": "sp-2", "scope": "User.Read"},
]


class _CutPages(FakeGraph):
    """Each ``paged`` fan-out item answers its first page with ``first`` rows and a next link whose page fails."""

    def __init__(self, paged: dict[str, list[dict[str, Any]]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.paged = paged

    def get_batch(self, requests):
        out = super().get_batch(requests)
        for request, item in zip(requests, out, strict=True):
            if request["path"] in self.paged:
                next_link = f"{GRAPH_ROOT}/synthetic-next{request['path']}?$skiptoken=1"
                item.update(status=200, body={"value": list(self.paged[request["path"]]), "@odata.nextLink": next_link})
        return out

    def iter_items(self, path, params=None, result_limit=None):
        if path.startswith(f"{GRAPH_ROOT}/synthetic-next"):
            def failing():
                raise GraphError("Service unavailable", status=503, request=path)
                yield  # pragma: no cover
            return failing()
        return super().iter_items(path, params=params, result_limit=result_limit)


def _snapshot(fake: FakeGraph) -> dict[str, Any]:
    result = AppConsentCollector().run({"client": fake, "top": None})
    return build_normalized_snapshot(
        tenant_name="lab", run_id="run", collector_payloads={"app_consent": result.payload},
        coverage_rows=result.coverage,
    )


def _owner_counts(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {row["service_principal_id"]: row.get("owner_count") for row in snapshot["application_consents"]["records"]
            if row.get("source_name") == "oauth2PermissionGrants"}


def test_a_cut_owner_read_has_no_exact_owner_count() -> None:
    fake = _CutPages(
        {"/servicePrincipals/sp-1/owners": [], "/servicePrincipals/sp-2/owners": [{"id": "owner-1"}]},
        lists={"/servicePrincipals": SPS, "/oauth2PermissionGrants": GRANTS},
    )
    assert _owner_counts(_snapshot(fake)) == {"sp-1": None, "sp-2": None}


def test_a_complete_owner_read_keeps_its_exact_owner_count() -> None:
    fake = FakeGraph(lists={"/servicePrincipals": SPS, "/oauth2PermissionGrants": GRANTS,
                            "/servicePrincipals/sp-1/owners": [], "/servicePrincipals/sp-2/owners": [{"id": "owner-1"}]})
    assert _owner_counts(_snapshot(fake)) == {"sp-1": 0, "sp-2": 1}


def test_two_cut_assignment_reads_are_two_distinct_collection_gaps() -> None:
    fake = _CutPages(
        {"/servicePrincipals/sp-1/appRoleAssignedTo": [{"id": "a-1"}],
         "/servicePrincipals/sp-2/appRoleAssignedTo": [{"id": "a-2"}]},
        lists={"/servicePrincipals": SPS, "/oauth2PermissionGrants": GRANTS},
    )
    gaps = [row for row in _snapshot(fake)["collection_gaps"]["records"]
            if row["source"] == "app_consent.servicePrincipalAppRoleAssignments"]
    assert sorted(row["endpoint"] for row in gaps) == [
        "/servicePrincipals/sp-1/appRoleAssignedTo", "/servicePrincipals/sp-2/appRoleAssignedTo"]
    assert len({row["id"] for row in gaps}) == 2
    assert len({row["key"] for row in gaps}) == 2
