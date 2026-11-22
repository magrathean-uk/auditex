"""R030/R045: a failed next page of a $batch fan-out item is a recorded gap on that object, not a crashed collector."""
from __future__ import annotations

from typing import Any

from graph_fakes import FakeGraph

from azure_tenant_audit.collectors.app_consent import AppConsentCollector
from azure_tenant_audit.collectors.intune_depth import IntuneDepthCollector
from azure_tenant_audit.collectors.sharepoint_access import SharePointAccessCollector
from azure_tenant_audit.graph import GRAPH_ROOT, GraphError

NEXT = f"{GRAPH_ROOT}/synthetic-next-page?$skiptoken=1"


class _NextPageFails(FakeGraph):
    """Answers the fan-out item ``paged`` with one row and a next link whose page fails with 503."""

    def __init__(self, paged: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.paged = paged

    def get_batch(self, requests):
        out = super().get_batch(requests)
        for request, item in zip(requests, out, strict=True):
            if request["path"] == self.paged:
                item.update(status=200, body={"value": [{"id": "first-page-row"}], "@odata.nextLink": NEXT})
        return out

    def iter_items(self, path, params=None, result_limit=None):
        if path == NEXT:
            def failing():
                yield {"id": "second-page-row"}
                raise GraphError("Service unavailable", status=503, request=path)
            return failing()
        return super().iter_items(path, params=params, result_limit=result_limit)


def _row(result, name: str, **match: str) -> dict[str, Any]:
    return next(r for r in result.coverage if r["name"] == name and all(r.get(k) == v for k, v in match.items()))


def test_app_consent_keeps_its_evidence_when_a_fanout_next_page_fails() -> None:
    fake = _NextPageFails(
        "/servicePrincipals/sp-1/appRoleAssignedTo",
        lists={"/servicePrincipals": [{"id": "sp-1", "appId": "app-1", "displayName": "One", "accountEnabled": True}],
               "/oauth2PermissionGrants": [{"id": "g-1", "clientId": "sp-1", "resourceId": "sp-1", "scope": "User.Read"}],
               "/servicePrincipals/sp-1/owners": []},
    )
    result = AppConsentCollector().run({"client": fake, "top": None})
    assert result.payload["servicePrincipals"]["value"] and result.payload["oauth2PermissionGrants"]["value"]
    row = _row(result, "servicePrincipalAppRoleAssignments")
    assert row["status"] == "failed" and row["error_class"] == "graph_transient"
    assert row["collection_truncated"] is True and row["truncation_reason"] == "pagination_failed"
    entry = result.payload["servicePrincipalAppRoleAssignments"]["value"][0]
    assert [a["id"] for a in entry["assignments"]] == ["first-page-row", "second-page-row"]
    assert entry["collection_truncated"] is True
    assert result.status == "partial"


def test_intune_depth_keeps_its_sections_when_an_assignment_next_page_fails() -> None:
    fake = _NextPageFails(
        "/deviceManagement/deviceConfigurations/cfg-1/assignments",
        lists={"/deviceManagement/deviceConfigurations": [{"id": "cfg-1", "displayName": "Baseline"}],
               "/deviceManagement/deviceManagementScripts": [{"id": "script-1"}]},
    )
    result = IntuneDepthCollector().run({"client": fake, "top": None})
    assert result.payload["deviceConfigurations"]["value"]
    row = _row(result, "deviceConfigurationAssignments", policy_id="cfg-1")
    assert row["status"] == "failed" and row["truncation_reason"] == "pagination_failed"
    # Assignment reads are section-scoped by design: the unassigned-policy rule reports their gap itself.
    assert row.get("section_scoped") is True


def test_sharepoint_access_keeps_its_sections_when_a_permission_next_page_fails() -> None:
    fake = _NextPageFails(
        "/sites/site-1/permissions",
        lists={"/sites": [{"id": "site-1", "displayName": "Team", "webUrl": "https://contoso.sharepoint.com/sites/team"}]},
        objects={"/admin/sharepoint/settings": {"sharingCapability": "externalUserSharingOnly"}},
    )
    result = SharePointAccessCollector().run({"client": fake, "top": None})
    assert result.payload["sites"]["value"]
    row = _row(result, "sitePermissions", site_id="site-1")
    assert row["status"] == "failed" and row["truncation_reason"] == "pagination_failed"
    assert result.status == "partial"
