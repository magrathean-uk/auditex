"""R032: failed per-object owner and federated-credential reads are recorded gaps, never an 'ok' collector."""
from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.app_credentials import AppCredentialsCollector
from azure_tenant_audit.graph import GraphError

APPS = [{"id": "app-1", "displayName": "One", "appId": "11111111-1111-1111-1111-111111111111"},
        {"id": "app-2", "displayName": "Two", "appId": "22222222-2222-2222-2222-222222222222"}]
SPS = [{"id": "sp-1", "displayName": "One", "appId": "11111111-1111-1111-1111-111111111111"}]


class _Throttled:
    def __init__(self, failing: set[str]) -> None:
        self.failing = failing

    def get_all(self, path: str, params: Any = None) -> list[dict[str, Any]]:
        return {"/applications": APPS, "/servicePrincipals": SPS}.get(path, [])

    def get_json(self, path: str, params: Any = None, full_url: bool = False) -> dict[str, Any]:
        if path in self.failing:
            raise GraphError("Too many requests", status=429, request=path)
        return {"value": [{"id": "owner-1"}] if path.endswith("/owners") else []}


def _row(result, name: str) -> dict[str, Any]:
    return next(row for row in result.coverage if row["name"] == name)


def test_failed_owner_and_federated_reads_make_the_collector_partial() -> None:
    client = _Throttled({"/applications/app-1/owners", "/applications/app-1/federatedIdentityCredentials",
                         "/servicePrincipals/sp-1/owners"})
    result = AppCredentialsCollector().run({"client": client})
    assert result.status == "partial"
    apps = {row["id"]: row for row in result.payload["applicationCredentials"]["value"]}
    assert apps["app-1"]["owner_count"] is None and apps["app-1"]["federated_credentials"] is None
    assert apps["app-2"]["owner_count"] == 1 and apps["app-2"]["federated_credentials"] == []
    for name, failed in (("applicationOwners", 1), ("applicationFederatedCredentials", 1), ("servicePrincipalOwners", 1)):
        row = _row(result, name)
        assert row["status"] == "failed" and row["failed_operation_count"] == failed
        assert row["error_class"] == "graph_http_429"


def test_clean_fanouts_stay_ok() -> None:
    result = AppCredentialsCollector().run({"client": _Throttled(set())})
    assert result.status == "ok"
    assert _row(result, "applicationOwners")["status"] == "ok"
