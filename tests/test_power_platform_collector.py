from __future__ import annotations

from typing import Any

from azure_tenant_audit.collectors.power_platform import PowerPlatformCollector


class _FakeBapClient:
    def __init__(
        self,
        *,
        environments: list[dict[str, Any]] | Exception | None = None,
        dlp_policies: list[dict[str, Any]] | Exception | None = None,
        tenant_settings: dict[str, Any] | Exception | None = None,
    ) -> None:
        self._environments = environments
        self._dlp_policies = dlp_policies
        self._tenant_settings = tenant_settings
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        self.calls.append(path)
        if path.endswith("/environments"):
            if isinstance(self._environments, Exception):
                raise self._environments
            return {"value": list(self._environments or [])}
        if path.endswith("/policies"):
            if isinstance(self._dlp_policies, Exception):
                raise self._dlp_policies
            return {"value": list(self._dlp_policies or [])}
        if path.endswith("listTenantSettings"):
            if isinstance(self._tenant_settings, Exception):
                raise self._tenant_settings
            return self._tenant_settings or {}
        raise AssertionError(f"unexpected path: {path}")


def test_collector_returns_environments_and_dlp_policies() -> None:
    client = _FakeBapClient(
        environments=[
            {
                "name": "default",
                "properties": {
                    "displayName": "Default",
                    "environmentSku": "Default",
                    "isDefault": True,
                    "createdTime": "2024-01-01T00:00:00Z",
                },
            }
        ],
        dlp_policies=[
            {
                "name": "policy-1",
                "displayName": "Tenant DLP",
                "environmentType": "AllEnvironments",
                "connectorGroups": [
                    {"classification": "Business", "connectors": [{"name": "shared_office365"}]},
                    {"classification": "NonBusiness", "connectors": []},
                    {"classification": "Blocked", "connectors": [{"name": "shared_twitter"}]},
                ],
            }
        ],
        tenant_settings={"isPowerAppsEnabled": True},
    )

    collector = PowerPlatformCollector()
    result = collector.run({"power_platform_client": client, "top": 100})

    assert result.status == "ok"
    envs = result.payload["environments"]["value"]
    assert envs[0]["name"] == "default"
    policies = result.payload["dlpPolicies"]["value"]
    assert policies[0]["business_connector_count"] == 1
    assert policies[0]["blocked_connector_count"] == 1


def test_collector_marks_capability_unavailable_when_token_missing() -> None:
    collector = PowerPlatformCollector()
    result = collector.run({"power_platform_client": None, "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    assert all(row["status"] == "skipped" or row["status"] == "failed" for row in coverage)
    assert any(row.get("error_class") == "service_not_available" for row in coverage)


def test_collector_records_403_as_insufficient_permissions() -> None:

    class _Forbidden(Exception):
        pass

    client = _FakeBapClient(
        environments=_Forbidden("403 forbidden"),
        dlp_policies=[],
        tenant_settings={},
    )

    collector = PowerPlatformCollector()
    result = collector.run({"power_platform_client": client, "top": 100})

    assert result.status == "partial"
    coverage = result.coverage or []
    failed = [row for row in coverage if row["status"] == "failed"]
    assert failed and failed[0]["error_class"] in {"client_error", "service_not_available"}


def test_collector_handles_no_environments_gracefully() -> None:
    client = _FakeBapClient(environments=[], dlp_policies=[], tenant_settings={})
    collector = PowerPlatformCollector()
    result = collector.run({"power_platform_client": client, "top": 100})

    assert result.status == "ok"
    assert result.payload["environments"]["value"] == []
    assert result.payload["dlpPolicies"]["value"] == []
