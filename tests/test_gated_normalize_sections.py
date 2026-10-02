"""A7: exercise the new normalize sections for capability-gated collectors.

Each gated collector now flattens a small, structured payload into the
normalized snapshot when the underlying service is provisioned. These tests
feed synthetic payloads (the shape Microsoft Graph returns) and assert the
records make it into the snapshot.
"""
from __future__ import annotations

from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot(collector_payloads: dict[str, object]) -> dict[str, object]:
    return build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=collector_payloads,
    )


def test_power_platform_environments_flatten_to_section() -> None:
    snapshot = _snapshot(
        {
            "power_platform": {
                "environments": {
                    "value": [
                        {
                            "id": "env-1",
                            "name": "default",
                            "display_name": "Default",
                            "environment_sku": "Production",
                            "is_default": True,
                            "created_time": "2025-01-01T00:00:00Z",
                        }
                    ]
                },
                "dlpPolicies": {"value": []},
                "tenantSettings": {"value": []},
            }
        }
    )
    section = snapshot.get("power_platform_environment_objects")
    assert section is not None
    assert section["records"][0]["display_name"] == "Default"
    assert section["records"][0]["is_default"] is True


def test_power_platform_dlp_policies_flatten_to_section() -> None:
    snapshot = _snapshot(
        {
            "power_platform": {
                "environments": {"value": []},
                "dlpPolicies": {
                    "value": [
                        {
                            "id": "dlp-1",
                            "display_name": "Tenant DLP",
                            "environment_type": "AllEnvironments",
                            "business_connector_count": 12,
                            "non_business_connector_count": 4,
                            "blocked_connector_count": 0,
                        }
                    ]
                },
                "tenantSettings": {"value": []},
            }
        }
    )
    section = snapshot.get("power_platform_dlp_policy_objects")
    assert section is not None
    record = section["records"][0]
    assert record["display_name"] == "Tenant DLP"
    assert record["business_connector_count"] == 12


def test_sentinel_xdr_incidents_flatten_to_section() -> None:
    snapshot = _snapshot(
        {
            "sentinel_xdr": {
                "xdrIncidents": {
                    "value": [
                        {
                            "id": "inc-1",
                            "displayName": "Suspicious sign-in",
                            "severity": "high",
                            "status": "active",
                            "classification": "truePositive",
                        }
                    ]
                },
                "xdrAlerts": {"value": []},
            }
        }
    )
    section = snapshot.get("sentinel_xdr_incident_objects")
    assert section is not None
    assert section["records"][0]["severity"] == "high"


def test_defender_cloud_apps_consent_requests_flatten_to_section() -> None:
    snapshot = _snapshot(
        {
            "defender_cloud_apps": {
                "appConsentRequests": {
                    "value": [{"id": "req-1", "appId": "app-1", "createdDateTime": "2026-09-01T00:00:00Z"}]
                },
            }
        }
    )
    section = snapshot.get("defender_cloud_apps_consent_objects")
    assert section is not None
    assert section["records"][0]["app_id"] == "app-1"
    assert snapshot.get("defender_cloud_apps_profile_objects") is None


def test_copilot_admin_settings_flatten_to_section() -> None:
    snapshot = _snapshot(
        {
            "copilot_governance": {
                "copilotAdminSettings": {
                    "value": [
                        {
                            "id": "settings",
                            "enterpriseDataProtection": True,
                            "webGroundingEnabled": False,
                        }
                    ]
                },
                "copilotUsageReports": {"value": []},
            }
        }
    )
    section = snapshot.get("copilot_admin_setting_objects")
    assert section is not None
    record = section["records"][0]
    assert record["enterpriseDataProtection"] is True


def test_gated_sections_absent_when_collector_payload_empty() -> None:
    """Empty source → no section in the snapshot (pruning happens in normalize)."""
    snapshot = _snapshot(
        {
            "power_platform": {
                "environments": {"value": []},
                "dlpPolicies": {"value": []},
                "tenantSettings": {"value": []},
            },
            "sentinel_xdr": {"xdrIncidents": {"value": []}, "xdrAlerts": {"value": []}},
            "defender_cloud_apps": {
                "appConsentRequests": {"value": []},
            },
            "copilot_governance": {
                "copilotAdminSettings": {"value": []},
                "copilotUsageReports": {"value": []},
            },
        }
    )
    assert snapshot.get("power_platform_environment_objects") is None
    assert snapshot.get("sentinel_xdr_incident_objects") is None
    assert snapshot.get("defender_cloud_apps_consent_objects") is None
    assert snapshot.get("copilot_admin_setting_objects") is None
