"""R019: a failed or skipped capability-gated read keeps its error in the payload section, so it is never 'collected'."""
from __future__ import annotations

from azure_tenant_audit.collectors.sentinel_xdr import SentinelXdrCollector
from azure_tenant_audit.detection_coverage import build_detection_signals, section_state
from azure_tenant_audit.graph import GraphError

LICENCES = {"licensing": {"subscribedSkus": {"value": [
    {"capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "WINDEFATP", "provisioningStatus": "Success"}]},
]}}}


class _Refusing:
    def get_json(self, path, params=None, full_url=False):
        raise GraphError("Missing role permissions on the request.", status=403, request=path)


def _alert_signal(payload: dict) -> dict:
    rows = build_detection_signals({"sentinel_xdr": payload, **LICENCES})
    return next(row for row in rows if row["name"] == "defender_alert_api")


def test_refused_alerts_read_is_not_collected_and_not_on() -> None:
    result = SentinelXdrCollector().run({"client": _Refusing()})
    assert _alert_signal(result.payload)["status"] != "on"
    section = result.payload["xdrAlerts"]
    assert section["value"] == [] and section["error_class"] == "insufficient_permissions" and section["error"]
    assert section_state({"sentinel_xdr": result.payload}, [], "sentinel_xdr", "xdrAlerts")[0] == "blocked"


def test_skipped_gated_read_carries_its_skip() -> None:
    result = SentinelXdrCollector().run({})
    section = result.payload["xdrAlerts"]
    assert section["status"] == "skipped" and section["error_class"] == "service_not_available" and section["error"]
    assert section_state({"sentinel_xdr": result.payload}, [], "sentinel_xdr", "xdrAlerts")[0] != "collected"
