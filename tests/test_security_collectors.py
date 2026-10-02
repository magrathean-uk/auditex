from __future__ import annotations

from azure_tenant_audit.collectors.conditional_access import ConditionalAccessCollector
from azure_tenant_audit.collectors.defender import DefenderCollector
from azure_tenant_audit.collectors.security import SecurityCollector
from azure_tenant_audit.graph import GraphError


class _SecurityClient:
    def __init__(self) -> None:
        self.calls: dict[str, dict[str, str]] = {}

    def get_all(self, path, params=None):  # noqa: ANN001
        self.calls[path] = dict(params or {})
        if path == "/auditLogs/signIns":
            return [{"id": "si-1"}]
        if path == "/auditLogs/directoryAudits":
            return [{"id": "da-1"}]
        if path == "/identity/conditionalAccess/policies":
            return [{"id": "ca-1"}]
        if path == "/identity/conditionalAccess/namedLocations":
            return [{"id": "nl-1"}]
        if path == "/policies/authenticationStrengthPolicies":
            return [{"id": "as-1"}]
        if path == "/identity/conditionalAccess/authenticationContextClassReferences":
            return [{"id": "ac-1"}]
        if path == "/security/alerts_v2":
            return [{"id": "alert-1"}]
        if path == "/security/incidents":
            return [{"id": "incident-1"}]
        if path == "/security/secureScores":
            return [{"id": "score-1"}]
        if path == "/security/secureScoreControlProfiles":
            return [{"id": "control-1"}]
        raise AssertionError(f"unexpected path: {path}")

    def get_json(self, path, params=None):  # noqa: ANN001
        values = self.get_all(path, params=params)
        if isinstance(values, list):
            return {"value": values}
        if isinstance(values, dict):
            return values
        return {"value": []}


def test_security_collector_collects_sign_ins_and_directory_audits_and_time_filters() -> None:
    client = _SecurityClient()
    collector = SecurityCollector()

    result = collector.run(
        {
            "client": client,
            "top": 250,
            "since": "2026-04-01T00:00:00Z",
            "until": "2026-04-02T00:00:00Z",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert result.payload["signIns"]["value"][0]["id"] == "si-1"
    assert result.payload["directoryAudits"]["value"][0]["id"] == "da-1"
    assert "createdDateTime ge 2026-04-01T00:00:00Z" in client.calls["/auditLogs/signIns"]["$filter"]
    assert "activityDateTime ge 2026-04-01T00:00:00Z" in client.calls["/auditLogs/directoryAudits"]["$filter"]


def test_security_collector_marks_partial_when_directory_audits_are_blocked() -> None:
    class _PartialSecurityClient(_SecurityClient):
        def get_all(self, path, params=None):  # noqa: ANN001
            if path == "/auditLogs/directoryAudits":
                raise GraphError("Forbidden", status=403)
            return super().get_all(path, params=params)

    collector = SecurityCollector()
    result = collector.run({"client": _PartialSecurityClient(), "top": 100, "audit_logger": None})

    assert result.status == "partial"
    failed_items = [row for row in (result.coverage or []) if row["status"] != "ok"]
    assert any(row["name"] == "directoryAudits" for row in failed_items)


def test_defender_collector_collects_security_alerts_incidents_scores_and_time_filters() -> None:
    client = _SecurityClient()
    collector = DefenderCollector()

    result = collector.run(
        {
            "client": client,
            "top": 200,
            "since": "2026-04-01T00:00:00Z",
            "until": "2026-04-02T00:00:00Z",
            "audit_logger": None,
        }
    )

    assert result.status == "ok"
    assert result.payload["securityAlerts"]["value"][0]["id"] == "alert-1"
    assert result.payload["defenderIncidents"]["value"][0]["id"] == "incident-1"
    assert result.payload["secureScores"]["value"][0]["id"] == "score-1"
    assert result.payload["secureScoreControlProfiles"]["value"][0]["id"] == "control-1"
    assert "createdDateTime ge 2026-04-01T00:00:00Z" in client.calls["/security/incidents"]["$filter"]


def test_defender_collector_marks_partial_for_blocked_incident_surfaces() -> None:
    class _BlockedDefenderClient(_SecurityClient):
        def get_all(self, path, params=None):  # noqa: ANN001
            if path in {"/security/incidents", "/security/secureScoreControlProfiles"}:
                raise GraphError("Forbidden", status=403)
            return super().get_all(path, params=params)

        def get_json(self, path, params=None):  # noqa: ANN001
            if path in {"/security/incidents", "/security/secureScoreControlProfiles"}:
                raise GraphError("Forbidden", status=403)
            return super().get_json(path, params=params)

    collector = DefenderCollector()
    result = collector.run({"client": _BlockedDefenderClient(), "top": 100, "audit_logger": None})

    assert result.status == "partial"
    failed_items = {
        row["name"]: row["error_class"]
        for row in (result.coverage or [])
        if row["status"] != "ok"
    }
    assert failed_items["defenderIncidents"] == "insufficient_permissions"
    assert failed_items["secureScoreControlProfiles"] == "insufficient_permissions"


def test_conditional_access_collector_collects_policy_dependency_surfaces() -> None:
    client = _SecurityClient()
    collector = ConditionalAccessCollector()

    result = collector.run({"client": client, "top": 100, "audit_logger": None})

    assert result.status == "ok"
    assert result.payload["conditionalAccessPolicies"]["value"][0]["id"] == "ca-1"
    assert result.payload["namedLocations"]["value"][0]["id"] == "nl-1"
    assert result.payload["authenticationStrengthPolicies"]["value"][0]["id"] == "as-1"
    assert result.payload["authenticationContextClassReferences"]["value"][0]["id"] == "ac-1"
