"""Deep-review regressions for Google Workspace findings (alerts, logins, OAuth scopes, POP, super admins)."""
from __future__ import annotations

from typing import Any

import pytest

from auditex.google_workspace.findings import build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot


def _findings(payloads: dict[str, Any], **kwargs: Any) -> list[dict[str, Any]]:
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="run-1", collector_payloads=payloads, domain="example.com", **kwargs
    )
    return build_google_findings(snapshot)


def _rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("rule_id")) for item in findings]


# ---- R011: closed or deleted Alert Center alerts are not active -----------------------------------------------


def _alert(alert_id: str, *, status: str | None, deleted: bool | None = None) -> dict[str, Any]:
    alert: dict[str, Any] = {"alertId": alert_id, "type": "Suspicious login", "metadata": {"severity": "HIGH"}}
    if status is not None:
        alert["metadata"]["status"] = status
    if deleted is not None:
        alert["deleted"] = deleted
    return alert


@pytest.mark.parametrize("status", ["CLOSED", "closed"])
def test_r011_closed_alert_is_not_reported_as_active(status: str) -> None:
    findings = _findings({"google_alert_center": {"alerts": {"value": [_alert("a-1", status=status)]}}})
    assert "google.alert_active" not in _rule_ids(findings)


def test_r011_open_alerts_are_still_reported() -> None:
    alerts = [_alert("a-1", status="NOT_STARTED"), _alert("a-2", status="IN_PROGRESS"), _alert("a-3", status=None)]
    findings = _findings({"google_alert_center": {"alerts": {"value": alerts}}})
    assert _rule_ids(findings).count("google.alert_active") == 3


def test_r011_deleted_alert_is_not_collected_as_active() -> None:
    from auditex.google_workspace.client import GoogleWorkspaceClient

    class _Request:
        def execute(self) -> dict[str, Any]:
            return {"alerts": [_alert("a-1", status="NOT_STARTED", deleted=True), _alert("a-2", status="NOT_STARTED")]}

    class _Alerts:
        def list(self, **_kwargs: Any) -> _Request:
            return _Request()

    client = GoogleWorkspaceClient(credentials=None)
    assert client._services is not None
    client._services[("alertcenter", "v1beta1")] = type("S", (), {"alerts": lambda self: _Alerts()})()
    alerts = client.list_alerts()
    assert [alert["alertId"] for alert in alerts] == ["a-2"]
    findings = _findings({"google_alert_center": {"alerts": {"value": list(alerts)}}})
    assert _rule_ids(findings).count("google.alert_active") == 1
