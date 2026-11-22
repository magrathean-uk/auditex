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


# ---- R012: a passed 2-step verification challenge is not a suspicious login --------------------------------


def _login(event: str, *, status: str | None = None) -> dict[str, Any]:
    parameters = [{"name": "login_challenge_status", "value": status}] if status else []
    return {"id": {"uniqueQualifier": f"{event}-{status}"}, "actor": {"email": "user@example.com"},
            "events": [{"name": event, "parameters": parameters}]}


def _login_findings(*activities: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item for item in _findings({"google_reports": {"loginActivities": {"value": list(activities)}}})
        if item.get("rule_id") == "google.login_suspicious_event"
    ]


def test_r012_passed_login_challenge_is_not_suspicious() -> None:
    assert _login_findings(_login("login_challenge", status="Challenge Passed")) == []


def test_r012_failed_login_challenge_is_suspicious() -> None:
    assert len(_login_findings(_login("login_challenge", status="Challenge Failed"))) == 1


@pytest.mark.parametrize(
    "event",
    ["suspicious_login", "suspicious_login_activity", "suspicious_login_less_secure_app", "suspicious_programmatic_login"],
)
def test_r012_google_suspicious_login_events_are_reported(event: str) -> None:
    assert len(_login_findings(_login(event))) == 1


# ---- R013: the broad Gmail scopes are high-risk OAuth grants ------------------------------------------------


def _grant_findings(scopes: list[str]) -> list[dict[str, Any]]:
    payload = {
        "google_directory": {
            "users": {"value": [{"id": "u1", "primaryEmail": "user@example.com"}]},
            "oauthGrants": {"value": [{"userKey": "user@example.com", "clientId": "app-1", "displayText": "App", "scopes": scopes}]},
        }
    }
    return [item for item in _findings(payload) if item.get("rule_id") == "google.oauth_high_risk_scope"]


@pytest.mark.parametrize(
    "scope",
    [
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.compose",
        "https://www.googleapis.com/auth/gmail.insert",
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.sharing",
    ],
)
def test_r013_each_mail_scope_is_a_high_risk_grant(scope: str) -> None:
    assert len(_grant_findings([scope])) == 1


@pytest.mark.parametrize(
    "scope",
    ["https://www.googleapis.com/auth/userinfo.email", "openid", "https://mail.google.com.example.net/"],
)
def test_r013_narrow_or_lookalike_scopes_are_not_high_risk(scope: str) -> None:
    assert _grant_findings([scope]) == []
