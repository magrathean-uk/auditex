"""Deep-review regressions for the Google Workspace lane, repair round 1 (review blockers)."""
from __future__ import annotations

from typing import Any

import pytest

from auditex.google_workspace import client as google_client
from auditex.google_workspace.findings import build_google_findings
from auditex.google_workspace.normalize import build_google_normalized_snapshot


class _HttpError(Exception):
    def __init__(self, status: int, message: str | None = None) -> None:
        super().__init__(message or f"HTTP {status}")
        self.resp = type("Resp", (), {"status": status})()


class _Request:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome

    def execute(self) -> Any:
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.fixture(autouse=True)
def _no_backoff_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(google_client, "_sleep", lambda _delay: None, raising=False)


# ---- R011: a deleted alert replayed offline is not active ------------------------------------------------------


def test_r011_deleted_alert_replayed_offline_is_not_active() -> None:
    alert = {"alertId": "a-1", "type": "Suspicious login", "deleted": True,
             "metadata": {"severity": "HIGH", "status": "NOT_STARTED"}}
    snapshot = build_google_normalized_snapshot(
        tenant_name="Example", run_id="run-1", domain="example.com",
        collector_payloads={"google_alert_center": {"alerts": {"value": [alert]}}},
    )
    rule_ids = [str(item.get("rule_id")) for item in build_google_findings(snapshot)]
    assert "google.alert_active" not in rule_ids
