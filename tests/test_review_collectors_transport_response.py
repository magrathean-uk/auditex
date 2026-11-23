"""R086: the lab response plane refuses adapters and actions it cannot run, instead of crashing or failing blind."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit.response import (
    ALLOWED_RESPONSE_ADAPTERS,
    ResponseConfig,
    run_response,
)


def _token(tenant_id: str) -> str:
    import base64

    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{part({'alg': 'none'})}.{part({'tid': tenant_id})}.constructed-token"


SESSION = {"kind": "exchange_online", "access_token": _token("lab-tenant"), "organization": "lab.onmicrosoft.com"}


@pytest.fixture(autouse=True)
def _response_on(monkeypatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")


class _Adapter:
    name = "powershell_graph"

    def __init__(self) -> None:
        self.sessions: list[object] = []

    def dependency_check(self) -> bool:
        return True

    def run(self, command, log_event=None, session=None):  # noqa: ANN001, ARG002
        self.sessions.append(session)
        return {"command": command, "value": [], "duration_ms": 1.0}


def _config(tmp_path: Path, **overrides) -> ResponseConfig:
    values = dict(tenant_name="lab", out_dir=tmp_path, tenant_id="lab-tenant", action="message_trace",
                  target="user@example.com", intent="lab check", auditor_profile="exchange-reader", execute=True,
                  allow_lab_response=True, run_name="r")
    values.update(overrides)
    return ResponseConfig(**values)


def _blockers(tmp_path: Path) -> list[dict]:
    return json.loads((tmp_path / "lab-r" / "blockers" / "blockers.json").read_text(encoding="utf-8"))


def test_only_adapters_that_run_commands_are_allowed() -> None:
    assert set(ALLOWED_RESPONSE_ADAPTERS) == {"m365dsc", "powershell_graph"}


def test_teams_rest_override_is_refused_not_a_crash(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    rc = run_response(_config(tmp_path, adapter_override="teams_admin_rest", allow_adapter_override=True,
                              exchange_session=SESSION))
    assert rc == 1
    assert any(row["error_class"] == "response_invalid_adapter_override" for row in _blockers(tmp_path))


def test_purview_export_is_named_retired(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    rc = run_response(_config(tmp_path, action="purview_audit_export", since="2026-01-01T00:00:00Z",
                              until="2026-01-02T00:00:00Z", allow_write=True))
    assert rc == 1
    assert [(row["error_class"], row.get("reason")) for row in _blockers(tmp_path)] == [
        ("toolchain_unavailable", "response_action_retired")]


def test_message_trace_without_an_exchange_session_is_blocked_before_running(tmp_path: Path, monkeypatch) -> None:
    adapter = _Adapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    rc = run_response(_config(tmp_path))
    assert rc == 1
    assert adapter.sessions == []
    assert [(row["error_class"], row["item"]) for row in _blockers(tmp_path)] == [
        ("session_not_connected", "response.session:message_trace")]


def test_message_trace_runs_inside_the_supplied_exchange_session(tmp_path: Path, monkeypatch) -> None:
    adapter = _Adapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    assert run_response(_config(tmp_path, exchange_session=SESSION)) == 0
    assert adapter.sessions == [SESSION]
    assert "constructed-token" not in repr(_config(tmp_path, exchange_session=SESSION))


def test_a_session_token_with_an_out_of_range_expiry_is_refused_not_a_crash(tmp_path: Path, monkeypatch) -> None:
    import base64

    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    token = f"{part({'alg': 'none'})}.{part({'tid': 'lab-tenant', 'exp': 10**30})}.constructed-token"
    adapter = _Adapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})
    rc = run_response(_config(tmp_path, exchange_session={**SESSION, "access_token": token}))
    assert rc == 1
    assert adapter.sessions == []
    assert [(row["error_class"], row["item"]) for row in _blockers(tmp_path)] == [
        ("lab_guard", "response.session:message_trace")]
