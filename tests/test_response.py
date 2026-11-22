from __future__ import annotations

import json
from pathlib import Path

import pytest

from azure_tenant_audit.response import ResponseConfig, run_response


class _FakeAdapter:
    name = "powershell_graph"

    def __init__(self) -> None:
        self.run_calls: list[str] = []

    def dependency_check(self) -> bool:
        return True

    def run(self, command: str, log_event=None, session=None):  # noqa: ANN001, ARG002
        self.run_calls.append(command)
        return {
            "command": command,
            "value": [{"id": "trace-1"}],
            "duration_ms": 1.0,
        }


def test_response_execute_requires_matching_lab_tenant_even_with_allow_flag(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="not-lab-tenant",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            execute=True,
            allow_lab_response=True,
            run_name="response-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []

    run_dir = tmp_path / "contoso-response-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert blockers[0]["error_class"] == "lab_guard"
    assert manifest["overall_status"] == "partial"
    assert manifest["contract_status"] == "valid"
    assert validation["valid"] is True


def test_response_execute_runs_when_lab_guard_is_satisfied(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"lab-tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="lab-tenant",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            execute=True,
            allow_lab_response=True,
            run_name="response-allowed",
            exchange_session={"kind": "exchange_online", "access_token": "constructed", "organization": "lab.onmicrosoft.com"},
        )
    )

    assert rc == 0
    assert adapter.run_calls == ['Get-MessageTrace -RecipientAddress "user@example.com" -StartDate "" -EndDate ""']

    run_dir = tmp_path / "contoso-response-allowed"
    normalized = json.loads((run_dir / "normalized" / "response.json").read_text(encoding="utf-8"))
    ai_context = json.loads((run_dir / "ai_context.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    data_handling = json.loads((run_dir / "data-handling.json").read_text(encoding="utf-8"))
    assert normalized["response"]["ran"] is True
    assert normalized["response"]["adapter"] == "powershell_graph"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert manifest["plane"] == "response"
    assert manifest["data_handling_path"] == "data-handling.json"
    assert data_handling["read_only"] is True
    assert data_handling["write_actions"] is False
    assert data_handling["events"][0]["action"] == "message_trace"
    assert manifest["overall_status"] == "ok"
    assert manifest["contract_status"] == "valid"
    assert ai_context["coverage"]["coverage_row_count"] == 1
    assert validation["valid"] is True


def test_response_refuses_a_saved_auth_context_before_writing_anything(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Saved auth contexts were removed"):
        run_response(ResponseConfig(tenant_name="contoso", out_dir=tmp_path, action="message_trace",
                                    auth_context="customer-token"))
    assert list(tmp_path.iterdir()) == []


def test_response_execute_blocks_command_override_without_explicit_allow(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="tenant",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            allow_lab_response=True,
            command_override='Get-MessageTrace -RecipientAddress "admin"',
            run_name="response-command-override-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []
    run_dir = tmp_path / "contoso-response-command-override-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert blockers[0]["item"] == "response.command_override"
    assert blockers[0]["error_class"] == "response_command_override_disabled"


def test_response_execute_blocks_adapter_override_without_explicit_allow(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="tenant",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            allow_lab_response=True,
            adapter_override="m365dsc",
            run_name="response-adapter-override-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []
    run_dir = tmp_path / "contoso-response-adapter-override-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert blockers[0]["item"] == "response.adapter_override"
    assert blockers[0]["error_class"] == "response_adapter_override_disabled"


def test_response_execute_blocks_write_action_without_allow_write(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="tenant",
            action="user_audit_history",
            target="user@example.com",
            since="2026-01-01T00:00:00Z",
            until="2026-01-02T00:00:00Z",
            intent="review smoke",
            auditor_profile="exchange-reader",
            allow_lab_response=True,
            run_name="response-write-guard-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []
    run_dir = tmp_path / "contoso-response-write-guard-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert any(item["error_class"] == "response_write_guard" for item in blockers)


def test_response_execute_blocks_unsafe_target_field(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="tenant",
            action="message_trace",
            target='user@example.com";Remove-Item "C:\\*',
            intent="review smoke",
            auditor_profile="exchange-reader",
            allow_lab_response=True,
            run_name="response-unsafe-target-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []
    run_dir = tmp_path / "contoso-response-unsafe-target-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert any(item["error_class"] == "response_argument_unsafe" for item in blockers)


def test_response_execute_blocks_malformed_timestamp_field(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant"})

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            tenant_id="tenant",
            action="user_audit_history",
            target="user@example.com",
            since="2026-01-01",
            until="n0t-a-date",
            intent="review smoke",
            auditor_profile="exchange-reader",
            allow_lab_response=True,
            run_name="response-unsafe-timestamps-blocked",
        )
    )

    assert rc == 1
    assert adapter.run_calls == []
    run_dir = tmp_path / "contoso-response-unsafe-timestamps-blocked"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert any(item["error_class"] == "response_argument_malformed" for item in blockers)
