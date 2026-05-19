from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.response import ResponseConfig, run_response


class _FakeAdapter:
    name = "powershell_graph"

    def __init__(self) -> None:
        self.run_calls: list[str] = []

    def dependency_check(self) -> bool:
        return True

    def run(self, command: str, log_event=None):  # noqa: ANN001, ARG002
        self.run_calls.append(command)
        return {
            "command": command,
            "value": [{"id": "trace-1"}],
            "duration_ms": 1.0,
        }


def _jwt(payload: dict[str, object]) -> str:
    import base64

    def _encode(value: dict[str, object]) -> str:
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_encode({'alg': 'none', 'typ': 'JWT'})}.{_encode(payload)}.sig"


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
        )
    )

    assert rc == 0
    assert adapter.run_calls == ['Get-MessageTrace -RecipientAddress "user@example.com" -StartDate "" -EndDate ""']

    run_dir = tmp_path / "contoso-response-allowed"
    normalized = json.loads((run_dir / "normalized" / "response.json").read_text(encoding="utf-8"))
    ai_context = json.loads((run_dir / "ai_context.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert normalized["response"]["ran"] is True
    assert normalized["response"]["adapter"] == "powershell_graph"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert manifest["plane"] == "response"
    assert manifest["overall_status"] == "ok"
    assert manifest["contract_status"] == "valid"
    assert ai_context["coverage"]["coverage_row_count"] == 1
    assert validation["valid"] is True


def test_response_execute_uses_jwt_saved_auth_context_and_writes_auth_artifact(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant-saved"})
    monkeypatch.setattr(
        "auditex.auth.resolve_auth_context",
        lambda name=None: {
            "name": name or "customer-token",
            "auth_type": "imported_token",
            "tenant_id": "tenant-saved",
            "token": _jwt(
                {
                    "tid": "tenant-saved",
                    "aud": "https://graph.microsoft.com",
                    "scp": "Directory.Read.All",
                    "upn": "reader@contoso.test",
                    "exp": 1893456000,
                }
            ),
            "token_claims": {
                "tenant_id": "tenant-saved",
                "audience": "https://graph.microsoft.com",
                "delegated_scopes": ["Directory.Read.All"],
                "app_roles": [],
                "user_principal_name": "reader@contoso.test",
                "expires_at_utc": "2030-01-01T00:00:00Z",
            },
        },
    )

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            tenant_id=None,
            auth_context="customer-token",
            execute=True,
            allow_lab_response=True,
            run_name="response-auth-context",
        )
    )

    assert rc == 0
    run_dir = tmp_path / "contoso-response-auth-context"
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert auth_context["name"] == "customer-token"
    assert auth_context["tenant_id"] == "tenant-saved"
    assert auth_context["token_claims"]["delegated_scopes"] == ["Directory.Read.All"]
    assert manifest["tenant_id"] == "tenant-saved"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    assert manifest["auth_context_path"] == "auth-context.json"
    assert manifest["contract_status"] == "valid"
    assert validation["valid"] is True
    assert (run_dir / "index" / "evidence.sqlite").exists()


def test_response_execute_uses_saved_auth_context_and_writes_auth_artifact(tmp_path: Path, monkeypatch) -> None:
    adapter = _FakeAdapter()
    monkeypatch.setattr("azure_tenant_audit.response.get_adapter", lambda _name: adapter)
    monkeypatch.setattr("azure_tenant_audit.response._lab_tenant_ids", lambda: {"tenant-saved"})
    monkeypatch.setattr(
        "auditex.auth.resolve_auth_context",
        lambda name=None: {
            "name": name or "customer-token",
            "auth_type": "imported_token",
            "tenant_id": "tenant-saved",
            "token": "saved-token",
            "token_claims": {
                "tenant_id": "tenant-saved",
                "audience": "https://graph.microsoft.com",
                "delegated_scopes": ["Directory.Read.All"],
                "app_roles": [],
                "user_principal_name": "reader@contoso.test",
                "expires_at_utc": "2030-01-01T00:00:00Z",
            },
        },
    )

    rc = run_response(
        ResponseConfig(
            tenant_name="contoso",
            out_dir=tmp_path,
            auth_context="customer-token",
            action="message_trace",
            target="user@example.com",
            intent="review smoke",
            auditor_profile="exchange-reader",
            allow_lab_response=True,
            run_name="response-auth-context",
        )
    )

    assert rc == 0

    run_dir = tmp_path / "contoso-response-auth-context"
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert auth_context["name"] == "customer-token"
    assert auth_context["auth_type"] == "imported_token"
    assert auth_context["tenant_id"] == "tenant-saved"
    assert auth_context["token_claims"]["delegated_scopes"] == ["Directory.Read.All"]
    assert manifest["auth_context_path"] == "auth-context.json"
    assert manifest["session_context_path"] == "session-context.json"
    assert manifest["session_context"]["tenant_id"] == "tenant-saved"
    assert (run_dir / "session-context.json").exists()


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
