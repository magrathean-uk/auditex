from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.probe import ProbeConfig, run_live_probe


class _FakeCollector:
    name = "identity"

    def run(self, _context):
        return CollectorResult(
            name="identity",
            status="ok",
            item_count=1,
            message="ok",
            payload={"users": {"value": [{"id": "1", "displayName": "User One"}]}},
            coverage=[
                {
                    "collector": "identity",
                    "type": "graph",
                    "name": "users",
                    "endpoint": "/users",
                    "status": "ok",
                    "item_count": 1,
                }
            ],
        )


class _FakeClient:
    def __init__(self, auth, audit_event=None):
        self.auth = auth
        self.audit_event = audit_event


def test_probe_live_writes_capability_and_toolchain_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeClient)
    monkeypatch.setattr("azure_tenant_audit.probe._acquire_azure_cli_access_token", lambda *_, **__: "token")
    monkeypatch.setattr(
        "azure_tenant_audit.probe._capture_signed_in_context",
        lambda *_, **__: {"user_principal_name": "auditor@contoso.test", "roles": ["Global Reader"]},
    )
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [
            {
                "collector": "toolchain",
                "surface": "az_cli_graph",
                "type": "toolchain",
                "name": "az_cli_graph",
                "toolchain": "az",
                "status": "supported",
                "item_count": 1,
                "message": "Azure CLI Graph token available",
            }
        ],
    )
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {"identity": _FakeCollector()})

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="tenant-id",
            mode="delegated",
            surface="identity",
            run_name="probe-live",
        )
    )
    assert rc == 0

    run_dir = tmp_path / "contoso-probe-live"
    capability_matrix = json.loads((run_dir / "capability-matrix.json").read_text(encoding="utf-8"))
    toolchain = json.loads((run_dir / "toolchain-readiness.json").read_text(encoding="utf-8"))
    live_readiness = json.loads((run_dir / "live-readiness.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert capability_matrix[0]["surface"] == "identity"
    assert capability_matrix[0]["toolchain"] == "graph"
    assert live_readiness["trust_level"] == "live_verified"
    assert live_readiness["trusted_collectors"] == ["identity"]
    assert toolchain["az_cli_graph"]["status"] == "supported"
    assert manifest["probe_mode"] == "delegated"
    assert manifest["probe_surface"] == "identity"
    assert manifest["capability_matrix_path"] == "capability-matrix.json"
    assert manifest["toolchain_readiness_path"] == "toolchain-readiness.json"
    assert manifest["live_readiness_path"] == "live-readiness.json"
    assert (run_dir / "index" / "evidence.sqlite").exists()


def test_response_probe_requires_lab_guard_but_still_writes_blockers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [],
    )

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="not-lab-tenant",
            auditor_profile="exchange-reader",
            mode="response",
            surface="all",
            run_name="probe-response",
            allow_lab_response=True,
        )
    )
    assert rc == 1

    run_dir = tmp_path / "contoso-probe-response"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    capability_matrix = json.loads((run_dir / "capability-matrix.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert blockers[0]["error_class"] == "lab_guard"
    assert capability_matrix[0]["surface"] == "response.lab_guard"
    assert capability_matrix[0]["status"] == "blocked"
    assert manifest["lab_guard_state"] == "blocked"


def test_delegated_probe_without_token_source_writes_auth_blocker(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [],
    )

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="tenant-id",
            mode="delegated",
            surface="identity",
            run_name="probe-missing-auth",
            use_azure_cli_token=False,
        )
    )
    assert rc == 1

    run_dir = tmp_path / "contoso-probe-missing-auth"
    blockers = json.loads((run_dir / "blockers" / "blockers.json").read_text(encoding="utf-8"))
    assert blockers[0]["collector"] == "probe_auth"
    assert blockers[0]["error_class"] == "unauthenticated"


def test_probe_live_uses_saved_auth_context_and_writes_auth_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeClient)
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [],
    )
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {"identity": _FakeCollector()})
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

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            auth_context="customer-token",
            mode="delegated",
            surface="identity",
            run_name="probe-auth-context",
        )
    )
    assert rc == 0

    run_dir = tmp_path / "contoso-probe-auth-context"
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))

    assert auth_context["name"] == "customer-token"
    assert auth_context["tenant_id"] == "tenant-saved"
    assert auth_context["token_claims"]["delegated_scopes"] == ["Directory.Read.All"]
    assert manifest["auth_path"] == "saved_context"
    assert manifest["auth_context_path"] == "auth-context.json"


def test_probe_live_app_mode_writes_token_claims(tmp_path: Path, monkeypatch) -> None:
    class _FakeAppClient(_FakeClient):
        def token_claims(self):
            return {
                "tenant_id": "tenant-app",
                "audience": "https://graph.microsoft.com",
                "delegated_scopes": [],
                "app_roles": ["AuditLog.Read.All", "Directory.Read.All"],
                "app_id": "app-id",
            }

    monkeypatch.setattr("azure_tenant_audit.probe.GraphClient", _FakeAppClient)
    monkeypatch.setattr(
        "azure_tenant_audit.probe._probe_toolchain_statuses",
        lambda **_: [],
    )
    monkeypatch.setattr("azure_tenant_audit.probe.REGISTRY", {"identity": _FakeCollector()})

    rc = run_live_probe(
        ProbeConfig(
            tenant_name="contoso",
            output_dir=tmp_path,
            tenant_id="tenant-app",
            mode="app",
            client_id="app-id",
            client_secret="app-secret",
            surface="identity",
            run_name="probe-app-context",
        )
    )
    assert rc == 0

    run_dir = tmp_path / "contoso-probe-app-context"
    auth_context = json.loads((run_dir / "auth-context.json").read_text(encoding="utf-8"))
    assert auth_context["auth_mode"] == "app"
    assert auth_context["token_claims"]["app_roles"] == ["AuditLog.Read.All", "Directory.Read.All"]
