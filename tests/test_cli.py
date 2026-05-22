from __future__ import annotations

import json
from pathlib import Path
import sys

from azure_tenant_audit import cli
from azure_tenant_audit.collectors.base import CollectorResult


class _IdentityCollector:
    def __init__(self, name: str = "identity") -> None:
        self.name = name

    def run(self, _context: dict) -> CollectorResult:
        return CollectorResult(
            name=self.name,
            status="ok",
            item_count=1,
            message="ok",
            payload={"value": [{"id": "1"}]},
        )


def test_offline_creates_bundle(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = {
        "identity": {"value": [{"id": "1"}]},
        "security": {"value": [{"id": "2"}, {"id": "3"}]},
    }
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_offline(sample_path, tmp_path, "contoso", "run1")
    assert rc == 0

    output_dir = tmp_path / "contoso-run1"
    assert output_dir.exists()
    assert (output_dir / "run-manifest.json").exists()
    assert (output_dir / "summary.json").exists()
    assert (output_dir / "summary.md").exists()
    assert (output_dir / "raw" / "sample_input.json").exists()


def test_main_offline_preserves_plane_and_time_window(tmp_path: Path) -> None:
    sample = {"identity": {"value": [{"id": "1"}]}}
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = cli.main(
        [
            "--tenant-name",
            "contoso",
            "--offline",
            "--sample",
            str(sample_path),
            "--out",
            str(tmp_path),
            "--run-name",
            "offline-plane-test",
            "--auditor-profile",
            "global-reader",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
        ]
    )
    assert rc == 0

    manifest = json.loads((tmp_path / "contoso-offline-plane-test" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["auditor_profile"] == "global-reader"
    assert manifest["plane"] == "full"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"


def test_parser_accepts_waiver_file() -> None:
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--offline",
            "--waiver-file",
            "waivers.json",
        ]
    )

    assert args.waiver_file == "waivers.json"


def test_offline_missing_sample_fails(tmp_path: Path) -> None:
    rc = cli.run_offline(
        tmp_path / "missing.json",
        tmp_path,
        "contoso",
        "run1",
    )
    assert rc == 2


def test_interactive_defaults_tenant_id_to_organizations(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth):
            self.tenant_id = auth.tenant_id

    captured = {}
    class _FakeClientFactory:
        def __new__(cls, auth, **kwargs):  # noqa: ANN001
            captured["tenant_id"] = auth.tenant_id
            return _FakeClient(auth)

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--interactive",
            "--client-id",
            "app-id",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", _FakeClientFactory)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _IdentityCollector()})
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    rc = cli.run_live(args)

    assert rc == 0
    assert captured["tenant_id"] == "organizations"


def test_run_live_logs_run_events(tmp_path: Path, monkeypatch) -> None:
    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
                coverage=[{"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1}],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.audit_event = audit_event

    def _fake_client_factory(auth, **kwargs):
        return _FakeClient(auth, audit_event=kwargs.get("audit_event"))

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--client-id",
            "app-id",
            "--client-secret",
            "secret",
            "--collectors",
            "identity",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
            "--out",
            str(tmp_path),
        ]
    )
    monkeypatch.setattr(cli, "GraphClient", _fake_client_factory)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    rc = cli.run_live(args)
    assert rc == 0
    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs, "run output directory should exist"
    output_dir = output_dirs[0]
    log_path = output_dir / "audit-log.jsonl"
    assert log_path.exists()
    events = [json.loads(line)["event"] for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    assert "run.started" in events
    assert "collector.started" in events
    assert "collector.finished" in events
    assert "run.complete" in events

    output_dir = output_dirs[0]
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["coverage_count"] == 1
    assert manifest["plane"] == "full"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"
    assert (output_dir / "coverage.json").exists()
    assert (output_dir / "index" / "coverage.jsonl").exists()


def test_run_live_writes_auth_context_and_capability_artifacts(tmp_path: Path, monkeypatch) -> None:
    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"users": {"value": [{"id": "1"}]}},
                coverage=[{"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1}],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})
    monkeypatch.setattr(
        cli,
        "_inspect_access_token",
        lambda token: {
            "tenant_id": "tenant-ctx",
            "audience": "https://graph.microsoft.com",
            "delegated_scopes": ["Directory.Read.All", "User.Read.All", "Group.Read.All", "Application.Read.All"],
            "app_roles": [],
            "expires_at_utc": "2030-01-01T00:00:00Z",
        },
    )
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "tenant-ctx",
            "--access-token",
            "token-value",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)

    assert rc == 0
    output_dir = next(tmp_path.glob("acme-*"))
    auth_context = json.loads((output_dir / "normalized" / "auth_context.json").read_text(encoding="utf-8"))
    capability_matrix = json.loads((output_dir / "normalized" / "capability_matrix.json").read_text(encoding="utf-8"))
    coverage_ledger = json.loads((output_dir / "normalized" / "coverage_ledger.json").read_text(encoding="utf-8"))
    live_readiness = json.loads((output_dir / "live-readiness.json").read_text(encoding="utf-8"))
    data_handling = json.loads((output_dir / "data-handling.json").read_text(encoding="utf-8"))
    ai_context = json.loads((output_dir / "ai_context.json").read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    report_pack = json.loads((output_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))

    assert auth_context["auth_mode"] == "access_token"
    assert auth_context["token_claims"]["tenant_id"] == "tenant-ctx"
    assert capability_matrix["records"][0]["collector"] == "identity"
    assert capability_matrix["records"][0]["status"] == "supported_exact_scope"
    assert coverage_ledger["records"][0]["collector"] == "identity"
    assert coverage_ledger["records"][0]["coverage_status"] == "complete_exact_scope"
    assert ai_context["privacy"]["safe_for_external_llm"] is False
    assert manifest["auth_context_path"] == "normalized/auth_context.json"
    assert manifest["capability_matrix_path"] == "normalized/capability_matrix.json"
    assert manifest["coverage_ledger_path"] == "normalized/coverage_ledger.json"
    assert manifest["live_readiness_path"] == "live-readiness.json"
    assert manifest["data_handling_path"] == "data-handling.json"
    assert manifest["ai_context_path"] == "ai_context.json"
    assert live_readiness["trust_level"] == "live_verified"
    assert data_handling["read_only"] is True
    assert data_handling["content_reads"] is False
    assert data_handling["write_actions"] is False
    assert data_handling["scope_risk"] == "read_only_scopes"
    assert data_handling["write_capable_scopes"] == []
    assert "live-readiness.json" in report_pack["evidence_paths"]
    assert "data-handling.json" in report_pack["evidence_paths"]
    assert (output_dir / "index" / "evidence.sqlite").exists()


def test_run_live_app_mode_uses_client_token_claims(tmp_path: Path, monkeypatch) -> None:
    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"users": {"value": [{"id": "1"}]}},
                coverage=[{"collector": "identity", "name": "users", "type": "graph", "status": "ok", "item_count": 1}],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

        def token_claims(self):
            return {
                "tenant_id": "tenant-app",
                "audience": "https://graph.microsoft.com",
                "delegated_scopes": [],
                "app_roles": ["Directory.Read.All"],
                "app_id": "app-id",
            }

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "tenant-app",
            "--client-id",
            "app-id",
            "--client-secret",
            "app-secret",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)

    assert rc == 0
    output_dir = next(tmp_path.glob("acme-*"))
    auth_context = json.loads((output_dir / "normalized" / "auth_context.json").read_text(encoding="utf-8"))
    capability_matrix = json.loads((output_dir / "normalized" / "capability_matrix.json").read_text(encoding="utf-8"))

    assert auth_context["auth_mode"] == "app"
    assert auth_context["token_claims"]["app_roles"] == ["Directory.Read.All"]
    assert capability_matrix["records"][0]["observed_permissions"] == ["Directory.Read.All"]


def test_run_live_applies_waiver_file_to_findings_and_report_pack(tmp_path: Path, monkeypatch) -> None:
    class _FailingCollector:
        name = "security"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="partial",
                item_count=0,
                message="security collector failed",
                error="security collector failed",
                payload={"securityAlerts": {"error": "forbidden"}},
                coverage=[
                    {
                        "collector": "security",
                        "type": "graph",
                        "name": "securityAlerts",
                        "endpoint": "/security/alerts",
                        "status": "failed",
                        "item_count": 0,
                        "error_class": "insufficient_permissions",
                        "error": "Forbidden",
                    }
                ],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    waiver_path = tmp_path / "waivers.json"
    waiver_path.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "rule_id": "collector.issue.permission",
                        "comment": "Expected in delegated-reader tenant",
                        "expires_on": "2099-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(cli, "REGISTRY", {"security": _FailingCollector()})
    monkeypatch.setattr(
        cli,
        "_inspect_access_token",
        lambda token: {
            "tenant_id": "tenant-ctx",
            "audience": "https://graph.microsoft.com",
            "delegated_scopes": ["SecurityEvents.Read.All"],
            "app_roles": [],
            "expires_at_utc": "2030-01-01T00:00:00Z",
        },
    )

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--access-token",
            "token-value",
            "--collectors",
            "security",
            "--waiver-file",
            str(waiver_path),
            "--out",
            str(tmp_path),
        ]
    )

    rc = cli.run_live(args)

    assert rc == 1
    output_dir = next(tmp_path.glob("acme-*"))
    findings = json.loads((output_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    report_pack = json.loads((output_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))

    assert findings[0]["status"] == "accepted_risk"
    assert findings[0]["rule_id"] == "collector.issue.permission"
    assert report_pack["summary"]["accepted_count"] == 1
    assert report_pack["summary"]["open_count"] == 0
    assert report_pack["action_plan"] == []


def test_run_live_applies_collector_preset_and_limits_selected_collectors(tmp_path: Path, monkeypatch) -> None:
    class _IdentityCollector:
        name = "identity"
        run_calls = 0

        def run(self, context):
            self.__class__.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    class _SecurityCollector:
        name = "security"
        run_calls = 0

        def run(self, context):
            self.__class__.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "2"}]},
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(
        cli,
        "load_collector_presets",
        lambda: {
            "identity-only": {
                "description": "Identity only",
                "include": ["identity"],
                "exclude": [],
                "plane": "inventory",
            }
        },
    )
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _IdentityCollector(), "security": _SecurityCollector()})
    monkeypatch.setattr(
        cli,
        "_inspect_access_token",
        lambda token: {
            "tenant_id": "tenant-ctx",
            "audience": "https://graph.microsoft.com",
            "delegated_scopes": ["User.Read"],
            "app_roles": [],
            "expires_at_utc": "2030-01-01T00:00:00Z",
        },
    )

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--access-token",
            "token-value",
            "--collector-preset",
            "identity-only",
            "--out",
            str(tmp_path),
        ]
    )

    rc = cli.run_live(args)

    assert rc == 0
    assert _IdentityCollector.run_calls == 1
    assert _SecurityCollector.run_calls == 0

    output_dir = next(tmp_path.glob("acme-*"))
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))

    assert manifest["collector_preset"] == "identity-only"
    assert manifest["selected_collectors"] == ["identity"]
    assert [row["name"] for row in summary["collectors"]] == ["identity"]


def test_run_live_writes_diagnostics(tmp_path: Path, monkeypatch) -> None:
    class _FailingCollector:
        name = "security"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="partial",
                item_count=0,
                message="security collector failed",
                error="security collector failed",
                payload={"securityAlerts": {"error": "forbidden"}},
                coverage=[
                    {
                        "collector": "security",
                        "type": "graph",
                        "name": "securityAlerts",
                        "endpoint": "/security/alerts",
                        "status": "failed",
                        "item_count": 0,
                        "error_class": "insufficient_permissions",
                        "error": "Forbidden",
                    }
                ],
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth))
    monkeypatch.setattr(cli, "REGISTRY", {"security": _FailingCollector()})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--client-id",
            "app-id",
            "--client-secret",
            "secret",
            "--collectors",
            "security",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 1
    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    output_dir = output_dirs[0]
    diagnostics_path = output_dir / "diagnostics.json"
    assert diagnostics_path.exists()
    diagnostics = json.loads(diagnostics_path.read_text(encoding="utf-8"))
    assert isinstance(diagnostics, list)
    assert diagnostics
    assert diagnostics[0]["collector"] == "security"
    assert diagnostics[0]["recommendations"]["required_graph_scopes"]


def test_run_live_probe_first_skips_known_blocked_collectors(tmp_path: Path, monkeypatch) -> None:
    class _BlockedCollector:
        name = "security"
        run_calls = 0

        def run(self, context):
            self.__class__.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="partial",
                item_count=0,
                message="security blocked",
                payload={"securityAlerts": {"error": "forbidden"}},
                coverage=[
                    {
                        "collector": "security",
                        "type": "graph",
                        "name": "securityAlerts",
                        "endpoint": "/security/alerts",
                        "status": "failed",
                        "item_count": 0,
                        "error_class": "insufficient_permissions",
                        "error": "Forbidden",
                    }
                ],
            )

    class _IdentityCollector:
        name = "identity"
        run_calls = 0

        def run(self, context):
            self.__class__.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
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

    security = _BlockedCollector()
    identity = _IdentityCollector()
    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, audit_event=kwargs.get("audit_event")))
    monkeypatch.setattr(cli, "REGISTRY", {"security": security, "identity": identity})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--client-id",
            "app-id",
            "--client-secret",
            "secret",
            "--collectors",
            "security,identity",
            "--probe-first",
            "--out",
            str(tmp_path),
        ]
    )

    rc = cli.run_live(args)

    assert rc == 1
    assert security.run_calls == 1
    assert identity.run_calls == 2
    output_dir = next(tmp_path.glob("acme-*"))
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    log_lines = (output_dir / "audit-log.jsonl").read_text(encoding="utf-8").splitlines()

    rows = {item["name"]: item for item in summary["collectors"]}
    assert rows["security"]["status"] == "skipped"
    assert rows["identity"]["status"] == "ok"
    assert manifest["overall_status"] == "partial"
    assert manifest["preflight_path"] == "preflight-plan.json"
    assert any('"event": "preflight.completed"' in line for line in log_lines)
    assert any('"event": "collector.skipped"' in line for line in log_lines)


def test_interactive_without_client_id_falls_back_to_azure_cli_token(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.audit_event = audit_event

        def get_json(self, path):
            assert path == "/me"
            return {
                "displayName": "Fallback User",
                "userPrincipalName": "fallback@tenant.local",
                "id": "fallback-user",
            }

        def get_all(self, path, params=None):
            assert path == "/me/memberOf/microsoft.graph.directoryRole"
            return []

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--interactive",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "fallback-token")
    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, audit_event=kwargs.get("audit_event")))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _IdentityCollector()})
    rc = cli.run_live(args)
    assert rc == 0

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "azure_cli"


def test_run_live_with_azure_cli_token_uses_azure_cli_mode(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    def _fake_client_factory(auth, **kwargs):
        return _FakeClient(auth)

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    monkeypatch.setattr(cli, "GraphClient", _fake_client_factory)
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    monkeypatch.setattr(sys, "argv", ["audit", "--tenant-name", "acme", "--tenant-id", "t-123", "--use-azure-cli-token", "--collectors", "identity", "--out", str(tmp_path)])


def test_run_live_resume_skips_completed_collectors(tmp_path: Path, monkeypatch) -> None:
    class _IdentityCollector:
        name = "identity"
        run_calls = 0

        def run(self, context):
            self.__class__.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "identity"}]},
            )

    class _SecurityCollector:
        name = "security"
        run_calls = 0

        def run(self, context):
            self.__class__.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=2,
                message="ok",
                payload={"value": [{"id": "1"}, {"id": "2"}]},
            )

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.audit_event = audit_event

        def get_json(self, path):
            return {}

        def get_all(self, path, params=None):  # noqa: ARG002
            return []

    identity_collector = _IdentityCollector()
    security_collector = _SecurityCollector()

    run_dir = tmp_path / "acme-resume-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "checkpoints").mkdir(exist_ok=True)
    (run_dir / "raw").mkdir(exist_ok=True)
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "collectors": [
                    {
                        "name": "identity",
                        "status": "ok",
                        "item_count": 1,
                        "message": "identity already collected",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "raw" / "identity.json").write_text(
        json.dumps({"users": {"value": [{"id": "identity", "displayName": "Identity User"}]}}),
        encoding="utf-8",
    )
    (run_dir / "checkpoints" / "checkpoint-state.json").write_text(
        json.dumps(
            {
                "run_id": "resume-run",
                "collectors": {
                    "identity": {
                        "status": "ok",
                        "item_count": 1,
                        "message": "previous successful identity",
                        "ts_utc": "2026-04-17T00:00:00Z",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--use-azure-cli-token",
            "--collectors",
            "identity,security",
            "--out",
            str(tmp_path),
            "--resume-from",
            str(run_dir),
        ]
    )

    monkeypatch.setattr(cli, "GraphClient", _FakeClient)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": identity_collector, "security": security_collector})
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")

    rc = cli.run_live(args)

    assert rc == 0
    assert identity_collector.run_calls == 0
    assert security_collector.run_calls == 1

    output_dir = run_dir
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    checkpoint_state = json.loads((output_dir / "checkpoints" / "checkpoint-state.json").read_text(encoding="utf-8"))
    normalized_snapshot = json.loads((output_dir / "normalized" / "snapshot.json").read_text(encoding="utf-8"))
    assert manifest["run_id"] == "resume-run"
    identity_rows = [item for item in summary.get("collectors", []) if item.get("name") == "identity"]
    assert len(identity_rows) == 1
    assert identity_rows[0]["status"] == "ok"
    assert identity_rows[0]["item_count"] == 1
    assert checkpoint_state["collectors"]["identity"]["status"] == "ok"
    assert checkpoint_state["collectors"]["identity"]["item_count"] == 1
    assert not (output_dir / "blockers" / "blockers.json").exists()
    assert normalized_snapshot["collector_count"] == 2
    assert normalized_snapshot["object_counts"]["users"] == 1
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--use-azure-cli-token",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 0

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs


def test_run_live_exchange_can_be_explicitly_selected_without_include_flag(tmp_path: Path, monkeypatch) -> None:
    class _FakeCollector:
        name = "exchange"

        def __init__(self):
            self.run_calls = 0

        def run(self, context):
            self.run_calls += 1
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=0,
                message="ok",
                payload={},
            )

    exchange_collector = _FakeCollector()

    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(cli, "REGISTRY", {"exchange": exchange_collector})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--client-id",
            "app-id",
            "--client-secret",
            "secret",
            "--collectors",
            "exchange",
            "--out",
            str(tmp_path),
        ]
    )

    rc = cli.run_live(args)
    assert rc == 0
    assert exchange_collector.run_calls == 1

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert "exchange" in manifest["selected_collectors"]
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["mode"] == "app"


def test_command_line_redaction_in_manifest_when_access_token_is_on_command_line(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    secret = "super-secret-token"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python3",
            "-m",
            "azure_tenant_audit",
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--access-token",
            secret,
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ],
    )
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--access-token",
            secret,
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 0


def test_azure_cli_run_captures_session_context(tmp_path: Path, monkeypatch) -> None:
    class _FakeClient:
        def __init__(self, auth, audit_event=None):
            self.auth = auth
            self.audit_event = audit_event

        def get_json(self, path):
            assert path == "/me"
            return {
                "displayName": "Example Operator",
                "userPrincipalName": "operator@contoso.test",
                "id": "user-123",
            }

        def get_all(self, path, params=None):
            assert path == "/me/memberOf/microsoft.graph.directoryRole"
            return [
                {"displayName": "Global Administrator"},
                {"displayName": "Global Reader"},
            ]

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "1"}]},
            )

    monkeypatch.setattr(cli, "GraphClient", lambda auth, **kwargs: _FakeClient(auth, **kwargs))
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *_, **__: "cached-token")
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})

    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--tenant-id",
            "t-123",
            "--use-azure-cli-token",
            "--collectors",
            "identity",
            "--out",
            str(tmp_path),
        ]
    )
    rc = cli.run_live(args)
    assert rc == 0

    output_dirs = list(tmp_path.glob("acme-*"))
    assert output_dirs
    manifest = json.loads((output_dirs[0] / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["session_context"]["user_principal_name"] == "operator@contoso.test"
    assert manifest["session_context"]["roles"] == ["Global Administrator", "Global Reader"]


def test_scrub_command_line_redacts_tokens() -> None:
    scrubbed = cli._scrub_command_line(
        [
            "python3",
            "--tenant-name",
            "acme",
            "--access-token",
            "super-secret-token",
            "--client-secret=foo",
            "--collectors=identity",
        ]
    )
    assert scrubbed == [
        "python3",
        "--tenant-name",
        "acme",
        "--access-token",
        "***redacted***",
        "--client-secret=***redacted***",
        "--collectors=identity",
    ]
