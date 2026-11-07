from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

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


def test_parser_supports_version_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("azure_tenant_audit.cli.package_version_line", lambda name="auditex": f"{name} 9.9.9")

    with pytest.raises(SystemExit) as excinfo:
        cli.build_parser().parse_args(["--version"])

    assert excinfo.value.code == 0


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
            "delegated_scopes": [
                "Directory.Read.All",
                "User.Read.All",
                "Group.Read.All",
                "Application.Read.All",
                "AuditLog.Read.All",
            ],
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
    assert manifest["provider_adapter_version"] == "2026-05-31"
    assert manifest["api_inventory_recorder_version"] == "2026-05-31"
    assert live_readiness["trust_level"] == "live_verified"
    assert data_handling["read_only"] is True
    assert data_handling["content_reads"] is False
    assert data_handling["write_actions"] is False
    assert data_handling["scope_risk"] == "read_only_scopes"
    assert data_handling["write_capable_scopes"] == []
    assert "live-readiness.json" in report_pack["evidence_paths"]
    assert "data-handling.json" in report_pack["evidence_paths"]
    assert (output_dir / "index" / "evidence.sqlite").exists()


def test_live_run_does_not_trust_teams_when_every_read_is_skipped(tmp_path: Path, monkeypatch) -> None:
    from auditex.gate import gate_findings
    from azure_tenant_audit.collectors.teams_policy import TeamsPolicyCollector

    class Identity:
        name = "identity"

        def run(self, _context):
            return CollectorResult(
                name=self.name, status="ok", item_count=1, message="ok",
                payload={"users": {"value": [{"id": "1"}]}},
                coverage=[{"collector": "identity", "type": "graph", "name": "users", "status": "ok", "item_count": 1}],
            )

    def no_adapter(_name):
        raise AssertionError("Teams adapter should not run without a certificate token")

    monkeypatch.setattr(cli, "GraphClient", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"identity": Identity(), "teams_policy": TeamsPolicyCollector()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    monkeypatch.setattr("azure_tenant_audit.collectors.teams_policy.get_adapter", no_adapter)
    args = cli.build_parser().parse_args([
        "--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
        "--collectors", "identity,teams_policy", "--out", str(tmp_path), "--run-name", "skipped",
    ])

    assert cli.run_live(args) == 0
    run_dir = tmp_path / "fixture-skipped"
    summary = json.loads((run_dir / "summary.json").read_text())
    coverage = json.loads((run_dir / "coverage.json").read_text())
    readiness = json.loads((run_dir / "live-readiness.json").read_text())
    plan = json.loads((run_dir / "audit-plan.json").read_text())
    teams_rows = [row for row in coverage if row["collector"] == "teams_policy"]

    assert len(teams_rows) == 7
    assert all(row["status"] == "skipped" and row["error_class"] == "teams_token_unavailable" for row in teams_rows)
    assert next(row for row in summary["collectors"] if row["name"] == "teams_policy")["status"] == "ok"
    assert summary["overall_status"] == "ok"
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "pass"
    assert readiness["trust_level"] == "partial"
    assert readiness["trusted_collectors"] == ["identity"]
    assert readiness["unverified_collectors"] == ["teams_policy"]
    assert readiness["cannot_trust"] == ["teams_policy"]
    assert readiness["statement"] != "Live evidence is verified for all selected collectors."
    assert plan["quality_gate"]["trusted_gate_count"] == 1
    assert plan["quality_gate"]["status"] == "partial"
    assert readiness["evidence_gates"] == plan["evidence_gates"]
    manifest = json.loads((run_dir / "run-manifest.json").read_text())
    assert plan["quality_gate"]["reasons"] == ["coverage gap: " + manifest["coverage_gaps"][0]["message"]]

    from auditex.exporters import run_exporter
    from auditex.mcp_server import summarize_run
    from auditex.notify import send_notification
    from auditex.reporting import enterprise_handoff, permissions_ledger

    assert enterprise_handoff(run_dir)["quality"]["live_readiness"] == "partial"
    permissions = {row["collector"]: row for row in permissions_ledger(run_dir)["collectors"]}
    assert permissions["teams_policy"]["status"] == "unverified"
    assert summarize_run(str(run_dir))["live_readiness"]["cannot_trust"] == ["teams_policy"]
    notification = send_notification(run_dir=str(run_dir), sink="teams", dry_run=True)
    assert notification["payload"]["live_readiness"]["trust_level"] == "partial"
    export_path = tmp_path / "report.json"
    run_exporter(name="json", run_dir=str(run_dir), include_sections=["summary"], output_path=str(export_path))
    assert json.loads(export_path.read_text())["sections"]["summary"]["live_readiness"]["cannot_trust"] == ["teams_policy"]


def test_explorer_marks_unscoped_all_skipped_reads_unverified(tmp_path: Path, monkeypatch) -> None:
    from auditex.explorer import _collector_rows

    class Skipped:
        name = "identity"

        def run(self, _context):
            return CollectorResult(
                name=self.name, status="ok", item_count=0, payload={},
                coverage=[{"collector": self.name, "type": "graph", "name": "users", "status": "skipped",
                           "item_count": 0, "error_class": "not_applicable"}],
            )

    monkeypatch.setattr(cli, "GraphClient", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"identity": Skipped()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    args = cli.build_parser().parse_args([
        "--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
        "--collectors", "identity", "--out", str(tmp_path), "--run-name", "unscoped",
    ])
    assert cli.run_live(args) == 0
    run_dir = tmp_path / "fixture-unscoped"
    manifest = json.loads((run_dir / "run-manifest.json").read_text())
    readiness = json.loads((run_dir / "live-readiness.json").read_text())
    plan = json.loads((run_dir / "audit-plan.json").read_text())
    assert readiness["trust_level"] == "setup_only"
    assert readiness["unverified_collectors"] == ["identity"]
    assert plan["quality_gate"]["status"] == "complete"
    assert plan["quality_gate"]["human_reviewer_required"] is False
    assert plan["quality_gate"]["trusted_gate_count"] == 0
    assert plan["quality_gate"]["reasons"] == []
    assert _collector_rows(run_dir, manifest, {})[0]["status"] == "not_verified"


def test_explorer_recognises_successful_empty_read_with_a_skipped_section(tmp_path: Path, monkeypatch) -> None:
    from auditex.explorer import _collector_rows
    from azure_tenant_audit.collection_gaps import IPPS_SKIP_TEXT

    class EmptyRead:
        name = "identity"

        def run(self, _context):
            return CollectorResult(name=self.name, status="ok", item_count=0, payload={}, coverage=[
                {"collector": self.name, "type": "graph", "name": "users", "status": "ok", "item_count": 0},
                {"collector": self.name, "type": "command", "name": "optional", "status": "skipped", "item_count": 0,
                 "section_scoped": True, "reason": "ipps_session_not_opened", "error_class": "ipps_session_not_opened"},
            ])

    monkeypatch.setattr(cli, "GraphClient", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"identity": EmptyRead()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    args = cli.build_parser().parse_args([
        "--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
        "--collectors", "identity", "--out", str(tmp_path), "--run-name", "empty-mixed",
    ])
    assert cli.run_live(args) == 0
    run_dir = tmp_path / "fixture-empty-mixed"
    manifest = json.loads((run_dir / "run-manifest.json").read_text())
    readiness = json.loads((run_dir / "live-readiness.json").read_text())
    assert readiness["trust_level"] == "live_verified"
    row = _collector_rows(run_dir, manifest, {})[0]
    assert row["status"] == "verified"
    assert row["reason"] == IPPS_SKIP_TEXT


def test_resume_does_not_trust_stale_success_after_all_reads_are_skipped(tmp_path: Path, monkeypatch) -> None:
    class Rerun:
        name = "identity"
        calls = 0

        def run(self, _context):
            self.calls += 1
            if self.calls == 1:
                rows = [
                    {"collector": self.name, "type": "graph", "name": "users", "status": "ok", "item_count": 1},
                    {"collector": self.name, "type": "graph", "name": "groups", "status": "failed", "item_count": 0},
                ]
                return CollectorResult(name=self.name, status="partial", item_count=1, payload={}, coverage=rows)
            rows = [{"collector": self.name, "type": "graph", "name": "users", "status": "skipped", "item_count": 0}]
            return CollectorResult(name=self.name, status="ok", item_count=0, payload={}, coverage=rows)

    monkeypatch.setattr(cli, "GraphClient", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "REGISTRY", {"identity": Rerun()})
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    argv = ["--tenant-name", "fixture", "--tenant-id", "constructed", "--access-token", "constructed",
            "--collectors", "identity", "--out", str(tmp_path), "--run-name", "resume-trust"]
    run_dir = tmp_path / "fixture-resume-trust"

    assert cli.run_live(cli.build_parser().parse_args(argv)) == 1
    assert cli.run_live(cli.build_parser().parse_args([*argv, "--resume-from", str(run_dir)])) == 0
    readiness = json.loads((run_dir / "live-readiness.json").read_text())
    coverage = json.loads((run_dir / "coverage.json").read_text())
    assert readiness["trust_level"] == "setup_only"
    assert readiness["unverified_collectors"] == ["identity"]
    assert [row["status"] for row in coverage] == ["skipped"]


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


@pytest.mark.parametrize("flag", ["--access-token", "--client-secret"])
@pytest.mark.parametrize("inline", [False, True])
def test_command_line_redaction_in_manifest_and_logs(tmp_path: Path, monkeypatch, flag: str, inline: bool) -> None:
    class _FakeClient:
        def __init__(self, auth, **kwargs):
            self.auth = auth

    class _FakeCollector:
        name = "identity"

        def run(self, context):
            return CollectorResult(
                name=self.name,
                status="ok",
                item_count=1,
                message="ok",
                payload={"value": [{"id": "constructed-identity"}]},
            )

    # Exercise main -> run_live -> real bundle finalisation, with auth and all
    # tenant reads replaced by constructed adapters. No sign-in or API calls.
    for name in ("AZURE_CLIENT_SECRET", "AZURE_ACCESS_TOKEN", "AZURE_TENANT_ID", "AZURE_CLIENT_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "GraphClient", _FakeClient)
    monkeypatch.setattr(cli, "REGISTRY", {"identity": _FakeCollector()})
    canary = "constructed-canary-argv-zz9"
    credentials = [f"{flag}={canary}"] if inline else [flag, canary]
    argv = [
        "--tenant-name", "constructed", "--tenant-id", "constructed-tenant",
        "--client-id", "constructed-app", *credentials, "--collectors", "identity",
        "--out", str(tmp_path), "--run-name", "canary",
    ]
    assert cli.main(argv) == 0

    output_dir = tmp_path / "constructed-canary"
    manifest = json.loads((output_dir / "run-manifest.json").read_text(encoding="utf-8"))
    command_line = manifest["command_line"]
    assert command_line[:1] == ["azure-tenant-audit"]
    if inline:
        assert f"{flag}=***redacted***" in command_line
    else:
        assert command_line[command_line.index(flag) + 1] == "***redacted***"
    assert (output_dir / "audit-log.jsonl").is_file()
    for path in output_dir.rglob("*"):
        if path.is_file():
            assert canary.encode() not in path.read_bytes(), str(path.relative_to(output_dir))


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


@pytest.mark.parametrize("resume", [False, True], ids=["fresh", "resume"])
@pytest.mark.parametrize("include_other", [False, True], ids=["pair", "context-isolation"])
def test_run_live_dns_accepted_domain_handoff(tmp_path: Path, monkeypatch, resume, include_other) -> None:
    envelope = {"value": [{"DomainName": "Contoso.com", "IsCoexistenceDomain": False}]}
    calls = []
    contexts = {}

    class _Collector:
        def __init__(self, name):
            self.name = name

        def run(self, context):
            calls.append(self.name)
            contexts[self.name] = dict(context)
            payload = {"acceptedDomains": envelope} if self.name == "exchange_policy" else {}
            return CollectorResult(name=self.name, status="ok", item_count=1, message="ok", payload=payload)

    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def get_json(self, *args, **kwargs):
            return {}

        def get_all(self, *args, **kwargs):
            return []

    monkeypatch.setattr(cli, "GraphClient", _Client)
    monkeypatch.setattr(cli, "REGISTRY", {
        name: _Collector(name) for name in ("dns_posture", "exchange_policy", "identity")
    })
    # An explicit token and fake client keep this orchestration test entirely offline.
    argv = ["--tenant-name", "fixture", "--tenant-id", "tenant-id", "--access-token", "constructed-token",
            "--collectors", "dns_posture,exchange_policy" + (",identity" if include_other else ""),
            "--out", str(tmp_path), "--run-name", "handoff"]
    if resume:
        run_dir = tmp_path / "fixture-handoff"
        (run_dir / "raw").mkdir(parents=True)
        (run_dir / "checkpoints").mkdir()
        (run_dir / "raw/exchange_policy.json").write_text(json.dumps({"acceptedDomains": envelope}))
        (run_dir / "summary.json").write_text(json.dumps({"collectors": [
            {"name": "exchange_policy", "status": "ok", "item_count": 1, "message": "ok"}
        ]}))
        (run_dir / "checkpoints/checkpoint-state.json").write_text(json.dumps({
            "run_id": "handoff", "collectors": {"exchange_policy": {
                "status": "ok", "item_count": 1, "message": "ok",
            }},
        }))
        argv += ["--resume-from", str(run_dir)]

    assert cli.run_live(cli.build_parser().parse_args(argv)) == 0
    assert calls == ([] if resume else ["exchange_policy"]) + ["dns_posture"] + (["identity"] if include_other else [])
    assert contexts["dns_posture"]["exchange_accepted_domains"] == envelope
    if not resume:
        assert "exchange_accepted_domains" not in contexts["exchange_policy"]
    if include_other:
        # This collector runs after Exchange, so an unconditional hand-off would leak the envelope here.
        assert "exchange_accepted_domains" not in contexts["identity"]


@pytest.mark.parametrize("collector,operation,error_class,expected_rc", [
    ("exchange_policy", "transportConfig", "session_not_connected", 0),
    ("dns_posture", "spf_records", "dns_resolver_error", 0),
    ("identity", "users", "unauthenticated", 1),
])
def test_offline_failure_preserves_partial_status_and_workload_exit_rule(tmp_path, collector, operation, error_class, expected_rc):
    sample = tmp_path / "constructed.json"
    sample.write_text(json.dumps({collector: {operation: {
        "value": [], "error_class": error_class, "error": "constructed read failure",
    }}}))
    assert cli.run_offline(sample, tmp_path, "constructed", "failure") == expected_rc
    manifest = json.loads((tmp_path / "constructed-failure" / "run-manifest.json").read_text())
    assert manifest["overall_status"] == "partial"


@pytest.mark.parametrize("mode_args", [["--interactive"], ["--use-azure-cli-token"], ["--access-token", "constructed"]])
def test_non_app_default_run_omits_workloads_and_prints_one_selection_notice(tmp_path, monkeypatch, caplog, mode_args):
    from azure_tenant_audit.config import CollectorConfig

    class Healthy:
        def __init__(self, name):
            self.name = name

        def run(self, context):
            return CollectorResult(name=self.name, status="ok", payload={}, item_count=0)

    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    monkeypatch.setattr(cli, "REGISTRY", {name: Healthy(name) for name in config.default_order})
    monkeypatch.setattr(cli, "GraphClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(cli, "_capture_signed_in_context", lambda *args, **kwargs: {})
    monkeypatch.setattr(cli, "_acquire_azure_cli_access_token", lambda *args, **kwargs: "constructed")
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    caplog.set_level("INFO", logger="azure_tenant_audit")
    args = cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "constructed", "--client-id", "constructed",
        "--out", str(tmp_path), "--run-name", "default", *mode_args,
    ])
    assert cli.run_live(args) == 0
    manifest = json.loads((tmp_path / "acme-default/run-manifest.json").read_text())
    assert {"exchange_policy", "dns_posture"}.isdisjoint(manifest["selected_collectors"])
    assert manifest["overall_status"] == "ok"
    notices = [row.message for row in caplog.records if "Defaults/preset did not select" in row.message]
    assert len(notices) == 1
    assert "exchange_policy, dns_posture" in notices[0] and "app-mode only" in notices[0]


def test_required_preflight_skipped_licensing_keeps_existing_selected_contract(tmp_path, monkeypatch):
    from graph_fakes import FakeGraph, run_collectors, load
    from azure_tenant_audit.collectors.licensing import LicensingCollector

    refused = FakeGraph(errors={path: (403, "Forbidden") for path in ("/subscribedSkus", "/users", "/groups")})

    class BlockedLicensing(LicensingCollector):
        def run(self, context):
            return super().run({**context, "client": refused})

    monkeypatch.setitem(cli.REGISTRY, "licensing", BlockedLicensing())
    monkeypatch.setattr(cli.run_core, "collector_pause_seconds", lambda _: 0)
    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(), "identity,licensing", "--probe-first")
    assert rc == 1
    manifest = load(run_dir, "run-manifest.json")
    assert manifest["selected_collectors"] == ["identity"]
    assert manifest["overall_status"] == "partial"
    preflight = load(run_dir, "preflight-plan.json")
    licensing_probe = next(row for row in preflight["collectors"] if row["collector"] == "licensing")
    assert licensing_probe["cause_error_class"] == "insufficient_permissions"
    readiness = load(run_dir, "live-readiness.json")
    assert readiness["selected_collectors"] == ["identity", "licensing"]
    assert "licensing" not in readiness["trusted_collectors"]
    assert "licensing" in readiness["cannot_trust"]
    assert readiness["trust_level"] == "partial"
    assert readiness["statement"] != "Live evidence is verified for all selected collectors."
    licensing = next(row for row in readiness["evidence_gates"] if row["collector"] == "licensing")
    assert licensing["status"] == "unverified"
    assert licensing["missing_permissions"]
    assert licensing["reason"] == "missing_required_permissions"
    assert licensing["blocker_kind"] == "auth_scope"
    assert licensing["next_step"] == "Grant the listed read permissions or scopes, then rerun doctor/probe."
    plan = load(run_dir, "audit-plan.json")
    assert plan["selected_collectors"] == ["identity"]
    assert plan["evidence_gates"] == readiness["evidence_gates"]
