from __future__ import annotations

import json
from pathlib import Path
import sys
import types
import argparse

import pytest

from auditex import cli as auditex_cli
from auditex.mcp_server import (
    build_google_command,
    build_cli_command,
    build_response_command,
    build_probe_command,
    compare_many_runs,
    list_adapters,
    list_collectors,
    list_available_exporters,
    preview_notification,
    preview_report,
    rules_inventory,
    list_response_actions,
    main as mcp_main,
    analyze_report,
    api_inventory,
    enterprise_handoff,
    permissions_ledger,
    proof_table,
    summarize_run,
    tool_specs,
    verify_customer_pack,
)
from azure_tenant_audit.contracts import contract_schema_manifest
from azure_tenant_audit.cli import build_parser, run_offline
from azure_tenant_audit.profiles import get_profile, profile_choices
from support import RunBundleBuilder, write_json


def test_profile_choices_include_global_reader() -> None:
    assert "global-reader" in profile_choices()
    assert "reports-reader" in profile_choices()
    assert get_profile("global-reader").name == "global-reader"
    assert "inventory" in get_profile("global-reader").supported_planes
    assert "sharepoint_access" in get_profile("global-reader").default_collectors
    assert "app_consent" in get_profile("global-reader").default_collectors
    assert "licensing" in get_profile("global-reader").default_collectors
    assert "service_health" in get_profile("global-reader").default_collectors
    assert "reports_usage" in get_profile("global-reader").default_collectors
    assert "external_identity" in get_profile("global-reader").default_collectors
    assert "consent_policy" in get_profile("global-reader").default_collectors
    assert "domains_hybrid" in get_profile("global-reader").default_collectors
    assert "onedrive_posture" in get_profile("global-reader").default_collectors


def test_parser_accepts_auditor_profile() -> None:
    args = build_parser().parse_args(["--tenant-name", "acme", "--offline", "--auditor-profile", "global-reader"])
    assert args.auditor_profile == "global-reader"


def test_parser_accepts_plane_and_time_window() -> None:
    args = build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--offline",
            "--plane",
            "full",
            "--since",
            "2026-04-01T00:00:00Z",
            "--until",
            "2026-04-02T00:00:00Z",
        ]
    )
    assert args.plane == "full"
    assert args.since == "2026-04-01T00:00:00Z"
    assert args.until == "2026-04-02T00:00:00Z"


def test_parser_rejects_unimplemented_response_plane() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--tenant-name", "acme", "--offline", "--plane", "response"])


def test_offline_manifest_records_profile(tmp_path: Path) -> None:
    sample = {"identity": {"value": [{"id": "1"}]}}
    sample_path = tmp_path / "sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_offline(
        sample_path,
        tmp_path,
        "contoso",
        "run1",
        auditor_profile="global-reader",
        plane="full",
        since="2026-04-01T00:00:00Z",
        until="2026-04-02T00:00:00Z",
    )
    assert rc == 0

    manifest = json.loads((tmp_path / "contoso-run1" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["auditor_profile"] == "global-reader"
    assert manifest["plane"] == "full"
    assert manifest["time_window"]["since"] == "2026-04-01T00:00:00Z"
    assert manifest["time_window"]["until"] == "2026-04-02T00:00:00Z"


def test_mcp_tool_specs_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)
    names = {item["name"] for item in tool_specs()}
    assert "auditex_run_delegated_audit" in names
    assert "auditex_google_doctor" in names
    assert "auditex_google_probe" in names
    assert "auditex_run_google_workspace_audit" in names
    assert "auditex_summarize_run" in names
    assert "auditex_diff_runs" in names
    assert "auditex_compare_runs" in names
    assert "auditex_probe_live" in names
    assert "auditex_probe_summarize" in names
    assert "auditex_list_collectors" in names
    assert "auditex_list_adapters" in names
    assert "auditex_list_blockers" in names
    assert "auditex_report_preview" in names
    assert "auditex_export_list" in names
    assert "auditex_api_inventory" in names
    assert "auditex_permissions_ledger" in names
    assert "auditex_proof_table" in names
    assert "auditex_enterprise_handoff" in names
    assert "auditex_verify_customer_pack" in names
    assert "auditex_notify_preview" in names
    assert "auditex_rules_inventory" in names
    assert "auditex_list_response_actions" not in names
    assert "auditex_run_response_action" not in names
    assert "auditex_auth_status" in names
    assert "auditex_auth_inspect_token" in names
    assert "auditex_auth_capability" in names
    assert "auditex_contract_schema_manifest" in names


def test_mcp_tool_specs_can_include_lab_response_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    names = {item["name"] for item in tool_specs()}

    assert "auditex_list_response_actions" in names
    assert "auditex_run_response_action" in names


def test_root_cli_hides_response_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.cli import _build_root_parser

    monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)

    parser = _build_root_parser()
    actions = [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]  # noqa: SLF001
    choices = set(actions[0].choices)

    assert "response" not in choices


def test_root_cli_can_show_lab_response_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.cli import _build_root_parser

    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")

    parser = _build_root_parser()
    actions = [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]  # noqa: SLF001
    choices = set(actions[0].choices)

    assert "response" in choices


def test_contract_schema_manifest_lists_shipped_schemas() -> None:
    manifest = contract_schema_manifest("schemas")

    assert manifest["contract_version"] == "2026-04-21"
    assert "run_manifest.schema.json" in manifest["schemas"]
    assert "validation.schema.json" in manifest["schemas"]


def test_mcp_main_uses_current_fastmcp_tool_decorator(monkeypatch: pytest.MonkeyPatch) -> None:
    registered: list[tuple[str, bool]] = []

    class _FakeFastMCP:
        def __init__(self, _name: str) -> None:
            self._tools: list[str] = []

        def tool(self, **metadata):
            def decorator(func):
                self._tools.append(func.__name__)
                registered.append((metadata["name"], metadata["annotations"]["readOnlyHint"]))
                return func

            return decorator

        def run(self, transport: str = "stdio") -> None:
            assert transport == "stdio"

    fake_module = types.ModuleType("mcp.server.fastmcp")
    fake_module.FastMCP = _FakeFastMCP
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_module)

    assert mcp_main() == 0
    expected = [(item["name"], item["readOnlyHint"]) for item in tool_specs()]
    assert registered == expected


def test_list_collectors_tool_shape_matches_definitions() -> None:
    result = list_collectors()
    assert result["path"].endswith("configs/collector-definitions.json")
    assert isinstance(result["collectors"], list)
    collector_names = {item["name"] for item in result["collectors"]}
    assert {
        "identity",
        "security",
        "conditional_access",
        "defender",
        "service_health",
        "reports_usage",
        "external_identity",
        "consent_policy",
        "domains_hybrid",
        "onedrive_posture",
        "sharepoint_access",
        "app_consent",
        "licensing",
        "identity_governance",
        "intune_depth",
        "teams_policy",
        "exchange_policy",
    }.issubset(collector_names)


def test_list_collectors_can_show_google_registry() -> None:
    result = list_collectors(provider="google")

    collector_names = {item["name"] for item in result["collectors"]}
    assert result["provider"] == "google"
    assert "google_directory" in collector_names
    assert "google_drive_posture" in collector_names
    assert "google_calendar_posture" in collector_names
    drive = next(item for item in result["collectors"] if item["name"] == "google_drive_posture")
    calendar = next(item for item in result["collectors"] if item["name"] == "google_calendar_posture")
    assert "https://www.googleapis.com/auth/drive.metadata.readonly" in drive["required_permissions"]
    assert "https://www.googleapis.com/auth/calendar.acls.readonly" in calendar["required_permissions"]


def test_list_adapters_tool_shape() -> None:
    result = list_adapters()
    assert result["count"] >= 1
    assert isinstance(result["adapters"], list)
    adapter_names = {item["name"] for item in result["adapters"]}
    assert {"m365_cli", "m365dsc", "powershell_graph"}.issubset(adapter_names)


def test_build_cli_command_uses_profile_and_cli_token() -> None:
    command = build_cli_command(
        tenant_name="ACME",
        tenant_id="contoso.onmicrosoft.com",
        out_dir="outputs/live",
        auditor_profile="global-reader",
        plane="full",
        since="2026-04-01T00:00:00Z",
        until="2026-04-02T00:00:00Z",
    )
    assert "--use-azure-cli-token" in command
    assert command[0]
    assert "--auditor-profile" in command
    assert "global-reader" in command
    assert "--plane" in command
    assert "full" in command
    assert "--since" in command
    assert "--until" in command


def test_build_cli_command_rejects_unimplemented_response_plane() -> None:
    with pytest.raises(ValueError, match="response"):
        build_cli_command(
            tenant_name="ACME",
            out_dir="outputs/live",
            plane="response",
        )


def test_build_probe_command_rejects_response_mode_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)
    with pytest.raises(ValueError, match="response plane is disabled"):
        build_probe_command(
            tenant_name="ACME",
            out_dir="outputs/probes",
            mode="response",
        )


def test_build_probe_command_uses_mode_surface_and_lab_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    command = build_probe_command(
        tenant_name="ACME",
        out_dir="outputs/probes",
        tenant_id="contoso.onmicrosoft.com",
        auditor_profile="global-reader",
        mode="response",
        surface="exchange",
        allow_lab_response=True,
        since="2026-04-01T00:00:00Z",
        until="2026-04-02T00:00:00Z",
    )
    assert command[:3] == [command[0], "-m", "auditex"]
    assert "probe" in command
    assert "live" in command
    assert "--mode" in command
    assert "response" in command
    assert "--surface" in command
    assert "exchange" in command
    assert "--allow-lab-response" in command
    assert "--since" in command
    assert "--until" in command


def test_build_probe_command_includes_app_credentials() -> None:
    command = build_probe_command(
        tenant_name="ACME",
        out_dir="outputs/probes",
        tenant_id="contoso.onmicrosoft.com",
        mode="app",
        client_id="app-id",
        client_secret="app-secret",
    )
    assert "--client-id" in command
    assert "app-id" in command
    assert "--client-secret" in command
    assert "app-secret" in command


def test_build_google_command_uses_workspace_path() -> None:
    command = build_google_command(
        tenant_name="bolyki-google",
        out_dir="outputs/google",
        domain="bolyki.eu",
        customer_id="my_customer",
        subject="bolyki@bolyki.eu",
        service_account_key="/creds/key.json",
        collectors="google_directory,google_reports",
        top=500,
    )

    assert command[:4] == [command[0], "-m", "auditex", "google"]
    assert "run" in command
    assert command[command.index("--domain") + 1] == "bolyki.eu"
    assert command[command.index("--service-account-key") + 1] == "/creds/key.json"


def test_build_cli_command_can_use_app_credentials() -> None:
    command = build_cli_command(
        tenant_name="ACME",
        tenant_id="contoso.onmicrosoft.com",
        out_dir="outputs/live",
        use_azure_cli_token=False,
        client_id="app-id",
        client_secret="app-secret",
    )
    assert "--use-azure-cli-token" not in command
    assert "--client-id" in command
    assert "app-id" in command
    assert "--client-secret" in command
    assert "app-secret" in command


def test_build_probe_command_supports_saved_auth_context() -> None:
    command = build_probe_command(
        tenant_name="ACME",
        out_dir="outputs/probes",
        auditor_profile="global-reader",
        mode="delegated",
        auth_context="customer-token",
    )
    assert "--auth-context" in command
    assert "customer-token" in command
    assert "--use-azure-cli-token" not in command


def test_probe_parser_accepts_saved_auth_context() -> None:
    from auditex.cli import _build_probe_parser

    args = _build_probe_parser().parse_args(
        [
            "live",
            "--tenant-name",
            "ACME",
            "--auth-context",
            "customer-token",
        ]
    )
    assert args.auth_context == "customer-token"


def test_list_response_actions_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUDITEX_ENABLE_RESPONSE", raising=False)
    result = list_response_actions()
    assert result["enabled"] is False
    assert result["count"] == 0
    assert result["actions"] == []


def test_list_response_actions_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    result = list_response_actions()
    assert result["enabled"] is True
    assert result["count"] >= 1
    assert "message_trace" in result["actions"]


def test_build_response_command_uses_guarded_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    command = build_response_command(
        tenant_name="ACME",
        out_dir="outputs/response",
        action="message_trace",
        tenant_id="contoso.onmicrosoft.com",
        auditor_profile="exchange-reader",
        target="user@contoso.com",
        intent="triage mail flow",
        auth_context="customer-token",
    )
    assert command[:3] == [command[0], "-m", "auditex"]
    assert "response" in command
    assert "run" in command
    assert "--action" in command
    assert "message_trace" in command
    assert "--intent" in command
    assert "triage mail flow" in command


def test_build_response_command_supports_saved_auth_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_ENABLE_RESPONSE", "1")
    command = build_response_command(
        tenant_name="ACME",
        out_dir="outputs/response",
        action="message_trace",
        tenant_id="contoso.onmicrosoft.com",
        auditor_profile="exchange-reader",
        target="user@contoso.com",
        intent="triage mail flow",
        auth_context="customer-token",
    )
    assert "--auth-context" in command
    assert "customer-token" in command


def test_response_parser_accepts_saved_auth_context() -> None:
    from auditex.cli import _build_response_parser

    args = _build_response_parser().parse_args(
        [
            "run",
            "--tenant-name",
            "ACME",
            "--action",
            "message_trace",
            "--intent",
            "triage mail flow",
            "--auth-context",
            "customer-token",
        ]
    )
    assert args.auth_context == "customer-token"


def test_summarize_run_reads_manifest(tmp_path: Path) -> None:
    run_dir = RunBundleBuilder(tmp_path).summary_md("# Audit Summary").build()

    summary = summarize_run(str(run_dir))
    assert summary["manifest"]["tenant_name"] == "acme"
    assert summary["summary_md_path"].endswith("summary.md")
    assert summary["summary_md"] == "# Audit Summary"


def test_summarize_run_reads_probe_artifacts(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .capability_matrix([{"surface": "identity"}])
        .toolchain_readiness({"m365_cli": {"status": "blocked"}})
        .live_readiness({"trust_level": "partial", "trusted_collectors": ["identity"], "cannot_trust": ["mail"]})
        .build()
    )

    summary = summarize_run(str(run_dir))
    assert summary["capability_matrix"][0]["surface"] == "identity"
    assert summary["toolchain_readiness"]["m365_cli"]["status"] == "blocked"
    assert summary["live_readiness"]["trust_level"] == "partial"
    assert summary["live_readiness_path"].endswith("live-readiness.json")
    assert summary["metadata"]["live_readiness"]["cannot_trust"] == ["mail"]


def test_summarize_run_reads_probe_auth_context_artifact(tmp_path: Path) -> None:
    run_dir = RunBundleBuilder(tmp_path).auth_context({"name": "customer-token"}).build()

    summary = summarize_run(str(run_dir))
    assert summary["auth_context"]["name"] == "customer-token"


def test_api_inventory_tool_reads_customer_call_ledger(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "declared_collectors": [{"collector": "identity"}],
                "observed_calls": [{"collector": "identity", "endpoint": "/users", "method": "GET"}],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True},
            }
        )
        .build()
    )

    result = api_inventory(str(run_dir))

    assert result["present"] is True
    assert result["observed_calls"][0]["endpoint"] == "/users"


def test_permissions_ledger_reads_scope_requirements(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "google_workspace",
                "declared_collectors": [
                    {
                        "collector": "google_reports",
                        "status": "blocked_by_scope",
                        "required_permissions": ["admin.reports.audit.readonly"],
                        "observed_permissions": [],
                        "missing_permissions": ["admin.reports.audit.readonly"],
                        "observed_call_count": 0,
                    }
                ],
                "observed_calls": [],
                "counts": {"observed_calls": 0},
                "safety": {"read_only": True, "no_content_reads": True},
            }
        )
        .build()
    )
    write_json(
        run_dir / "audit-plan.json",
        {
            "schema_version": "2026-04-21",
            "platform": "google_workspace",
            "evidence_gates": [
                {
                    "collector": "google_reports",
                    "status": "blocked",
                    "required_permissions": ["admin.reports.audit.readonly"],
                    "missing_permissions": ["admin.reports.audit.readonly"],
                    "reason": "missing scope",
                    "blocker_kind": "auth_scope",
                    "next_step": "Grant the missing readonly Reports scope.",
                }
            ],
            "quality_gate": {"status": "partial"},
        },
    )

    result = permissions_ledger(str(run_dir))

    assert result["counts"]["missing_permissions"] == 1
    assert result["missing_permissions"] == ["admin.reports.audit.readonly"]
    assert result["collectors"][0]["collector"] == "google_reports"
    assert result["collectors"][0]["next_step"] == "Grant the missing readonly Reports scope."


def test_proof_table_tool_reads_customer_evidence_rows(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "partial"},
            findings=[
                {
                    "id": "finding-1",
                    "rule_id": "google.gmail_external_forwarding",
                    "title": "External forwarding",
                    "severity": "high",
                    "status": "open",
                    "evidence_refs": [
                        {
                            "artifact_path": "summary.json",
                            "artifact_kind": "summary",
                            "collector": "google_gmail_settings",
                            "record_key": "user:alice",
                            "json_pointer": "/records/0",
                        }
                    ],
                }
            ],
            evidence_paths=["summary.json"],
        )
        .build()
    )

    result = proof_table(str(run_dir))

    assert result["present"] is True
    assert result["counts"]["proof_rows"] == 1
    assert result["counts"]["supported"] == 1
    assert result["proof_table"][0]["collector"] == "google_gmail_settings"
    assert result["proof_table"][0]["record_key"] == "user:alice"


def test_enterprise_handoff_indexes_customer_review_artifacts(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(platform="google_workspace")
        .summary(tenant_name="acme", run_id="run-1", overall_status="ok", collectors=[])
        .data_handling(
            {
                "schema_version": "2026-04-21",
                "platform": "google_workspace",
                "read_only": True,
                "content_reads": False,
                "write_actions": False,
                "scope_risk": "read_only_scopes",
                "write_capable_scopes": [],
                "provider_assertions": {"gmail_body_reads": False, "drive_file_content_reads": False},
            }
        )
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "google_workspace",
                "declared_collectors": [{"collector": "google_directory"}],
                "observed_calls": [
                    {
                        "collector": "google_directory",
                        "endpoint": "admin.directory.users.list",
                        "method": "GET",
                        "status": "ok",
                        "item_count": 1,
                    }
                ],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True, "write_actions": False},
            }
        )
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "ok"},
            findings=[
                {
                    "id": "finding-1",
                    "rule_id": "google.admin_2sv_missing",
                    "title": "Admin missing 2SV",
                    "severity": "high",
                    "status": "open",
                    "evidence_refs": [
                        {
                            "artifact_path": "summary.json",
                            "artifact_kind": "summary",
                            "collector": "google_directory",
                            "record_key": "admin",
                        }
                    ],
                }
            ],
            evidence_paths=["summary.json"],
        )
        .build()
    )
    write_json(
        run_dir / "validation.json",
        {
            "schema_version": "2026-04-21",
            "contract_version": "2026-04-21",
            "valid": True,
            "issue_count": 0,
            "error_count": 0,
            "warning_count": 0,
        },
    )

    result = enterprise_handoff(str(run_dir))

    assert result["handoff_status"] == "ready"
    assert result["safety"]["read_only"] is True
    assert result["safety"]["no_content_reads"] is True
    assert result["counts"]["api_calls"] == 1
    assert result["counts"]["proof_rows"] == 1
    assert result["review_commands"]["api_calls"].startswith("auditex report api-calls")
    artifacts = {row["path"]: row for row in result["artifacts"]}
    assert artifacts["api-inventory.json"]["present"] is True
    assert artifacts["api-inventory.json"]["sha256"]
    assert artifacts["reports/report-pack.json"]["present"] is True


def test_report_api_calls_command_prints_markdown(tmp_path: Path, capsys) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "google_workspace",
                "declared_collectors": [{"collector": "google_directory"}],
                "observed_calls": [
                    {
                        "collector": "google_directory",
                        "endpoint": "admin.directory.users.list",
                        "method": "GET",
                        "status": "ok",
                        "item_count": 1,
                        "data_class": "directory_identity",
                    }
                ],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True},
            }
        )
        .build()
    )

    rc = auditex_cli.main(["report", "api-calls", str(run_dir), "--format", "md"])
    output = capsys.readouterr().out

    assert rc == 0
    assert "# Auditex API Call Inventory" in output
    assert "admin.directory.users.list" in output
    assert "Read-only: True" in output


def test_report_proof_table_command_prints_markdown(tmp_path: Path, capsys) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "partial"},
            findings=[
                {
                    "id": "finding-1",
                    "rule_id": "identity.admin_mfa_missing",
                    "title": "Admin missing MFA",
                    "severity": "high",
                    "status": "open",
                    "evidence_refs": [
                        {
                            "artifact_path": "summary.json",
                            "artifact_kind": "summary",
                            "collector": "auth_methods",
                            "record_key": "admin",
                        }
                    ],
                }
            ],
            evidence_paths=["summary.json"],
        )
        .build()
    )

    rc = auditex_cli.main(["report", "proof-table", str(run_dir), "--format", "md"])
    output = capsys.readouterr().out

    assert rc == 0
    assert "# Auditex Proof Table" in output
    assert "identity.admin_mfa_missing" in output
    assert "auth_methods" in output
    assert "admin" in output


def test_report_handoff_command_prints_markdown(tmp_path: Path, capsys) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .data_handling(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "read_only": True,
                "content_reads": False,
                "write_actions": False,
                "provider_assertions": {},
            }
        )
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "declared_collectors": [{"collector": "identity"}],
                "observed_calls": [{"collector": "identity", "endpoint": "/users", "method": "GET"}],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True, "write_actions": False},
            }
        )
        .report_pack(summary={"tenant_name": "acme", "overall_status": "ok"}, findings=[], evidence_paths=[])
        .build()
    )
    write_json(
        run_dir / "validation.json",
        {
            "schema_version": "2026-04-21",
            "contract_version": "2026-04-21",
            "valid": True,
            "issue_count": 0,
            "error_count": 0,
            "warning_count": 0,
        },
    )

    rc = auditex_cli.main(["report", "handoff", str(run_dir), "--format", "md"])
    output = capsys.readouterr().out

    assert rc == 0
    assert "# Auditex Enterprise Handoff" in output
    assert "Status: ready" in output
    assert "api-inventory.json" in output
    assert "auditex report proof-table" in output


def test_report_customer_docs_can_write_output_files(tmp_path: Path, capsys) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .data_handling(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "read_only": True,
                "content_reads": False,
                "write_actions": False,
                "provider_assertions": {},
            }
        )
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "declared_collectors": [{"collector": "identity"}],
                "observed_calls": [{"collector": "identity", "endpoint": "/users", "method": "GET"}],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True, "write_actions": False},
            }
        )
        .report_pack(summary={"tenant_name": "acme", "overall_status": "ok"}, findings=[], evidence_paths=[])
        .build()
    )
    write_json(
        run_dir / "validation.json",
        {
            "schema_version": "2026-04-21",
            "contract_version": "2026-04-21",
            "valid": True,
            "issue_count": 0,
            "error_count": 0,
            "warning_count": 0,
        },
    )
    handoff_path = tmp_path / "handoff.md"
    api_path = tmp_path / "api-calls.json"
    permissions_path = tmp_path / "permissions.md"
    proof_path = tmp_path / "proof-table.md"

    assert auditex_cli.main(["report", "handoff", str(run_dir), "--format", "md", "--output", str(handoff_path)]) == 0
    assert auditex_cli.main(["report", "api-calls", str(run_dir), "--format", "json", "--output", str(api_path)]) == 0
    assert auditex_cli.main(["report", "permissions", str(run_dir), "--format", "md", "--output", str(permissions_path)]) == 0
    assert auditex_cli.main(["report", "proof-table", str(run_dir), "--format", "md", "--output", str(proof_path)]) == 0
    output = capsys.readouterr().out

    assert '"output_path"' in output
    assert handoff_path.read_text(encoding="utf-8").startswith("# Auditex Enterprise Handoff")
    assert json.loads(api_path.read_text(encoding="utf-8"))["observed_calls"][0]["endpoint"] == "/users"
    assert permissions_path.read_text(encoding="utf-8").startswith("# Auditex Permission Ledger")
    assert proof_path.read_text(encoding="utf-8").startswith("# Auditex Proof Table")


def _build_customer_pack_run(tmp_path: Path) -> Path:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .data_handling(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "read_only": True,
                "content_reads": False,
                "write_actions": False,
                "provider_assertions": {},
            }
        )
        .api_inventory(
            {
                "schema_version": "2026-04-21",
                "platform": "m365",
                "declared_collectors": [{"collector": "identity"}],
                "observed_calls": [{"collector": "identity", "endpoint": "/users", "method": "GET"}],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True, "write_actions": False},
            }
        )
        .report_pack(summary={"tenant_name": "acme", "overall_status": "ok"}, findings=[], evidence_paths=[])
        .build()
    )
    write_json(
        run_dir / "validation.json",
        {
            "schema_version": "2026-04-21",
            "contract_version": "2026-04-21",
            "valid": True,
            "issue_count": 0,
            "error_count": 0,
            "warning_count": 0,
        },
    )
    return run_dir


def test_report_customer_pack_writes_complete_handoff_folder(tmp_path: Path, capsys) -> None:
    run_dir = _build_customer_pack_run(tmp_path)
    output_dir = tmp_path / "customer-pack"

    assert auditex_cli.main(["report", "customer-pack", str(run_dir), "--output-dir", str(output_dir)]) == 0
    output = json.loads(capsys.readouterr().out)

    expected = {
        "handoff.md",
        "handoff.json",
        "report.md",
        "api-calls.md",
        "api-calls.json",
        "permissions.md",
        "permissions.json",
        "proof-table.md",
        "proof-table.json",
        "README.md",
        "checksums.sha256",
        "pack-manifest.json",
    }
    assert expected.issubset({path.name for path in output_dir.iterdir()})
    assert (output_dir / "source-artifacts" / "run-manifest.json").exists()
    assert (output_dir / "source-artifacts" / "data-handling.json").exists()
    assert (output_dir / "source-artifacts" / "api-inventory.json").exists()
    assert (output_dir / "source-artifacts" / "reports" / "report-pack.json").exists()
    assert output["handoff_status"] == "ready"
    assert output["pack_manifest_path"].endswith("pack-manifest.json")
    assert all(item["sha256"] for item in output["generated_files"])
    copied = {item["source_path"]: item for item in output["source_artifacts"]}
    assert copied["api-inventory.json"]["present"] is True
    assert copied["api-inventory.json"]["sha256"]
    assert copied["live-readiness.json"]["present"] is False
    assert (output_dir / "README.md").read_text(encoding="utf-8").startswith("# Auditex Customer Pack")
    checksums = (output_dir / "checksums.sha256").read_text(encoding="utf-8")
    assert "api-calls.md" in checksums
    assert "permissions.md" in checksums
    assert "source-artifacts/api-inventory.json" in checksums
    assert (output_dir / "handoff.md").read_text(encoding="utf-8").startswith("# Auditex Enterprise Handoff")
    assert json.loads((output_dir / "pack-manifest.json").read_text(encoding="utf-8"))["kind"] == "auditex_enterprise_handoff_pack"

    assert auditex_cli.main(["report", "verify-pack", str(output_dir)]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["valid"] is True
    assert verification["issue_count"] == 0
    assert verify_customer_pack(str(output_dir))["valid"] is True


def test_report_verify_pack_accepts_relative_output_dir_paths(tmp_path: Path, monkeypatch, capsys) -> None:
    run_dir = _build_customer_pack_run(tmp_path)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)

    output_dir = Path("customer-pack")
    assert auditex_cli.main(["report", "customer-pack", str(run_dir), "--output-dir", str(output_dir)]) == 0
    capsys.readouterr()

    manifest = json.loads((workspace / output_dir / "pack-manifest.json").read_text(encoding="utf-8"))
    assert manifest["output_dir"] == "customer-pack"
    assert manifest["generated_files"][0]["path"] == "customer-pack/handoff.md"

    assert auditex_cli.main(["report", "verify-pack", str(output_dir)]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["valid"] is True
    assert verification["issue_count"] == 0


def test_report_verify_pack_detects_tampered_file(tmp_path: Path, capsys) -> None:
    run_dir = _build_customer_pack_run(tmp_path)
    output_dir = tmp_path / "customer-pack"
    assert auditex_cli.main(["report", "customer-pack", str(run_dir), "--output-dir", str(output_dir)]) == 0
    capsys.readouterr()

    with (output_dir / "handoff.md").open("a", encoding="utf-8") as handle:
        handle.write("\nTampered.\n")

    assert auditex_cli.main(["report", "verify-pack", str(output_dir)]) == 1
    verification = json.loads(capsys.readouterr().out)

    assert verification["valid"] is False
    assert any(issue["code"] == "checksum_mismatch" for issue in verification["issues"])


def test_summarize_run_reads_response_auth_context_artifact(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .session_context({"tenant_id": "tenant-saved"})
        .auth_context(
            {
                "name": "customer-token",
                "auth_type": "imported_token",
                "tenant_id": "tenant-saved",
                "token_claims": {"delegated_scopes": ["Directory.Read.All"]},
            }
        )
        .build()
    )

    summary = summarize_run(str(run_dir))
    assert summary["auth_context_path"].endswith("auth-context.json")
    assert summary["auth_context"]["name"] == "customer-token"
    assert summary["auth_context"]["tenant_id"] == "tenant-saved"


def test_summarize_run_reads_report_pack_and_action_plan_artifacts(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .report_pack(summary={"overall_status": "partial"}, findings=[], evidence_paths=[])
        .action_plan({"open_findings": [], "waived_findings": [], "blocked": []})
        .build()
    )

    summary = summarize_run(str(run_dir))

    assert summary["report_pack_path"].endswith("reports/report-pack.json")
    assert summary["report_pack"]["summary"]["overall_status"] == "partial"
    assert summary["action_plan_path"].endswith("reports/action-plan.json")
    assert summary["action_plan"]["blocked"] == []


def test_analyze_report_exposes_basic_license_intelligence_for_mcp(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(platform="m365")
        .summary(tenant_name="acme", run_id="run-1", overall_status="ok", collectors=[])
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "ok"},
            findings=[
                {
                    "id": "finding-1",
                    "rule_id": "identity.admin_mfa_missing",
                    "severity": "high",
                    "title": "Admin missing MFA",
                    "status": "open",
                    "category": "identity",
                    "evidence_refs": [
                        {
                            "artifact_path": "summary.json",
                            "artifact_kind": "summary",
                            "collector": "identity",
                            "record_key": "admin",
                        }
                    ],
                }
            ],
            evidence_paths=["summary.json"],
        )
        .build()
    )

    result = analyze_report(str(run_dir))

    assert result["license_profile"]["requires_premium_license"] is False
    assert result["replay_context"]["requires_live_tenant"] is False
    assert result["auditor_score"]["score"] > 0


def test_summarize_run_exposes_coverage_gaps_for_mcp_clients(tmp_path: Path) -> None:
    gap = {
        "surface": "mail",
        "status": "partial",
        "severity": "medium",
        "collectors": ["google_gmail_settings"],
        "error_classes": ["invalid_scope"],
        "message": "mail coverage is partial; affected collectors: google_gmail_settings",
    }
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(coverage_gaps=[gap])
        .summary(coverage_gaps=[gap])
        .build()
    )

    summary = summarize_run(str(run_dir))

    assert summary["coverage_gaps"] == [gap]


def test_summarize_run_exposes_provider_scorecard_for_mcp_clients(tmp_path: Path) -> None:
    scorecard = {
        "platform": "google_workspace",
        "score": 80,
        "grade": "usable",
        "surface_count": 2,
        "coverage_gap_count": 1,
        "surfaces": [
            {"surface": "identity", "status": "complete", "score": 100},
            {"surface": "mail", "status": "partial", "score": 60},
        ],
    }
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(provider_scorecard=scorecard)
        .summary(provider_scorecard=scorecard)
        .build()
    )

    summary = summarize_run(str(run_dir))

    assert summary["provider_scorecard"] == scorecard


def test_compare_many_runs_uses_same_tenant_gate(tmp_path: Path) -> None:
    run_a = (
        RunBundleBuilder(tmp_path, name="run-a")
        .manifest(run_id="run-a", created_utc="2026-04-18T09:00:00Z")
        .build()
    )
    run_b = (
        RunBundleBuilder(tmp_path, name="run-b")
        .manifest(run_id="run-b", created_utc="2026-04-18T09:00:00Z")
        .build()
    )

    result = compare_many_runs([str(run_a), str(run_b)])

    assert result["compare_context"]["same_tenant"] is True
    assert len(result["runs"]) == 2


def test_compare_many_runs_blocks_cross_provider_runs(tmp_path: Path) -> None:
    run_a = (
        RunBundleBuilder(tmp_path, name="run-a")
        .manifest(tenant_name="acme", run_id="run-a", platform="m365", created_utc="2026-04-18T09:00:00Z")
        .build()
    )
    run_b = (
        RunBundleBuilder(tmp_path, name="run-b")
        .manifest(tenant_name="acme", run_id="run-b", platform="google_workspace", created_utc="2026-04-18T09:01:00Z")
        .build()
    )

    result = compare_many_runs([str(run_a), str(run_b)])

    assert result["compare_context"]["same_platform"] is False
    assert result["baseline_diff"]["status"] == "blocked"
    assert result["baseline_diff"]["reason"] == "same_platform_required"
    assert result["baseline_diff"]["compare_context"]["same_tenant"] is True
    assert result["baseline_diff"]["compare_context"]["same_platform"] is False


def test_preview_report_and_notification_are_read_only_helpers(tmp_path: Path) -> None:
    finding = {"id": "finding-1", "title": "Fix sharing", "severity": "high", "status": "open"}
    run_dir = (
        RunBundleBuilder(tmp_path)
        .report_pack(
            summary={"tenant_name": "acme", "overall_status": "partial", "finding_count": 1},
            findings=[finding],
            action_plan=[{"id": "finding-1", "title": "Fix sharing", "severity": "high"}],
        )
        .action_plan([{"id": "finding-1", "title": "Fix sharing", "severity": "high"}])
        .findings([finding])
        .build()
    )

    report = preview_report(str(run_dir), format_name="json")
    notification = preview_notification(str(run_dir), sink="teams")

    assert report["format"] == "json"
    assert "\"tenant_name\": \"acme\"" in report["content"]
    assert notification["dry_run"] is True
    assert notification["payload"]["tenant_name"] == "acme"


def test_export_list_and_rules_inventory_helpers_return_rows() -> None:
    exporters = list_available_exporters()
    rules = rules_inventory(product_family="identity")
    google_rules = rules_inventory(platform="google_workspace", product_family="gmail")

    assert "exporters" in exporters
    assert exporters["exporters"]
    assert rules["count"] >= 1
    assert google_rules["count"] >= 1
    assert {row["platform"] for row in google_rules["rules"]} == {"google_workspace"}


def test_rules_inventory_cli_exports_sorted_json(monkeypatch, capsys) -> None:
    seen: dict[str, object] = {}

    def _fake_list_rule_inventory(*, tag=None, path_prefix=None):  # noqa: ANN001
        seen["tag"] = tag
        seen["path_prefix"] = path_prefix
        return [
            {"name": "zeta", "path": "rules/zeta.json"},
            {"name": "alpha", "path": "rules/alpha.json"},
        ]

    monkeypatch.setattr("auditex.cli.list_rule_inventory", _fake_list_rule_inventory)

    rc = auditex_cli.main(["rules", "inventory", "--tag", "now", "--path-prefix", "rules/"])

    assert rc == 0
    assert seen == {"tag": "now", "path_prefix": "rules/"}
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert [item["name"] for item in payload["rules"]] == ["alpha", "zeta"]
