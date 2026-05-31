from __future__ import annotations

import json

from auditex import cli as auditex_cli
from auditex.mcp_registry import iter_tool_specs
from auditex.mcp_server import setup_guide as mcp_setup_guide
from auditex.setup_guide import build_setup_guide, render_setup_guide_markdown


def test_google_setup_guide_outputs_dwd_scopes_and_readonly_claims() -> None:
    payload = build_setup_guide(provider="google", collector_preset="everything", auth="domain-delegation")

    assert payload["provider"] == "google_workspace"
    assert "google_drive_posture" in payload["selected_collectors"]
    assert "https://www.googleapis.com/auth/admin.reports.audit.readonly" in payload["required_scopes"]
    assert "https://www.googleapis.com/auth/drive.metadata.readonly" in payload["scopes_csv"]
    assert payload["provider_assertions"]["drive_file_content_reads"] is False
    assert any(row["scope"] == "https://www.googleapis.com/auth/gmail.settings.sharing" for row in payload["scope_warnings"])
    assert "Domain-wide delegation" in " ".join(payload["setup_steps"])


def test_m365_setup_guide_outputs_permissions_roles_and_commands() -> None:
    payload = build_setup_guide(provider="m365", auditor_profile="global-reader", collector_preset="full", tenant_id="contoso.onmicrosoft.com")

    assert payload["provider"] == "m365"
    assert "identity" in payload["selected_collectors"]
    assert "Policy.Read.All" in payload["graph_permissions"]
    assert "Global Reader" in payload["minimum_role_hints"]
    assert payload["provider_assertions"]["production_writes"] is False
    assert "az login --allow-no-subscriptions --tenant contoso.onmicrosoft.com" == payload["commands"]["delegated_login"]


def test_setup_guide_markdown_includes_commands_and_sources() -> None:
    payload = build_setup_guide(provider="google", collector_preset="identity")
    markdown = render_setup_guide_markdown(payload)

    assert "# Auditex Setup Guide: google_workspace" in markdown
    assert "```text" in markdown
    assert "auditex google probe" in markdown
    assert "Google Workspace domain-wide delegation" in markdown


def test_setup_guide_cli_json_and_markdown(capsys) -> None:
    assert auditex_cli.main(["setup-guide", "google", "--collector-preset", "identity", "--format", "json"]) == 0
    google_payload = json.loads(capsys.readouterr().out)
    assert google_payload["provider"] == "google_workspace"
    assert "scopes_csv" in google_payload

    assert auditex_cli.main(["setup-guide", "m365", "--collector-preset", "identity-only", "--format", "md"]) == 0
    markdown = capsys.readouterr().out
    assert "Microsoft Graph Permissions" in markdown
    assert "Directory.Read.All" in markdown


def test_setup_guide_mcp_tool_is_registered_and_callable() -> None:
    names = {row["name"] for row in iter_tool_specs()}
    assert "auditex_setup_guide" in names

    payload = mcp_setup_guide(provider="m365", collector_preset="identity-only")
    assert payload["provider"] == "m365"
    assert "Application.Read.All" in payload["graph_permissions"]
    artifact_paths = {row["artifact_path"] for row in payload["citations"]}
    assert "src/auditex/setup_guide.py" in artifact_paths
    assert "configs/collector-definitions.json" in artifact_paths
