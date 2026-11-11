from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from auditex import cli as auditex_cli
from auditex.mcp_registry import iter_tool_specs
from auditex.mcp_server import setup_guide as mcp_setup_guide
from auditex.setup_guide import build_setup_guide, render_setup_guide_markdown
from azure_tenant_audit import cli as tenant_cli


def test_google_setup_guide_outputs_dwd_scopes_and_readonly_claims() -> None:
    payload = build_setup_guide(provider="google", collector_preset="everything", auth="domain-delegation")

    assert payload["provider"] == "google_workspace"
    assert "google_drive_posture" in payload["selected_collectors"]
    assert "https://www.googleapis.com/auth/admin.reports.audit.readonly" in payload["required_scopes"]
    assert "https://www.googleapis.com/auth/drive.metadata.readonly" in payload["scopes_csv"]
    assert payload["provider_assertions"]["drive_file_content_reads"] is False
    assert any(row["scope"] == "https://www.googleapis.com/auth/gmail.settings.basic" for row in payload["scope_warnings"])
    assert "gmail.settings.sharing" not in payload["scopes_csv"]
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


def test_m365_setup_guide_lists_signin_and_report_settings_scopes() -> None:
    payload = build_setup_guide(provider="m365", auditor_profile="global-reader", collector_preset="full")

    assert "reports_usage" in payload["selected_collectors"]
    assert "ReportSettings.Read.All" in payload["graph_permissions"]
    assert "AuditLog.Read.All" in payload["graph_permissions"]
    assert "CloudApp-Discovery.Read.All" not in payload["graph_permissions"]
    assert not [scope for scope in payload["graph_permissions"] if "ReadWrite" in scope]
    rows = {row["collector"]: row for row in payload["collector_permissions"]}
    assert "AuditLog.Read.All" in rows["identity"]["required_permissions"]
    assert "ReportSettings.Read.All" in rows["reports_usage"]["required_permissions"]
    markdown = render_setup_guide_markdown(payload)
    assert "ReportSettings.Read.All" in markdown


def test_m365_setup_guide_defender_cloud_apps_uses_consent_request_scope() -> None:
    payload = build_setup_guide(provider="m365", collectors=["defender_cloud_apps"])

    assert payload["selected_collectors"] == ["defender_cloud_apps"]
    assert payload["graph_permissions"] == ["ConsentRequest.Read.All"]


def test_optional_power_platform_setup_notes_are_selected_only_on_opt_in():
    optional = build_setup_guide(provider="m365", collector_preset="power-platform", mode="app", plane="inventory")
    rows = {row["collector"]: row for row in optional["collector_permissions"]}
    assert optional["selected_collectors"] == ["identity", "licensing", "power_platform", "power_bi"]
    for name in ("power_platform", "power_bi"):
        assert rows[name]["required_permissions"] == []
        assert "off by default" in rows[name]["notes"]
        assert "write-capable admin role used read-only" in rows[name]["notes"]
        assert "no delegated token path" in rows[name]["notes"]
    assert "New-PowerAppManagementApp -ApplicationId <app id>" in rows["power_platform"]["notes"]
    assert "blast radius is UNKNOWN" in rows["power_platform"]["notes"]
    assert "https://service.powerapps.com//.default" in rows["power_platform"]["notes"]
    assert "TENANT_SETTINGS_METHOD remains pinned GET" in rows["power_platform"]["notes"]
    assert "https://analysis.windows.net/powerbi/api/.default" in rows["power_bi"]["notes"]
    assert "Service principals can access read-only admin APIs" in rows["power_bi"]["notes"]
    assert "never grant Tenant.Read.All" in rows["power_bi"]["notes"]
    baseline = build_setup_guide(provider="m365", collector_preset="full")
    assert "New-PowerAppManagementApp" not in json.dumps(baseline)
    assert "Service principals can access read-only admin APIs" not in json.dumps(baseline)
    # The opt-in adds no Graph permission beyond identity and licensing.
    supporting = build_setup_guide(provider="m365", collectors=["identity", "licensing"])
    assert optional["graph_permissions"] == supporting["graph_permissions"]


@pytest.mark.parametrize("selection", [
    {"collector_preset": "power-platform"},
    {"collectors": ["identity", "licensing", "power_platform", "power_bi"]},
    {"collectors": "identity,power_platform"},
    {"collectors": ["power_bi"]},
    {"collector_preset": "power-platform", "exclude": ["power_bi"]},
    {"collector_preset": "full", "collectors": ["power_bi", "identity"]},
])
def test_optional_setup_commands_preserve_resolved_selection(selection) -> None:
    payload = build_setup_guide(provider="m365", mode="app", plane="inventory", **selection)
    commands = payload["commands"]
    probe = auditex_cli._build_probe_parser().parse_args(shlex.split(commands["app_probe"])[2:])
    run = tenant_cli.build_parser().parse_args(shlex.split(commands["app_run"])[2:])

    assert probe.mode == "app"
    assert probe.surface.split(",") == [*payload["selected_collectors"], "windows365"]
    assert run.collectors.split(",") == payload["selected_collectors"]
    assert run.collector_preset == selection.get("collector_preset")
    assert run.plane == "inventory"
    assert run.client_id == probe.client_id == "<app-id>"


@pytest.mark.parametrize("selection", [
    {},
    {"collector_preset": "full"},
    {"collectors": ["identity", "licensing"]},
    {"collector_preset": "power-platform", "exclude": ["power_platform", "power_bi"]},
])
def test_setup_commands_without_power_collectors_preserve_requested_scope(selection) -> None:
    payload = build_setup_guide(provider="m365", **selection)
    probe = auditex_cli._build_probe_parser().parse_args(shlex.split(payload["commands"]["app_probe"])[2:])
    run = tenant_cli.build_parser().parse_args(shlex.split(payload["commands"]["app_run"])[2:])
    assert run.auditor_profile == probe.auditor_profile == "global-reader"
    assert run.plane == "full" and probe.mode == "app"
    assert run.collectors.split(",") == payload["authentication_plans"]["app"]["selected_collectors"]
    assert probe.surface.split(",") == [*run.collectors.split(","), "windows365"]
    assert {"power_platform", "power_bi"}.isdisjoint(payload["selected_collectors"])


def test_documented_optional_run_and_probe_examples_parse() -> None:
    guide = (Path(__file__).resolve().parents[1] / "docs/guides/admin-permission-guide.md").read_text()
    optional = guide.split("## Power Platform and Power BI (optional)", 1)[1]
    examples = [block.split("```", 1)[0] for block in optional.split("```bash\n")[1:]]
    run_words, probe_words = [shlex.split(example.replace("\\\n", "")) for example in examples[:2]]
    assert run_words[:2] == ["auditex", "run"]
    assert probe_words[:3] == ["auditex", "probe", "live"]
    run = tenant_cli.build_parser().parse_args(run_words[2:])
    probe = auditex_cli._build_probe_parser().parse_args(probe_words[2:])
    assert run.collector_preset == "power-platform"
    assert run.plane == "inventory"
    assert probe.mode == "app"
    assert probe.surface == "identity,licensing,power_platform,power_bi"


def test_default_app_setup_discloses_sessions_public_resolver_and_failures():
    guide = build_setup_guide(provider="m365", mode="app")
    text = render_setup_guide_markdown(guide)
    for phrase in ("Exchange Online PowerShell session", "Exchange.ManageAsApp", "Global Reader",
                   "cannot open this session", "Cloudflare", "https://cloudflare-dns.com/dns-query",
                   "Only domain names, no user data", "MTA-STS", "OpenID discovery", "verified domains",
                   "--exclude exchange_policy,dns_posture", "not assessed", "partial",
                   "Exchange accepted domains", "coexistence excluded", "Email service"):
        assert phrase in text
    assert "Exchange.ManageAsApp" not in guide["graph_permissions"]
    assert guide["exchange_application_permissions"] == ["Exchange.ManageAsApp"]
    assert {"pwsh", "ExchangeOnlineManagement"} <= set(guide["tool_requirements"])
    warning = next(row for row in guide["scope_warnings"] if row["permission"] == "Exchange.ManageAsApp")
    assert warning["risk"] == "write_capable"
    for phrase in ("read-only Get-*", "no mutating cmdlet", "Global Reader only"):
        assert phrase in warning["note"]


def test_default_delegated_setup_omits_app_mode_workloads():
    guide = build_setup_guide(provider="m365", mode="delegated")
    assert {"exchange_policy", "dns_posture"}.isdisjoint(guide["selected_collectors"])
    assert guide["exchange_application_permissions"] == ["Exchange.ManageAsApp"]
    assert "pwsh" in guide["tool_requirements"]
    delegated = guide["authentication_plans"]["delegated"]
    assert not delegated["exchange_application_permissions"]
    assert "pwsh" not in delegated["tool_requirements"]
    app = guide["authentication_plans"]["app"]
    assert {"exchange_policy", "dns_posture"} <= set(app["selected_collectors"])
    text = render_setup_guide_markdown(guide)
    assert "Cloudflare" in text and "Exchange Online PowerShell session" in text
    assert "app-mode only" in render_setup_guide_markdown(guide)


@pytest.mark.parametrize("exclude", ["exchange_policy", "dns_posture", "exchange_policy,dns_posture"])
def test_setup_guide_deselection_survives_generated_run_commands(tmp_path, exclude):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    guide = build_setup_guide(provider="m365", mode="app", exclude=exclude)
    assert set(exclude.split(",")).isdisjoint(guide["selected_collectors"])
    for key in ("app_probe", "delegated_probe"):
        args = auditex_cli._build_probe_parser().parse_args(shlex.split(guide["commands"][key])[2:])
        assert args.surface.split(",") == [*guide["authentication_plans"][key.split("_")[0]]["selected_collectors"], "windows365"]
    for key in ("app_run", "delegated_run"):
        args = tenant_cli.build_parser().parse_args(shlex.split(guide["commands"][key])[2:])
        plan = build_live_run_plan(args, output_dir=tmp_path,
                                   collector_config=CollectorConfig.from_path(Path("configs/collector-definitions.json")),
                                   permission_hints={}, collector_presets=load_collector_presets())
        assert plan.selected_collectors == guide["authentication_plans"][key.split("_")[0]]["selected_collectors"]
        if key.startswith("delegated"):
            assert {"exchange_policy", "dns_posture"}.isdisjoint(plan.selected_collectors)


@pytest.mark.parametrize("collectors", ["exchange_policy", "dns_posture", "exchange_policy,dns_posture"])
def test_setup_explicit_app_only_scope_does_not_emit_empty_delegated_commands(collectors):
    guide = build_setup_guide(provider="m365", mode="app", collectors=collectors)
    assert not any(key.startswith("delegated_") for key in guide["commands"])
    assert "delegated" not in guide["authentication_plans"]
    assert "delegated" not in guide["alternate_setup_steps"]
    assert f"--collectors {collectors}" in guide["commands"]["app_run"]
    assert "Delegated setup omitted" in render_setup_guide_markdown(guide)


def test_app_exchange_reader_with_only_app_collectors_omits_delegated_guide(tmp_path):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    guide = build_setup_guide(
        provider="m365", mode="app", auditor_profile="exchange-reader", exclude="exchange,security,identity"
    )
    assert guide["selected_collectors"] == ["exchange_policy"]
    args = tenant_cli.build_parser().parse_args(shlex.split(guide["commands"]["app_run"])[2:])
    plan = build_live_run_plan(args, output_dir=tmp_path,
                               collector_config=CollectorConfig.from_path(Path("configs/collector-definitions.json")),
                               permission_hints={}, collector_presets=load_collector_presets())
    assert plan.selected_collectors == guide["selected_collectors"]
    assert "delegated" not in guide["authentication_plans"]
    assert "delegated" not in guide["alternate_setup_steps"]
    assert not any(key.startswith("delegated_") for key in guide["commands"])
    notice = "Delegated setup omitted: no selected collectors support generated delegated commands."
    assert guide["setup_notices"] == [notice]
    markdown = render_setup_guide_markdown(guide)
    assert markdown.count(notice) == 1
    assert "## Delegated command requirements" not in markdown
    assert "### delegated_" not in markdown


@pytest.mark.parametrize("selection", [
    {"mode": "delegated", "auditor_profile": "exchange-reader", "exclude": "exchange,security,identity"},
    {"mode": "delegated", "collectors": "exchange_policy"},
    {"mode": "app", "collectors": "identity", "exclude": "identity"},
    {"mode": "delegated", "collectors": "identity", "exclude": "identity"},
])
def test_setup_guide_rejects_empty_requested_mode(selection):
    with pytest.raises(ValueError, match="No collectors selected"):
        build_setup_guide(provider="m365", **selection)


def test_exchange_tooling_follows_explicit_selection_in_other_profiles():
    guide = build_setup_guide(provider='m365', mode='app', auditor_profile='security-reader', collectors='exchange_policy')
    assert {'pwsh', 'ExchangeOnlineManagement'} <= set(guide['authentication_plans']['app']['tool_requirements'])


@pytest.mark.parametrize('collectors', ['identity,exchange_policy', 'identity,dns_posture',
                                        'identity,exchange_policy,dns_posture'])
@pytest.mark.parametrize('mode', ['app', 'delegated'])
def test_setup_discloses_explicit_names_filtered_from_delegated_commands(collectors, mode):
    guide = build_setup_guide(provider='m365', mode=mode, collectors=collectors)
    steps = guide['authentication_plans']['delegated']['setup_steps']
    assert sum('app-mode only' in step for step in steps) == 1
    assert any('including explicitly selected names' in step for step in steps)
    if 'identity' in collectors:
        for key in ('app_probe', 'delegated_probe'):
            args = auditex_cli._build_probe_parser().parse_args(shlex.split(guide['commands'][key])[2:])
            assert args.surface.split(',')[-1] == 'windows365'
        args = tenant_cli.build_parser().parse_args(shlex.split(guide['commands']['delegated_run'])[2:])
        assert args.collectors == 'identity'
    assert 'app-mode only' in render_setup_guide_markdown(guide)
