from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit import cli
from auditex.rules import list_rule_inventory
from auditex import cli as auditex_cli


def test_parser_accepts_collector_preset() -> None:
    args = cli.build_parser().parse_args(
        [
            "--tenant-name",
            "acme",
            "--offline",
            "--collector-preset",
            "identity-only",
        ]
    )

    assert args.collector_preset == "identity-only"


def test_collector_preset_resolves_before_profile_defaults(tmp_path: Path) -> None:
    from azure_tenant_audit.presets import load_collector_presets, resolve_collector_selection

    preset_path = tmp_path / "collector-presets.json"
    preset_path.write_text(
        json.dumps(
            {
                "presets": {
                    "identity-only": {
                        "description": "Identity only",
                        "include": ["identity", "security"],
                        "exclude": ["security"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    presets = load_collector_presets(preset_path)
    resolved = resolve_collector_selection(
        available=["identity", "security", "sharepoint"],
        profile_default_collectors=("sharepoint",),
        preset_name="identity-only",
        presets=presets,
    )

    assert resolved == ["identity"]


def test_explicit_collectors_override_preset(tmp_path: Path) -> None:
    from azure_tenant_audit.presets import load_collector_presets, resolve_collector_selection

    preset_path = tmp_path / "collector-presets.json"
    preset_path.write_text(
        json.dumps({"presets": {"identity-only": {"include": ["identity"]}}}),
        encoding="utf-8",
    )

    presets = load_collector_presets(preset_path)
    resolved = resolve_collector_selection(
        available=["identity", "security", "sharepoint"],
        profile_default_collectors=("sharepoint",),
        preset_name="identity-only",
        presets=presets,
        explicit_collectors=["security"],
        excluded_collectors=["sharepoint"],
    )

    assert resolved == ["security"]


def test_rule_inventory_lists_sorted_rows(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.list_rule_inventory",
        lambda **_: [
            {"name": "zeta.rule", "tags": ["security"]},
            {"name": "alpha.rule", "tags": ["identity"]},
        ],
    )

    rc = auditex_cli.main(["rules", "inventory"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [row["name"] for row in payload["rules"]] == ["alpha.rule", "zeta.rule"]


def test_rule_inventory_filters_by_tag(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.list_rule_inventory",
        lambda **_: [{"name": "alpha.rule", "tags": ["identity"]}],
    )

    rc = auditex_cli.main(["rules", "inventory", "--tag", "identity"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["rules"][0]["name"] == "alpha.rule"


def test_rule_inventory_lists_generated_m365_and_google_rules() -> None:
    rows = list_rule_inventory()
    by_name = {row["name"]: row for row in rows}

    m365 = by_name["identity.global_admin_mfa_not_registered"]
    google = by_name["google.admin_2sv_not_enforced"]

    assert m365["platform"] == "m365"
    assert m365["product_family"] == "identity"
    assert m365["framework_mappings"]["cis_m365_v7"]
    assert "m365.identity" in m365["packs"]
    assert google["platform"] == "google_workspace"
    assert google["product_family"] == "identity"
    assert google["framework_mappings"]["google_workspace_baseline"] == ["identity.2sv"]


def test_rule_inventory_includes_operator_metadata_for_m365_and_google() -> None:
    rows = list_rule_inventory()
    by_name = {row["name"]: row for row in rows}

    m365 = by_name["identity.global_admin_mfa_not_registered"]
    google = by_name["google.gmail_external_forwarding"]

    assert m365["risk_rating"] == "critical"
    assert "phishing-resistant MFA" in m365["remediation"]
    assert m365["expected_value"]
    assert google["risk_rating"] == "high"
    assert google["description"] == "A mailbox forwards incoming mail to an external address."
    assert "Disable unapproved forwarding" in google["remediation"]
    assert google["expected_value"]


def test_google_rule_inventory_has_specific_metadata_for_every_rule() -> None:
    rows = list_rule_inventory(platform="google_workspace")

    assert rows
    for row in rows:
        assert row["description"] != "Google Workspace evidence is outside the approved audit baseline."
        assert row["risk_rating"] in {"low", "medium", "high", "critical"}
        assert row["remediation"]
        assert row["expected_value"]


def test_rule_inventory_filters_by_platform_and_product_family() -> None:
    rows = list_rule_inventory(platform="google_workspace", product_family="gmail")

    assert rows
    assert {row["platform"] for row in rows} == {"google_workspace"}
    assert {row["product_family"] for row in rows} == {"gmail"}
    assert "google.gmail_external_forwarding" in {row["name"] for row in rows}


def test_power_platform_opt_in_selects_disabled_collectors_without_extending_defaults(tmp_path):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.profiles import get_profile
    from azure_tenant_audit.run import build_live_run_plan

    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    presets = load_collector_presets()
    optional = {"power_platform", "power_bi"}
    assert all(config.collectors[name].enabled is False for name in optional)
    assert presets["power-platform"]["plane"] == "inventory"
    for name, preset in presets.items():
        if name != "power-platform":
            assert optional.isdisjoint(preset["include"]), name
    assert optional.isdisjoint(get_profile("global-reader").default_collectors)

    def plan(extra):
        args = cli.build_parser().parse_args(["--tenant-name", "constructed", *extra])
        return build_live_run_plan(args, output_dir=tmp_path, collector_config=config,
                                   permission_hints={}, collector_presets=presets)

    selected = plan(["--collector-preset", "power-platform", "--plane", "inventory"])
    assert selected.selected_collectors == ["identity", "licensing", "power_platform", "power_bi"]
    assert selected.execution_plane == "inventory"
    assert optional.isdisjoint(plan([]).selected_collectors)
    assert optional.isdisjoint(plan(["--collector-preset", "full"]).selected_collectors)


def test_default_workload_selection_and_unchanged_presets(tmp_path):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.profiles import PROFILES
    from azure_tenant_audit.run import build_live_run_plan

    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    presets = load_collector_presets()
    baseline = "identity app_consent security conditional_access defender service_health auth_methods reports_usage external_identity consent_policy domains_hybrid licensing identity_governance intune sharepoint onedrive_posture teams".split()
    assert list(PROFILES["auto"].default_collectors) == baseline + ["exchange_policy", "dns_posture"]
    reader = baseline[:15] + ["sharepoint_access"] + baseline[15:]
    assert list(PROFILES["global-reader"].default_collectors) == reader + ["exchange_policy", "dns_posture"]
    assert presets["full"]["include"] == reader + ["exchange_policy", "dns_posture"]
    assert list(PROFILES["app-readonly-full"].default_collectors) == "identity app_consent security conditional_access defender service_health auth_methods reports_usage external_identity consent_policy domains_hybrid licensing identity_governance intune intune_depth sharepoint sharepoint_access onedrive_posture teams teams_policy purview ediscovery exchange exchange_policy dns_posture".split()
    assert presets["config-only"]["include"] == "identity app_consent conditional_access auth_methods external_identity consent_policy domains_hybrid licensing identity_governance sharepoint teams".split()
    assert presets["power-platform"]["include"] == ["identity", "licensing", "power_platform", "power_bi"]
    unchanged = {
        "security-reader": "identity app_consent security conditional_access defender auth_methods identity_governance",
        "reports-reader": "identity security service_health reports_usage",
        "exchange-reader": "exchange exchange_policy security identity",
        "intune-reader": "intune intune_depth",
    }
    for profile, expected in unchanged.items():
        assert list(PROFILES[profile].default_collectors) == expected.split()
    for name in ("exchange_policy", "dns_posture"):
        assert config.collectors[name].enabled is True
    for profile in ("auto", "global-reader", "app-readonly-full"):
        for mode_args in ([], ["--interactive"], ["--use-azure-cli-token"]):
            args = cli.build_parser().parse_args(["--auditor-profile", profile, *mode_args])
            plan = build_live_run_plan(args, output_dir=tmp_path, collector_config=config, permission_hints={}, collector_presets=presets)
            if not mode_args:
                assert {"exchange_policy", "dns_posture"} <= set(plan.selected_collectors)
                assert plan.selection_notices == ()
            else:
                assert {"exchange_policy", "dns_posture"}.isdisjoint(plan.selected_collectors)
                assert len(plan.selection_notices) == 1
                assert "app-mode only" in plan.selection_notices[0]


def test_deselect_default_workloads_in_both_clis(tmp_path, monkeypatch):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    captured = []
    monkeypatch.setattr(auditex_cli, "tenant_audit_main", lambda argv: captured.append(cli.build_parser().parse_args(argv)) or 0)
    for entrypoint in ("engine", "product"):
        for extra, absent in (
            (["--exclude", "exchange_policy"], {"exchange_policy"}),
            (["--exclude", "dns_posture"], {"dns_posture"}),
            (["--collector-preset", "full", "--exclude", "exchange_policy,dns_posture"], {"exchange_policy", "dns_posture"}),
            (["--collectors", "identity,conditional_access"], {"exchange_policy", "dns_posture"}),
            (["--collector-preset", "config-only"], {"exchange_policy", "dns_posture"}),
        ):
            if entrypoint == "product":
                assert auditex_cli.main(["run", *extra]) == 0
                args = captured[-1]
            else:
                args = cli.build_parser().parse_args(extra)
            plan = build_live_run_plan(args, output_dir=tmp_path, collector_config=config, permission_hints={}, collector_presets=load_collector_presets())
            assert absent.isdisjoint(plan.selected_collectors)
            if extra == ["--exclude", "exchange_policy"]:
                assert "dns_posture" in plan.selected_collectors
            if extra == ["--exclude", "dns_posture"]:
                assert "exchange_policy" in plan.selected_collectors


def test_non_app_only_explicit_collectors_override_app_default_boundary(tmp_path):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    config = CollectorConfig.from_path(Path("configs/collector-definitions.json"))
    for mode in (["--interactive"], ["--use-azure-cli-token"], ["--access-token", "constructed"]):
        for selection in (["--collectors", "exchange_policy,dns_posture"], ["--collector-preset", "full"], ["--include-exchange"]):
            args = cli.build_parser().parse_args([*mode, *selection])
            plan = build_live_run_plan(args, output_dir=tmp_path, collector_config=config,
                                       permission_hints={}, collector_presets=load_collector_presets())
            if selection[0] == "--collectors":
                assert {"exchange_policy", "dns_posture"} <= set(plan.selected_collectors)
                assert not plan.selection_notices
            else:
                assert {"exchange_policy", "dns_posture"}.isdisjoint(plan.selected_collectors)
                assert len(plan.selection_notices) == 1
                if selection == ["--include-exchange"]:
                    assert "exchange" in plan.selected_collectors
