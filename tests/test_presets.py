from __future__ import annotations

import json
from pathlib import Path

import pytest

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


@pytest.mark.parametrize("preset_name", ["config-only", "full"])
def test_broad_presets_select_teams_policy_after_teams(preset_name, tmp_path):
    from azure_tenant_audit.config import CollectorConfig
    from azure_tenant_audit.presets import load_collector_presets
    from azure_tenant_audit.run import build_live_run_plan

    expected = [
        "identity", "app_consent", "conditional_access", "auth_methods",
        "external_identity", "consent_policy", "domains_hybrid", "licensing",
        "identity_governance", "sharepoint", "teams", "teams_policy",
    ]
    if preset_name == "full":
        expected = [
            "identity", "app_consent", "security", "conditional_access", "defender",
            "service_health", "auth_methods", "reports_usage", "external_identity",
            "consent_policy", "domains_hybrid", "licensing", "identity_governance",
            "intune", "sharepoint", "sharepoint_access", "onedrive_posture",
            "teams", "teams_policy",
        ]
    presets = load_collector_presets()
    assert presets[preset_name]["include"] == expected
    args = cli.build_parser().parse_args([
        "--tenant-name", "constructed", "--collector-preset", preset_name,
    ])
    plan = build_live_run_plan(
        args, output_dir=tmp_path,
        collector_config=CollectorConfig.from_path(Path("configs/collector-definitions.json")),
        permission_hints={}, collector_presets=presets,
    )
    assert plan.selected_collectors == expected


def test_other_preset_lists_remain_unchanged():
    from azure_tenant_audit.presets import load_collector_presets

    presets = load_collector_presets()
    assert {name: preset["include"] for name, preset in presets.items()
            if name not in {"config-only", "full"}} == {
        "identity-only": ["identity", "app_consent"],
        "security-only": ["security", "conditional_access", "defender", "auth_methods", "identity_governance"],
        "power-platform": ["identity", "licensing", "power_platform", "power_bi"],
    }


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
