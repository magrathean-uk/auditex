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
    assert m365["framework_mappings"]["cis_m365_v3"]
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
