from __future__ import annotations

from pathlib import Path

from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.diagnostics import load_permission_hints
from auditex.setup_guide import build_setup_guide


def test_m365_scope_catalog_merges_definition_and_hint_truth() -> None:
    from azure_tenant_audit.scope_catalog import aggregate_catalog_rows, build_m365_scope_catalog

    config = CollectorConfig.from_path("configs/collector-definitions.json")
    hints = load_permission_hints(Path("configs/collector-permissions.json"))

    catalog = build_m365_scope_catalog(
        collector_config=config,
        permission_hints=hints,
    )
    identity = catalog["identity"]

    assert "Directory.Read.All" in identity["required_permissions"]
    assert "Application.Read.All" in identity["required_permissions"]
    assert "Security Reader" in identity["minimum_role_hints"]
    assert identity["description"] == config.collectors["identity"].description

    aggregate = aggregate_catalog_rows(catalog, ["identity", "reports_usage"])
    assert "Directory.Read.All" in aggregate["required_permissions"]
    assert "Reports Reader" in aggregate["minimum_role_hints"]


def test_google_scope_catalog_exposes_scope_risk_and_api_enablement() -> None:
    from azure_tenant_audit.scope_catalog import aggregate_catalog_rows, build_google_scope_catalog

    catalog = build_google_scope_catalog()
    gmail = catalog["google_gmail_settings"]
    drive = catalog["google_drive_posture"]

    assert "Gmail API" in gmail["api_enablement"]
    assert any(row["scope"] == "https://www.googleapis.com/auth/gmail.settings.sharing" for row in gmail["scope_warnings"])
    assert "Google Drive API" in drive["api_enablement"]
    assert any(row["scope"] == "https://www.googleapis.com/auth/drive.readonly" for row in drive["scope_warnings"])

    aggregate = aggregate_catalog_rows(catalog, ["google_gmail_settings", "google_drive_posture"])
    assert "https://www.googleapis.com/auth/gmail.settings.sharing" in aggregate["required_permissions"]
    assert any(row["scope"] == "https://www.googleapis.com/auth/drive.readonly" for row in aggregate["scope_warnings"])


def test_m365_setup_guide_matches_scope_catalog_aggregate() -> None:
    from azure_tenant_audit.scope_catalog import aggregate_catalog_rows, build_m365_scope_catalog

    payload = build_setup_guide(
        provider="m365",
        auditor_profile="global-reader",
        collector_preset="identity-only",
        tenant_id="contoso.onmicrosoft.com",
    )
    config = CollectorConfig.from_path("configs/collector-definitions.json")
    hints = load_permission_hints(Path("configs/collector-permissions.json"))
    catalog = build_m365_scope_catalog(
        collector_config=config,
        permission_hints=hints,
    )
    aggregate = aggregate_catalog_rows(catalog, payload["selected_collectors"])

    assert payload["graph_permissions"] == aggregate["required_permissions"]
    assert payload["minimum_role_hints"] == aggregate["minimum_role_hints"]
