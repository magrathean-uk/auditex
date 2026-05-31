from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.resources import shipped_resource_manifest


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_m365_known_bad_sample_emits_high_signal_findings(tmp_path: Path) -> None:
    run_dir = tmp_path / "contoso-known-bad"

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "known_bad_result.json",
        tmp_path,
        "contoso",
        "known-bad",
        auditor_profile="global-reader",
        plane="inventory",
    )

    assert rc == 0
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    api_inventory = json.loads((run_dir / "api-inventory.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))

    assert manifest["contract_status"] == "valid"
    assert manifest["provider_adapter_version"] == "2026-05-31"
    assert manifest["api_inventory_recorder_version"] == "2026-05-31"
    assert manifest["fixture_provenance"]["fixture_id"] == "m365-known-bad"
    assert manifest["fixture_provenance"]["seed_kind"] == "known_bad"
    assert "_fixture_provenance" not in manifest["selected_collectors"]
    assert validation["valid"] is True, validation["issues"]
    assert api_inventory["platform"] == "m365"
    assert report_pack["summary"]["risk"]["grade"] in {"high", "critical"}
    assert report_pack["citation_summary"]["citation_count"] >= 4
    assert report_pack["citation_summary"]["artifact_count"] >= 4
    assert report_pack["citation_summary"]["record_key_count"] >= 1
    assert report_pack["fixture_provenance"]["fixture_id"] == "m365-known-bad"

    finding_ids = {item["id"] for item in findings}
    assert {
        "mailbox_forwarding:u1:rule-1:external_forward",
        "exchange_transport:Redirect invoices:external_redirect",
        "exchange_remote_domain:Default:auto_forward_enabled",
        "dns_posture:contoso.com:spf_missing",
        "dns_posture:contoso.com:dmarc_monitor_only",
        "dns_posture:contoso.com:dkim_missing",
        "app_credentials:app-1:secret_expired",
        "app_credentials:app-1:redirect_insecure",
        "app_credentials:app-1:no_owner",
        "app_credentials:app-1:multi_tenant_audience",
        "cross_tenant_access:default:b2b_direct_connect_inbound_open",
        "cross_tenant_access:default:auto_user_consent_inbound_enabled",
        "cross_tenant_access:partner:11111111-1111-1111-1111-111111111111:b2b_direct_connect_no_mfa",
    }.issubset(finding_ids)


def test_google_known_bad_sample_emits_high_signal_findings(tmp_path: Path) -> None:
    from auditex.google_workspace.run import run_google_offline

    run_dir = tmp_path / "Example-google-known-bad"

    rc = run_google_offline(
        sample_path=REPO_ROOT / "examples" / "google_workspace_sample.json",
        out=tmp_path,
        tenant_name="Example",
        run_name="google-known-bad",
        domain="example.com",
        customer_id="C123",
    )

    assert rc == 0
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))

    assert manifest["platform"] == "google_workspace"
    assert manifest["contract_status"] == "valid"
    assert manifest["provider_adapter_version"] == "2026-05-31"
    assert manifest["api_inventory_recorder_version"] == "2026-05-31"
    assert manifest["fixture_provenance"]["fixture_id"] == "google-known-bad"
    assert manifest["fixture_provenance"]["seed_kind"] == "known_bad"
    assert "_fixture_provenance" not in manifest["selected_collectors"]
    assert validation["valid"] is True, validation["issues"]
    assert report_pack["summary"]["risk"]["grade"] in {"high", "critical"}
    assert report_pack["citation_summary"]["citation_count"] >= 4
    assert report_pack["citation_summary"]["artifact_count"] >= 4
    assert report_pack["citation_summary"]["record_key_count"] >= 1
    assert report_pack["fixture_provenance"]["fixture_id"] == "google-known-bad"

    rule_ids = {item["rule_id"] for item in findings}
    open_join = next(item for item in findings if item["rule_id"] == "google.group_anyone_can_join")
    assert {
        "google.collector_issue",
        "google.admin_2sv_not_enforced",
        "google.group_external_member",
        "google.oauth_high_risk_scope",
        "google.gmail_imap_enabled",
        "google.gmail_pop_enabled",
        "google.gmail_vacation_external_reply",
        "google.gmail_external_forwarding",
        "google.gmail_external_forwarding_address_ready",
        "google.gmail_filter_external_forwarding",
        "google.gmail_hidden_forwarding_filter",
        "google.gmail_external_send_as",
        "google.gmail_external_delegate",
        "google.drive_anyone_with_link",
        "google.drive_public_discoverable",
        "google.drive_domain_permission",
        "google.drive_external_permission",
        "google.shared_drive_external_members_allowed",
        "google.calendar_public_acl",
        "google.calendar_external_acl",
        "google.calendar_domain_acl",
        "google.group_anyone_can_join",
        "google.group_domain_can_join",
        "google.group_external_members_allowed",
        "google.group_anyone_can_post",
        "google.group_anyone_can_post_unmoderated",
        "google.group_domain_can_post",
        "google.group_domain_can_post_unmoderated",
        "google.group_public_view",
        "google.group_public_membership",
        "google.group_domain_view",
        "google.group_domain_membership",
        "google.mobile_device_compromised",
        "google.mobile_device_stale_sync",
        "google.chromeos_device_stale_sync",
        "google.chromeos_device_inactive_assignment",
        "google.login_suspicious_event",
        "google.admin_privilege_event",
        "google.dns_spf_missing",
        "google.dns_dmarc_monitor_only",
        "google.dns_dkim_missing",
    }.issubset(rule_ids)
    assert open_join["collector"] == "google_groups_settings"
    assert open_join["evidence_refs"][0]["artifact_path"] == "normalized/google_group_settings.json"


def test_shipped_resource_manifest_lists_known_bad_samples() -> None:
    manifest = shipped_resource_manifest()

    assert "examples/sample_audit_bundle/known_bad_result.json" in manifest["resources"]
    assert "examples/google_workspace_sample.json" in manifest["resources"]
