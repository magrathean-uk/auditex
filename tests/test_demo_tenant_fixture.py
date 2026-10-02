from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.resources import shipped_resource_manifest


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "examples" / "demo_tenant" / "demo_tenant.json"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+#-]+@([A-Za-z0-9.-]+)")
_URL_HOST_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/:\s\"'?#]+)", re.IGNORECASE)
_REAL_TLD_RE = re.compile(r"[A-Za-z0-9-]\.(?:com|net|org|io|co\.uk|uk|eu|de)\b", re.IGNORECASE)

EXPECTED_FINDING_IDS = {
    # Identity: Global Administrator sprawl, missing MFA, stale password, disabled holder.
    "identity:global_admin_sprawl",
    "identity:global_admin_mfa_not_registered:0d3e1a7f-0000-4000-8000-000100000003",
    "identity:global_admin_stale_password:0d3e1a7f-0000-4000-8000-000100000004",
    "identity:global_admin_disabled:0d3e1a7f-0000-4000-8000-000100000005",
    "identity:user_mfa_not_registered:0d3e1a7f-0000-4000-8000-000100000008",
    "security_signin:0d3e1a7f-0000-4000-8000-000700000003:risky",
    "security_directory_audit:Directory_0d3e1a7f-0000-4000-8000-000800000001:privilege_change",
    "security_directory_audit:Directory_0d3e1a7f-0000-4000-8000-000800000002:privilege_change",
    # Conditional Access.
    "conditional_access:ca_reporting_only:0d3e1a7f-0000-4000-8000-000500000002",
    "conditional_access:ca_break_glass_exclusion:0d3e1a7f-0000-4000-8000-000500000003",
    # Applications: ShipTrack Sync consent and credential hygiene.
    "app_consent:shiptrack-graph-allprincipals:high_privilege",
    "app_credentials:0d3e1a7f-0000-4000-8000-000300000001:secret_expired",
    "app_credentials:0d3e1a7f-0000-4000-8000-000300000001:secret_long_validity",
    "app_credentials:0d3e1a7f-0000-4000-8000-000300000001:redirect_insecure",
    "app_credentials:0d3e1a7f-0000-4000-8000-000300000001:no_owner",
    "app_credentials:0d3e1a7f-0000-4000-8000-000300000001:multi_tenant_audience",
    "consent_policy:adminConsentRequestPolicy:admin_consent_workflow_disabled",
    "external_identity:authorizationPolicy:broad_guest_invite_policy",
    # Cross-tenant access.
    "cross_tenant_access:default:b2b_collaboration_inbound_open",
    "cross_tenant_access:partner:0d3e1a7f-0000-4000-8000-00000000a001:b2b_direct_connect_no_mfa",
    # Mail flow.
    "mailbox_forwarding:0d3e1a7f-0000-4000-8000-000100000008:AQAAAHB-rule-01:external_forward",
    "mailbox_forwarding:0d3e1a7f-0000-4000-8000-000100000008:AQAAAHB-rule-02:hide_from_user",
    "exchange_transport:Redirect invoices:external_redirect",
    "exchange_remote_domain:Default:auto_forward_enabled",
    "exchange:Dispatch Desk:mailbox_forwarding",
    "dns_posture:halcyonfreight.example:dmarc_monitor_only",
    "dns_posture:halcyonfreight.example:dkim_missing",
    # SharePoint, OneDrive, Teams.
    "sharepoint:halcyonfreight.sharepoint.example,0d3e1a7f-0000-4000-8000-000b00000001,"
    "0d3e1a7f-0000-4000-8000-000c00000001:fin-p4:sharing",
    "sharepoint_permission:halcyonfreight.sharepoint.example,0d3e1a7f-0000-4000-8000-000b00000001,"
    "0d3e1a7f-0000-4000-8000-000c00000001:fin-p3:sam.okafor@parcel-partners.example:external_principal",
    "teams_policy:Global:external_federation_open",
    # Intune and service health.
    "intune:0d3e1a7f-0000-4000-8000-001000000003:device_noncompliant",
    "intune:0d3e1a7f-0000-4000-8000-001000000006:device_stale_sync",
    "intune:intune_policies_without_assignments",
    "identity_governance:standing_privilege_only",
    "service_health:EX918274:active_service_issue",
}

EXPECTED_RULE_IDS = {
    "identity.global_admin_sprawl",
    "identity.global_admin_mfa_not_registered",
    "identity.global_admin_stale_password",
    "identity.global_admin_disabled",
    "identity.user_mfa_not_registered",
    "security.risky_signin",
    "security.privilege_change_event",
    "app_consent.high_privilege",
    "app_credentials.secret_expired",
    "app_credentials.secret_long_validity",
    "app_credentials.redirect_insecure",
    "app_credentials.no_owner",
    "app_credentials.multi_tenant_audience",
    "app_credentials.certificate_expired",
    "app_credentials.credential_dormant",
    "consent_policy.admin_consent_workflow_disabled",
    "external_identity.broad_guest_invite_policy",
    "cross_tenant_access.default_b2b_collaboration_inbound_open",
    "cross_tenant_access.default_b2b_collaboration_outbound_open",
    "cross_tenant_access.partner_inbound_no_mfa",
    "mailbox_forwarding.external_inbox_rule",
    "mailbox_forwarding.hide_from_user",
    "exchange.transport_external_redirect",
    "exchange.remote_domain_auto_forward_enabled",
    "dns_posture.dmarc_monitor_only",
    "dns_posture.dkim_missing",
    "sharepoint.broad_link",
    "sharepoint.external_principal",
    "intune.device_noncompliant",
    "intune.device_stale_sync",
    "service_health.active_service_issue",
}


def _run_demo(tmp_path: Path) -> Path:
    rc = run_offline(
        FIXTURE,
        tmp_path,
        "halcyon-freight",
        "demo",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "halcyon-freight-demo"


def _load(run_dir: Path, relative: str) -> Any:
    return json.loads((run_dir / relative).read_text(encoding="utf-8"))


def _walk(value: Any, key: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _walk(child, str(child_key))
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child, key)
    else:
        yield key, value


def test_demo_tenant_fixture_produces_valid_critical_bundle(tmp_path: Path) -> None:
    run_dir = _run_demo(tmp_path)
    manifest = _load(run_dir, "run-manifest.json")
    validation = _load(run_dir, "validation.json")
    report_pack = _load(run_dir, "reports/report-pack.json")
    findings = _load(run_dir, "findings/findings.json")

    assert validation["valid"] is True, validation["issues"]
    assert manifest["contract_status"] == "valid"
    provenance = manifest["fixture_provenance"]
    assert provenance["fixture_id"] == "m365-demo-tenant"
    assert provenance["seed_kind"] == "demo"
    assert provenance["synthetic"] is True
    assert "fictional" in provenance["description"]
    assert report_pack["fixture_provenance"]["seed_kind"] == "demo"
    assert "_fixture_provenance" not in manifest["selected_collectors"]

    assert report_pack["summary"]["risk"]["grade"] == "critical"
    assert len(findings) >= 30
    assert len({item["category"] for item in findings}) >= 8
    severities = Counter(item["severity"] for item in findings)
    assert severities["critical"] >= 3
    assert severities["high"] >= 10

    finding_ids = {item["id"] for item in findings}
    missing_ids = EXPECTED_FINDING_IDS - finding_ids
    assert not missing_ids, sorted(missing_ids)
    rule_ids = {item.get("rule_id") for item in findings}
    missing_rules = EXPECTED_RULE_IDS - rule_ids
    assert not missing_rules, sorted(missing_rules)

    proof_table = report_pack["proof_table"]
    assert proof_table
    assert {row["proof_status"] for row in proof_table} == {"supported"}
    assert {row["finding_id"] for row in proof_table} == finding_ids
    assert report_pack["report_qa"]["checks"]["every_finding_has_evidence"] is True
    assert report_pack["attack_paths"], "demo story should produce a multi-stage attack path"


def test_demo_tenant_counts_nested_sections_and_keeps_attack_path_seed(tmp_path: Path) -> None:
    run_dir = _run_demo(tmp_path)
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    checkpoint_state = _load(run_dir, "checkpoints/checkpoint-state.json")

    identity_records = sum(len(section["value"]) for section in fixture["identity"].values())
    assert checkpoint_state["collectors"]["identity"]["item_count"] == identity_records

    # Attack-path seed: an ordinary user owns an app holding a tier-0 Graph application permission.
    owners = {
        row["displayName"]: [owner["userPrincipalName"] for owner in row["owners"]]
        for row in fixture["app_consent"]["servicePrincipalOwners"]["value"]
    }
    assert owners["Payroll Export"] == ["tom.fielding@halcyonfreight.example"]
    owner_id = next(
        user["id"]
        for user in fixture["identity"]["users"]["value"]
        if user["userPrincipalName"] == "tom.fielding@halcyonfreight.example"
    )
    assert owner_id not in {item["principalId"] for item in fixture["identity"]["roleAssignments"]["value"]}
    graph_assignments = next(
        row["assignments"]
        for row in fixture["app_consent"]["servicePrincipalAppRoleAssignments"]["value"]
        if row["displayName"] == "Microsoft Graph"
    )
    assert any(
        item["principalDisplayName"] == "Payroll Export" and item["appRoleValue"] == "RoleManagement.ReadWrite.Directory"
        for item in graph_assignments
    )
    consents = _load(run_dir, "normalized/application_consents.json")["records"]
    assert any(
        item.get("source_name") == "servicePrincipalAppRoleAssignments"
        and item.get("principal_display_name") == "Payroll Export"
        for item in consents
    )


def test_demo_tenant_fixture_uses_only_reserved_example_domains() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    fixture = json.loads(text)

    for banned in ("contoso", "fabrikam", "northwind", "adatum", "wingtip", "litware"):
        assert banned not in text.lower(), banned
    assert not _REAL_TLD_RE.findall(text)

    hosts: set[str] = set()
    for key, value in _walk(fixture):
        if not isinstance(value, str):
            continue
        hosts.update(match.lower() for match in _EMAIL_RE.findall(value))
        hosts.update(match.lower() for match in _URL_HOST_RE.findall(value))
        if "domain" in key.lower() and "." in value and value != "*":
            hosts.add(value.lower())
    assert hosts
    # Teams channel ids use the "19:<id>@thread.tacv2" form, which is an identifier, not a mail domain.
    allowed = {"localhost", "thread.tacv2"}
    bad = sorted(host for host in hosts if not (host.endswith(".example") or host in allowed))
    assert not bad, bad

    tenant_id = fixture["identity"]["organization"]["value"][0]["id"]
    assert tenant_id == "0d3e1a7f-0000-4000-8000-00000000d3e0"


def test_shipped_resource_manifest_lists_demo_tenant() -> None:
    manifest = shipped_resource_manifest()

    assert "examples/demo_tenant/demo_tenant.json" in manifest["resources"]
    assert "examples/demo_tenant" in manifest["areas"]
