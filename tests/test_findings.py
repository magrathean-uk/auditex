from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

import azure_tenant_audit.findings as findings_module
from azure_tenant_audit.findings import build_findings, build_report_pack


def _utc_days_ago(days: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_build_findings_classifies_permission_and_partial_failures() -> None:
    diagnostics = [
        {
            "collector": "security",
            "item": "securityAlerts",
            "status": "failed",
            "error_class": "insufficient_permissions",
            "error": "Forbidden",
            "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
        },
        {
            "collector": "sharepoint",
            "item": "sites",
            "status": "partial",
            "error_class": "service_unavailable",
            "error": "Tenant mysite not provisioned",
            "recommendations": {"notes": ["OneDrive not provisioned"]},
        },
    ]

    findings = build_findings(diagnostics)

    assert len(findings) == 2
    permission_finding = findings[0]
    assert permission_finding["id"] == "security:securityAlerts"
    assert permission_finding["severity"] == "high"
    assert permission_finding["risk_rating"] == "high"
    assert permission_finding["category"] == "permission"
    assert permission_finding["recommendations"]["required_graph_scopes"] == ["SecurityEvents.Read.All"]
    assert permission_finding["evidence_refs"][0]["artifact_path"] == "raw/security.json"

    service_finding = findings[1]
    assert service_finding["severity"] == "medium"
    assert service_finding["category"] == "service"
    assert service_finding["affected_objects"] == ["sites"]


def test_build_report_pack_includes_findings_and_evidence_paths() -> None:
    findings = [
        {
            "id": "security:securityAlerts",
            "rule_id": "collector.issue.permission",
            "severity": "high",
            "title": "security collector issue",
            "status": "open",
            "category": "permission",
            "affected_objects": ["securityAlerts"],
            "remediation": "Grant the missing read scope or reduce the collector set.",
        }
    ]

    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=findings,
        evidence_paths=["run-manifest.json", "findings/findings.json"],
        blocker_count=1,
    )

    assert report["summary"]["tenant_name"] == "acme"
    assert report["summary"]["overall_status"] == "partial"
    assert report["summary"]["finding_count"] == 1
    assert report["summary"]["blocker_count"] == 1
    assert report["summary"]["open_count"] == 1
    assert report["summary"]["accepted_count"] == 0
    assert report["privacy"] == {}
    assert report["summary"]["risk"]["score"] == 40
    assert report["summary"]["risk"]["grade"] == "high"
    assert report["summary"]["risk"]["open_weight"] == 4
    assert report["findings"][0]["id"] == "security:securityAlerts"
    assert report["evidence_paths"] == ["run-manifest.json", "findings/findings.json"]
    assert report["action_plan"][0]["rule_id"] == "collector.issue.permission"


def test_build_report_pack_risk_rollup_ignores_non_open_findings() -> None:
    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=[
            {"id": "critical-open", "severity": "critical", "status": "open", "title": "Crit"},
            {"id": "high-waived", "severity": "high", "status": "waived", "title": "Waived"},
            {"id": "medium-accepted", "severity": "medium", "status": "accepted_risk", "title": "Accepted"},
        ],
        evidence_paths=[],
    )

    assert report["summary"]["risk"] == {
        "score": 60,
        "grade": "critical",
        "open_weight": 6,
        "counts_by_open_severity": {"critical": 1},
        "top_open_findings": [{"id": "critical-open", "severity": "critical", "title": "Crit", "category": None}],
    }


def test_build_report_pack_promotes_coverage_gaps_into_risk_and_action_plan() -> None:
    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=[
            {
                "id": "medium-open",
                "rule_id": "identity.user_mfa_not_registered",
                "severity": "medium",
                "status": "open",
                "title": "User missing MFA",
                "category": "identity",
            }
        ],
        coverage_gaps=[
            {
                "surface": "mail",
                "status": "blocked",
                "severity": "high",
                "collectors": ["google_gmail_settings"],
                "error_classes": ["invalid_scope"],
                "message": "mail coverage is blocked; affected collectors: google_gmail_settings",
            }
        ],
        evidence_paths=[],
    )

    assert report["summary"]["coverage_gap_count"] == 1
    assert report["summary"]["risk"]["score"] == 40
    assert report["summary"]["risk"]["coverage_gap_weight"] == 4
    assert report["action_plan"][0]["id"] == "coverage_gap:mail"
    assert report["action_plan"][0]["rule_id"] == "coverage.gap"
    assert report["action_plan"][0]["error_classes"] == ["invalid_scope"]


def test_build_report_pack_adds_reviewer_index() -> None:
    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=[
            {
                "id": "mail:fwd",
                "rule_id": "google.gmail_external_forwarding",
                "severity": "high",
                "status": "open",
                "title": "External forwarding",
                "category": "mail",
                "collector": "google_gmail_settings",
                "remediation": "Disable forwarding.",
                "evidence_refs": [
                    {
                        "artifact_path": "normalized/google_mailbox_settings.json",
                        "artifact_kind": "normalized",
                        "collector": "google_gmail_settings",
                        "record_key": "google_mailbox_setting:admin@example.com",
                        "json_pointer": "/records/0",
                    }
                ],
            }
        ],
        coverage_gaps=[
            {
                "surface": "mail",
                "status": "blocked",
                "severity": "high",
                "message": "mail coverage is blocked",
                "collectors": ["google_gmail_settings"],
            }
        ],
        evidence_paths=["normalized/google_mailbox_settings.json"],
        blocker_count=1,
    )

    reviewer_index = report["reviewer_index"]
    assert reviewer_index["start_here"][0]["section"] == "executive_summary"
    assert reviewer_index["start_here"][0]["artifact_path"] == "reports/report-pack.json"
    assert reviewer_index["prove_this"][0]["finding_id"] == "mail:fwd"
    assert reviewer_index["prove_this"][0]["artifact_path"] == "normalized/google_mailbox_settings.json"
    known_limit_statuses = {row["status"] for row in reviewer_index["known_limits"]}
    assert "blocked" in known_limit_statuses


def test_build_findings_applies_waivers_and_adds_richer_fields(tmp_path: Path) -> None:
    waiver_path = tmp_path / "waivers.json"
    waiver_path.write_text(
        """
        {
          "waivers": [
            {
              "rule_id": "collector.issue.permission",
              "comment": "Expected in reader-only tenant",
              "expires_on": "2099-01-01"
            }
          ]
        }
        """.strip(),
        encoding="utf-8",
    )
    diagnostics = [
        {
            "collector": "security",
            "item": "securityAlerts",
            "status": "failed",
            "error_class": "insufficient_permissions",
            "error": "Forbidden",
            "recommendations": {"required_graph_scopes": ["SecurityEvents.Read.All"]},
        }
    ]

    findings = build_findings(diagnostics, waiver_file=waiver_path)

    assert findings[0]["rule_id"] == "collector.issue.permission"
    assert findings[0]["status"] == "accepted_risk"
    assert findings[0]["waiver"]["comment"] == "Expected in reader-only tenant"
    assert findings[0]["description"]
    assert findings[0]["impact"]
    assert findings[0]["remediation"]
    assert findings[0]["references"]


def test_build_findings_uses_registry_metadata_for_templates_and_framework_mappings() -> None:
    findings = build_findings(
        [
            {
                "collector": "security",
                "item": "securityAlerts",
                "status": "failed",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
            }
        ]
    )

    finding = findings[0]
    assert finding["rule_id"] == "collector.issue.permission"
    assert finding["description"] == "Auditex could not read the requested Microsoft 365 surface with the supplied identity."
    assert finding["impact"] == "The report has a confirmed evidence gap for this area, so the related control cannot be asserted from this run."
    assert finding["remediation"] == "Rerun with the minimum read permission required for the blocked surface, or exclude that surface from the agreed scope."
    assert finding["control_ids"] == ["AUDITEX-COLLECTOR-PERMISSION"]
    assert finding["framework_mappings"]["cis_m365_v3"] == ["1.1.1"]
    assert finding["framework_mappings"]["nist_800_53"] == ["AC-3", "AC-6", "AU-2"]
    assert finding["framework_mappings"]["mitre_attack"] == ["T1078"]
    assert finding["framework_mappings"]["iso_27001"] == ["A.5.15", "A.8.2"]
    assert finding["framework_mappings"]["nis2"] == ["Article 21(2)(d)"]
    assert finding["framework_mappings"]["dora"] == ["Article 9(2)"]


def test_build_findings_keeps_python_fallback_when_registry_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(findings_module, "_FINDING_TEMPLATE_REGISTRY", {})
    monkeypatch.setattr(findings_module, "_CONTROL_MAPPING_REGISTRY", {})

    findings = build_findings(
        [
            {
                "collector": "security",
                "item": "securityAlerts",
                "status": "failed",
                "error_class": "insufficient_permissions",
                "error": "Forbidden",
            }
        ]
    )

    finding = findings[0]
    assert finding["description"] == "Auditex could not read the requested Microsoft 365 surface with the supplied identity."
    assert finding["impact"] == "The report has a confirmed evidence gap for this area, so the related control cannot be asserted from this run."
    assert finding["remediation"] == "Rerun with the minimum read permission required for the blocked surface, or exclude that surface from the agreed scope."
    assert finding["references"] == ["Microsoft Graph permission review", "Auditex collector permission matrix"]
    assert "framework_mappings" not in finding


def test_finding_schema_includes_framework_mappings() -> None:
    schema = json.loads(Path("schemas/finding.schema.json").read_text(encoding="utf-8"))

    assert "framework_mappings" in schema["properties"]


def test_finding_schema_framework_mappings_match_contract_keys() -> None:
    from azure_tenant_audit.contracts import _KNOWN_FRAMEWORK_KEYS

    schema = json.loads(Path("schemas/finding.schema.json").read_text(encoding="utf-8"))
    allowed = set(schema["properties"]["framework_mappings"]["properties"])

    assert _KNOWN_FRAMEWORK_KEYS.issubset(allowed)


def test_build_report_pack_excludes_accepted_findings_from_action_plan() -> None:
    findings = [
        {
            "id": "security:securityAlerts",
            "rule_id": "collector.issue.permission",
            "severity": "high",
            "title": "security collector issue",
            "status": "accepted_risk",
            "category": "permission",
            "affected_objects": ["securityAlerts"],
            "remediation": "Grant the missing read scope or reduce the collector set.",
        },
        {
            "id": "sharepoint:site-1",
            "rule_id": "sharepoint.broad_link",
            "severity": "high",
            "title": "Broad SharePoint link",
            "status": "open",
            "category": "exposure",
            "affected_objects": ["site-1"],
            "remediation": "Disable anonymous links.",
        },
    ]

    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=findings,
        evidence_paths=["run-manifest.json"],
        blocker_count=1,
    )

    assert report["summary"]["accepted_count"] == 1
    assert report["summary"]["open_count"] == 1
    assert len(report["action_plan"]) == 1
    assert report["action_plan"][0]["rule_id"] == "sharepoint.broad_link"


def test_build_findings_promotes_normalized_workload_risks() -> None:
    normalized = {
        "sharepoint_sharing_findings": {
            "records": [
                {
                    "id": "site-1:perm-1:sharing",
                    "site_id": "site-1",
                    "site_name": "Executive",
                    "link_scope": "anonymous",
                    "severity": "high",
                }
            ]
        },
        "sharepoint_site_posture_objects": {
            "records": [
                {
                    "id": "site-1",
                    "site_name": "Executive",
                    "site_kind": "personal",
                    "sharing_capability": "externalUserAndGuestSharing",
                    "permission_count": 1,
                    "principal_count": 1,
                    "anonymous_link_count": 1,
                    "ownership_state": "weak",
                }
            ]
        },
        "sharepoint_permission_edges": {
            "records": [
                {
                    "id": "site-1:perm-2:external-user",
                    "site_id": "site-1",
                    "site_name": "Executive",
                    "permission_id": "perm-2",
                    "target_type": "user",
                    "target_id": "external-user",
                    "target_name": "consultant@external.test",
                    "roles": ["write"],
                },
                {
                    "id": "site-1:perm-3:internal-user",
                    "site_id": "site-1",
                    "site_name": "Executive",
                    "permission_id": "perm-3",
                    "target_type": "user",
                    "target_id": "internal-user",
                    "target_name": "alice@contoso.com",
                    "roles": ["read"],
                },
            ]
        },
        "application_consents": {
            "records": [
                {
                    "id": "grant-1",
                    "service_principal_name": "Contoso App",
                    "scope": "Directory.Read.All Mail.Read",
                    "owner_count": 0,
                }
            ]
        },
        "exchange_policy_objects": {
            "records": [
                {
                    "id": "forwarding-user-1",
                    "source_name": "mailboxForwarding",
                    "display_name": "Alice Example",
                    "forwarding_smtp_address": "external@example.net",
                }
            ]
        },
        "teams_policy_objects": {
            "records": [
                {
                    "id": "teams-federation-1",
                    "source_name": "tenantFederationConfiguration",
                    "policy_name": "Global",
                    "allow_public_users": True,
                    "allow_federated_users": True,
                }
            ]
        },
        "service_health_objects": {
            "records": [
                {
                    "id": "issue-1",
                    "source_name": "serviceIssues",
                    "service": "Exchange Online",
                    "title": "Mail delivery delay",
                    "status": "serviceDegradation",
                }
            ]
        },
        "external_identity_objects": {
            "records": [
                {
                    "id": "authz-1",
                    "source_name": "authorizationPolicy",
                    "allow_invites_from": "everyone",
                }
            ]
        },
        "consent_policy_objects": {
            "records": [
                {
                    "id": "consent-1",
                    "source_name": "adminConsentRequestPolicy",
                    "is_enabled": False,
                }
            ]
        },
        "onedrive_posture_objects": {
            "records": [
                {
                    "id": "od-1",
                    "site_name": "Alice OneDrive",
                    "site_kind": "personal",
                    "sharing_capability": "externalUserAndGuestSharing",
                },
                {
                    "id": "team-1",
                    "site_name": "Team Site",
                    "site_kind": "team",
                    "sharing_capability": "externalUserAndGuestSharing",
                },
            ]
        },
        "domain_hybrid_objects": {
            "records": [
                {
                    "id": "contoso.com",
                    "source_name": "domains",
                    "is_verified": True,
                }
            ]
        },
        "snapshot": {"tenant_name": "acme", "run_id": "run-1", "object_counts": {}},
    }

    findings = build_findings([], normalized_snapshot=normalized)
    ids = {item["id"] for item in findings}

    assert "sharepoint:site-1:perm-1:sharing" in ids
    assert "sharepoint_permission:site-1:perm-2:external-user:external_principal" in ids
    assert "sharepoint_site_posture:site-1:weak_ownership" in ids
    assert "onedrive_posture:od-1:external_sharing_enabled" in ids
    assert "app_consent:grant-1:high_privilege" in ids
    assert "exchange:forwarding-user-1:mailbox_forwarding" in ids
    assert "teams_policy:teams-federation-1:external_federation_open" in ids
    assert "service_health:issue-1:active_service_issue" in ids
    assert "external_identity:authz-1:broad_guest_invite_policy" in ids
    assert "consent_policy:consent-1:admin_consent_workflow_disabled" in ids


def test_build_findings_does_not_guess_external_sharepoint_principal_without_tenant_domain() -> None:
    normalized = {
        "sharepoint_permission_edges": {
            "records": [
                {
                    "id": "site-1:perm-2:user",
                    "site_id": "site-1",
                    "site_name": "Executive",
                    "target_type": "user",
                    "target_name": "consultant@external.test",
                    "roles": ["write"],
                }
            ]
        },
        "snapshot": {"tenant_name": "acme", "run_id": "run-1", "object_counts": {}},
    }

    findings = build_findings([], normalized_snapshot=normalized)

    assert all(finding["rule_id"] != "sharepoint.external_principal" for finding in findings)


def test_build_findings_makes_conditional_access_ids_unique() -> None:
    normalized = {
        "ca_findings": {
            "records": [
                {"id": "ca-1", "finding_type": "ca_reporting_only", "policy_id": "policy-1", "policy_name": "One"},
                {"id": "ca-2", "finding_type": "ca_reporting_only", "policy_id": "policy-2", "policy_name": "Two"},
            ]
        }
    }

    findings = build_findings([], normalized_snapshot=normalized)

    assert {item["id"] for item in findings} == {
        "conditional_access:ca_reporting_only:policy-1",
        "conditional_access:ca_reporting_only:policy-2",
    }


def test_build_findings_flags_m365_global_admin_resilience() -> None:
    too_few = {
        "role_definitions": {
            "records": [
                {
                    "id": "role-global-admin",
                    "display_name": "Global Administrator",
                }
            ]
        },
        "role_assignments": {
            "records": [
                {
                    "id": "assignment-1",
                    "principal_id": "user-1",
                    "role_definition_id": "role-global-admin",
                }
            ]
        },
    }
    sprawl = {
        "role_definitions": too_few["role_definitions"],
        "role_assignments": {
            "records": [
                {
                    "id": f"assignment-{index}",
                    "principal_id": f"user-{index}",
                    "role_definition_id": "role-global-admin",
                }
                for index in range(6)
            ]
        },
    }

    too_few_ids = {item["rule_id"] for item in build_findings([], normalized_snapshot=too_few)}
    sprawl_ids = {item["rule_id"] for item in build_findings([], normalized_snapshot=sprawl)}

    assert "identity.global_admin_singleton" in too_few_ids
    assert "identity.global_admin_sprawl" in sprawl_ids


def test_build_findings_flags_disabled_global_admin_assignment() -> None:
    normalized = {
        "users": {
            "records": [
                {
                    "id": "user-1",
                    "principal_name": "disabled-admin@example.com",
                    "enabled": False,
                }
            ]
        },
        "role_definitions": {
            "records": [
                {
                    "id": "role-global-admin",
                    "display_name": "Global Administrator",
                }
            ]
        },
        "role_assignments": {
            "records": [
                {
                    "id": "assignment-1",
                    "principal_id": "user-1",
                    "role_definition_id": "role-global-admin",
                },
                {
                    "id": "assignment-2",
                    "principal_id": "user-2",
                    "role_definition_id": "role-global-admin",
                },
            ]
        },
    }

    findings = build_findings([], normalized_snapshot=normalized)
    disabled = next(item for item in findings if item["rule_id"] == "identity.global_admin_disabled")

    assert disabled["severity"] == "high"
    assert disabled["affected_objects"] == ["disabled-admin@example.com"]


def test_build_findings_flags_global_admin_stale_password() -> None:
    normalized = {
        "users": {
            "records": [
                {
                    "id": "user-1",
                    "principal_name": "stale-admin@example.com",
                    "enabled": True,
                    "last_password_change_at": "2020-01-01T00:00:00Z",
                },
                {
                    "id": "user-2",
                    "principal_name": "fresh-admin@example.com",
                    "enabled": True,
                    "last_password_change_at": "2026-01-01T00:00:00Z",
                },
            ]
        },
        "role_definitions": {
            "records": [
                {
                    "id": "role-global-admin",
                    "display_name": "Global Administrator",
                }
            ]
        },
        "role_assignments": {
            "records": [
                {
                    "id": "assignment-1",
                    "principal_id": "user-1",
                    "role_definition_id": "role-global-admin",
                },
                {
                    "id": "assignment-2",
                    "principal_id": "user-2",
                    "role_definition_id": "role-global-admin",
                },
            ]
        },
    }

    findings = build_findings([], normalized_snapshot=normalized)
    stale = next(item for item in findings if item["rule_id"] == "identity.global_admin_stale_password")

    assert stale["severity"] == "medium"
    assert stale["affected_objects"] == ["stale-admin@example.com"]


def test_build_findings_flags_global_admin_without_mfa_registration() -> None:
    normalized = {
        "users": {
            "records": [
                {
                    "id": "user-1",
                    "principal_name": "no-mfa-admin@example.com",
                    "enabled": True,
                },
                {
                    "id": "user-2",
                    "principal_name": "mfa-admin@example.com",
                    "enabled": True,
                },
            ]
        },
        "role_definitions": {
            "records": [
                {
                    "id": "role-global-admin",
                    "display_name": "Global Administrator",
                }
            ]
        },
        "role_assignments": {
            "records": [
                {
                    "id": "assignment-1",
                    "principal_id": "user-1",
                    "role_definition_id": "role-global-admin",
                },
                {
                    "id": "assignment-2",
                    "principal_id": "user-2",
                    "role_definition_id": "role-global-admin",
                },
            ]
        },
        "auth_method_registration_objects": {
            "records": [
                {
                    "id": "user-1",
                    "user_principal_name": "no-mfa-admin@example.com",
                    "is_mfa_registered": False,
                },
                {
                    "id": "user-2",
                    "user_principal_name": "mfa-admin@example.com",
                    "is_mfa_registered": True,
                },
            ]
        },
    }

    findings = build_findings([], normalized_snapshot=normalized)
    mfa = next(item for item in findings if item["rule_id"] == "identity.global_admin_mfa_not_registered")

    assert mfa["severity"] == "critical"
    assert mfa["affected_objects"] == ["no-mfa-admin@example.com"]


def test_build_findings_flags_active_user_without_mfa_registration() -> None:
    normalized = {
        "users": {
            "records": [
                {
                    "id": "user-1",
                    "principal_name": "no-mfa@example.com",
                    "enabled": True,
                    "user_type": "Member",
                },
                {
                    "id": "user-2",
                    "principal_name": "disabled@example.com",
                    "enabled": False,
                    "user_type": "Member",
                },
                {
                    "id": "user-3",
                    "principal_name": "admin@example.com",
                    "enabled": True,
                    "user_type": "Member",
                },
            ]
        },
        "role_definitions": {
            "records": [{"id": "role-global-admin", "display_name": "Global Administrator"}]
        },
        "role_assignments": {
            "records": [{"id": "assignment-1", "principal_id": "user-3", "role_definition_id": "role-global-admin"}]
        },
        "auth_method_registration_objects": {
            "records": [
                {
                    "id": "user-1",
                    "user_principal_name": "no-mfa@example.com",
                    "is_mfa_registered": False,
                    "is_admin": False,
                    "user_type": "Member",
                },
                {
                    "id": "user-2",
                    "user_principal_name": "disabled@example.com",
                    "is_mfa_registered": False,
                    "is_admin": False,
                    "user_type": "Member",
                },
                {
                    "id": "user-3",
                    "user_principal_name": "admin@example.com",
                    "is_mfa_registered": False,
                    "is_admin": True,
                    "user_type": "Member",
                },
            ]
        },
    }

    findings = [
        item
        for item in build_findings([], normalized_snapshot=normalized)
        if item["rule_id"] == "identity.user_mfa_not_registered"
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["affected_objects"] == ["no-mfa@example.com"]


def test_build_findings_flags_risky_m365_signin() -> None:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads={
            "security": {
                "signIns": {
                    "value": [
                        {
                            "id": "signin-1",
                            "createdDateTime": "2026-05-22T08:00:00Z",
                            "userPrincipalName": "alice@example.com",
                            "riskLevelAggregated": "high",
                            "riskState": "atRisk",
                            "status": {"errorCode": 0},
                        },
                        {
                            "id": "signin-2",
                            "createdDateTime": "2026-05-22T09:00:00Z",
                            "userPrincipalName": "bob@example.com",
                            "riskLevelAggregated": "none",
                            "riskState": "none",
                            "status": {"errorCode": 0},
                        },
                    ]
                }
            }
        },
    )

    findings = [item for item in build_findings([], normalized_snapshot=normalized) if item["rule_id"] == "security.risky_signin"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["affected_objects"] == ["alice@example.com"]


def test_build_findings_flags_m365_privilege_change_audit_event() -> None:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads={
            "security": {
                "directoryAudits": {
                    "value": [
                        {
                            "id": "audit-1",
                            "activityDateTime": "2026-05-22T08:00:00Z",
                            "category": "RoleManagement",
                            "activityDisplayName": "Add member to role",
                            "result": "success",
                            "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}},
                            "targetResources": [{"displayName": "Global Administrator", "type": "Role"}],
                        },
                        {
                            "id": "audit-2",
                            "activityDateTime": "2026-05-22T09:00:00Z",
                            "category": "UserManagement",
                            "activityDisplayName": "Update user",
                            "result": "success",
                        },
                    ]
                }
            }
        },
    )

    findings = [item for item in build_findings([], normalized_snapshot=normalized) if item["rule_id"] == "security.privilege_change_event"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["affected_objects"] == ["admin@example.com"]


def test_build_findings_flags_noncompliant_intune_device() -> None:
    normalized = {
        "devices": {
            "records": [
                {
                    "id": "device-1",
                    "display_name": "Laptop 1",
                    "platform": "Windows",
                    "compliance_state": "noncompliant",
                },
                {
                    "id": "device-2",
                    "display_name": "Laptop 2",
                    "platform": "Windows",
                    "compliance_state": "compliant",
                },
            ]
        }
    }

    findings = build_findings([], normalized_snapshot=normalized)
    device = next(item for item in findings if item["rule_id"] == "intune.device_noncompliant")

    assert device["severity"] == "medium"
    assert device["affected_objects"] == ["Laptop 1"]


def test_build_findings_flags_stale_intune_device_sync() -> None:
    stale_sync = _utc_days_ago(365)
    fresh_sync = _utc_days_ago(1)
    normalized = {
        "devices": {
            "records": [
                {
                    "id": "device-1",
                    "display_name": "Old Laptop",
                    "platform": "Windows",
                    "compliance_state": "compliant",
                    "last_sync_at": stale_sync,
                },
                {
                    "id": "device-2",
                    "display_name": "Fresh Laptop",
                    "platform": "Windows",
                    "compliance_state": "compliant",
                    "last_sync_at": fresh_sync,
                },
            ]
        }
    }

    findings = [item for item in build_findings([], normalized_snapshot=normalized) if item["rule_id"] == "intune.device_stale_sync"]

    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert findings[0]["affected_objects"] == ["Old Laptop"]
