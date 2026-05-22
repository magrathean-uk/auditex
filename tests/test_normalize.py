from __future__ import annotations

from azure_tenant_audit.normalize import build_ai_safe_summary, build_normalized_snapshot


def test_build_normalized_snapshot_extracts_core_objects() -> None:
    collector_payloads = {
        "identity": {
            "users": {
                "value": [
                    {
                        "id": "user-1",
                        "displayName": "Alice Example",
                        "userPrincipalName": "alice@example.com",
                        "department": "Sales",
                        "accountEnabled": True,
                    }
                ]
            },
            "groups": {
                "value": [
                    {
                        "id": "group-1",
                        "displayName": "Sales Team",
                        "mail": "sales@example.com",
                        "groupTypes": ["Unified"],
                    }
                ]
            },
            "roleDefinitions": {"value": [{"id": "role-def-1", "displayName": "Global Reader"}]},
            "roleAssignments": {"value": [{"id": "role-assign-1", "roleDefinitionId": "role-def-1", "principalId": "user-1"}]},
        },
        "intune": {
            "managedDevices": {
                "value": [
                    {
                        "id": "device-1",
                        "deviceName": "W365-01",
                        "operatingSystem": "Windows",
                        "complianceState": "compliant",
                    }
                ]
            },
            "deviceCompliancePolicies": {"value": [{"id": "policy-1", "displayName": "Windows Compliance"}]},
        },
        "conditional_access": {
            "conditionalAccessPolicies": {
                "value": [
                    {
                        "id": "ca-1",
                        "displayName": "Require MFA for Admins",
                        "state": "enabled",
                    }
                ]
            }
        },
        "sharepoint": {
            "sites": {
                "value": [
                    {
                        "id": "site-1",
                        "displayName": "Executive Portal",
                        "webUrl": "https://contoso.sharepoint.com/sites/executive",
                    }
                ]
            }
        },
    }
    diagnostics = [
        {
            "collector": "security",
            "item": "directoryAudits",
            "status": "failed",
            "error_class": "insufficient_permissions",
        }
    ]

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-1",
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
    )

    assert normalized["snapshot"]["tenant_name"] == "acme"
    assert normalized["snapshot"]["run_id"] == "run-1"
    assert normalized["snapshot"]["object_counts"]["users"] == 1
    assert normalized["snapshot"]["object_counts"]["groups"] == 1
    assert normalized["snapshot"]["object_counts"]["devices"] == 1
    assert normalized["snapshot"]["object_counts"]["policies"] == 2
    assert normalized["snapshot"]["object_counts"]["sites"] == 1
    assert normalized["snapshot"]["blocker_count"] == 1

    user = normalized["users"]["records"][0]
    assert user["key"] == "user:user-1"
    assert user["principal_name"] == "alice@example.com"

    device = normalized["devices"]["records"][0]
    assert device["key"] == "device:device-1"
    assert device["platform"] == "Windows"

    policy_keys = {record["key"] for record in normalized["policies"]["records"]}
    assert "policy:deviceCompliancePolicies:policy-1" in policy_keys
    assert "policy:conditionalAccessPolicies:ca-1" in policy_keys


def test_build_ai_safe_summary_uses_normalized_snapshot_counts() -> None:
    normalized = {
        "snapshot": {
            "tenant_name": "acme",
            "run_id": "run-1",
            "object_counts": {"users": 2, "groups": 3, "devices": 1},
            "blocker_count": 1,
        },
        "translation_catalog": {"records": [{"key": "translation:user:user-1"}]},
        "users": {"records": [{"key": "user:user-1"}, {"key": "user:user-2"}]},
    }
    findings = [{"id": "security:securityAlerts", "severity": "high"}]

    ai_safe = build_ai_safe_summary(normalized, findings=findings)

    assert ai_safe["tenant_name"] == "acme"
    assert ai_safe["run_id"] == "run-1"
    assert ai_safe["object_counts"]["groups"] == 3
    assert ai_safe["normalized_counts"]["groups"] == 3
    assert ai_safe["safe_for_external_llm"] is True
    assert ai_safe["findings_count"] == 1
    assert ai_safe["blocker_count"] == 1
    assert ai_safe["translation_catalog_count"] == 1


def test_build_normalized_snapshot_extracts_auth_method_registrations() -> None:
    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-auth",
        collector_payloads={
            "auth_methods": {
                "userRegistrationDetails": {
                    "value": [
                        {
                            "id": "user-1",
                            "userPrincipalName": "admin@example.com",
                            "isMfaRegistered": False,
                            "isMfaCapable": True,
                            "isPasswordlessCapable": False,
                            "isSsprEnabled": True,
                        }
                    ]
                }
            }
        },
    )

    record = normalized["auth_method_registration_objects"]["records"][0]

    assert record["user_principal_name"] == "admin@example.com"
    assert record["is_mfa_registered"] is False
    assert record["is_mfa_capable"] is True


def test_build_normalized_snapshot_extracts_security_incidents_scores_and_exchange_mailboxes() -> None:
    collector_payloads = {
        "defender": {
            "defenderIncidents": {
                "value": [
                    {
                        "id": "incident-1",
                        "displayName": "Suspicious Inbox Rule",
                        "severity": "high",
                        "status": "active",
                    }
                ]
            },
            "secureScores": {
                "value": [
                    {
                        "id": "score-1",
                        "currentScore": 41.5,
                        "maxScore": 82.0,
                        "createdDateTime": "2026-04-01T00:00:00Z",
                    }
                ]
            },
        },
        "exchange": {
            "mailboxCount": {
                "value": [
                    {
                        "ExternalDirectoryObjectId": "mailbox-1",
                        "DisplayName": "Alice Example",
                        "PrimarySmtpAddress": "alice@example.com",
                        "RecipientTypeDetails": "UserMailbox",
                    }
                ]
            }
        },
    }

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-2",
        collector_payloads=collector_payloads,
    )

    assert normalized["snapshot"]["object_counts"]["incidents"] == 1
    assert normalized["snapshot"]["object_counts"]["security_scores"] == 1
    assert normalized["snapshot"]["object_counts"]["mailboxes"] == 1
    assert normalized["incidents"]["records"][0]["severity"] == "high"
    assert normalized["security_scores"]["records"][0]["current_score"] == 41.5
    assert normalized["mailboxes"]["records"][0]["primary_smtp_address"] == "alice@example.com"


def test_build_normalized_snapshot_orders_records_and_builds_translation_catalog() -> None:
    collector_payloads = {
        "identity": {
            "users": {
                "value": [
                    {"id": "user-2", "displayName": "Zulu User", "userPrincipalName": "zulu@example.com"},
                    {"id": "user-1", "displayName": "Alpha User", "userPrincipalName": "alpha@example.com"},
                ]
            },
            "groups": {
                "value": [
                    {"id": "group-2", "displayName": "Zulu Group"},
                    {"id": "group-1", "displayName": "Alpha Group"},
                ]
            },
            "applications": {
                "value": [
                    {"id": "app-2", "displayName": "Zulu App"},
                    {"id": "app-1", "displayName": "Alpha App"},
                ]
            },
        },
        "sharepoint": {
            "sites": {
                "value": [
                    {"id": "site-2", "displayName": "Zulu Site", "webUrl": "https://contoso.sharepoint.com/sites/zulu"},
                    {"id": "site-1", "displayName": "Alpha Site", "webUrl": "https://contoso.sharepoint.com/sites/alpha"},
                ]
            }
        },
    }

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-order",
        collector_payloads=collector_payloads,
    )

    assert [item["id"] for item in normalized["users"]["records"]] == ["user-1", "user-2"]
    assert [item["id"] for item in normalized["groups"]["records"]] == ["group-1", "group-2"]
    assert [item["id"] for item in normalized["sites"]["records"]] == ["site-1", "site-2"]
    translation_records = normalized["translation_catalog"]["records"]
    assert any(item["object_id"] == "user-1" and item["display_name"] == "Alpha User" for item in translation_records)
    assert any(item["object_id"] == "group-1" and item["display_name"] == "Alpha Group" for item in translation_records)
    assert any(item["object_id"] == "app-1" and item["display_name"] == "Alpha App" for item in translation_records)
    assert any(item["object_id"] == "site-1" and item["display_name"] == "Alpha Site" for item in translation_records)


def test_build_normalized_snapshot_extracts_enterprise_depth_sections() -> None:
    collector_payloads = {
        "sharepoint_access": {
            "sharePointSettings": {"sharingCapability": "externalUserAndGuestSharing"},
            "sitePermissionsBySite": {
                "value": [
                    {
                        "siteId": "site-1",
                        "siteName": "Executive",
                        "webUrl": "https://contoso-my.sharepoint.com/personal/alice_contoso_com",
                        "siteKind": "personal",
                        "sharingCapability": "externalUserAndGuestSharing",
                        "permissionCount": 1,
                        "principalCount": 1,
                        "userPrincipalCount": 1,
                        "groupPrincipalCount": 0,
                        "applicationPrincipalCount": 0,
                        "anonymousLinkCount": 1,
                        "organizationLinkCount": 0,
                        "writeLikePermissionCount": 0,
                        "ownershipState": "weak",
                        "permissions": [
                            {
                                "id": "perm-1",
                                "roles": ["read"],
                                "grantedToIdentitiesV2": [{"user": {"id": "user-1", "displayName": "Alice Example"}}],
                                "link": {"scope": "anonymous", "type": "view"},
                            }
                        ],
                    }
                ]
            }
        },
        "app_consent": {
            "oauth2PermissionGrants": {
                "value": [
                    {
                        "id": "grant-1",
                        "clientId": "sp-1",
                        "resourceId": "graph-sp",
                        "scope": "Directory.Read.All Mail.Read",
                        "consentType": "AllPrincipals",
                    }
                ]
            },
            "servicePrincipals": {"value": [{"id": "sp-1", "displayName": "Contoso App", "appId": "app-1"}]},
            "servicePrincipalOwners": {"value": [{"servicePrincipalId": "sp-1", "owners": []}]},
        },
        "licensing": {
            "subscribedSkus": {
                "value": [
                    {
                        "skuId": "sku-1",
                        "skuPartNumber": "ENTERPRISEPREMIUM",
                        "consumedUnits": 12,
                        "prepaidUnits": {"enabled": 25},
                    }
                ]
            }
        },
        "exchange_policy": {"transportRules": {"value": [{"Name": "Block Forwarding"}]}},
        "identity_governance": {
            "accessReviews": {"value": [{"id": "review-1", "displayName": "Admins review"}]},
            "roleEligibilitySchedules": {"value": [{"id": "eligibility-1"}]},
        },
        "intune_depth": {
            "deviceConfigurationAssignments": {
                "value": [{"policyId": "config-1", "assignments": [{"id": "assign-1", "target": {"groupId": "group-1"}}]}]
            }
        },
        "teams_policy": {
            "meetingPolicies": {"value": [{"Identity": "Global", "AllowCloudRecording": True}]},
        },
        "service_health": {
            "healthOverviews": {"value": [{"id": "exchange", "service": "Exchange Online", "status": "serviceOperational"}]},
            "serviceIssues": {"value": [{"id": "issue-1", "service": "Microsoft Teams", "status": "serviceDegradation"}]},
            "messages": {"value": [{"id": "msg-1", "title": "Planned maintenance"}]},
        },
        "reports_usage": {
            "office365ActiveUserCounts": {"value": [{"Report Refresh Date": "2026-04-18", "Exchange": "10"}]},
            "oneDriveUsageAccountDetail": {
                "value": [{"Report Refresh Date": "2026-04-18", "Owner Principal Name": "user@contoso.test"}]
            },
        },
        "external_identity": {
            "crossTenantAccessPolicy": {"id": "xtap", "displayName": "Cross-tenant"},
            "authorizationPolicy": {"id": "authz", "allowInvitesFrom": "everyone"},
            "authenticationFlowsPolicy": {"id": "flows", "displayName": "Flows"},
        },
        "consent_policy": {
            "adminConsentRequestPolicy": {"id": "admin-consent", "isEnabled": False},
            "permissionGrantPolicies": {"value": [{"id": "grant-policy-1", "displayName": "Default user consent"}]},
            "authorizationPolicy": {"id": "authz", "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["grant-policy-1"]}},
        },
        "domains_hybrid": {
            "organization": {"value": [{"id": "org-1", "displayName": "Contoso"}]},
            "domains": {"value": [{"id": "contoso.com", "isDefault": True, "authenticationType": "Managed"}]},
            "syncSampleUsers": {"value": [{"id": "user-1", "userPrincipalName": "user@contoso.com", "onPremisesSyncEnabled": True}]},
        },
        "onedrive_posture": {
            "sharePointSettings": {"sharingCapability": "externalUserAndGuestSharing"},
            "oneDriveSites": {
                "value": [
                    {
                        "id": "od-1",
                        "displayName": "Alice OneDrive",
                        "webUrl": "https://contoso-my.sharepoint.com/personal/alice",
                        "siteKind": "personal",
                        "sharingCapability": "externalUserAndGuestSharing",
                    }
                ]
            },
            "teamSites": {
                "value": [
                    {
                        "id": "team-1",
                        "displayName": "Team Site",
                        "webUrl": "https://contoso.sharepoint.com/sites/team",
                        "siteKind": "team",
                        "sharingCapability": "externalUserAndGuestSharing",
                    }
                ]
            },
        },
    }

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-depth",
        collector_payloads=collector_payloads,
    )

    assert normalized["snapshot"]["object_counts"]["sharepoint_permission_edges"] == 1
    assert normalized["snapshot"]["object_counts"]["sharepoint_sharing_findings"] == 1
    assert normalized["snapshot"]["object_counts"]["application_consents"] == 1
    assert normalized["snapshot"]["object_counts"]["license_inventory"] == 1
    assert normalized["snapshot"]["object_counts"]["exchange_policy_objects"] == 1
    assert normalized["snapshot"]["object_counts"]["governance_objects"] == 2
    assert normalized["snapshot"]["object_counts"]["intune_assignment_objects"] == 1
    assert normalized["snapshot"]["object_counts"]["teams_policy_objects"] == 1
    assert normalized["snapshot"]["object_counts"]["service_health_objects"] == 3
    assert normalized["snapshot"]["object_counts"]["usage_report_objects"] == 2
    assert normalized["snapshot"]["object_counts"]["external_identity_objects"] == 3
    assert normalized["snapshot"]["object_counts"]["consent_policy_objects"] == 3
    assert normalized["snapshot"]["object_counts"]["domain_hybrid_objects"] == 2
    assert normalized["snapshot"]["object_counts"]["sharepoint_site_posture_objects"] == 1
    assert normalized["snapshot"]["object_counts"]["onedrive_posture_objects"] == 2
    assert normalized["sharepoint_sharing_findings"]["records"][0]["link_scope"] == "anonymous"
    assert normalized["sharepoint_site_posture_objects"]["records"][0]["site_kind"] == "personal"
    assert normalized["sharepoint_site_posture_objects"]["records"][0]["sharing_capability"] == "externalUserAndGuestSharing"
    assert normalized["sharepoint_site_posture_objects"]["records"][0]["anonymous_link_count"] == 1
    assert normalized["sharepoint_site_posture_objects"]["records"][0]["ownership_state"] == "weak"
    assert normalized["onedrive_posture_objects"]["records"][0]["site_kind"] == "personal"
    assert normalized["onedrive_posture_objects"]["records"][0]["sharing_capability"] == "externalUserAndGuestSharing"
    assert normalized["onedrive_posture_objects"]["records"][1]["site_kind"] == "team"
    assert normalized["application_consents"]["records"][0]["scope"] == "Directory.Read.All Mail.Read"
    assert normalized["license_inventory"]["records"][0]["sku_part_number"] == "ENTERPRISEPREMIUM"
    assert normalized["teams_policy_objects"]["records"][0]["policy_name"] == "Global"
    assert normalized["service_health_objects"]["records"][1]["status"] == "serviceDegradation"
    assert any(
        item["source_name"] == "crossTenantAccessPolicy"
        for item in normalized["external_identity_objects"]["records"]
    )


def _make_large_identity_payload(*, users: int, groups: int, applications: int) -> dict:
    return {
        "users": {"value": [{"id": f"user-{idx}", "displayName": f"User {idx}"} for idx in range(users)]},
        "groups": {
            "value": [
                {
                    "id": f"group-{idx}",
                    "displayName": f"Group-{idx}" if idx != 0 else "Emergency-Response",
                    "groupTypes": [],
                }
                for idx in range(groups)
            ]
        },
        "applications": {
            "value": [
                {"id": f"app-{idx}", "displayName": f"App {idx}", "appId": f"app-id-{idx}"}
                for idx in range(applications)
            ]
        },
        "roleDefinitions": {
            "value": [
                {"id": "role-admin", "displayName": "Global Administrator"},
            ]
        },
        "roleAssignments": {
            "value": [
                {"id": "role-admin-assignment", "roleDefinitionId": "role-admin", "principalId": "user-0"},
            ]
        },
    }


def test_conditional_access_graph_scales_with_large_identity_and_multiple_policies() -> None:
    user_count = 2000
    group_count = 180
    app_count = 120
    location_count = 16
    auth_strength_count = 8
    policy_count = 600

    identities = _make_large_identity_payload(users=user_count, groups=group_count, applications=app_count)
    conditional_access = {
        "conditionalAccessPolicies": {
            "value": [
                {
                    "id": f"ca-{idx}",
                    "displayName": f"Policy {idx}",
                    "state": "enabled",
                    "conditions": {
                        "users": {
                            "includeUsers": [f"user-{idx % user_count}"],
                            "excludeUsers": [f"user-{(idx + 1) % user_count}"],
                            "includeGroups": [f"group-{idx % group_count}"],
                            "excludeGroups": [f"group-{(idx + 1) % group_count}"],
                        },
                        "applications": {
                            "includeApplications": [f"app-{idx % app_count}"],
                            "excludeApplications": [f"app-{(idx + 1) % app_count}"],
                        },
                        "locations": {
                            "includeLocations": [f"loc-{idx % location_count}"],
                            "excludeLocations": [f"loc-{(idx + 1) % location_count}"],
                        },
                        "authenticationStrength": {"includePolicies": [f"as-{idx % auth_strength_count}"]},
                    },
                    "grantControls": {"builtInControls": ["mfa"], "operator": "AND"},
                }
                for idx in range(policy_count)
            ]
        },
        "namedLocations": {
            "value": [{"id": f"loc-{idx}", "displayName": f"loc-{idx}"} for idx in range(location_count)]
        },
        "authenticationStrengthPolicies": {
            "value": [{"id": f"as-{idx}", "displayName": f"auth-strength-{idx}"} for idx in range(auth_strength_count)]
        },
        "authenticationContextClassReferences": {"value": []},
    }

    first = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-large-1",
        collector_payloads={
            "identity": identities,
            "conditional_access": conditional_access,
            "auth_methods": {"userRegistrationDetails": {"value": [{"isMfaRegistered": True}, {"isMfaRegistered": False}]}},
        },
    )

    second = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-large-1",
        collector_payloads={
            "identity": identities,
            "conditional_access": conditional_access,
            "auth_methods": {"userRegistrationDetails": {"value": [{"isMfaRegistered": True}, {"isMfaRegistered": False}]}},
        },
    )

    assert first["snapshot"]["object_counts"]["users"] == user_count
    assert first["snapshot"]["object_counts"]["groups"] == group_count
    assert first["snapshot"]["object_counts"]["conditional_access_graph"] == policy_count
    assert first["snapshot"]["object_counts"]["relationships"] == policy_count * 9
    assert first["snapshot"]["object_counts"]["ca_findings"] >= 1
    assert first["conditional_access_graph"]["records"][0]["enabled_for_reporting"] is False
    assert first["conditional_access_graph"]["records"][0]["relationships"]
    assert first["snapshot"]["object_counts"]["ca_findings"] == len(first["ca_findings"]["records"])
    assert second["conditional_access_graph"]["records"] == first["conditional_access_graph"]["records"]
    assert second["relationships"]["records"] == first["relationships"]["records"]
