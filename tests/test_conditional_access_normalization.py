from __future__ import annotations

from azure_tenant_audit.normalize import build_normalized_snapshot


def test_conditional_access_graph_builds_relationships_and_findings() -> None:
    collector_payloads = {
        "identity": {
            "users": {
                "value": [
                    {"id": "admin-user", "displayName": "Global Admin", "userPrincipalName": "admin@example.com"},
                    {"id": "user-1", "displayName": "Alice", "userPrincipalName": "alice@example.com"},
                ]
            },
            "groups": {"value": [{"id": "group-1", "displayName": "Team One", "groupTypes": []}]},
            "roleDefinitions": {
                "value": [
                    {"id": "role-1", "displayName": "Global Administrator"},
                ]
            },
            "roleAssignments": {
                "value": [
                    {"id": "assign-1", "roleDefinitionId": "role-1", "principalId": "admin-user"},
                ]
            },
        },
        "auth_methods": {
            "userRegistrationDetails": {
                "value": [
                    {"userPrincipalName": "admin@example.com", "isMfaRegistered": True},
                    {"userPrincipalName": "alice@example.com", "isMfaRegistered": False},
                ]
            }
        },
        "conditional_access": {
            "conditionalAccessPolicies": {
                "value": [
                    {
                        "id": "ca-1",
                        "displayName": "Require MFA for admins",
                        "state": "enabled",
                        "conditions": {
                            "users": {"includeUsers": ["admin-user"]},
                            "locations": {"includeLocations": ["loc-missing"]},
                            "applications": {"includeApplications": ["app-1"]},
                        },
                        "grantControls": {
                            "builtInControls": ["mfa"],
                            "operator": "OR",
                            "authenticationStrength": {"id": "strength-1"},
                        },
                    },
                    {
                        "id": "ca-2",
                        "displayName": "Report only user MFA",
                        "state": "enabledForReportingButNotEnforced",
                        "conditions": {"users": {"includeUsers": ["all"]}},
                    },
                ]
            },
            "namedLocations": {"value": [{"id": "loc-1", "displayName": "HQ"}]},
            "authenticationStrengthPolicies": {"value": [{"id": "strength-1", "displayName": "MFA Policy"}]},
            "authenticationContextClassReferences": {"value": []},
        },
    }

    normalized = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-ca",
        collector_payloads=collector_payloads,
    )

    graph = normalized["conditional_access_graph"]["records"]
    assert len(graph) == 2
    report_only_policy = next(node for node in graph if node["key"] == "conditional_access_policy:ca-2")
    assert report_only_policy["enabled_for_reporting"] is True

    relationships = normalized["relationships"]["records"]
    assert any(
        rel["source_id"] == "ca-1"
        and rel["relationship_type"] == "location"
        and rel["resolution"] == "unresolved"
        for rel in relationships
    )

    findings = normalized["ca_findings"]["records"]
    assert any(finding["finding_type"] == "ca_reporting_only" for finding in findings)
    assert any(
        finding["finding_type"] == "ca_break_glass_exclusion"
        and finding["policy_id"] == "ca-1"
        for finding in findings
    )

    assert normalized["snapshot"]["object_counts"]["conditional_access_graph"] == 2


def test_conditional_access_relationships_have_citable_keys_and_grant_auth_strength() -> None:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="run-ca-keys",
        collector_payloads={
            "identity": {"users": {"value": [{"id": "admin-user", "displayName": "Admin"}]}},
            "conditional_access": {
                "conditionalAccessPolicies": {
                    "value": [
                        {
                            "id": "ca-1",
                            "displayName": "Require phishing-resistant MFA",
                            "state": "enabled",
                            "conditions": {"users": {"includeUsers": ["admin-user"]}},
                            "grantControls": {"operator": "OR", "authenticationStrength": {"id": "strength-1"}},
                        }
                    ]
                },
                "authenticationStrengthPolicies": {"value": [{"id": "strength-1", "displayName": "Phishing-resistant"}]},
            },
        },
    )

    relationships = snapshot["relationships"]["records"]
    assert relationships, "relationships are emitted"
    assert all(record.get("key") and record.get("id") for record in relationships)
    assert len({record["key"] for record in relationships}) == len(relationships)
    assert any(record.get("target_type") == "auth_strength" and record.get("target_id") == "strength-1" for record in relationships)
