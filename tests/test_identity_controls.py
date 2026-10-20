"""Effective MFA, legacy authentication and user consent verdicts, and the rules built on them."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.collectors.conditional_access import ConditionalAccessCollector
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.identity_controls import (
    Evidence,
    evaluate_effective_mfa,
    evaluate_legacy_authentication_block,
    evaluate_user_consent,
)
from azure_tenant_audit.normalize import build_normalized_snapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
IDENTITY_CONTROLS_SAMPLE = REPO_ROOT / "examples" / "sample_audit_bundle" / "identity_controls_result.json"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
MFA_STRENGTH = "00000000-0000-0000-0000-000000000002"

LOOKUPS = {
    "user": {"user-bg": "breakglass@example.test"},
    "group": {"group-bg": "Break Glass Accounts"},
    "role": {GLOBAL_ADMIN: "Global Administrator"},
}


def _policy(
    policy_id: str = "ca-1",
    *,
    state: str = "enabled",
    users: dict[str, Any] | None = None,
    applications: dict[str, Any] | None = None,
    grant: dict[str, Any] | None = None,
    client_app_types: list[str] | None = None,
    **conditions: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "users": {"includeUsers": ["All"]} if users is None else users,
        "applications": {"includeApplications": ["All"]} if applications is None else applications,
        "clientAppTypes": ["all"] if client_app_types is None else client_app_types,
    }
    body.update(conditions)
    return {
        "id": policy_id,
        "displayName": f"Policy {policy_id}",
        "state": state,
        "conditions": body,
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]} if grant is None else grant,
    }


def _collected(*rows: dict[str, Any]) -> Evidence:
    return Evidence("collected", tuple(rows))


def _defaults(enabled: bool | None) -> Evidence:
    if enabled is None:
        return Evidence("absent")
    return _collected({"id": "00000000-0000-0000-0000-000000000005", "isEnabled": enabled})


def _mfa(
    *policies: dict[str, Any],
    policy_evidence: Evidence | None = None,
    defaults: Evidence | None = None,
    strengths: Evidence | None = None,
) -> dict[str, Any]:
    return evaluate_effective_mfa(
        policies=policy_evidence if policy_evidence is not None else _collected(*policies),
        security_defaults=defaults if defaults is not None else _defaults(False),
        authentication_strengths=strengths if strengths is not None else _collected(),
        lookups=LOOKUPS,
    )


def _legacy(
    *policies: dict[str, Any],
    policy_evidence: Evidence | None = None,
    defaults: Evidence | None = None,
) -> dict[str, Any]:
    return evaluate_legacy_authentication_block(
        policies=policy_evidence if policy_evidence is not None else _collected(*policies),
        security_defaults=defaults if defaults is not None else _defaults(False),
        lookups=LOOKUPS,
    )


def _block_policy(policy_id: str = "ca-block", **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("client_app_types", ["exchangeActiveSync", "other"])
    kwargs.setdefault("grant", {"operator": "OR", "builtInControls": ["block"]})
    return _policy(policy_id, **kwargs)


# --- effective MFA: enforced ------------------------------------------------------------------


def test_security_defaults_on_enforces_mfa_even_without_conditional_access() -> None:
    verdict = _mfa(policy_evidence=Evidence("blocked", detail="insufficient_permissions"), defaults=_defaults(True))

    assert verdict["verdict"] == "enforced"
    assert verdict["basis"] == ["security_defaults"]
    assert verdict["policy_collection"]["state"] == "blocked"
    assert verdict["security_defaults"]["enabled"] is True


def test_all_users_all_apps_mfa_policy_enforces_mfa() -> None:
    verdict = _mfa(_policy())

    assert verdict["verdict"] == "enforced"
    assert verdict["basis"] == ["conditional_access_policy"]
    assert [row["id"] for row in verdict["qualifying_policies"]] == ["ca-1"]
    assert verdict["excluded_principals"] == []
    assert verdict["excluded_principal_count"] == 0


def test_authentication_strength_grant_enforces_mfa() -> None:
    strength = {"id": MFA_STRENGTH, "displayName": "Multifactor authentication", "requirementsSatisfied": "mfa"}
    verdict = _mfa(_policy(grant={"operator": "OR", "builtInControls": [], "authenticationStrength": strength}))

    assert verdict["verdict"] == "enforced"
    assert verdict["qualifying_policies"][0]["grant"]["authentication_strength"] == "Multifactor authentication"


def test_modern_client_types_cover_the_mfa_requirement() -> None:
    verdict = _mfa(_policy(client_app_types=["browser", "mobileAndDesktopClients"]))

    assert verdict["verdict"] == "enforced"


def test_exclusions_are_listed_and_resolved_for_an_enforcing_policy() -> None:
    policy = _policy(
        users={
            "includeUsers": ["All"],
            "excludeUsers": ["user-bg", "user-unknown"],
            "excludeGroups": ["group-bg"],
            "excludeRoles": [GLOBAL_ADMIN],
            "excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest,internalGuest"},
        },
        locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]},
    )

    verdict = _mfa(policy)

    assert verdict["verdict"] == "enforced"
    excluded = {(row["type"], row["id"]): row for row in verdict["excluded_principals"]}
    assert excluded[("user", "user-bg")]["display_name"] == "breakglass@example.test"
    assert excluded[("user", "user-unknown")]["resolved"] is False
    assert excluded[("group", "group-bg")]["display_name"] == "Break Glass Accounts"
    assert excluded[("role", GLOBAL_ADMIN)]["display_name"] == "Global Administrator"
    assert ("guests_or_external_users", "b2bCollaborationGuest,internalGuest") in excluded
    assert verdict["excluded_principal_count"] == 5
    assert verdict["excluded_locations"] == ["AllTrusted"]


def test_only_principals_excluded_from_every_qualifying_policy_are_reported() -> None:
    first = _policy("ca-1", users={"includeUsers": ["All"], "excludeUsers": ["user-bg", "user-a"]})
    second = _policy("ca-2", users={"includeUsers": ["All"], "excludeUsers": ["user-bg"]})

    verdict = _mfa(first, second)

    assert [row["id"] for row in verdict["excluded_principals"]] == ["user-bg"]
    assert verdict["excluded_principals"][0]["policy_ids"] == ["ca-1", "ca-2"]


def test_and_operator_with_mfa_and_another_control_still_enforces() -> None:
    verdict = _mfa(_policy(grant={"operator": "AND", "builtInControls": ["mfa", "compliantDevice"]}))

    assert verdict["verdict"] == "enforced"


# --- effective MFA: not enforced --------------------------------------------------------------


def test_registration_alone_never_produces_enforced() -> None:
    verdict = evaluate_effective_mfa(
        policies=_collected(),
        security_defaults=_defaults(False),
        authentication_strengths=_collected(),
        lookups=LOOKUPS,
        registration={"sampled_users": 40, "mfa_registered": 40, "mfa_not_registered": 0, "data": "sampled"},
    )

    assert verdict["verdict"] == "not_enforced"
    assert verdict["basis"] == []
    assert verdict["registration_context"]["mfa_registered"] == 40
    assert "never establishes enforcement" in verdict["registration_context"]["note"]


def test_policy_scoped_to_a_group_only_is_not_enforced() -> None:
    verdict = _mfa(_policy(users={"includeGroups": ["group-pilot"]}))

    assert verdict["verdict"] == "not_enforced"
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["not_all_users"]


def test_policy_scoped_to_roles_only_is_not_enforced() -> None:
    verdict = _mfa(_policy(users={"includeRoles": [GLOBAL_ADMIN]}))

    assert verdict["verdict"] == "not_enforced"
    assert "not_all_users" in verdict["non_qualifying_mfa_policies"][0]["reasons"]


def test_report_only_policy_does_not_enforce_and_is_listed() -> None:
    verdict = _mfa(_policy(state="enabledForReportingButNotEnforced"))

    assert verdict["verdict"] == "not_enforced"
    assert verdict["report_only_mfa_policies"][0]["reasons"] == ["report_only"]


def test_disabled_policy_is_ignored() -> None:
    verdict = _mfa(_policy(state="disabled"))

    assert verdict["verdict"] == "not_enforced"
    assert not verdict.get("non_qualifying_mfa_policies")
    assert not verdict.get("report_only_mfa_policies")


def test_grant_operator_or_with_another_control_is_not_enforced() -> None:
    verdict = _mfa(_policy(grant={"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}))

    assert verdict["verdict"] == "not_enforced"
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["grant_operator_or_with_other_controls"]


def test_policy_without_an_mfa_grant_is_not_mfa() -> None:
    verdict = _mfa(_policy(grant={"operator": "OR", "builtInControls": ["compliantDevice"]}))

    assert verdict["verdict"] == "not_enforced"
    assert not verdict.get("non_qualifying_mfa_policies")


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"applications": {"includeApplications": ["app-1"]}}, "not_all_cloud_apps"),
        ({"applications": {"includeApplications": ["All"], "includeUserActions": ["urn:user:registersecurityinfo"]}}, "not_all_cloud_apps"),
        ({"client_app_types": ["browser"]}, "client_app_types_not_covered"),
        ({"platforms": {"includePlatforms": ["android"]}}, "narrowed_by_platform"),
        ({"locations": {"includeLocations": ["AllTrusted"]}}, "narrowed_by_location"),
        ({"signInRiskLevels": ["high"]}, "narrowed_by_risk_condition"),
        ({"userRiskLevels": ["medium"]}, "narrowed_by_risk_condition"),
        ({"devices": {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq True"}}}, "narrowed_by_device_filter"),
        ({"authenticationFlows": {"transferMethods": "deviceCodeFlow"}}, "narrowed_by_authentication_flow"),
    ],
)
def test_narrowed_policy_does_not_count_as_enforcement(override: dict[str, Any], reason: str) -> None:
    verdict = _mfa(_policy(**override))

    assert verdict["verdict"] == "not_enforced"
    assert reason in verdict["non_qualifying_mfa_policies"][0]["reasons"]


EXCLUSION_CASES = [
    pytest.param(
        {"platforms": {"includePlatforms": ["all"], "excludePlatforms": ["android", "iOS"]}},
        "excludes_platforms",
        {"excluded_platforms": ["android", "iOS"]},
        id="excluded-platforms",
    ),
    pytest.param(
        {"devices": {"deviceFilter": {"mode": "exclude", "rule": "device.isCompliant -eq True"}}},
        "device_filter_excludes_devices",
        {"device_filter": {"mode": "exclude", "rule": "device.isCompliant -eq True"}},
        id="device-filter-exclude",
    ),
    pytest.param(
        {"applications": {"includeApplications": ["All"], "excludeApplications": ["00000002-0000-0ff1-ce00-000000000000"]}},
        "excludes_applications",
        {"excluded_applications": ["00000002-0000-0ff1-ce00-000000000000"]},
        id="excluded-applications",
    ),
]


@pytest.mark.parametrize(("override", "reason", "recorded"), EXCLUSION_CASES)
def test_policy_that_excludes_platforms_devices_or_apps_does_not_enforce_mfa(
    override: dict[str, Any], reason: str, recorded: dict[str, Any]
) -> None:
    verdict = _mfa(_policy(**override))

    assert verdict["verdict"] == "not_enforced"
    assert not verdict.get("qualifying_policies")
    [near_miss] = verdict["non_qualifying_mfa_policies"]
    assert near_miss["reasons"] == [reason]
    for key, value in recorded.items():
        assert near_miss[key] == value


@pytest.mark.parametrize(("override", "reason", "recorded"), EXCLUSION_CASES)
def test_block_policy_that_excludes_platforms_devices_or_apps_does_not_block_legacy_authentication(
    override: dict[str, Any], reason: str, recorded: dict[str, Any]
) -> None:
    verdict = _legacy(_block_policy(**override))

    assert verdict["verdict"] == "not_blocked"
    assert not verdict.get("blocking_policies")
    [near_miss] = verdict["non_qualifying_block_policies"]
    assert near_miss["reasons"] == [reason]
    for key, value in recorded.items():
        assert near_miss[key] == value


def test_include_mode_device_filter_and_all_platforms_still_read_as_narrowing_or_clean() -> None:
    clean = _mfa(_policy(platforms={"includePlatforms": ["all"]}, devices={"deviceFilter": {"mode": "include"}}))

    assert clean["verdict"] == "not_enforced"
    assert clean["non_qualifying_mfa_policies"][0]["reasons"] == ["narrowed_by_device_filter"]
    assert _mfa(_policy(platforms={"includePlatforms": ["all"]}))["verdict"] == "enforced"


def test_weak_authentication_strength_is_not_enforced() -> None:
    strength = {"id": "custom-1", "displayName": "Password or SMS", "requirementsSatisfied": "none"}
    verdict = _mfa(_policy(grant={"operator": "OR", "builtInControls": [], "authenticationStrength": strength}))

    assert verdict["verdict"] == "not_enforced"
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["authentication_strength_allows_single_factor"]


# --- effective MFA: unknown -------------------------------------------------------------------


@pytest.mark.parametrize("state", ["blocked", "truncated", "absent"])
def test_unreadable_policy_collection_is_unknown_not_a_pass_or_a_failure(state: str) -> None:
    verdict = _mfa(policy_evidence=Evidence(state, (_policy(),)), defaults=_defaults(False))

    assert verdict["verdict"] == "unknown"
    assert f"policy_collection_{state}" in verdict["reasons"]
    assert verdict["basis"] == []
    # Rows from an unreadable collection are not trusted in either direction.
    assert not verdict.get("qualifying_policies")


@pytest.mark.parametrize("state", ["blocked", "absent"])
def test_unreadable_security_defaults_with_no_qualifying_policy_is_unknown(state: str) -> None:
    verdict = _mfa(defaults=Evidence(state))

    assert verdict["verdict"] == "unknown"
    assert f"security_defaults_{state}" in verdict["reasons"]


def test_qualifying_policy_enforces_even_when_security_defaults_are_unreadable() -> None:
    verdict = _mfa(_policy(), defaults=Evidence("blocked", detail="insufficient_permissions"))

    assert verdict["verdict"] == "enforced"
    assert verdict["security_defaults"]["state"] == "blocked"


def test_security_defaults_without_an_enabled_flag_are_unknown() -> None:
    verdict = _mfa(defaults=_collected({"id": "00000000-0000-0000-0000-000000000005"}))

    assert verdict["verdict"] == "unknown"
    assert verdict["security_defaults"]["detail"] == "is_enabled_missing"


def test_unresolvable_authentication_strength_is_unknown_not_not_enforced() -> None:
    strength = {"id": "custom-9", "displayName": "Custom strength"}
    verdict = _mfa(_policy(grant={"operator": "OR", "builtInControls": [], "authenticationStrength": strength}))

    assert verdict["verdict"] == "unknown"
    assert verdict["reasons"] == ["authentication_strength_unverified"]
    assert verdict["unverified_policies"][0]["id"] == "ca-1"


def test_authentication_strength_is_resolved_from_the_collected_strength_list() -> None:
    strength = {"id": "custom-9", "displayName": "Custom strength"}
    grant = {"operator": "OR", "builtInControls": [], "authenticationStrength": strength}
    collected = _collected({"id": "custom-9", "requirementsSatisfied": "mfa", "allowedCombinations": ["fido2"]})

    verdict = _mfa(_policy(grant=grant), strengths=collected)

    assert verdict["verdict"] == "enforced"


def test_custom_strength_allowing_a_single_factor_does_not_enforce() -> None:
    strength = {"id": "custom-9", "displayName": "Custom strength"}
    grant = {"operator": "OR", "builtInControls": [], "authenticationStrength": strength}
    collected = _collected({"id": "custom-9", "allowedCombinations": ["password", "fido2"]})

    verdict = _mfa(_policy(grant=grant), strengths=collected)

    assert verdict["verdict"] == "not_enforced"


def _strength_grant(strength_id: str = "custom-9") -> dict[str, Any]:
    return {
        "operator": "OR",
        "builtInControls": [],
        "authenticationStrength": {"id": strength_id, "displayName": "Custom strength"},
    }


def test_federated_single_factor_strength_is_not_enforced() -> None:
    collected = _collected({"id": "custom-9", "allowedCombinations": ["fido2", "federatedSingleFactor"]})

    verdict = _mfa(_policy(grant=_strength_grant()), strengths=collected)

    assert verdict["verdict"] == "not_enforced"
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["authentication_strength_allows_single_factor"]


def test_unknown_single_entry_mode_is_unverified_not_mfa() -> None:
    collected = _collected({"id": "custom-9", "allowedCombinations": ["fido2", "someFutureMode"]})

    verdict = _mfa(_policy(grant=_strength_grant()), strengths=collected)

    assert verdict["verdict"] == "unknown"
    assert verdict["reasons"] == ["authentication_strength_unverified"]


def test_known_single_factor_mode_outranks_an_unknown_one() -> None:
    collected = _collected({"id": "custom-9", "allowedCombinations": ["someFutureMode", "password"]})

    assert _mfa(_policy(grant=_strength_grant()), strengths=collected)["verdict"] == "not_enforced"


def test_multi_entry_combinations_and_known_multi_factor_modes_are_mfa() -> None:
    collected = _collected(
        {
            "id": "custom-9",
            "allowedCombinations": ["password,hardwareOath", "password,microsoftAuthenticatorPush", "windowsHelloForBusiness", "fido2"],
        }
    )

    assert _mfa(_policy(grant=_strength_grant()), strengths=collected)["verdict"] == "enforced"


# --- legacy authentication --------------------------------------------------------------------


def test_block_policy_for_all_users_and_legacy_clients_blocks_legacy_authentication() -> None:
    verdict = _legacy(_block_policy())

    assert verdict["verdict"] == "blocked"
    assert verdict["basis"] == ["conditional_access_policy"]
    assert [row["id"] for row in verdict["blocking_policies"]] == ["ca-block"]


def test_security_defaults_block_legacy_authentication() -> None:
    verdict = _legacy(policy_evidence=Evidence("absent"), defaults=_defaults(True))

    assert verdict["verdict"] == "blocked"
    assert verdict["basis"] == ["security_defaults"]


def test_missing_block_policy_with_security_defaults_off_is_not_blocked() -> None:
    verdict = _legacy(_policy())

    assert verdict["verdict"] == "not_blocked"
    assert verdict["basis"] == []


def test_block_policy_for_only_one_legacy_client_type_is_not_blocked() -> None:
    verdict = _legacy(_block_policy(client_app_types=["exchangeActiveSync"]))

    assert verdict["verdict"] == "not_blocked"
    assert verdict["non_qualifying_block_policies"][0]["reasons"] == ["legacy_client_app_types_incomplete"]


def test_block_policy_scoped_to_a_group_is_not_blocked() -> None:
    verdict = _legacy(_block_policy(users={"includeGroups": ["group-1"]}))

    assert verdict["verdict"] == "not_blocked"
    assert "not_all_users" in verdict["non_qualifying_block_policies"][0]["reasons"]


def test_disabled_and_report_only_block_policies_do_not_block() -> None:
    verdict = _legacy(_block_policy("off", state="disabled"), _block_policy("watch", state="enabledForReportingButNotEnforced"))

    assert verdict["verdict"] == "not_blocked"
    assert [row["id"] for row in verdict["report_only_block_policies"]] == ["watch"]


def test_block_policy_lists_its_exclusions() -> None:
    verdict = _legacy(_block_policy(users={"includeUsers": ["All"], "excludeUsers": ["user-bg"]}))

    assert verdict["verdict"] == "blocked"
    assert verdict["excluded_principals"][0]["display_name"] == "breakglass@example.test"


@pytest.mark.parametrize("state", ["blocked", "truncated", "absent"])
def test_unreadable_policy_collection_leaves_legacy_authentication_unknown(state: str) -> None:
    verdict = _legacy(policy_evidence=Evidence(state))

    assert verdict["verdict"] == "unknown"
    assert f"policy_collection_{state}" in verdict["reasons"]


# --- user consent -----------------------------------------------------------------------------


def _authorization(assigned: Any = "missing") -> Evidence:
    defaults: dict[str, Any] = {"allowedToCreateApps": True}
    if assigned != "missing":
        defaults["permissionGrantPoliciesAssigned"] = assigned
    return _collected({"id": "authorizationPolicy", "defaultUserRolePermissions": defaults})


def _consent(authorization: Evidence, definitions: Evidence | None = None) -> dict[str, Any]:
    return evaluate_user_consent(
        authorization_policy=authorization,
        permission_grant_policies=definitions if definitions is not None else _collected(),
    )


def test_legacy_consent_policy_is_unrestricted() -> None:
    verdict = _consent(_authorization(["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]))

    assert verdict["verdict"] == "unrestricted"
    assert verdict["consent_mode"] == "unrestricted"
    assert verdict["unrestricted_policies"] == ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]


@pytest.mark.parametrize(
    ("assigned", "mode"),
    [
        (["ManagePermissionGrantsForSelf.microsoft-user-default-low"], "verified_publishers_low_risk_permissions"),
        (["ManagePermissionGrantsForSelf.microsoft-user-default-recommended"], "microsoft_managed"),
        ([], "none"),
        (["ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"], "none"),
    ],
)
def test_limited_or_no_user_consent_is_restricted(assigned: list[str], mode: str) -> None:
    verdict = _consent(_authorization(assigned))

    assert verdict["verdict"] == "restricted"
    assert verdict["consent_mode"] == mode


def test_unrestricted_policy_wins_over_a_limited_one() -> None:
    assigned = [
        "ManagePermissionGrantsForSelf.microsoft-user-default-low",
        "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",
    ]

    assert _consent(_authorization(assigned))["verdict"] == "unrestricted"


def test_custom_permission_grant_policy_is_unknown_and_named() -> None:
    definitions = _collected({"id": "contoso-consent", "displayName": "Contoso consent"})

    verdict = _consent(_authorization(["ManagePermissionGrantsForSelf.contoso-consent"]), definitions)

    assert verdict["verdict"] == "unknown"
    assert verdict["reasons"] == ["custom_permission_grant_policy_not_evaluated"]
    assert verdict["custom_policies"] == [
        {"id": "ManagePermissionGrantsForSelf.contoso-consent", "display_name": "Contoso consent"}
    ]


def test_missing_assigned_policy_list_is_unknown() -> None:
    verdict = _consent(_authorization())

    assert verdict["verdict"] == "unknown"
    assert verdict["reasons"] == ["permission_grant_policies_assigned_missing"]


@pytest.mark.parametrize("state", ["blocked", "absent"])
def test_unreadable_authorization_policy_is_unknown(state: str) -> None:
    verdict = _consent(Evidence(state))

    assert verdict["verdict"] == "unknown"
    assert f"authorization_policy_{state}" in verdict["reasons"]


# --- normalization, collection state and records ----------------------------------------------


def _snapshot(collector_payloads: dict[str, Any]) -> dict[str, Any]:
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=collector_payloads)


def _verdicts(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["control"]: row for row in snapshot["identity_control_verdicts"]["records"]}


def test_verdicts_are_normalized_per_tenant_from_live_shaped_payloads() -> None:
    snapshot = _snapshot(
        {
            "identity": {
                "users": {"value": [{"id": "user-bg", "userPrincipalName": "breakglass@example.test"}]},
                "groups": {"value": []},
                "roleDefinitions": {"value": []},
                "roleAssignments": {"value": []},
            },
            "conditional_access": {
                "conditionalAccessPolicies": {
                    "value": [_policy(users={"includeUsers": ["All"], "excludeUsers": ["user-bg"]})]
                },
                # Live singleton reads arrive as a bare object, not wrapped in "value".
                "identitySecurityDefaultsEnforcementPolicy": {"id": "sd", "isEnabled": False},
                "authenticationStrengthPolicies": {"value": []},
            },
        }
    )

    records = _verdicts(snapshot)
    mfa = records["effective_mfa"]
    assert mfa["verdict"] == "enforced"
    assert mfa["key"] == "identity_control_verdict:effective_mfa"
    assert mfa["excluded_principals"][0]["display_name"] == "breakglass@example.test"
    assert records["legacy_authentication_block"]["verdict"] == "not_blocked"
    assert "user_consent" not in records
    assert snapshot["snapshot"]["object_counts"]["identity_control_verdicts"] == 2


def test_wrapped_singleton_responses_are_read_too() -> None:
    snapshot = _snapshot(
        {
            "conditional_access": {
                "conditionalAccessPolicies": {"value": []},
                "identitySecurityDefaultsEnforcementPolicy": {"value": [{"id": "sd", "isEnabled": True}]},
            }
        }
    )

    assert _verdicts(snapshot)["effective_mfa"]["basis"] == ["security_defaults"]


def test_blocked_collection_gives_unknown_verdicts_in_the_snapshot() -> None:
    error = {"error": "Forbidden", "error_class": "insufficient_permissions"}
    snapshot = _snapshot(
        {
            "conditional_access": {
                "conditionalAccessPolicies": dict(error),
                "identitySecurityDefaultsEnforcementPolicy": dict(error),
            }
        }
    )

    records = _verdicts(snapshot)
    assert records["effective_mfa"]["verdict"] == "unknown"
    assert records["effective_mfa"]["policy_collection"]["detail"] == "insufficient_permissions"
    assert records["legacy_authentication_block"]["verdict"] == "unknown"


def test_truncated_policy_collection_gives_unknown_in_the_snapshot() -> None:
    snapshot = _snapshot(
        {
            "conditional_access": {
                "conditionalAccessPolicies": {
                    "value": [_policy()],
                    "item_count": 1,
                    "result_limit": 1,
                    "collection_limit_reached": True,
                },
                "identitySecurityDefaultsEnforcementPolicy": {"id": "sd", "isEnabled": False},
            }
        }
    )

    mfa = _verdicts(snapshot)["effective_mfa"]
    assert mfa["verdict"] == "unknown"
    assert mfa["policy_collection"] == {"state": "truncated", "row_count": 1, "detail": "collection_limit_reached"}


def test_empty_collector_payload_is_unknown_and_absent_collector_has_no_record() -> None:
    assert _verdicts(_snapshot({"conditional_access": {}}))["effective_mfa"]["verdict"] == "unknown"
    assert "identity_control_verdicts" not in _snapshot({"identity": {"users": {"value": []}}})


def test_policy_conditions_are_kept_in_the_normalized_policy_record() -> None:
    snapshot = _snapshot(
        {
            "conditional_access": {
                "conditionalAccessPolicies": {
                    "value": [
                        _policy(
                            users={"includeUsers": ["All"], "excludeGroups": ["group-bg"], "excludeRoles": [GLOBAL_ADMIN]},
                            client_app_types=["exchangeActiveSync", "other"],
                            grant={
                                "operator": "AND",
                                "builtInControls": ["mfa"],
                                "authenticationStrength": {"id": MFA_STRENGTH, "displayName": "MFA"},
                            },
                        )
                    ]
                }
            }
        }
    )

    targeting = snapshot["conditional_access_graph"]["records"][0]["targeting"]
    assert targeting["include_users"] == ["All"]
    assert targeting["exclude_groups"] == ["group-bg"]
    assert targeting["exclude_roles"] == [GLOBAL_ADMIN]
    assert targeting["include_applications"] == ["All"]
    assert targeting["client_app_types"] == ["exchangeActiveSync", "other"]
    assert targeting["grant"]["operator"] == "AND"
    assert targeting["grant"]["authentication_strength"]["id"] == MFA_STRENGTH


def test_authorization_policy_keeps_the_assigned_permission_grant_policies() -> None:
    snapshot = _snapshot(
        {
            "consent_policy": {
                "authorizationPolicy": {
                    "id": "authorizationPolicy",
                    "guestUserRoleId": "guest-role",
                    "defaultUserRolePermissions": {
                        "allowedToCreateApps": False,
                        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"],
                    },
                }
            }
        }
    )

    record = next(
        row for row in snapshot["consent_policy_objects"]["records"] if row["source_name"] == "authorizationPolicy"
    )
    assert record["permission_grant_policies_assigned"] == ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
    assert record["allowed_to_create_apps"] is False
    assert record["guest_user_role_id"] == "guest-role"
    assert _verdicts(snapshot)["user_consent"]["verdict"] == "restricted"


# --- rules ------------------------------------------------------------------------------------


def _findings(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["id"]: row for row in build_findings([], normalized_snapshot=snapshot)}


def _by_rule(snapshot: dict[str, Any], rule_id: str) -> list[dict[str, Any]]:
    return [row for row in build_findings([], normalized_snapshot=snapshot) if row.get("rule_id") == rule_id]


def _assert_refs_resolve(snapshot: dict[str, Any], finding: dict[str, Any]) -> None:
    assert finding["evidence_refs"]
    for ref in finding["evidence_refs"]:
        section = Path(ref["artifact_path"]).stem
        keys = {row.get("key") for row in (snapshot.get(section) or {}).get("records", [])}
        assert ref["record_key"] in keys, (finding["id"], ref)


def _not_enforced_snapshot() -> dict[str, Any]:
    return _snapshot(
        {
            "identity": {
                "users": {"value": [{"id": "user-bg", "userPrincipalName": "breakglass@example.test"}]},
            },
            "auth_methods": {
                "userRegistrationDetails": {
                    "value": [{"id": "user-1", "userPrincipalName": "a@example.test", "isMfaRegistered": True}]
                }
            },
            "conditional_access": {
                "conditionalAccessPolicies": {
                    "value": [
                        _policy("ca-group", users={"includeGroups": ["group-pilot"], "excludeUsers": ["user-bg"]}),
                        _policy("ca-report", state="enabledForReportingButNotEnforced"),
                        _block_policy("ca-eas", client_app_types=["exchangeActiveSync"]),
                    ]
                },
                "identitySecurityDefaultsEnforcementPolicy": {"id": "sd", "isEnabled": False},
            },
            "consent_policy": {
                "authorizationPolicy": {
                    "id": "authorizationPolicy",
                    "defaultUserRolePermissions": {
                        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
                    },
                }
            },
        }
    )


def test_mfa_not_enforced_rule_carries_severity_mappings_and_evidence() -> None:
    snapshot = _not_enforced_snapshot()

    [finding] = _by_rule(snapshot, "ca.mfa_not_enforced")

    assert finding["severity"] == "high"
    assert finding["status"] == "open"
    assert finding["collector"] == "conditional_access"
    assert finding["title"] == "Neither security defaults nor Conditional Access enforce MFA for all users"
    assert finding["framework_mappings"]["cis_m365_v7"] == ["5.2.2.2"]
    assert finding["framework_mappings"]["cisa_scuba"] == ["MS.AAD.3.2v1"]
    assert finding["control_ids"] == ["AUDITEX-CA-MFA-NOT-ENFORCED"]
    assert finding["returned_value"]["verdict"] == "not_enforced"
    near_miss = {row["id"]: row for row in finding["evidence"]["non_qualifying_mfa_policies"]}
    assert near_miss["ca-group"]["exclusions"][0]["display_name"] == "breakglass@example.test"
    assert [row["id"] for row in finding["evidence"]["report_only_mfa_policies"]] == ["ca-report"]
    assert finding["evidence"]["registration_context"]["mfa_registered"] == 1
    _assert_refs_resolve(snapshot, finding)
    refs = {ref["record_key"] for ref in finding["evidence_refs"]}
    assert {"identity_control_verdict:effective_mfa", "conditional_access_policy:ca-group"} <= refs


def test_legacy_auth_not_blocked_rule() -> None:
    snapshot = _not_enforced_snapshot()

    [finding] = _by_rule(snapshot, "ca.legacy_auth_not_blocked")

    assert finding["severity"] == "high"
    assert finding["framework_mappings"]["cis_m365_v7"] == ["5.2.2.3"]
    assert finding["framework_mappings"]["cisa_scuba"] == ["MS.AAD.1.1v1"]
    assert finding["evidence"]["non_qualifying_block_policies"][0]["reasons"] == ["legacy_client_app_types_incomplete"]
    _assert_refs_resolve(snapshot, finding)


def test_user_consent_unrestricted_rule() -> None:
    snapshot = _not_enforced_snapshot()

    [finding] = _by_rule(snapshot, "consent_policy.user_consent_unrestricted")

    assert finding["severity"] == "high"
    assert finding["category"] == "application"
    assert finding["framework_mappings"]["cis_m365_v7"] == ["5.1.5.1"]
    assert finding["framework_mappings"]["cisa_scuba"] == ["MS.AAD.5.2v1"]
    _assert_refs_resolve(snapshot, finding)
    assert {ref["artifact_path"] for ref in finding["evidence_refs"]} == {
        "normalized/identity_control_verdicts.json",
        "normalized/consent_policy_objects.json",
    }


def test_enforced_blocked_and_restricted_tenants_raise_none_of_the_rules() -> None:
    snapshot = _snapshot(
        {
            "conditional_access": {
                "conditionalAccessPolicies": {"value": [_policy("ca-mfa"), _block_policy()]},
                "identitySecurityDefaultsEnforcementPolicy": {"id": "sd", "isEnabled": False},
            },
            "consent_policy": {
                "authorizationPolicy": {
                    "defaultUserRolePermissions": {
                        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]
                    }
                }
            },
        }
    )

    rule_ids = {row.get("rule_id") for row in build_findings([], normalized_snapshot=snapshot)}

    assert not rule_ids & {
        "ca.mfa_not_enforced",
        "ca.legacy_auth_not_blocked",
        "consent_policy.user_consent_unrestricted",
        "ca.enforcement_unverified",
        "consent_policy.user_consent_unverified",
    }


def test_unknown_outcomes_raise_the_unverified_rules_and_never_the_failure_rules() -> None:
    error = {"error": "Forbidden", "error_class": "insufficient_permissions"}
    snapshot = _snapshot(
        {
            "conditional_access": {
                "conditionalAccessPolicies": dict(error),
                "identitySecurityDefaultsEnforcementPolicy": dict(error),
            },
            "consent_policy": {"authorizationPolicy": dict(error)},
        }
    )

    findings = build_findings([], normalized_snapshot=snapshot)
    rule_ids = [row.get("rule_id") for row in findings]

    assert "ca.mfa_not_enforced" not in rule_ids
    assert "ca.legacy_auth_not_blocked" not in rule_ids
    assert "consent_policy.user_consent_unrestricted" not in rule_ids
    unverified = {row["id"]: row for row in findings if row.get("rule_id") in {"ca.enforcement_unverified", "consent_policy.user_consent_unverified"}}
    assert set(unverified) == {
        "conditional_access:effective_mfa:unverified",
        "conditional_access:legacy_authentication_block:unverified",
        "consent_policy:user_consent:unverified",
    }
    for finding in unverified.values():
        assert finding["severity"] == "medium"
        assert finding["returned_value"]["verdict"] == "unknown"
        assert finding["returned_value"]["reasons"]
        assert not finding.get("framework_mappings", {}).get("cis_m365_v7")
        _assert_refs_resolve(snapshot, finding)


def test_collector_not_in_the_run_raises_no_verdict_findings() -> None:
    snapshot = _snapshot({"auth_methods": {"userRegistrationDetails": {"value": []}}})

    assert not [row for row in build_findings([], normalized_snapshot=snapshot) if str(row.get("rule_id", "")).startswith("ca.")]


def test_new_rules_have_templates_mappings_and_catalog_entries() -> None:
    templates = json.loads((REPO_ROOT / "configs" / "finding-templates.json").read_text(encoding="utf-8"))
    mappings = json.loads((REPO_ROOT / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
    for rule_id in (
        "ca.mfa_not_enforced",
        "ca.legacy_auth_not_blocked",
        "ca.enforcement_unverified",
        "consent_policy.user_consent_unrestricted",
        "consent_policy.user_consent_unverified",
        "identity.privileged_mfa_not_registered",
    ):
        assert templates[rule_id]["risk_rating"] in {"medium", "high"}
        assert mappings[rule_id]["nist_800_53"]


# --- renamed MFA registration findings and the privileged rule --------------------------------


def _registration_snapshot(registrations: list[dict[str, Any]], assignments: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    users = [
        {
            "id": row["id"],
            "userPrincipalName": row["userPrincipalName"],
            "accountEnabled": row.get("enabled", True),
            "userType": str(row.get("userType", "member")).capitalize(),
        }
        for row in registrations
    ]
    payloads: dict[str, Any] = {
        "identity": {
            "users": {"value": users},
            "roleDefinitions": {
                "value": [
                    {"id": GLOBAL_ADMIN, "displayName": "Global Administrator"},
                    {"id": EXCHANGE_ADMIN, "displayName": "Exchange Administrator"},
                    {"id": "reader-role", "displayName": "Global Reader"},
                ]
            },
            "roleAssignments": {"value": assignments},
        },
        "auth_methods": {"userRegistrationDetails": {"value": registrations}},
    }
    payloads.update(extra)
    return _snapshot(payloads)


def _live_row(user_id: str, upn: str, registered: bool = False, **extra: Any) -> dict[str, Any]:
    """A userRegistrationDetails row as the collector's $select returns it, with isAdmin and userType set."""
    return {"id": user_id, "userPrincipalName": upn, "isMfaRegistered": registered, **extra}


def test_non_global_admin_role_holder_without_mfa_gets_the_privileged_rule() -> None:
    # Regression: before isAdmin was selected, a live row carried no isAdmin and this account
    # fell through to the generic medium user finding with no sign that it was privileged.
    snapshot = _registration_snapshot(
        [_live_row("u-exo", "exo@example.test", isAdmin=False, userType="member")],
        [{"id": "a1", "roleDefinitionId": EXCHANGE_ADMIN, "principalId": "u-exo"}],
    )

    findings = build_findings([], normalized_snapshot=snapshot)

    assert not [row for row in findings if row.get("rule_id") == "identity.user_mfa_not_registered"]
    [finding] = [row for row in findings if row.get("rule_id") == "identity.privileged_mfa_not_registered"]
    assert finding["severity"] == "high"
    assert finding["affected_objects"] == ["exo@example.test"]
    assert finding["evidence"]["privileged_roles"] == [{"role": "Exchange Administrator", "assignment": "active"}]
    assert finding["evidence"]["identified_by"] == ["directory_role"]
    assert finding["framework_mappings"]["cis_m365_v7"] == ["5.2.2.1", "5.2.3.4"]
    _assert_refs_resolve(snapshot, finding)
    assert {ref["record_key"] for ref in finding["evidence_refs"]} == {
        "auth_method_registration:u-exo",
        "role_assignment:a1",
    }


def test_registration_report_admin_flag_alone_routes_to_the_privileged_rule() -> None:
    snapshot = _registration_snapshot([_live_row("u-1", "one@example.test", isAdmin=True, userType="member")], [])

    [finding] = _by_rule(snapshot, "identity.privileged_mfa_not_registered")

    assert finding["evidence"]["identified_by"] == ["registration_report_is_admin"]
    assert finding["evidence"]["privileged_roles"] == []
    _assert_refs_resolve(snapshot, finding)


def test_pim_eligible_administrator_without_mfa_gets_the_privileged_rule() -> None:
    snapshot = _registration_snapshot(
        [_live_row("u-eligible", "eligible@example.test", userType="member")],
        [],
        identity_governance={
            "roleEligibilitySchedules": {
                "value": [{"id": "elig-1", "principalId": "u-eligible", "roleDefinitionId": EXCHANGE_ADMIN}]
            }
        },
    )

    [finding] = _by_rule(snapshot, "identity.privileged_mfa_not_registered")

    assert finding["evidence"]["privileged_roles"] == [{"role": "Exchange Administrator", "assignment": "eligible"}]
    _assert_refs_resolve(snapshot, finding)
    assert "role_eligibility_schedule:elig-1" in {ref["record_key"] for ref in finding["evidence_refs"]}


def test_global_administrator_keeps_its_critical_rule_and_gets_no_duplicate() -> None:
    snapshot = _registration_snapshot(
        [_live_row("u-ga", "ga@example.test", isAdmin=True, userType="member")],
        [{"id": "a1", "roleDefinitionId": GLOBAL_ADMIN, "principalId": "u-ga"}],
    )

    rules = [row.get("rule_id") for row in build_findings([], normalized_snapshot=snapshot)]

    assert "identity.global_admin_mfa_not_registered" in rules
    assert "identity.privileged_mfa_not_registered" not in rules
    assert "identity.user_mfa_not_registered" not in rules


def test_ordinary_user_stays_on_the_user_rule_and_other_cases_stay_skipped() -> None:
    snapshot = _registration_snapshot(
        [
            _live_row("u-plain", "plain@example.test", isAdmin=False, userType="member"),
            _live_row("u-reader", "reader@example.test", isAdmin=False, userType="member"),
            _live_row("u-guest", "guest@example.test", userType="guest"),
            _live_row("u-off", "off@example.test", isAdmin=True, userType="member", enabled=False),
            _live_row("u-ok", "ok@example.test", registered=True, isAdmin=True, userType="member"),
        ],
        [{"id": "a1", "roleDefinitionId": "reader-role", "principalId": "u-reader"}],
    )

    findings = build_findings([], normalized_snapshot=snapshot)

    user_findings = [row for row in findings if row.get("rule_id") == "identity.user_mfa_not_registered"]
    assert sorted(row["affected_objects"][0] for row in user_findings) == ["plain@example.test", "reader@example.test"]
    assert all(row["severity"] == "medium" for row in user_findings)
    assert not [row for row in findings if row.get("rule_id") == "identity.privileged_mfa_not_registered"]


def test_guest_holding_an_administrator_role_without_mfa_gets_the_privileged_rule() -> None:
    snapshot = _registration_snapshot(
        [
            _live_row("g-role", "role.guest@example.test", isAdmin=False, userType="guest"),
            _live_row("g-flag", "flag.guest@example.test", isAdmin=True, userType="guest"),
            _live_row("g-plain", "plain.guest@example.test", isAdmin=False, userType="guest"),
        ],
        [{"id": "a1", "roleDefinitionId": EXCHANGE_ADMIN, "principalId": "g-role"}],
    )

    findings = build_findings([], normalized_snapshot=snapshot)

    privileged = {row["affected_objects"][0]: row for row in findings if row.get("rule_id") == "identity.privileged_mfa_not_registered"}
    assert set(privileged) == {"role.guest@example.test", "flag.guest@example.test"}
    assert privileged["role.guest@example.test"]["evidence"]["user_type"] == "guest"
    assert privileged["role.guest@example.test"]["evidence"]["identified_by"] == ["directory_role"]
    # An ordinary guest stays out of the member-only user rule.
    assert not [row for row in findings if row.get("rule_id") == "identity.user_mfa_not_registered"]
    for finding in privileged.values():
        _assert_refs_resolve(snapshot, finding)


def test_mfa_not_enforced_template_states_that_per_user_mfa_is_out_of_scope() -> None:
    templates = json.loads((REPO_ROOT / "configs" / "finding-templates.json").read_text(encoding="utf-8"))
    template = templates["ca.mfa_not_enforced"]

    assert "per-user" in template["description"].lower()
    assert "not read" in template["description"].lower()
    assert "per-user" in template["impact"].lower()
    assert "guest" in templates["identity.privileged_mfa_not_registered"]["description"].lower()


def test_mfa_registration_findings_report_registration_not_enforcement() -> None:
    templates = json.loads((REPO_ROOT / "configs" / "finding-templates.json").read_text(encoding="utf-8"))

    for rule_id in (
        "identity.user_mfa_not_registered",
        "identity.global_admin_mfa_not_registered",
        "identity.privileged_mfa_not_registered",
    ):
        template = templates[rule_id]
        description = template["description"].lower()
        assert "registered" in description and "registration only" in description, rule_id
        assert "not whether mfa is required" in description, rule_id
        assert "ca.mfa_not_enforced" in template["remediation"], rule_id
        assert "enforced" not in template["expected_value"].lower(), rule_id


# --- collection, configuration and the offline fixture ----------------------------------------


class _PolicyClient:
    def __init__(self) -> None:
        self.json_calls: list[tuple[str, dict[str, Any]]] = []

    def get_all(self, path, params=None):  # noqa: ANN001
        return []

    def get_json(self, path, params=None, full_url=False):  # noqa: ANN001, ARG002
        self.json_calls.append((path, dict(params or {})))
        return {"id": "00000000-0000-0000-0000-000000000005", "isEnabled": True}


def test_security_defaults_are_collected_with_a_single_read_only_get() -> None:
    client = _PolicyClient()

    result = ConditionalAccessCollector().run({"client": client, "top": 50, "audit_logger": None})

    assert ("/policies/identitySecurityDefaultsEnforcementPolicy", {}) in client.json_calls
    assert result.payload["identitySecurityDefaultsEnforcementPolicy"]["isEnabled"] is True
    row = next(row for row in result.coverage if row["name"] == "identitySecurityDefaultsEnforcementPolicy")
    assert row["endpoint"] == "/policies/identitySecurityDefaultsEnforcementPolicy"
    assert row["status"] == "ok"


def test_new_call_is_declared_and_permissions_stay_read_only() -> None:
    definitions = json.loads((REPO_ROOT / "configs" / "collector-definitions.json").read_text(encoding="utf-8"))
    permissions = json.loads((REPO_ROOT / "configs" / "collector-permissions.json").read_text(encoding="utf-8"))
    conditional_access = definitions["collectors"]["conditional_access"]

    assert "identitySecurityDefaultsEnforcementPolicy" in conditional_access["query_plan"]
    for scopes in (
        conditional_access["required_permissions"],
        permissions["collector_permissions"]["conditional_access"]["graph_scopes"],
        permissions["collector_permissions"]["auth_methods"]["graph_scopes"],
    ):
        assert "Policy.Read.All" in scopes or "Reports.Read.All" in scopes
        assert not [scope for scope in scopes if "ReadWrite" in scope or scope.endswith(".Write.All")]
    assert "identitySecurityDefaultsEnforcementPolicy" in (REPO_ROOT / "docs" / "reference" / "api-call-catalog.md").read_text(
        encoding="utf-8"
    )


def test_identity_controls_sample_exercises_the_verdicts_and_rules_offline(tmp_path: Path) -> None:
    assert run_offline(IDENTITY_CONTROLS_SAMPLE, tmp_path, "ci", "identity-controls") == 0
    run_dir = tmp_path / "ci-identity-controls"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))
    verdicts = json.loads((run_dir / "normalized" / "identity_control_verdicts.json").read_text(encoding="utf-8"))

    assert validation["valid"] is True, validation["issues"]
    assert {row["control"]: row["verdict"] for row in verdicts["records"]} == {
        "effective_mfa": "not_enforced",
        "legacy_authentication_block": "not_blocked",
        "user_consent": "unrestricted",
    }
    rules = {row.get("rule_id") for row in findings}
    assert {
        "ca.mfa_not_enforced",
        "ca.legacy_auth_not_blocked",
        "consent_policy.user_consent_unrestricted",
        "identity.privileged_mfa_not_registered",
        "identity.user_mfa_not_registered",
    } <= rules
    # Every reference from a new finding points at a record that exists in the bundle.
    new_rules = {rule for rule in rules if rule and (rule.startswith("ca.") or rule in {
        "consent_policy.user_consent_unrestricted",
        "identity.privileged_mfa_not_registered",
    })}
    for finding in findings:
        if finding.get("rule_id") not in new_rules:
            continue
        for ref in finding["evidence_refs"]:
            records = json.loads((run_dir / ref["artifact_path"]).read_text(encoding="utf-8"))["records"]
            assert ref["record_key"] in {row.get("key") for row in records}, (finding["id"], ref)
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    assert {row["finding_id"] for row in report_pack["proof_table"]} == {row["id"] for row in findings}
