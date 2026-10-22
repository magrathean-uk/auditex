"""Principal exclusions, the administrator MFA verdict and the controls built on them (CE+ review 2026-10-22).

A policy that targets everyone but excludes the Global Administrator role, an all-staff group or every guest does not
require MFA of them. The verdicts say so (``*_with_exclusions``), and no CIS or ScubaGear control passes on it unless
every exclusion is an emergency access account the operator listed. Registration reports never decide an
enforcement control.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.identity_controls import (
    AdminScope,
    Evidence,
    evaluate_administrator_mfa,
    evaluate_effective_mfa,
    evaluate_legacy_authentication_block,
)
from azure_tenant_audit.normalize import build_normalized_snapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
PHISHING_RESISTANT = "00000000-0000-0000-0000-000000000004"
MFA_STRENGTH = "00000000-0000-0000-0000-000000000002"
ALL_STAFF = "g-all-staff"
BREAK_GLASS_USER = "u-bg"
BREAK_GLASS_GROUP = "g-bg"
ADMIN = "u-admin"
LOOKUPS = {
    "user": {BREAK_GLASS_USER: "bg@example.test", ADMIN: "admin@example.test"},
    "group": {ALL_STAFF: "All Staff", BREAK_GLASS_GROUP: "Break Glass"},
    "role": {GLOBAL_ADMIN: "Global Administrator", EXCHANGE_ADMIN: "Exchange Administrator"},
}


def _policy(
    policy_id: str = "ca-1",
    *,
    users: dict[str, Any] | None = None,
    grant: dict[str, Any] | None = None,
    client_app_types: list[str] | None = None,
    state: str = "enabled",
    applications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": policy_id,
        "displayName": f"Policy {policy_id}",
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["All"]} if users is None else users,
            "applications": {"includeApplications": ["All"]} if applications is None else applications,
            "clientAppTypes": ["all"] if client_app_types is None else client_app_types,
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]} if grant is None else grant,
    }


def _all_users(**exclusions: list[str]) -> dict[str, Any]:
    return {"includeUsers": ["All"], **exclusions}


def _collected(*rows: dict[str, Any]) -> Evidence:
    return Evidence("collected", tuple(rows))


def _defaults(enabled: bool = False) -> Evidence:
    return _collected({"id": "00000000-0000-0000-0000-000000000005", "isEnabled": enabled})


def _mfa(*policies: dict[str, Any], sanctioned: frozenset[str] = frozenset(), defaults: bool = False) -> dict[str, Any]:
    return evaluate_effective_mfa(
        policies=_collected(*policies),
        security_defaults=_defaults(defaults),
        authentication_strengths=_collected(),
        lookups=LOOKUPS,
        sanctioned=sanctioned,
    )


def _legacy(*policies: dict[str, Any], sanctioned: frozenset[str] = frozenset()) -> dict[str, Any]:
    return evaluate_legacy_authentication_block(
        policies=_collected(*policies), security_defaults=_defaults(False), lookups=LOOKUPS, sanctioned=sanctioned
    )


def _block(policy_id: str = "ca-block", **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("client_app_types", ["exchangeActiveSync", "other"])
    kwargs.setdefault("grant", {"operator": "OR", "builtInControls": ["block"]})
    return _policy(policy_id, **kwargs)


# --- effective MFA with exclusions -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "users"),
    [
        ("administrator role", _all_users(excludeRoles=[GLOBAL_ADMIN])),
        ("all-staff group", _all_users(excludeGroups=[ALL_STAFF])),
        (
            "every guest type",
            _all_users(
                excludeGuestsOrExternalUsers={
                    "guestOrExternalUserTypes": "b2bCollaborationGuest,b2bCollaborationMember,internalGuest,serviceProvider"
                }
            ),
        ),
    ],
)
def test_mfa_that_excludes_a_role_a_group_or_the_guests_is_enforced_with_exclusions(label: str, users: dict[str, Any]) -> None:
    verdict = _mfa(_policy(users=users))

    assert verdict["verdict"] == "enforced_with_exclusions", label
    assert verdict["unsanctioned_exclusion_count"] == 1
    assert verdict["basis"] == ["conditional_access_policy"]


def test_an_excluded_role_is_never_sanctioned_even_when_its_id_is_on_the_operator_list() -> None:
    verdict = _mfa(_policy(users=_all_users(excludeRoles=[GLOBAL_ADMIN])), sanctioned=frozenset({GLOBAL_ADMIN.lower()}))

    assert verdict["verdict"] == "enforced_with_exclusions"


def test_exclusions_that_are_all_operator_listed_emergency_accounts_still_enforce() -> None:
    policy = _policy(users=_all_users(excludeUsers=[BREAK_GLASS_USER], excludeGroups=[BREAK_GLASS_GROUP]))

    verdict = _mfa(policy, sanctioned=frozenset({BREAK_GLASS_USER, BREAK_GLASS_GROUP}))

    assert verdict["verdict"] == "enforced"
    assert verdict["excluded_principal_count"] == 2 and verdict["unsanctioned_exclusion_count"] == 0
    assert all(row["sanctioned"] for row in verdict["excluded_principals"])
    assert verdict["sanctioned_exclusion_source"] == "operator"


def test_the_same_exclusions_without_an_operator_list_are_a_gap() -> None:
    policy = _policy(users=_all_users(excludeUsers=[BREAK_GLASS_USER]))

    assert _mfa(policy)["verdict"] == "enforced_with_exclusions"


def test_one_unsanctioned_exclusion_beside_a_sanctioned_one_is_still_a_gap() -> None:
    policy = _policy(users=_all_users(excludeUsers=[BREAK_GLASS_USER], excludeGroups=[ALL_STAFF]))

    verdict = _mfa(policy, sanctioned=frozenset({BREAK_GLASS_USER}))

    assert verdict["verdict"] == "enforced_with_exclusions"
    assert [row["id"] for row in verdict["unsanctioned_exclusions"]] == [ALL_STAFF]


def test_a_second_policy_that_covers_what_the_first_excludes_enforces_for_everyone() -> None:
    first = _policy("ca-1", users=_all_users(excludeGroups=[ALL_STAFF]))
    second = _policy("ca-2", users=_all_users(excludeGroups=[BREAK_GLASS_GROUP]))

    verdict = _mfa(first, second, sanctioned=frozenset({BREAK_GLASS_GROUP}))

    assert verdict["verdict"] == "enforced", "nobody is excluded from both policies"


def test_security_defaults_enforce_whatever_a_policy_excludes() -> None:
    verdict = _mfa(_policy(users=_all_users(excludeGroups=[ALL_STAFF])), defaults=True)

    assert verdict["verdict"] == "enforced"


def test_legacy_authentication_block_that_excludes_a_group_is_blocked_with_exclusions() -> None:
    verdict = _legacy(_block(users=_all_users(excludeGroups=[ALL_STAFF])))

    assert verdict["verdict"] == "blocked_with_exclusions"
    assert verdict["unsanctioned_exclusion_count"] == 1
    assert _legacy(_block(users=_all_users(excludeGroups=[ALL_STAFF])), sanctioned=frozenset({ALL_STAFF}))["verdict"] == "blocked"


# --- the administrator MFA verdict ---------------------------------------------------------------------


def _scope(*, complete: bool = True, held: tuple[str, ...] = (GLOBAL_ADMIN,), admins: tuple[str, ...] = (ADMIN,), guests: int | None = 0) -> AdminScope:
    return AdminScope(
        complete=complete,
        privileged_role_ids=frozenset({GLOBAL_ADMIN, EXCHANGE_ADMIN}),
        held_role_ids=frozenset(held),
        admin_principal_ids=frozenset(admins),
        guest_admin_count=guests,
    )


def _admin(
    *policies: dict[str, Any],
    scope: AdminScope | None = None,
    defaults: bool = False,
    sanctioned: frozenset[str] = frozenset(),
    strengths: Evidence | None = None,
    policy_evidence: Evidence | None = None,
) -> dict[str, Any]:
    return evaluate_administrator_mfa(
        policies=policy_evidence if policy_evidence is not None else _collected(*policies),
        security_defaults=_defaults(defaults),
        authentication_strengths=strengths if strengths is not None else _collected(),
        lookups=LOOKUPS,
        admin_scope=scope if scope is not None else _scope(),
        sanctioned=sanctioned,
    )


def test_security_defaults_require_mfa_of_administrators_but_not_a_phishing_resistant_method() -> None:
    verdict = _admin(defaults=True)

    assert verdict["verdict"] == "enforced" and verdict["basis"] == ["security_defaults"]
    assert verdict["phishing_resistant_verdict"] == "not_enforced"


def test_no_policy_and_no_security_defaults_is_not_enforced_for_administrators() -> None:
    verdict = _admin()

    assert verdict["verdict"] == "not_enforced"
    assert verdict["phishing_resistant_verdict"] == "not_enforced"
    assert verdict["limitations"], "per-user MFA is not read"


def test_an_all_users_mfa_policy_reaches_every_administrator() -> None:
    verdict = _admin(_policy())

    assert verdict["verdict"] == "enforced"
    assert verdict["qualifying_policies"][0]["reach"] == "all_users"


def test_excluding_a_role_an_administrator_holds_leaves_administrators_without_mfa() -> None:
    verdict = _admin(_policy(users=_all_users(excludeRoles=[GLOBAL_ADMIN])))

    assert verdict["verdict"] == "not_enforced"
    assert [row["id"] for row in verdict["administrator_exclusions"]] == [GLOBAL_ADMIN]
    assert "administrators" in verdict["basis_summary"]


def test_excluding_a_role_nobody_holds_does_not_matter_when_the_set_is_complete() -> None:
    verdict = _admin(_policy(users=_all_users(excludeRoles=[EXCHANGE_ADMIN])))

    assert verdict["verdict"] == "enforced"


def test_excluding_an_administrator_user_is_a_gap_and_excluding_another_user_is_not() -> None:
    assert _admin(_policy(users=_all_users(excludeUsers=[ADMIN])))["verdict"] == "not_enforced"
    assert _admin(_policy(users=_all_users(excludeUsers=["u-someone-else"])))["verdict"] == "enforced"


def test_an_excluded_group_may_hold_administrators_so_the_verdict_has_exclusions() -> None:
    verdict = _admin(_policy(users=_all_users(excludeGroups=[ALL_STAFF])))

    assert verdict["verdict"] == "enforced_with_exclusions"
    assert [row["id"] for row in verdict["administrator_exclusions"]] == [ALL_STAFF]


def test_guests_excluded_only_matter_when_a_guest_is_an_administrator_or_unknown() -> None:
    guests = {"guestOrExternalUserTypes": "b2bCollaborationGuest"}
    policy = _policy(users=_all_users(excludeGuestsOrExternalUsers=guests))

    assert _admin(policy, scope=_scope(guests=0))["verdict"] == "enforced"
    assert _admin(policy, scope=_scope(guests=1))["verdict"] == "enforced_with_exclusions"
    assert _admin(policy, scope=_scope(complete=False, guests=None))["verdict"] == "enforced_with_exclusions"


def test_an_emergency_account_the_operator_listed_may_be_excluded() -> None:
    policy = _policy(users=_all_users(excludeUsers=[ADMIN]))

    assert _admin(policy, sanctioned=frozenset({ADMIN}))["verdict"] == "enforced"


def test_a_policy_for_every_role_an_administrator_holds_enforces_when_the_set_is_complete() -> None:
    policy = _policy(users={"includeRoles": [GLOBAL_ADMIN, EXCHANGE_ADMIN]})

    verdict = _admin(policy, scope=_scope(held=(GLOBAL_ADMIN, EXCHANGE_ADMIN)))

    assert verdict["verdict"] == "enforced"
    assert verdict["qualifying_policies"][0]["reach"] == "administrator_roles"


def test_a_policy_for_some_of_the_roles_administrators_hold_is_not_enough() -> None:
    policy = _policy(users={"includeRoles": [GLOBAL_ADMIN]})

    verdict = _admin(policy, scope=_scope(held=(GLOBAL_ADMIN, EXCHANGE_ADMIN)))

    assert verdict["verdict"] == "not_enforced"
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["covers_only_some_administrator_roles"]


def test_a_role_policy_cannot_be_judged_against_an_incomplete_administrator_set() -> None:
    policy = _policy(users={"includeRoles": [GLOBAL_ADMIN]})

    verdict = _admin(policy, scope=_scope(complete=False))

    assert verdict["verdict"] == "unknown"
    assert verdict["reasons"] == ["administrator_set_unknown"]
    assert verdict["phishing_resistant_verdict"] == "unknown"


def test_a_group_scoped_policy_does_not_count_for_administrators() -> None:
    verdict = _admin(_policy(users={"includeGroups": ["g-pilot"]}))

    assert verdict["verdict"] == "not_enforced"
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["not_all_administrators"]


def test_narrowed_report_only_and_unreadable_policies_do_not_enforce() -> None:
    narrowed = _policy("narrow", applications={"includeApplications": ["app-1"]})
    report_only = _policy("watch", state="enabledForReportingButNotEnforced")

    verdict = _admin(narrowed, report_only)

    assert verdict["verdict"] == "not_enforced"
    assert [row["id"] for row in verdict["report_only_mfa_policies"]] == ["watch"]
    assert _admin(policy_evidence=Evidence("blocked", detail="insufficient_permissions"))["verdict"] == "unknown"


def test_no_administrator_scope_still_lets_an_all_users_policy_enforce_but_not_a_role_policy() -> None:
    all_users = evaluate_administrator_mfa(
        policies=_collected(_policy()),
        security_defaults=_defaults(False),
        authentication_strengths=_collected(),
        lookups=LOOKUPS,
        admin_scope=None,
    )
    by_role = evaluate_administrator_mfa(
        policies=_collected(_policy(users={"includeRoles": [GLOBAL_ADMIN]})),
        security_defaults=_defaults(False),
        authentication_strengths=_collected(),
        lookups=LOOKUPS,
        admin_scope=None,
    )

    assert all_users["verdict"] == "enforced" and all_users["administrator_set"] == {"state": "absent"}
    assert by_role["verdict"] == "unknown"


# --- phishing-resistant MFA ----------------------------------------------------------------------------


def _strength_grant(strength_id: str = PHISHING_RESISTANT, *, operator: str = "OR", controls: list[str] | None = None, **strength: Any) -> dict[str, Any]:
    return {
        "operator": operator,
        "builtInControls": controls or [],
        "authenticationStrength": {"id": strength_id, "displayName": "Strength", **strength},
    }


def test_the_built_in_phishing_resistant_strength_makes_the_administrator_verdict_phishing_resistant() -> None:
    verdict = _admin(_policy(grant=_strength_grant()))

    assert verdict["verdict"] == "enforced"
    assert verdict["phishing_resistant_verdict"] == "enforced"
    assert verdict["phishing_resistant_policy_ids"] == ["ca-1"]


def test_plain_mfa_or_a_strength_that_allows_a_weaker_method_is_not_phishing_resistant() -> None:
    plain = _admin(_policy())
    push = _admin(_policy(grant=_strength_grant("custom-1", allowedCombinations=["fido2", "deviceBasedPush"])))
    sms = _admin(_policy(grant=_strength_grant("custom-3", allowedCombinations=["fido2", "sms"])))
    either = _admin(_policy(grant=_strength_grant(operator="OR", controls=["mfa"])))

    assert plain["verdict"] == "enforced" and plain["phishing_resistant_verdict"] == "not_enforced"
    assert push["verdict"] == "enforced" and push["phishing_resistant_verdict"] == "not_enforced"
    assert sms["verdict"] == "not_enforced", "a strength that a single factor can meet is not MFA at all"
    assert either["phishing_resistant_verdict"] == "not_enforced", "the user may pick plain MFA instead of the strength"


def test_a_custom_strength_of_only_phishing_resistant_methods_counts_and_and_with_mfa_keeps_the_strength() -> None:
    custom = _admin(_policy(grant=_strength_grant("custom-2", allowedCombinations=["fido2", "windowsHelloForBusiness"])))
    both = _admin(_policy(grant=_strength_grant(operator="AND", controls=["mfa"])))

    assert custom["phishing_resistant_verdict"] == "enforced"
    assert both["phishing_resistant_verdict"] == "enforced"


def test_a_phishing_resistant_policy_that_excludes_a_group_is_enforced_with_exclusions() -> None:
    policy = _policy(grant=_strength_grant(), users=_all_users(excludeGroups=[ALL_STAFF]))

    verdict = _admin(policy)

    assert verdict["verdict"] == "enforced_with_exclusions"
    assert verdict["phishing_resistant_verdict"] == "enforced_with_exclusions"


# --- from the collectors to the controls ---------------------------------------------------------------


def _payloads(policies: list[dict[str, Any]], *, registered: bool = True, defaults: bool = False, admin_roles: tuple[str, ...] = (GLOBAL_ADMIN,)) -> dict[str, Any]:
    return {
        "identity": {
            "users": {
                "value": [
                    {"id": ADMIN, "userPrincipalName": "admin@example.test", "displayName": "Admin", "accountEnabled": True, "userType": "Member"},
                    {"id": BREAK_GLASS_USER, "userPrincipalName": "bg@example.test", "displayName": "Break glass", "accountEnabled": True, "userType": "Member"},
                    {"id": "u-staff", "userPrincipalName": "staff@example.test", "displayName": "Staff", "accountEnabled": True, "userType": "Member"},
                ]
            },
            "groups": {"value": [{"id": ALL_STAFF, "displayName": "All Staff"}, {"id": BREAK_GLASS_GROUP, "displayName": "Break Glass"}]},
            "roleDefinitions": {
                "value": [
                    {"id": GLOBAL_ADMIN, "displayName": "Global Administrator"},
                    {"id": EXCHANGE_ADMIN, "displayName": "Exchange Administrator"},
                ]
            },
            "roleAssignments": {
                "value": [{"id": f"ra-{role}", "roleDefinitionId": role, "principalId": ADMIN} for role in admin_roles]
            },
        },
        "identity_governance": {
            "roleAssignmentSchedules": {"error": "license", "error_class": "license_required"},
            "roleEligibilitySchedules": {"error": "license", "error_class": "license_required"},
        },
        "conditional_access": {
            "conditionalAccessPolicies": {"value": policies},
            "identitySecurityDefaultsEnforcementPolicy": {"id": "sd", "isEnabled": defaults},
            "authenticationStrengthPolicies": {"value": []},
        },
        "auth_methods": {
            "userRegistrationDetails": {
                "value": [
                    {"id": user, "userPrincipalName": f"{user}@example.test", "isMfaRegistered": registered, "isAdmin": user == ADMIN}
                    for user in (ADMIN, BREAK_GLASS_USER, "u-staff")
                ]
            }
        },
    }


COMPLETE = [
    {"collector": name, "coverage_status": "complete_exact_scope"}
    for name in ("identity", "auth_methods", "conditional_access", "consent_policy")
] + [{"collector": "identity_governance", "coverage_status": "not_applicable"}]


def _alignment(policies: list[dict[str, Any]], *, accounts: list[str] | None = None, **kwargs: Any) -> tuple[dict[str, dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads=_payloads(policies, **kwargs), break_glass_accounts=accounts
    )
    findings = build_findings([], normalized_snapshot=snapshot)
    alignment = build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=COMPLETE)
    controls = {
        (framework, control["control_id"]): control
        for framework, entry in alignment["frameworks"].items()
        for control in entry["controls"]
    }
    return controls, snapshot, findings


def _status(controls: dict[tuple[str, str], dict[str, Any]], framework: str, control_id: str) -> str:
    return controls[(framework, control_id)]["status"]


def test_excluding_the_global_administrator_role_fails_the_mfa_controls_it_used_to_pass() -> None:
    controls, snapshot, findings = _alignment([_policy(users=_all_users(excludeRoles=[GLOBAL_ADMIN]))])

    verdicts = {row["control"]: row["verdict"] for row in snapshot["identity_control_verdicts"]["records"]}
    assert verdicts["effective_mfa"] == "enforced_with_exclusions"
    assert verdicts["administrator_mfa"] == "not_enforced"
    assert _status(controls, "cis_m365_v7", "5.2.2.2") == "fail"
    assert _status(controls, "cisa_scuba", "MS.AAD.3.2v1") == "fail"
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "fail"
    assert _status(controls, "cisa_scuba", "MS.AAD.3.6v1") == "fail"
    assert _status(controls, "ms_secure_score", "AdminMFAV2") == "fail"
    rules = {row.get("rule_id"): row for row in findings}
    assert rules["ca.mfa_not_enforced"]["severity"] == "medium"
    assert "Global Administrator" in rules["ca.mfa_not_enforced"]["description"]
    assert rules["ca.admin_mfa_not_enforced"]["severity"] == "high"


def test_an_all_staff_group_and_all_guests_excluded_fail_the_user_controls_but_not_the_administrator_ones() -> None:
    policy = _policy(
        users=_all_users(
            excludeGroups=[ALL_STAFF],
            excludeGuestsOrExternalUsers={"guestOrExternalUserTypes": "b2bCollaborationGuest,internalGuest"},
        )
    )

    controls, _snapshot, _findings = _alignment([policy])

    assert _status(controls, "cis_m365_v7", "5.2.2.2") == "fail"
    assert _status(controls, "cisa_scuba", "MS.AAD.3.2v1") == "fail"
    # The group may hold administrators, so administrator MFA is judged to have exclusions, which also fails 5.2.2.1.
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "fail"


def test_a_block_policy_with_a_group_excluded_fails_the_legacy_authentication_controls() -> None:
    controls, _snapshot, findings = _alignment([_block(users=_all_users(excludeGroups=[ALL_STAFF]))])

    assert _status(controls, "cis_m365_v7", "5.2.2.3") == "fail"
    assert _status(controls, "cisa_scuba", "MS.AAD.1.1v1") == "fail"
    finding = next(row for row in findings if row.get("rule_id") == "ca.legacy_auth_not_blocked")
    assert finding["severity"] == "medium" and finding["returned_value"]["verdict"] == "blocked_with_exclusions"


def test_exclusions_limited_to_the_operators_emergency_account_pass_every_mfa_control() -> None:
    policy = _policy(users=_all_users(excludeUsers=[BREAK_GLASS_USER]))

    controls, snapshot, findings = _alignment([policy], accounts=["bg@example.test"])

    verdicts = {row["control"]: row["verdict"] for row in snapshot["identity_control_verdicts"]["records"]}
    assert verdicts["effective_mfa"] == "enforced" and verdicts["administrator_mfa"] == "enforced"
    assert _status(controls, "cis_m365_v7", "5.2.2.2") == "pass"
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "pass"
    assert not [row for row in findings if row.get("rule_id") in {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced"}]


def test_registered_administrators_never_pass_an_enforcement_control_while_nothing_requires_mfa() -> None:
    """The review's regression: security defaults off, no policy, every account registered."""
    controls, snapshot, _findings = _alignment([], registered=True)

    verdicts = {row["control"]: row["verdict"] for row in snapshot["identity_control_verdicts"]["records"]}
    assert verdicts["effective_mfa"] == "not_enforced"
    for framework, control_id in (
        ("cis_m365_v7", "5.2.2.1"),
        ("cis_m365_v7", "5.2.2.2"),
        ("cisa_scuba", "MS.AAD.3.2v1"),
        ("cisa_scuba", "MS.AAD.3.6v1"),
        ("ms_secure_score", "AdminMFAV2"),
    ):
        assert _status(controls, framework, control_id) == "fail", (framework, control_id)
    # Registration is still judged, by the controls that are about registration.
    assert _status(controls, "cis_m365_v7", "5.2.3.4") == "pass"


def test_no_catalogued_mfa_enforcement_control_passes_while_the_mfa_verdict_is_not_enforced() -> None:
    catalog = json.loads((REPO_ROOT / "configs" / "framework-catalog.json").read_text(encoding="utf-8"))["frameworks"]
    controls, _snapshot, _findings = _alignment([], registered=True)
    registration_controls = {("cis_m365_v7", "5.2.3.4"), ("ms_secure_score", "MFARegistrationV2")}

    for framework in ("cis_m365_v7", "cisa_scuba", "ms_secure_score"):
        for control_id, spec in catalog[framework]["controls"].items():
            title = (spec["title"] if isinstance(spec, dict) else spec).lower()
            if not any(word in title for word in ("mfa", "multifactor", "multi-factor")):
                continue
            if (framework, control_id) in registration_controls or (framework, control_id) not in controls:
                continue
            assert controls[(framework, control_id)]["status"] != "pass", (framework, control_id, title)


def test_phishing_resistant_mfa_for_administrators_passes_scuba_3_6_and_plain_mfa_fails_it() -> None:
    phishing_resistant = _policy(grant=_strength_grant())

    resistant, _snapshot, resistant_findings = _alignment([phishing_resistant])
    plain, _snapshot, plain_findings = _alignment([_policy()])

    assert _status(resistant, "cisa_scuba", "MS.AAD.3.6v1") == "pass"
    assert not [row for row in resistant_findings if row.get("rule_id") == "ca.admin_phishing_resistant_mfa_not_enforced"]
    assert _status(plain, "cis_m365_v7", "5.2.2.1") == "pass"
    assert _status(plain, "cisa_scuba", "MS.AAD.3.6v1") == "fail"
    finding = next(row for row in plain_findings if row.get("rule_id") == "ca.admin_phishing_resistant_mfa_not_enforced")
    assert finding["severity"] == "low"


def test_the_administrator_mfa_rule_reads_not_assessed_when_the_administrator_set_is_unknown() -> None:
    payloads = _payloads([_policy(users={"includeRoles": [GLOBAL_ADMIN]})])
    del payloads["identity"]["roleAssignments"]
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=payloads)
    findings = build_findings([], normalized_snapshot=snapshot)

    verdicts = {row["control"]: row for row in snapshot["identity_control_verdicts"]["records"]}
    assert verdicts["administrator_mfa"]["verdict"] == "unknown"
    assert not [row for row in findings if row.get("rule_id") == "ca.admin_mfa_not_enforced"]
    assert any(row["id"] == "conditional_access:administrator_mfa:unverified" for row in findings)
    alignment = build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=COMPLETE)
    cis = {row["control_id"]: row for row in alignment["frameworks"]["cis_m365_v7"]["controls"]}
    assert cis["5.2.2.1"]["status"] == "not_assessed"


def test_the_ce_admin_mfa_row_fails_on_the_administrator_verdict_with_partial_confidence() -> None:
    controls, _snapshot, _findings = _alignment([])

    row = controls[("cyber_essentials", "ce.uac.mfa_admin_accounts")]
    assert row["status"] == "fail"
    assert row["confidence"] == "partial"
    assert "per-user" in row["evidence_limits"].lower()
    assert {item["rule_id"]: item["confidence"] for item in row["rule_statuses"] if item["status"] == "fail"} == {
        "ca.admin_mfa_not_enforced": "partial"
    }


# --- user consent ---------------------------------------------------------------------------------------


def _consent_alignment(assigned: list[str]) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, Any]]]:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={
            "consent_policy": {
                "authorizationPolicy": {
                    "id": "authorizationPolicy",
                    "defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": assigned},
                },
                "permissionGrantPolicies": {"value": []},
            }
        },
    )
    findings = build_findings([], normalized_snapshot=snapshot)
    alignment = build_baseline_alignment(
        findings,
        normalized_snapshot=snapshot,
        # CIS 5.1.5.1 is also read by the application consent rule, which needs its own collector.
        coverage_ledger=[
            {"collector": name, "coverage_status": "complete_exact_scope"} for name in ("consent_policy", "app_consent")
        ],
    )
    return {
        (framework, control["control_id"]): control
        for framework, entry in alignment["frameworks"].items()
        for control in entry["controls"]
    }, findings


@pytest.mark.parametrize(
    "policy",
    ["microsoft-user-default-recommended", "microsoft-user-default-low", "microsoft-user-default-legacy"],
)
def test_user_consent_other_than_none_fails_cis_5_1_5_1_and_scuba_5_2(policy: str) -> None:
    controls, findings = _consent_alignment([f"ManagePermissionGrantsForSelf.{policy}"])

    assert controls[("cis_m365_v7", "5.1.5.1")]["status"] == "fail"
    assert controls[("cisa_scuba", "MS.AAD.5.2v1")]["status"] == "fail"
    rule = "consent_policy.user_consent_unrestricted" if policy.endswith("legacy") else "consent_policy.user_consent_limited"
    assert rule in {row.get("rule_id") for row in findings}


def test_no_user_consent_passes_cis_5_1_5_1_and_scuba_5_2() -> None:
    controls, findings = _consent_alignment([])

    assert controls[("cis_m365_v7", "5.1.5.1")]["status"] == "pass"
    assert controls[("cisa_scuba", "MS.AAD.5.2v1")]["status"] == "pass"
    assert not [row for row in findings if str(row.get("rule_id", "")).startswith("consent_policy.user_consent")]


def test_the_microsoft_managed_pair_is_limited_consent_not_a_custom_policy() -> None:
    _controls, findings = _consent_alignment(
        [
            "ManagePermissionGrantsForSelf.microsoft-user-default-recommended",
            "ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps",
        ]
    )

    rules = {row.get("rule_id") for row in findings}
    assert "consent_policy.user_consent_limited" in rules and "consent_policy.user_consent_unverified" not in rules


def test_the_legacy_guests_or_external_users_exclusion_counts_like_a_guest_type() -> None:
    policy = _policy(users=_all_users(excludeUsers=["GuestsOrExternalUsers"]))

    assert _admin(policy, scope=_scope(guests=0))["verdict"] == "enforced"
    assert _admin(policy, scope=_scope(guests=2))["verdict"] == "enforced_with_exclusions"


def _refs_resolve(snapshot: dict[str, Any], finding: dict[str, Any]) -> None:
    assert finding["evidence_refs"]
    for ref in finding["evidence_refs"]:
        section = Path(ref["artifact_path"]).stem
        keys = {row.get("key") for row in (snapshot.get(section) or {}).get("records", [])}
        assert ref["record_key"] in keys, (finding["id"], ref)


def test_findings_for_exclusions_and_administrator_mfa_cite_records_that_exist() -> None:
    policies = [
        _policy("ca-mfa", users=_all_users(excludeGroups=[ALL_STAFF])),
        _block(users=_all_users(excludeGroups=[ALL_STAFF])),
    ]
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=_payloads(policies))
    findings = {row["rule_id"]: row for row in build_findings([], normalized_snapshot=snapshot) if str(row.get("rule_id", "")).startswith("ca.")}

    assert {"ca.mfa_not_enforced", "ca.legacy_auth_not_blocked", "ca.admin_mfa_not_enforced", "ca.admin_phishing_resistant_mfa_not_enforced"} <= set(findings)
    for rule_id in ("ca.mfa_not_enforced", "ca.legacy_auth_not_blocked", "ca.admin_mfa_not_enforced"):
        _refs_resolve(snapshot, findings[rule_id])
    refs = [(ref["artifact_path"], ref["record_key"]) for ref in findings["ca.mfa_not_enforced"]["evidence_refs"]]
    assert len(refs) == len(set(refs)), "no reference is listed twice"
    assert "conditional_access_policy:ca-mfa" in {record_key for _path, record_key in refs}
