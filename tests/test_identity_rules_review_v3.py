"""Identity rules, third CE+ product review (2026-10-22): the eight confirmed findings and the service principal rule.

1. Emergency-access accounts are resolved against the full user and group lists, not the 20-row inline sample.
2. Security defaults do not pass the Conditional Access benchmark controls (CIS 5.2.2.x, SCuBA 3.2 and 1.1).
3. A country block is not the legacy-authentication block.
4. Administrator MFA is judged per administrator across every enabled policy.
5. A principal left out of every qualifying policy by a different route in each is excluded.
6. Administrator MFA must cover the benchmark role lists, not only the roles held today.
7. The administrator scope is built from the role definitions read in full.
8. A refused sign-in read gives the documented ``signin_activity_unavailable`` reason.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import baselines
from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.break_glass import resolve_accounts
from azure_tenant_audit.effective_admins import admin_scope as build_admin_scope
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.identity_controls import (
    CIS_ADMINISTRATOR_ROLES,
    SCUBA_PRIVILEGED_ROLES,
    AdminScope,
    Evidence,
    evaluate_administrator_mfa,
    evaluate_effective_mfa,
    evaluate_legacy_authentication_block,
)
from azure_tenant_audit.normalize import build_normalized_snapshot
from azure_tenant_audit.perf_runtime import EndpointAccumulator

REPO_ROOT = Path(__file__).resolve().parents[1]
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
PRIVILEGED_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"
PHISHING_RESISTANT = "00000000-0000-0000-0000-000000000004"
ALL_STAFF = "g-all-staff"
OPS = "g-ops"
STAFF = "u-staff"
ADMIN_A = "u-admin-a"
ADMIN_B = "u-admin-b"
LOOKUPS = {
    "user": {ADMIN_A: "a@example.test", ADMIN_B: "b@example.test", STAFF: "staff@example.test"},
    "group": {ALL_STAFF: "All Staff", OPS: "Ops"},
    "role": {GLOBAL_ADMIN: "Global Administrator", EXCHANGE_ADMIN: "Exchange Administrator"},
}


# --- policy and evidence builders ----------------------------------------------------------------------------


def _policy(
    policy_id: str = "ca-1",
    *,
    users: dict[str, Any] | None = None,
    grant: dict[str, Any] | None = None,
    client_app_types: list[str] | None = None,
    state: str = "enabled",
    **conditions: Any,
) -> dict[str, Any]:
    return {
        "id": policy_id,
        "displayName": f"Policy {policy_id}",
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["All"]} if users is None else users,
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["all"] if client_app_types is None else client_app_types,
            **conditions,
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]} if grant is None else grant,
    }


def _block(policy_id: str = "ca-block", **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("client_app_types", ["exchangeActiveSync", "other"])
    kwargs.setdefault("grant", {"operator": "OR", "builtInControls": ["block"]})
    return _policy(policy_id, **kwargs)


def _all_users(**exclusions: Any) -> dict[str, Any]:
    return {"includeUsers": ["All"], **exclusions}


def _roles(*roles: str, **exclusions: Any) -> dict[str, Any]:
    return {"includeRoles": list(roles), **exclusions}


def _collected(*rows: dict[str, Any]) -> Evidence:
    return Evidence("collected", tuple(rows))


def _defaults(enabled: bool = False) -> Evidence:
    return _collected({"id": "00000000-0000-0000-0000-000000000005", "isEnabled": enabled})


def _scope(
    principals: dict[str, tuple[str, ...]],
    *,
    complete: bool = True,
    groups: dict[str, tuple[str, ...]] | None = None,
    guests: tuple[str, ...] = (),
) -> AdminScope:
    roles = {principal: frozenset(held) for principal, held in principals.items()}
    return AdminScope(
        complete=complete,
        privileged_role_ids=frozenset({GLOBAL_ADMIN, EXCHANGE_ADMIN, SECURITY_ADMIN}),
        held_role_ids=frozenset(role for held in roles.values() for role in held),
        admin_principal_ids=frozenset(roles),
        guest_admin_count=len(guests),
        principal_roles=roles,
        group_members={group: frozenset(members) for group, members in (groups or {}).items()},
        guest_principal_ids=frozenset(guests),
    )


def _admin(*policies: dict[str, Any], scope: AdminScope, strengths: Evidence | None = None, **kwargs: Any) -> dict[str, Any]:
    return evaluate_administrator_mfa(
        policies=_collected(*policies),
        security_defaults=_defaults(False),
        authentication_strengths=strengths if strengths is not None else _collected(),
        lookups=LOOKUPS,
        admin_scope=scope,
        **kwargs,
    )


def _mfa(*policies: dict[str, Any], scope: AdminScope | None = None, **kwargs: Any) -> dict[str, Any]:
    return evaluate_effective_mfa(
        policies=_collected(*policies),
        security_defaults=_defaults(False),
        authentication_strengths=_collected(),
        lookups=LOOKUPS,
        admin_scope=scope,
        **kwargs,
    )


def _legacy(*policies: dict[str, Any], scope: AdminScope | None = None, **kwargs: Any) -> dict[str, Any]:
    return evaluate_legacy_authentication_block(
        policies=_collected(*policies), security_defaults=_defaults(False), lookups=LOOKUPS, admin_scope=scope, **kwargs
    )


# --- a tenant run through the real pipeline -------------------------------------------------------------------


def _write_chunk(root: Path, relative: str, rows: list[dict[str, Any]]) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return relative


def _endpoint(root: Path, name: str, rows: list[dict[str, Any]], page_size: int = 7) -> dict[str, Any]:
    """An endpoint as the collector writes it: a 20-row inline sample and the whole list in chunk files."""
    accumulator = EndpointAccumulator()
    for start in range(0, len(rows), page_size):
        page = rows[start:start + page_size]
        accumulator.add_page(page, chunk_file=_write_chunk(root, f"chunks/{name}-{start // page_size:05d}.jsonl", page))
    return accumulator.payload()


def _users(count: int = 25) -> list[dict[str, Any]]:
    people = [
        {"id": f"u-{index:03d}", "userPrincipalName": f"user{index}@example.test", "displayName": f"User {index}",
         "accountEnabled": True, "userType": "Member"}
        for index in range(count - 1)
    ]
    return [*people, {"id": "u-emergency", "userPrincipalName": "emergency@example.test", "displayName": "Emergency Access",
                      "accountEnabled": True, "userType": "Member"}]


def _groups(count: int = 25) -> list[dict[str, Any]]:
    groups = [{"id": f"g-{index:03d}", "displayName": f"Group {index}"} for index in range(count - 1)]
    return [*groups, {"id": "g-bg", "displayName": "Break Glass Group"}]


def _definitions(count_before: int = 22) -> list[dict[str, Any]]:
    """Role definitions with the roles that matter at the end of the list, beyond the inline sample."""
    fillers = [{"id": f"role-{index:03d}", "displayName": f"Filler role {index}"} for index in range(count_before)]
    return [
        *fillers,
        {"id": SECURITY_ADMIN, "displayName": "Security Administrator"},
        {"id": EXCHANGE_ADMIN, "displayName": "Exchange Administrator"},
        {"id": GLOBAL_ADMIN, "displayName": "Global Administrator"},
    ]


def _payloads(
    root: Path,
    policies: list[dict[str, Any]],
    *,
    assignments: list[tuple[str, str]] | None = None,
    users: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    defaults: bool = False,
    governance: bool = True,
    service_principals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    assigned = [("u-emergency", GLOBAL_ADMIN)] if assignments is None else assignments
    identity: dict[str, Any] = {
        "users": _endpoint(root, "users", users if users is not None else _users()),
        "groups": _endpoint(root, "groups", groups if groups is not None else _groups()),
        "roleDefinitions": _endpoint(root, "roleDefinitions", _definitions()),
        "roleAssignments": _endpoint(
            root,
            "roleAssignments",
            [{"id": f"ra-{index}", "principalId": principal, "roleDefinitionId": role} for index, (principal, role) in enumerate(assigned)],
        ),
        "servicePrincipals": _endpoint(root, "servicePrincipals", service_principals or []),
    }
    payloads: dict[str, Any] = {
        "identity": identity,
        "conditional_access": {
            "conditionalAccessPolicies": {"value": policies},
            "identitySecurityDefaultsEnforcementPolicy": {"id": "sd", "isEnabled": defaults},
            "authenticationStrengthPolicies": {"value": []},
        },
    }
    if governance:
        payloads["identity_governance"] = {
            "roleAssignmentSchedules": {"error": "license", "error_class": "license_required"},
            "roleEligibilitySchedules": {"error": "license", "error_class": "license_required"},
        }
    return payloads


COMPLETE = [
    {"collector": name, "coverage_status": "complete_exact_scope"}
    for name in ("identity", "auth_methods", "conditional_access", "consent_policy")
] + [{"collector": "identity_governance", "coverage_status": "not_applicable"}]


def _run(
    tmp_path: Path, policies: list[dict[str, Any]], *, accounts: list[str] | None = None, **kwargs: Any
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads=_payloads(tmp_path, policies, **kwargs),
        run_dir=tmp_path,
        break_glass_accounts=accounts,
    )
    findings = build_findings([], normalized_snapshot=snapshot)
    alignment = build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=COMPLETE)
    controls = {
        (framework, control["control_id"]): control
        for framework, entry in alignment["frameworks"].items()
        for control in entry["controls"]
    }
    return snapshot, findings, controls


def _verdicts(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["control"]: row for row in snapshot["identity_control_verdicts"]["records"]}


def _rules(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {row["rule_id"]: row for row in findings if row.get("rule_id")}


def _status(controls: dict[tuple[str, str], dict[str, Any]], framework: str, control_id: str) -> str:
    return controls[(framework, control_id)]["status"]


def _rule_row(controls: dict[tuple[str, str], dict[str, Any]], framework: str, control_id: str, rule_id: str) -> dict[str, Any]:
    return next(row for row in controls[(framework, control_id)]["rule_statuses"] if row["rule_id"] == rule_id)


# --- 1. emergency-access accounts beyond the inline sample -------------------------------------------------------


@pytest.mark.parametrize("entry", ["emergency@example.test", "u-emergency", "Emergency Access"])
def test_an_emergency_account_beyond_the_inline_sample_is_found_by_upn_object_id_or_display_name(tmp_path: Path, entry: str) -> None:
    policy = _policy(users=_all_users(excludeUsers=["u-emergency"]))

    snapshot, findings, controls = _run(tmp_path, [policy], accounts=[entry])

    users = snapshot["users"]["records"]
    assert len(users) == 25, "the whole list was read"
    verdicts = _verdicts(snapshot)
    assert verdicts["effective_mfa"]["verdict"] == "enforced"
    assert verdicts["administrator_mfa"]["verdict"] == "enforced"
    assert verdicts["effective_mfa"]["sanctioned_exclusion_source"] == "operator"
    assert not verdicts["effective_mfa"].get("unresolved_operator_accounts")
    assessment = snapshot["break_glass_assessment"]["records"][0]
    assert assessment["state"] == "assessed" and assessment["account_count"] == 1
    assert assessment["policies_missing_exclusion"] == 0
    assert not {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced"} & set(_rules(findings))
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "pass"
    assert _status(controls, "cis_m365_v7", "5.2.2.2") == "pass"


def test_an_emergency_group_beyond_the_inline_sample_is_found_by_display_name(tmp_path: Path) -> None:
    policy = _policy(users=_all_users(excludeGroups=["g-bg"]))

    snapshot, _findings, _controls = _run(tmp_path, [policy], accounts=["Break Glass Group"])

    assert _verdicts(snapshot)["effective_mfa"]["verdict"] == "enforced"
    assert snapshot["break_glass_assessment"]["records"][0]["accounts"] == ["Break Glass Group"]


def test_the_same_policy_without_the_operator_list_is_still_a_gap(tmp_path: Path) -> None:
    snapshot, findings, _controls = _run(tmp_path, [_policy(users=_all_users(excludeUsers=["u-emergency"]))])

    verdicts = _verdicts(snapshot)
    assert verdicts["effective_mfa"]["verdict"] == "enforced_with_exclusions"
    assert verdicts["administrator_mfa"]["verdict"] == "not_enforced"
    assert {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced"} <= set(_rules(findings))


def test_an_entry_that_matches_nothing_is_recorded_and_named_in_the_findings_not_dropped(tmp_path: Path) -> None:
    policy = _policy(users=_all_users(excludeUsers=["u-emergency"]))

    snapshot, findings, _controls = _run(tmp_path, [policy], accounts=["emergency@example.test", "typo@example.test"])

    assessment = snapshot["break_glass_assessment"]["records"][0]
    assert assessment["state"] == "assessed"
    assert assessment["unresolved_accounts"] == ["typo@example.test"]
    assert assessment["unresolved_account_details"] == [{"entry": "typo@example.test", "reason": "not_found"}]
    verdict = _verdicts(snapshot)["effective_mfa"]
    assert verdict["verdict"] == "enforced" and verdict["unresolved_operator_accounts"] == ["typo@example.test"]


def test_a_list_that_resolves_to_nothing_leaves_the_exclusion_a_gap_and_the_finding_says_why(tmp_path: Path) -> None:
    policy = _policy(users=_all_users(excludeUsers=["u-emergency"]))

    snapshot, findings, _controls = _run(tmp_path, [policy], accounts=["typo@example.test"])

    assessment = snapshot["break_glass_assessment"]["records"][0]
    assert assessment["state"] == "operator_accounts_unresolved"
    finding = _rules(findings)["ca.mfa_not_enforced"]
    assert finding["returned_value"]["unresolved_operator_accounts"] == ["typo@example.test"]
    assert "typo@example.test" in finding["description"]
    admin = _rules(findings)["ca.admin_mfa_not_enforced"]
    assert "typo@example.test" in admin["description"]


def test_the_break_glass_finding_names_the_entries_it_could_not_resolve(tmp_path: Path) -> None:
    # One enabled MFA policy that excludes neither account: the check flags it, and says what it could not resolve.
    snapshot, findings, _controls = _run(tmp_path, [_policy()], accounts=["emergency@example.test", "typo@example.test"])

    finding = _rules(findings)["ca.break_glass_exclusion_missing"]
    assert finding["returned_value"]["unresolved_accounts"] == ["typo@example.test"]
    assert finding["evidence"]["unresolved_account_details"] == [{"entry": "typo@example.test", "reason": "not_found"}]
    assert "typo@example.test" in finding["description"]


def test_a_display_name_that_two_accounts_share_is_ambiguous_and_not_guessed() -> None:
    users = [{"id": f"u-{index}", "userPrincipalName": f"x{index}@example.test", "displayName": "Emergency Access"} for index in (1, 2)]

    accounts = resolve_accounts(
        ["Emergency Access"], users=users, groups=[], role_assignments=[], role_definitions=[]
    )

    assert accounts.unresolved == ["Emergency Access"]
    assert accounts.unresolved_detail == [{"entry": "Emergency Access", "reason": "ambiguous_display_name"}]
    assert accounts.ids == set() and accounts.state == "operator_accounts_unresolved"


def test_an_object_id_that_is_not_in_the_directory_read_is_honoured_and_listed_as_unverified() -> None:
    accounts = resolve_accounts(
        ["11111111-2222-3333-4444-555555555555"], users=[], groups=[], role_assignments=[], role_definitions=[]
    )

    assert accounts.ids == {"11111111-2222-3333-4444-555555555555"}
    assert accounts.unverified == ["11111111-2222-3333-4444-555555555555"] and accounts.unresolved == []


# --- 2. security defaults alone do not pass the Conditional Access benchmark controls ---------------------------


def test_security_defaults_keep_the_verdicts_but_not_the_conditional_access_benchmark_controls(tmp_path: Path) -> None:
    snapshot, findings, controls = _run(tmp_path, [], defaults=True)

    verdicts = _verdicts(snapshot)
    assert verdicts["effective_mfa"]["verdict"] == "enforced" and verdicts["effective_mfa"]["basis"] == ["security_defaults"]
    assert verdicts["administrator_mfa"]["verdict"] == "enforced"
    assert verdicts["legacy_authentication_block"]["verdict"] == "blocked"
    for framework, control_id, rule_id in (
        ("cis_m365_v7", "5.2.2.1", "ca.admin_mfa_not_enforced"),
        ("cis_m365_v7", "5.2.2.2", "ca.mfa_not_enforced"),
        ("cis_m365_v7", "5.2.2.3", "ca.legacy_auth_not_blocked"),
        ("cisa_scuba", "MS.AAD.3.2v1", "ca.mfa_not_enforced"),
        ("cisa_scuba", "MS.AAD.1.1v1", "ca.legacy_auth_not_blocked"),
    ):
        assert _status(controls, framework, control_id) != "pass", (framework, control_id)
        assert _rule_row(controls, framework, control_id, rule_id) == {
            "rule_id": rule_id,
            "status": "not_assessed",
            "evaluated": False,
            "reason": "conditional_access_policy_required:basis_security_defaults",
        }
    assert not {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced", "ca.legacy_auth_not_blocked"} & set(_rules(findings))


def test_security_defaults_still_count_for_cyber_essentials_zero_trust_and_secure_score(tmp_path: Path) -> None:
    _snapshot, _findings, controls = _run(tmp_path, [], defaults=True)

    assert _rule_row(controls, "cyber_essentials", "ce.uac.mfa_admin_accounts", "ca.admin_mfa_not_enforced")["status"] == "pass"
    assert _rule_row(controls, "cyber_essentials", "ce.uac.mfa_cloud_services", "ca.mfa_not_enforced")["status"] == "pass"
    assert _status(controls, "ms_secure_score", "AdminMFAV2") == "pass"
    assert _status(controls, "ms_secure_score", "BlockLegacyAuthentication") == "pass"
    assert _rule_row(controls, "ms_zero_trust", "identities", "ca.mfa_not_enforced")["status"] == "pass"


def test_a_qualifying_conditional_access_policy_passes_the_benchmark_controls(tmp_path: Path) -> None:
    _snapshot, _findings, controls = _run(tmp_path, [_policy(), _block()])

    for framework, control_id in (
        ("cis_m365_v7", "5.2.2.1"),
        ("cis_m365_v7", "5.2.2.2"),
        ("cis_m365_v7", "5.2.2.3"),
        ("cisa_scuba", "MS.AAD.3.2v1"),
        ("cisa_scuba", "MS.AAD.1.1v1"),
    ):
        assert _status(controls, framework, control_id) == "pass", (framework, control_id)


def test_the_basis_requirements_name_real_rules_and_benchmark_controls() -> None:
    mappings = json.loads((REPO_ROOT / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
    requirements = baselines._shipped_verdict_basis_requirements()

    assert set(requirements) == {"ca.mfa_not_enforced", "ca.admin_mfa_not_enforced", "ca.legacy_auth_not_blocked"}
    for rule_id, spec in requirements.items():
        for framework, controls in spec["frameworks"].items():
            assert framework in {"cis_m365_v7", "cisa_scuba"}, "Cyber Essentials, Zero Trust and Secure Score keep reading the verdict"
            assert set(controls) <= set(mappings[rule_id][framework]), (rule_id, framework)


# --- 3. a country block is not the legacy-authentication block -----------------------------------------------


def test_a_country_block_is_not_a_legacy_authentication_block() -> None:
    geo = _policy(
        "geo",
        grant={"operator": "OR", "builtInControls": ["block"]},
        locations={"includeLocations": ["All"], "excludeLocations": ["loc-uk"]},
    )

    verdict = _legacy(geo)

    assert verdict["verdict"] == "not_blocked"
    assert verdict["blocking_policies"] == []
    assert set(verdict["non_qualifying_block_policies"][0]["reasons"]) == {"legacy_client_app_types_not_targeted", "excludes_locations"}


def test_a_legacy_block_that_exempts_a_location_or_is_limited_to_one_does_not_block() -> None:
    exempt = _block("office", locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})
    limited = _block("ru", locations={"includeLocations": ["loc-ru"]})

    assert _legacy(exempt)["non_qualifying_block_policies"][0]["reasons"] == ["excludes_locations"]
    assert _legacy(limited)["non_qualifying_block_policies"][0]["reasons"] == ["narrowed_by_location"]
    assert _legacy(exempt, limited)["verdict"] == "not_blocked"


def test_a_legacy_block_that_names_both_legacy_client_types_with_no_location_still_blocks() -> None:
    verdict = _legacy(_block(locations={"includeLocations": ["All"]}))

    assert verdict["verdict"] == "blocked" and verdict["basis"] == ["conditional_access_policy"]


def test_a_country_block_fails_the_legacy_authentication_controls_through_the_pipeline(tmp_path: Path) -> None:
    geo = _policy(
        "geo",
        grant={"operator": "OR", "builtInControls": ["block"]},
        locations={"includeLocations": ["All"], "excludeLocations": ["loc-uk"]},
    )

    snapshot, findings, controls = _run(tmp_path, [_policy(), geo])

    assert _verdicts(snapshot)["legacy_authentication_block"]["verdict"] == "not_blocked"
    assert _rules(findings)["ca.legacy_auth_not_blocked"]["severity"] == "high"
    for framework, control_id in (("cis_m365_v7", "5.2.2.3"), ("cisa_scuba", "MS.AAD.1.1v1"), ("ms_secure_score", "BlockLegacyAuthentication")):
        assert _status(controls, framework, control_id) == "fail", (framework, control_id)


# --- 4. administrator MFA is judged per administrator across every enabled policy -----------------------------


def _two_admins(**kwargs: Any) -> AdminScope:
    return _scope({ADMIN_A: (GLOBAL_ADMIN,), ADMIN_B: (EXCHANGE_ADMIN,)}, **kwargs)


def test_a_role_policy_covers_the_role_an_all_users_policy_excludes() -> None:
    everyone_but_ga = _policy("all", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    ga_only = _policy("ga", users=_roles(GLOBAL_ADMIN))

    verdict = _admin(everyone_but_ga, ga_only, scope=_two_admins())

    assert verdict["verdict"] == "enforced"
    assert verdict["basis"] == ["conditional_access_policy"]
    assert [row["id"] for row in verdict["qualifying_policies"]] == ["all"]
    assert [row["id"] for row in verdict["supplementary_policies"]] == ["ga"]
    assert verdict["non_qualifying_mfa_policies"][0]["reasons"] == ["covers_only_some_administrator_roles"]
    assert verdict["administrator_exclusions"] == []


def test_the_role_policy_is_judged_the_same_when_the_administrator_set_is_incomplete() -> None:
    everyone_but_ga = _policy("all", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    ga_only = _policy("ga", users=_roles(GLOBAL_ADMIN))

    verdict = _admin(everyone_but_ga, ga_only, scope=_two_admins(complete=False))

    assert verdict["verdict"] == "enforced", "every holder of the excluded role is reached by the policy that includes it"
    assert [row["id"] for row in verdict["unverified_policies"]] == ["ga"]


def test_an_administrator_no_other_policy_reaches_is_still_not_enforced() -> None:
    everyone_but_ga = _policy("all", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    exchange_only = _policy("exchange", users=_roles(EXCHANGE_ADMIN))

    verdict = _admin(everyone_but_ga, exchange_only, scope=_two_admins())

    assert verdict["verdict"] == "not_enforced"
    assert [row["id"] for row in verdict["administrator_exclusions"]] == [GLOBAL_ADMIN]


def test_the_policy_that_could_cover_an_excluded_role_cannot_be_verified_so_the_verdict_is_unknown() -> None:
    everyone_but_ga = _policy("all", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    unrated = _policy(
        "ga",
        users=_roles(GLOBAL_ADMIN),
        grant={"operator": "OR", "authenticationStrength": {"id": "custom-strength", "displayName": "Custom"}},
    )

    verdict = _admin(everyone_but_ga, unrated, scope=_two_admins())

    assert verdict["verdict"] == "unknown"
    assert verdict["reasons"] == ["authentication_strength_unverified"]


def test_several_role_policies_that_each_reach_some_administrators_cover_them_together() -> None:
    ga_only = _policy("ga", users=_roles(GLOBAL_ADMIN))
    exchange_only = _policy("exchange", users=_roles(EXCHANGE_ADMIN))

    verdict = _admin(ga_only, exchange_only, scope=_two_admins())

    assert verdict["verdict"] == "enforced"
    assert verdict["qualifying_policies"] == []
    assert verdict["basis"] == ["conditional_access_policy"]
    assert {row["id"] for row in verdict["supplementary_policies"]} == {"ga", "exchange"}


def test_role_policies_leave_an_administrator_with_another_role_uncovered() -> None:
    scope = _scope({ADMIN_A: (GLOBAL_ADMIN,), ADMIN_B: (EXCHANGE_ADMIN,), "u-admin-c": (SECURITY_ADMIN,)})

    verdict = _admin(_policy("ga", users=_roles(GLOBAL_ADMIN)), _policy("exchange", users=_roles(EXCHANGE_ADMIN)), scope=scope)

    assert verdict["verdict"] == "not_enforced"


def test_an_excluded_role_policy_does_not_cover_an_administrator_who_also_holds_the_excluded_role() -> None:
    scope = _scope({ADMIN_A: (GLOBAL_ADMIN, EXCHANGE_ADMIN)})
    includes_both_excludes_ga = _policy("mixed", users=_roles(GLOBAL_ADMIN, EXCHANGE_ADMIN, excludeRoles=[GLOBAL_ADMIN]))

    verdict = _admin(includes_both_excludes_ga, scope=scope)

    assert verdict["verdict"] == "not_enforced", "exclusion wins over inclusion"


def test_a_covering_policy_that_excludes_an_unread_group_leaves_the_verdict_unknown() -> None:
    everyone_but_ga = _policy("all", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    ga_but_not_ops = _policy("ga", users=_roles(GLOBAL_ADMIN, excludeGroups=[OPS]))

    verdict = _admin(everyone_but_ga, ga_but_not_ops, scope=_two_admins())

    assert verdict["verdict"] == "unknown" and verdict["reasons"] == ["administrator_exclusion_unresolved"]
    # An emergency group the operator listed is not that kind of doubt.
    assert _admin(everyone_but_ga, ga_but_not_ops, scope=_two_admins(), sanctioned=frozenset({OPS}))["verdict"] == "enforced"


def test_the_ga_role_split_through_the_pipeline_keeps_every_mfa_control_passing(tmp_path: Path) -> None:
    everyone_but_ga = _policy("all", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    ga_only = _policy("ga", users=_roles(GLOBAL_ADMIN))

    snapshot, findings, controls = _run(
        tmp_path,
        [everyone_but_ga, ga_only],
        assignments=[("u-emergency", GLOBAL_ADMIN), ("u-000", EXCHANGE_ADMIN)],
    )

    verdicts = _verdicts(snapshot)
    assert verdicts["administrator_mfa"]["verdict"] == "enforced"
    assert "ca.admin_mfa_not_enforced" not in _rules(findings)
    assert _rule_row(controls, "cyber_essentials", "ce.uac.mfa_admin_accounts", "ca.admin_mfa_not_enforced")["status"] == "pass"
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "pass"
    assert _status(controls, "ms_secure_score", "AdminMFAV2") == "pass"


# --- 5. a principal excluded by a different route in each policy -----------------------------------------------


def test_a_user_excluded_by_id_in_one_policy_and_through_a_role_in_another_is_excluded() -> None:
    by_id = _policy("by-id", users=_all_users(excludeUsers=[ADMIN_A]))
    by_role = _policy("by-role", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))
    scope = _two_admins()

    mfa = _mfa(by_id, by_role, scope=scope)
    admin = _admin(by_id, by_role, scope=scope)

    assert mfa["verdict"] == "enforced_with_exclusions"
    [row] = mfa["unsanctioned_exclusions"]
    assert row["type"] == "user" and row["id"] == ADMIN_A and row["display_name"] == "a@example.test"
    assert row["via"] == [
        {"policy_id": "by-id", "type": "user", "id": ADMIN_A},
        {"policy_id": "by-role", "type": "role", "id": GLOBAL_ADMIN},
    ]
    assert admin["verdict"] == "not_enforced"
    assert [row["id"] for row in admin["administrator_exclusions"]] == [ADMIN_A]


def test_without_the_administrator_scope_the_routes_cannot_be_compared() -> None:
    by_id = _policy("by-id", users=_all_users(excludeUsers=[ADMIN_A]))
    by_role = _policy("by-role", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))

    assert _mfa(by_id, by_role)["verdict"] == "enforced"


def test_a_user_excluded_by_id_and_through_a_role_assignable_group_is_excluded() -> None:
    by_id = _policy("by-id", users=_all_users(excludeUsers=[STAFF]))
    by_group = _policy("by-group", users=_all_users(excludeGroups=[OPS]))
    scope = _two_admins(groups={OPS: (STAFF,)})

    mfa = _mfa(by_id, by_group, scope=scope)
    legacy = _legacy(_block("block-id", users=_all_users(excludeUsers=[STAFF])), _block("block-group", users=_all_users(excludeGroups=[OPS])), scope=scope)

    assert mfa["verdict"] == "enforced_with_exclusions" and [row["id"] for row in mfa["unsanctioned_exclusions"]] == [STAFF]
    assert legacy["verdict"] == "blocked_with_exclusions" and [row["id"] for row in legacy["unsanctioned_exclusions"]] == [STAFF]
    # A staff member who is not an administrator does not change the administrator verdict.
    assert _admin(by_id, by_group, scope=scope)["verdict"] == "enforced"


def test_nested_group_members_count_and_so_do_two_groups_that_share_a_member() -> None:
    first = _policy("first", users=_all_users(excludeGroups=["g-outer"]))
    second = _policy("second", users=_all_users(excludeGroups=[OPS]))
    scope = _two_admins(groups={"g-outer": ("g-inner",), "g-inner": (STAFF,), OPS: (STAFF, ADMIN_B)})

    verdict = _mfa(first, second, scope=scope)

    assert [row["id"] for row in verdict["unsanctioned_exclusions"]] == [STAFF]


def test_a_member_of_the_emergency_group_the_operator_listed_is_sanctioned_whatever_the_route() -> None:
    by_id = _policy("by-id", users=_all_users(excludeUsers=[STAFF]))
    by_group = _policy("by-group", users=_all_users(excludeGroups=[OPS]))
    scope = _two_admins(groups={OPS: (STAFF,)})

    assert _mfa(by_id, by_group, scope=scope, sanctioned=frozenset({OPS}))["verdict"] == "enforced"
    assert _mfa(by_id, by_group, scope=scope, sanctioned=frozenset({STAFF}))["verdict"] == "enforced"


def test_exclusions_one_policy_makes_alone_are_not_common_to_both() -> None:
    first = _policy("first", users=_all_users(excludeUsers=[STAFF]))
    second = _policy("second", users=_all_users(excludeGroups=[OPS]))

    assert _mfa(first, second, scope=_two_admins(groups={OPS: (ADMIN_B,)}))["verdict"] == "enforced"


def test_group_members_the_run_read_decide_who_a_group_exclusion_leaves_out_through_the_pipeline(tmp_path: Path) -> None:
    by_id = _policy("by-id", users=_all_users(excludeUsers=["u-001"]))
    by_group = _policy("by-group", users=_all_users(excludeGroups=["g-ops"]))
    block_id = _block("block-id", users=_all_users(excludeUsers=["u-001"]))
    block_group = _block("block-group", users=_all_users(excludeGroups=["g-ops"]))
    payloads = _payloads(tmp_path, [by_id, by_group, block_id, block_group])
    payloads["identity"]["roleAssignableGroupMembers"] = {
        "value": [{"groupId": "g-ops", "displayName": "Ops", "members": [{"id": "u-001", "displayName": "User 1"}]}],
        "fanout": {"fanout_complete": True},
    }

    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=payloads, run_dir=tmp_path)

    verdicts = _verdicts(snapshot)
    # The MFA policies and the block policies are mixed on purpose: each verdict judges its own qualifying policies.
    assert verdicts["effective_mfa"]["verdict"] == "enforced_with_exclusions"
    [row] = verdicts["effective_mfa"]["unsanctioned_exclusions"]
    assert row["id"] == "u-001" and row["display_name"] == "user1@example.test"
    assert sorted(row["via"], key=lambda item: item["policy_id"]) == [
        {"policy_id": "by-group", "type": "group", "id": "g-ops"},
        {"policy_id": "by-id", "type": "user", "id": "u-001"},
    ]
    assert verdicts["legacy_authentication_block"]["verdict"] == "blocked_with_exclusions"
    assert [item["id"] for item in verdicts["legacy_authentication_block"]["unsanctioned_exclusions"]] == ["u-001"]
    assert verdicts["administrator_mfa"]["verdict"] == "enforced", "u-001 is not an administrator"


def test_two_policies_that_leave_an_administrator_out_by_different_routes_fail_the_mfa_controls(tmp_path: Path) -> None:
    by_id = _policy("by-id", users=_all_users(excludeUsers=["u-emergency"]))
    by_role = _policy("by-role", users=_all_users(excludeRoles=[GLOBAL_ADMIN]))

    snapshot, findings, controls = _run(tmp_path, [by_id, by_role])

    verdicts = _verdicts(snapshot)
    assert verdicts["effective_mfa"]["verdict"] == "enforced_with_exclusions"
    assert verdicts["administrator_mfa"]["verdict"] == "not_enforced"
    assert _rules(findings)["ca.admin_mfa_not_enforced"]["severity"] == "high"
    for framework, control_id in (("cis_m365_v7", "5.2.2.1"), ("cis_m365_v7", "5.2.2.2"), ("cisa_scuba", "MS.AAD.3.2v1"), ("ms_secure_score", "AdminMFAV2")):
        assert _status(controls, framework, control_id) == "fail", (framework, control_id)


# --- 6. the benchmark role lists, not only the roles held today ----------------------------------------------------


def test_the_catalogs_are_the_benchmark_role_lists_by_template_id() -> None:
    assert len(CIS_ADMINISTRATOR_ROLES) == 15 and len(SCUBA_PRIVILEGED_ROLES) == 8
    assert GLOBAL_ADMIN in CIS_ADMINISTRATOR_ROLES and PRIVILEGED_ROLE_ADMIN in SCUBA_PRIVILEGED_ROLES
    assert CIS_ADMINISTRATOR_ROLES["f2ef992c-3afb-46b9-b7cf-a126ee74c451"] == "Global Reader"
    assert SCUBA_PRIVILEGED_ROLES["8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"] == "Hybrid Identity Administrator"
    assert all(role == role.lower() for role in (*CIS_ADMINISTRATOR_ROLES, *SCUBA_PRIVILEGED_ROLES))


def test_a_role_policy_for_the_roles_held_today_is_enforced_but_not_the_whole_role_list() -> None:
    held_only = _policy(users=_roles(GLOBAL_ADMIN))

    verdict = _admin(held_only, scope=_scope({ADMIN_A: (GLOBAL_ADMIN,)}))

    assert verdict["verdict"] == "enforced", "Cyber Essentials reads the administrators there are"
    assert verdict["role_catalog_verdict"] == "not_enforced"
    uncovered = {row["id"]: row for row in verdict["role_catalog_uncovered_roles"]}
    assert set(uncovered) == set(CIS_ADMINISTRATOR_ROLES) - {GLOBAL_ADMIN}
    assert {row["reason"] for row in uncovered.values()} == {"not_included"}
    assert uncovered[EXCHANGE_ADMIN]["name"] == "Exchange Administrator"


def test_an_all_users_policy_that_excludes_a_role_nobody_holds_does_not_cover_the_role_list() -> None:
    verdict = _admin(_policy(users=_all_users(excludeRoles=[EXCHANGE_ADMIN])), scope=_scope({ADMIN_A: (GLOBAL_ADMIN,)}))

    assert verdict["verdict"] == "enforced"
    assert verdict["role_catalog_verdict"] == "not_enforced"
    assert verdict["role_catalog_uncovered_roles"] == [{"id": EXCHANGE_ADMIN, "name": "Exchange Administrator", "reason": "excluded"}]


def test_policies_that_cover_every_role_of_the_list_cover_it_whoever_holds_them() -> None:
    scope = _scope({ADMIN_A: (GLOBAL_ADMIN,)})
    every_role = _policy("every", users=_roles(*CIS_ADMINISTRATOR_ROLES))
    split = [
        _policy("first", users=_roles(*list(CIS_ADMINISTRATOR_ROLES)[:7])),
        _policy("second", users=_roles(*list(CIS_ADMINISTRATOR_ROLES)[7:])),
    ]

    assert _admin(_policy(), scope=scope)["role_catalog_verdict"] == "enforced"
    assert _admin(every_role, scope=scope)["role_catalog_verdict"] == "enforced"
    assert _admin(*split, scope=scope)["role_catalog_verdict"] == "enforced"


def test_a_role_only_a_policy_that_cannot_be_verified_covers_leaves_the_role_list_unknown() -> None:
    unrated = {"operator": "OR", "authenticationStrength": {"id": "custom-strength", "displayName": "Custom"}}

    verdict = _admin(_policy(), _policy("unrated", users=_roles(*CIS_ADMINISTRATOR_ROLES), grant=unrated), scope=_scope({ADMIN_A: (GLOBAL_ADMIN,)}))

    assert verdict["role_catalog_verdict"] == "enforced", "the all-users policy covers every role by itself"
    only_unrated = _admin(
        _policy("excludes", users=_all_users(excludeRoles=[EXCHANGE_ADMIN])),
        _policy("unrated", users=_roles(*CIS_ADMINISTRATOR_ROLES), grant=unrated),
        scope=_scope({ADMIN_A: (GLOBAL_ADMIN,)}),
    )
    assert only_unrated["role_catalog_verdict"] == "unknown"


def test_security_defaults_cover_every_administrator_role_but_not_a_phishing_resistant_method() -> None:
    verdict = evaluate_administrator_mfa(
        policies=_collected(),
        security_defaults=_defaults(True),
        authentication_strengths=_collected(),
        lookups=LOOKUPS,
        admin_scope=_scope({ADMIN_A: (GLOBAL_ADMIN,)}),
    )

    assert verdict["role_catalog_verdict"] == "enforced"
    assert verdict["phishing_resistant_verdict"] == "not_enforced"
    assert verdict["phishing_resistant_role_catalog_verdict"] == "not_enforced"


def test_the_phishing_resistant_reading_uses_scubas_privileged_roles() -> None:
    resistant = {"operator": "AND", "authenticationStrength": {"id": PHISHING_RESISTANT, "displayName": "Phishing-resistant MFA"}}
    scope = _scope({ADMIN_A: (GLOBAL_ADMIN,)})

    held_only = _admin(_policy(users=_roles(GLOBAL_ADMIN), grant=resistant), scope=scope)
    everyone = _admin(_policy(grant=resistant), scope=scope)
    excluding_scuba_role = _admin(_policy(users=_all_users(excludeRoles=[EXCHANGE_ADMIN]), grant=resistant), scope=scope)
    scuba_roles = _admin(_policy(users=_roles(*SCUBA_PRIVILEGED_ROLES), grant=resistant), scope=scope)

    assert held_only["phishing_resistant_verdict"] == "enforced"
    assert held_only["phishing_resistant_role_catalog_verdict"] == "not_enforced"
    assert everyone["phishing_resistant_role_catalog_verdict"] == "enforced"
    assert excluding_scuba_role["phishing_resistant_role_catalog_verdict"] == "not_enforced"
    assert scuba_roles["phishing_resistant_role_catalog_verdict"] == "enforced"
    # The CIS list is judged over every MFA policy, the resistant list over the resistant ones only.
    assert _admin(_policy(), _policy("resistant", users=_roles(*SCUBA_PRIVILEGED_ROLES), grant=resistant), scope=scope)[
        "phishing_resistant_role_catalog_verdict"
    ] == "enforced"


def test_a_policy_for_the_held_roles_only_fails_cis_and_scuba_but_not_cyber_essentials(tmp_path: Path) -> None:
    resistant = {"operator": "AND", "authenticationStrength": {"id": PHISHING_RESISTANT, "displayName": "Phishing-resistant MFA"}}
    held_only = _policy("held", users=_roles(GLOBAL_ADMIN), grant=resistant)

    snapshot, findings, controls = _run(tmp_path, [_policy("everyone"), held_only])

    assert _verdicts(snapshot)["administrator_mfa"]["verdict"] == "enforced"
    rules = _rules(findings)
    assert "ca.admin_mfa_not_enforced" not in rules
    # Every user is required to use MFA by the all-users policy, so the CIS list is covered; the resistant policy is not.
    assert "ca.admin_mfa_role_set_incomplete" not in rules
    finding = rules["ca.admin_phishing_resistant_mfa_not_enforced"]
    assert finding["severity"] == "low"
    assert finding["returned_value"]["phishing_resistant_role_catalog_verdict"] == "not_enforced"
    assert "ScubaGear" in finding["description"] and "Exchange Administrator" in finding["description"]
    assert _status(controls, "cisa_scuba", "MS.AAD.3.6v1") == "fail"
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "pass"
    assert _rule_row(controls, "cyber_essentials", "ce.uac.mfa_admin_accounts", "ca.admin_mfa_not_enforced")["status"] == "pass"


def test_a_role_policy_for_the_held_roles_only_fails_cis_5_2_2_1_through_the_pipeline(tmp_path: Path) -> None:
    held_only = _policy("held", users=_roles(GLOBAL_ADMIN))

    snapshot, findings, controls = _run(tmp_path, [held_only])

    assert _verdicts(snapshot)["administrator_mfa"]["verdict"] == "enforced"
    finding = _rules(findings)["ca.admin_mfa_role_set_incomplete"]
    assert finding["severity"] == "medium"
    assert finding["returned_value"]["role_catalog_verdict"] == "not_enforced"
    assert {row["id"] for row in finding["returned_value"]["uncovered_roles"]} == set(CIS_ADMINISTRATOR_ROLES) - {GLOBAL_ADMIN}
    assert "ca.admin_mfa_not_enforced" not in _rules(findings)
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "fail"
    assert "ca.admin_mfa_role_set_incomplete" in controls[("cis_m365_v7", "5.2.2.1")]["rule_ids"]
    # The rule maps to the benchmark, not to Cyber Essentials, whose row reads the roles held today.
    assert finding["framework_mappings"]["cis_m365_v7"] == ["5.2.2.1"]
    assert "cyber_essentials" not in finding["framework_mappings"] and "ms_secure_score" not in finding["framework_mappings"]
    assert _rule_row(controls, "cyber_essentials", "ce.uac.mfa_admin_accounts", "ca.admin_mfa_not_enforced")["status"] == "pass"
    assert _status(controls, "ms_secure_score", "AdminMFAV2") == "pass"


def test_an_all_users_policy_that_excludes_a_role_nobody_holds_fails_the_role_list_through_the_pipeline(tmp_path: Path) -> None:
    policy = _policy(users=_all_users(excludeRoles=[SECURITY_ADMIN]))

    snapshot, findings, controls = _run(tmp_path, [policy], assignments=[("u-emergency", GLOBAL_ADMIN)])

    assert _verdicts(snapshot)["administrator_mfa"]["verdict"] == "enforced"
    finding = _rules(findings)["ca.admin_mfa_role_set_incomplete"]
    assert finding["returned_value"]["uncovered_roles"] == [{"id": SECURITY_ADMIN, "name": "Security Administrator", "reason": "excluded"}]
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "fail"


def test_an_all_users_policy_with_no_exclusions_raises_no_role_set_finding(tmp_path: Path) -> None:
    _snapshot, findings, controls = _run(tmp_path, [_policy()])

    assert "ca.admin_mfa_role_set_incomplete" not in _rules(findings)
    assert _status(controls, "cis_m365_v7", "5.2.2.1") == "pass"


def test_the_role_set_rule_reads_not_assessed_while_administrator_mfa_is_unknown(tmp_path: Path) -> None:
    payloads = _payloads(tmp_path, [_policy(users=_roles(GLOBAL_ADMIN))], governance=False)
    del payloads["identity"]["roleAssignments"]
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads=payloads, run_dir=tmp_path)
    findings = build_findings([], normalized_snapshot=snapshot)

    assert _verdicts(snapshot)["administrator_mfa"]["verdict"] == "unknown"
    assert _verdicts(snapshot)["administrator_mfa"]["role_catalog_verdict"] == "unknown"
    assert "ca.admin_mfa_role_set_incomplete" not in _rules(findings)
    row = baselines._rule_evaluation("ca.admin_mfa_role_set_incomplete", {}, {}, {"conditional_access"}, snapshot)
    assert row["status"] == "not_assessed" and row["reason"] == "verdict_unknown:administrator_mfa"


# --- 7. the administrator scope is built from the role definitions read in full ----------------------------------------


def test_an_excluded_administrator_role_beyond_the_inline_sample_is_privileged_when_the_set_is_unknown(tmp_path: Path) -> None:
    policy = _policy(users=_all_users(excludeRoles=[SECURITY_ADMIN]))

    snapshot, findings, _controls = _run(
        tmp_path, [policy], assignments=[("u-000", SECURITY_ADMIN), ("u-emergency", GLOBAL_ADMIN)], governance=False
    )

    summary = next(row for row in snapshot["effective_admin_set"]["records"] if row["kind"] == "effective_admin_set_summary")
    assert summary["state"] == "unknown", "PIM was not read"
    assert len(snapshot["role_definitions"]["records"]) == 25
    verdict = _verdicts(snapshot)["administrator_mfa"]
    assert verdict["verdict"] == "not_enforced", "Security Administrator is an administrator role by name, read from the full list"
    assert _rules(findings)["ca.admin_mfa_not_enforced"]["severity"] == "high"


def test_the_admin_scope_reads_the_normalized_role_definitions_by_name() -> None:
    records = [
        {"kind": "effective_admin_set_summary", "state": "unknown", "guest_admin_count": 0},
        {"kind": "effective_admin", "principal_id": "U-1", "counted": True, "enabled": True,
         "roles": [{"role_definition_id": SECURITY_ADMIN}], "is_guest": False},
    ]
    definitions = [{"id": SECURITY_ADMIN, "display_name": "Security Administrator"}, {"id": "other", "display_name": "Reader"}]

    scope = build_admin_scope(records, definitions, [{"relationship": "member", "group_id": "G-1", "member_id": "U-1"}])

    assert scope is not None
    assert scope.privileged_role_ids == frozenset({SECURITY_ADMIN})
    assert scope.principal_roles == {"u-1": frozenset({SECURITY_ADMIN})}
    assert scope.group_members == {"g-1": frozenset({"u-1"})}
    # Raw Graph rows carry displayName, not display_name: the old call site's input was never privileged by name.
    assert build_admin_scope(records, [{"id": SECURITY_ADMIN, "displayName": "Security Administrator"}]).privileged_role_ids == frozenset()


def test_the_identity_collector_reads_the_directory_scope_of_each_role_assignment(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit.collectors import identity as identity_module

    seen: dict[str, Any] = {}

    def fake_run(name: str, client: Any, selectors: dict[str, Any], **kwargs: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        seen.update(selectors)
        return {}, []

    monkeypatch.setattr(identity_module, "run_graph_endpoints", fake_run)
    monkeypatch.setattr(identity_module.IdentityCollector, "_privileged_group_relations", lambda self, *args, **kwargs: {})

    identity_module.IdentityCollector().run({"client": object()})

    assert "directoryScopeId" in seen["roleAssignments"]["params"]["$select"].split(",")


# --- 8. a refused sign-in read gives the documented reason -----------------------------------------------------------


def test_a_licence_limited_identity_run_reads_the_sign_in_rules_not_assessed_with_the_documented_reason() -> None:
    summary = {"kind": "effective_admin_set_summary", "key": "effective_admin_set_summary:summary", "state": "complete", "licence_state": "known"}
    admin = {"kind": "effective_admin", "principal_id": "ga-1", "counted": True, "key": "effective_admin:ga-1"}
    users = [
        {"id": "ga-1", "enabled": True, "user_type": "member", "signin_data_available": None},
        {"id": "g-1", "enabled": True, "user_type": "guest", "signin_data_available": None},
    ]
    snapshot = {"effective_admin_set": {"records": [summary, admin]}, "users": {"records": users}}
    diagnostics = [{"collector": "identity", "item": "userSignInActivity", "status": "failed", "error_class": "license_required"}]
    ledger = [
        {"collector": "identity", "coverage_status": "partial_success", "diagnostics": diagnostics},
        *({"collector": name, "coverage_status": "complete_exact_scope"} for name in ("auth_methods", "licensing")),
        {"collector": "identity_governance", "coverage_status": "not_applicable"},
    ]

    alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger)

    rows = {
        rule["rule_id"]: rule
        for entry in alignment["frameworks"].values()
        for control in entry["controls"]
        for rule in control["rule_statuses"]
        if rule["rule_id"] in {"identity.stale_enabled_account", "identity.privileged_stale_account", "identity.stale_guest"}
    }
    assert set(rows) == {"identity.stale_enabled_account", "identity.privileged_stale_account", "identity.stale_guest"}
    for rule_id, row in rows.items():
        assert row["status"] == "not_assessed" and row["reason"] == "signin_activity_unavailable", rule_id
    # The administrator rules are still evaluated.
    assert baselines._rule_evaluation(
        "identity.global_admin_sprawl", {}, {}, {"auth_methods"}, snapshot, licence_limited_collectors={"identity"}
    )["status"] == "pass"


# --- the service principal rule ----------------------------------------------------------------------------------------


def _admin_row(principal_id: str, principal_type: str, role_id: str, role: str, route: str = "direct_active", **extra: Any) -> dict[str, Any]:
    return {
        "kind": "effective_admin",
        "key": f"effective_admin:{principal_id}",
        "id": principal_id,
        "principal_id": principal_id,
        "principal_type": principal_type,
        "counted": principal_type == "user",
        "display_name": f"Name of {principal_id}",
        "roles": [{"role": role, "role_definition_id": role_id, "route": route, "global_administrator": role_id == GLOBAL_ADMIN, "records": []}],
        "routes": [route],
        "state": "complete",
        **extra,
    }


def _admin_snapshot(*rows: dict[str, Any], state: str = "complete") -> dict[str, Any]:
    summary = {"kind": "effective_admin_set_summary", "key": "effective_admin_set_summary:summary", "id": "summary", "state": state, "reasons": []}
    return {
        "effective_admin_set": {"records": [summary, *rows]},
        "service_principals": {"records": [
            {"id": "sp-ga", "key": "service_principal:sp-ga", "app_id": "app-1", "service_principal_type": "Application"},
        ]},
    }


def test_a_service_principal_with_global_administrator_or_privileged_role_administrator_is_a_high_finding() -> None:
    snapshot = _admin_snapshot(
        _admin_row("sp-ga", "service_principal", GLOBAL_ADMIN, "Global Administrator", enabled=True),
        _admin_row("sp-pra", "service_principal", PRIVILEGED_ROLE_ADMIN, "Privileged Role Administrator", route="pim_eligible"),
        _admin_row("sp-exchange", "service_principal", EXCHANGE_ADMIN, "Exchange Administrator"),
        _admin_row("u-ga", "user", GLOBAL_ADMIN, "Global Administrator"),
        _admin_row("g-ga", "group", GLOBAL_ADMIN, "Global Administrator"),
    )

    findings = [row for row in build_findings([], normalized_snapshot=snapshot) if row.get("rule_id") == "identity.service_principal_privileged_role"]

    assert [row["id"] for row in findings] == [
        "identity:service_principal_privileged_role:sp-ga",
        "identity:service_principal_privileged_role:sp-pra",
    ]
    first = findings[0]
    assert first["severity"] == "high" and first["category"] == "identity"
    assert first["evidence"]["app_id"] == "app-1" and first["evidence"]["roles"] == [{"role": "Global Administrator", "route": "direct_active"}]
    assert first["framework_mappings"]["mcsb"] == ["PA-1", "PA-7"] and first["framework_mappings"]["ms_zero_trust"] == ["identities"]
    assert findings[1]["evidence"]["roles"] == [{"role": "Privileged Role Administrator", "route": "pim_eligible"}]
    assert {ref["record_key"] for ref in first["evidence_refs"]} >= {"effective_admin:sp-ga", "service_principal:sp-ga"}


def test_no_service_principal_finding_without_a_tenant_wide_role_or_an_administrator_set() -> None:
    assert not [
        row
        for row in build_findings(
            [], normalized_snapshot=_admin_snapshot(_admin_row("sp-exchange", "service_principal", EXCHANGE_ADMIN, "Exchange Administrator"))
        )
        if row.get("rule_id") == "identity.service_principal_privileged_role"
    ]
    assert not [row for row in build_findings([], normalized_snapshot={}) if row.get("rule_id") == "identity.service_principal_privileged_role"]


def test_the_service_principal_rule_is_not_assessed_unless_the_administrator_set_is_complete() -> None:
    rule = "identity.service_principal_privileged_role"
    complete = _admin_snapshot(_admin_row("u-ga", "user", GLOBAL_ADMIN, "Global Administrator"))
    unknown = _admin_snapshot(state="unknown")
    unknown["effective_admin_set"]["records"][0]["reasons"] = ["role_assignments_truncated"]

    assert baselines._rule_evaluation(rule, {}, {}, {"identity"}, complete)["status"] == "pass"
    assert baselines._rule_evaluation(rule, {rule: ["f"]}, {}, {"identity"}, unknown)["status"] == "fail"
    assert baselines._rule_evaluation(rule, {}, {}, {"identity"}, unknown) == {
        "rule_id": rule,
        "status": "not_assessed",
        "evaluated": False,
        "reason": "admin_set_unknown:role_assignments_truncated",
    }


def test_a_service_principal_with_global_administrator_is_found_through_the_pipeline(tmp_path: Path) -> None:
    sps = [{"id": "sp-ga", "displayName": "Deploy pipeline", "appId": "app-1", "servicePrincipalType": "Application", "accountEnabled": True}]

    snapshot, findings, controls = _run(
        tmp_path, [_policy()], assignments=[("u-emergency", GLOBAL_ADMIN), ("sp-ga", GLOBAL_ADMIN)], service_principals=sps
    )

    finding = _rules(findings)["identity.service_principal_privileged_role"]
    assert finding["affected_objects"] == ["Deploy pipeline"]
    assert finding["evidence"]["app_id"] == "app-1"
    assert _status(controls, "mcsb", "PA-1") == "fail"
    summary = next(row for row in snapshot["effective_admin_set"]["records"] if row["kind"] == "effective_admin_set_summary")
    assert summary["non_user_principal_count"] == 1, "a service principal is not counted as an administrator"
