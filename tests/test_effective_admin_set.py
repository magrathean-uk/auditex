"""The effective administrator set, the rules built on it and how baseline alignment reads them.

The set is resolved once in normalization (``normalized/effective_admin_set.json``): users only, by
every route (direct, PIM-eligible, through a role-assignable group), with an ``unknown`` state when a
source was blocked, truncated or not run. Every ``identity.global_admin_*`` rule reads it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import baselines
from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.effective_admins import (
    MAILBOX_SERVICE_PLANS,
    PRODUCTIVITY_SERVICE_PLANS,
    AdminSetEvidence,
    build_effective_admin_set,
)
from azure_tenant_audit.evidence_refs import EvidenceIndex
from azure_tenant_audit.findings import build_findings, stale_guest_days
from azure_tenant_audit.identity_controls import Evidence
from azure_tenant_audit.normalize import build_normalized_snapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "examples" / "sample_audit_bundle" / "admin_set_result.json"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1"
ALL_COLLECTORS = ("identity", "identity_governance", "auth_methods", "licensing")


def _user(user_id: str, **fields: Any) -> dict[str, Any]:
    return {
        "id": user_id,
        "displayName": user_id,
        "userPrincipalName": f"{user_id}@contoso.test",
        "accountEnabled": True,
        "userType": "Member",
        **fields,
    }


def _assignment(principal: str, role: str = GLOBAL_ADMIN, **fields: Any) -> dict[str, Any]:
    return {"id": f"ra-{principal}-{role[:4]}", "principalId": principal, "roleDefinitionId": role, **fields}


def _schedule(principal: str, role: str = GLOBAL_ADMIN, *, prefix: str = "elig") -> dict[str, Any]:
    return {"id": f"{prefix}-{principal}-{role[:4]}", "principalId": principal, "roleDefinitionId": role, "directoryScopeId": "/"}


def _identity(
    users: list[str] | None = None,
    assignments: list[dict[str, Any]] | None = None,
    *,
    user_rows: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    service_principals: list[dict[str, Any]] | None = None,
    members: list[dict[str, Any]] | None = None,
    fanout_complete: bool = True,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "users": {"value": user_rows if user_rows is not None else [_user(user) for user in users or []]},
        "groups": {"value": groups or []},
        "servicePrincipals": {"value": service_principals or []},
        "roleDefinitions": {
            "value": [
                {"id": GLOBAL_ADMIN, "displayName": "Global Administrator"},
                {"id": EXCHANGE_ADMIN, "displayName": "Exchange Administrator"},
                {"id": USER_ADMIN, "displayName": "User Administrator"},
                {"id": "reader-role", "displayName": "Global Reader"},
            ]
        },
        "roleAssignments": {"value": assignments or []},
    }
    if members is not None:
        payload["roleAssignableGroupMembers"] = {
            "value": members,
            "fanout": {"fanout_complete": fanout_complete, "collection_truncated": not fanout_complete},
        }
        payload["roleAssignableGroupOwners"] = {"value": []}
    payload.update(extra or {})
    return payload


def _governance(eligible: list[dict[str, Any]] | None = None, active: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "roleAssignmentSchedules": {"value": active or []},
        "roleEligibilitySchedules": {"value": eligible or []},
    }


def _snapshot(identity: dict[str, Any], governance: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    result_rows = extra.pop("result_rows", None)
    payloads: dict[str, Any] = {"identity": identity, "identity_governance": _governance() if governance is None else governance}
    payloads.update(extra)
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads, result_rows=result_rows)


def _records(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return snapshot["effective_admin_set"]["records"]


def _summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    (summary,) = [row for row in _records(snapshot) if row["kind"] == "effective_admin_set_summary"]
    return summary


def _rows(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["principal_id"]: row for row in _records(snapshot) if row["kind"] == "effective_admin"}


def _by_rule(snapshot: dict[str, Any], rule_id: str, **kwargs: Any) -> list[dict[str, Any]]:
    return [row for row in build_findings([], normalized_snapshot=snapshot, **kwargs) if row.get("rule_id") == rule_id]


def _assert_refs_resolve(snapshot: dict[str, Any], finding: dict[str, Any]) -> None:
    assert finding["evidence_refs"]
    for ref in finding["evidence_refs"]:
        section = Path(ref["artifact_path"]).stem
        keys = {row.get("key") for row in (snapshot.get(section) or {}).get("records", [])}
        assert ref["record_key"] in keys, (finding["id"], ref)


def _ledger(*collectors: str) -> list[dict[str, str]]:
    return [{"collector": name, "coverage_status": "complete_exact_scope"} for name in collectors]


def _rule_status(alignment: dict[str, Any], framework: str, control: str, rule_id: str) -> dict[str, Any]:
    (row,) = [
        status
        for entry in alignment["frameworks"][framework]["controls"]
        if entry["control_id"] == control
        for status in entry["rule_statuses"]
        if status["rule_id"] == rule_id
    ]
    return row


def _control(alignment: dict[str, Any], framework: str, control: str) -> dict[str, Any]:
    (row,) = [entry for entry in alignment["frameworks"][framework]["controls"] if entry["control_id"] == control]
    return row


def _alignment(snapshot: dict[str, Any]) -> dict[str, Any]:
    findings = build_findings([], normalized_snapshot=snapshot)
    return build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=_ledger(*ALL_COLLECTORS))


def _signed_in(names: list[str]) -> dict[str, Any]:
    """The sign-in activity read (Microsoft Entra ID P1) with a recent successful sign-in for each user."""
    stamp = "2026-10-01T00:00:00Z"
    return {
        "userSignInActivity": {
            "value": [
                {"id": name, "signInActivity": {"lastSignInDateTime": stamp, "lastSuccessfulSignInDateTime": stamp}}
                for name in names
            ]
        }
    }


def _registered(names: list[str]) -> dict[str, Any]:
    """The authentication method registration report, with an MFA answer for each user."""
    return {
        "auth_methods": {
            "userRegistrationDetails": {
                "value": [
                    {"id": name, "userPrincipalName": f"{name}@contoso.test", "userType": "member", "isMfaRegistered": True}
                    for name in names
                ]
            }
        }
    }


def _global_admins(count: int, *, signin: bool = False) -> dict[str, Any]:
    names = [f"ga-{index}" for index in range(count)]
    return _snapshot(
        _identity(names, [_assignment(name) for name in names], extra=_signed_in(names) if signin else None),
        **_registered(names),
    )


# --- set construction -------------------------------------------------------------------------------


def test_a_direct_active_assignment_is_one_counted_user_row() -> None:
    snapshot = _snapshot(_identity(["u1"], [_assignment("u1", directoryScopeId="/")]))

    summary, row = _summary(snapshot), _rows(snapshot)["u1"]

    assert summary["state"] == "complete" and summary["admin_count"] == 1 and summary["global_admin_count"] == 1
    assert row["principal_type"] == "user" and row["is_user"] is True and row["counted"] is True
    assert row["routes"] == ["direct_active"] and row["global_administrator"] is True and row["scope"] == "tenant"
    assert row["roles"][0]["records"] == [{"section": "role_assignments", "key": "role_assignment:ra-u1-62e9"}]
    assert row["state"] == "complete" and row["key"] == "effective_admin:u1"


def test_a_pim_eligible_administrator_is_counted() -> None:
    snapshot = _snapshot(_identity(["u1", "u2"], [_assignment("u1")]), _governance(eligible=[_schedule("u2")]))

    rows = _rows(snapshot)

    assert set(rows) == {"u1", "u2"}
    assert rows["u2"]["routes"] == ["pim_eligible"] and rows["u2"]["global_administrator"] is True
    assert rows["u2"]["roles"][0]["records"] == [{"section": "governance_objects", "key": "role_eligibility_schedule:elig-u2-62e9"}]
    assert _summary(snapshot)["pim_eligible_count"] == 1 and _summary(snapshot)["global_admin_count"] == 2


def test_a_pim_assignment_schedule_that_repeats_an_active_assignment_is_one_role() -> None:
    snapshot = _snapshot(
        _identity(["u1", "u2"], [_assignment("u1")]),
        _governance(active=[_schedule("u1", prefix="ras"), _schedule("u2", prefix="ras")]),
    )

    rows = _rows(snapshot)

    assert [role["route"] for role in rows["u1"]["roles"]] == ["direct_active"]
    assert rows["u1"]["roles"][0]["records"][0]["section"] == "role_assignments"
    # A time-bound or PIM-managed assignment that the assignments list lacks is still an active administrator.
    assert rows["u2"]["routes"] == ["direct_active"]
    assert rows["u2"]["roles"][0]["records"][0]["section"] == "governance_objects"


def test_a_role_assignable_group_expands_to_its_users_and_nested_groups_and_is_not_itself_counted() -> None:
    members = [
        {
            "groupId": "g-admins",
            "displayName": "Tier 0",
            "members": [
                {"id": "u-direct-member", "@odata.type": "#microsoft.graph.user"},
                {"id": "g-nested", "@odata.type": "#microsoft.graph.group"},
                {"id": "sp-member", "@odata.type": "#microsoft.graph.servicePrincipal"},
            ],
        },
        {"groupId": "g-nested", "displayName": "Nested", "members": [{"id": "u-nested-member", "@odata.type": "#microsoft.graph.user"}]},
    ]
    snapshot = _snapshot(
        _identity(
            ["u-direct-member", "u-nested-member"],
            [_assignment("g-admins")],
            groups=[{"id": "g-admins", "displayName": "Tier 0", "isAssignableToRole": True}, {"id": "g-nested", "displayName": "Nested"}],
            members=members,
        )
    )

    rows, summary = _rows(snapshot), _summary(snapshot)

    assert summary["state"] == "complete"
    assert rows["g-admins"]["principal_type"] == "group" and rows["g-admins"]["counted"] is False
    assert rows["g-admins"]["is_user"] is False and rows["g-admins"]["expanded_member_count"] == 3
    assert "g-nested" not in rows
    direct = rows["u-direct-member"]["roles"][0]
    assert direct["route"] == "via_group" and direct["group_id"] == "g-admins" and direct["group_name"] == "Tier 0"
    assert direct["group_assignment"] == "active" and "nested_group" not in direct
    nested = rows["u-nested-member"]["roles"][0]
    assert nested["route"] == "via_group" and nested["group_id"] == "g-admins" and nested["nested_group"] is True
    assert {record["section"] for record in nested["records"]} == {"role_assignments", "group_membership_edges"}
    # The service principal behind the group is listed, not counted.
    assert rows["sp-member"]["principal_type"] == "service_principal" and rows["sp-member"]["counted"] is False
    assert summary["admin_count"] == 2 and summary["global_admin_count"] == 2 and summary["non_user_principal_count"] == 2
    assert summary["group_expanded_count"] == 2


def test_an_eligible_group_passes_its_roles_on_as_eligible() -> None:
    members = [{"groupId": "g1", "displayName": "PIM group", "members": [{"id": "u1", "@odata.type": "#microsoft.graph.user"}]}]
    snapshot = _snapshot(
        _identity(["u1"], [], groups=[{"id": "g1", "displayName": "PIM group", "isAssignableToRole": True}], members=members),
        _governance(eligible=[_schedule("g1")]),
    )

    role = _rows(snapshot)["u1"]["roles"][0]

    assert role["route"] == "via_group" and role["group_assignment"] == "eligible"


def test_service_principals_and_groups_that_hold_the_role_are_listed_but_not_counted() -> None:
    snapshot = _snapshot(
        _identity(
            ["u1"],
            [_assignment("u1"), _assignment("sp-1"), _assignment("g1")],
            groups=[{"id": "g1", "displayName": "Admins group", "isAssignableToRole": True}],
            service_principals=[{"id": "sp-1", "displayName": "Automation", "accountEnabled": True}],
            members=[{"groupId": "g1", "displayName": "Admins group", "members": []}],
        )
    )

    rows, summary = _rows(snapshot), _summary(snapshot)

    assert rows["sp-1"]["principal_type"] == "service_principal" and rows["sp-1"]["counted"] is False
    assert rows["g1"]["principal_type"] == "group" and rows["g1"]["counted"] is False
    assert summary["admin_count"] == 1 and summary["global_admin_count"] == 1 and summary["non_user_principal_count"] == 2


def test_a_principal_no_inventory_resolves_is_counted_and_flagged() -> None:
    snapshot = _snapshot(_identity(["u1"], [_assignment("u1"), _assignment("ghost")]))

    row = _rows(snapshot)["ghost"]

    assert row["principal_type"] == "unresolved" and row["counted"] is True and "is_user" not in row
    assert _summary(snapshot)["unresolved_principal_count"] == 1 and _summary(snapshot)["admin_count"] == 2


def test_only_administrator_roles_make_a_principal_privileged_and_scope_is_reported() -> None:
    snapshot = _snapshot(
        _identity(
            ["u-exo", "u-reader", "u-scoped"],
            [
                _assignment("u-exo", EXCHANGE_ADMIN),
                _assignment("u-reader", "reader-role"),
                _assignment("u-scoped", USER_ADMIN, directoryScopeId="/administrativeUnits/au-1"),
            ],
        )
    )

    rows = _rows(snapshot)

    assert set(rows) == {"u-exo", "u-scoped"}
    assert rows["u-exo"]["global_administrator"] is False and rows["u-exo"]["scope"] == "unknown"
    assert rows["u-scoped"]["scope"] == "scoped" and rows["u-scoped"]["roles"][0]["scope"] == "/administrativeUnits/au-1"


def test_the_guest_flag_follows_the_user_type() -> None:
    snapshot = _snapshot(
        _identity(
            user_rows=[_user("g1", userType="Guest"), _user("m1"), {"id": "typeless", "displayName": "t"}],
            assignments=[_assignment("g1"), _assignment("m1"), _assignment("typeless")],
        )
    )

    rows = _rows(snapshot)

    assert rows["g1"]["is_guest"] is True and rows["m1"]["is_guest"] is False and "is_guest" not in rows["typeless"]
    assert _summary(snapshot)["guest_admin_count"] == 1


def test_the_section_is_absent_when_the_run_read_neither_identity_nor_governance() -> None:
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads={"auth_methods": {"userRegistrationDetails": {"value": []}}})

    assert "effective_admin_set" not in snapshot


def test_governance_alone_leaves_the_role_sources_unknown() -> None:
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"identity_governance": _governance(eligible=[_schedule("u1")])},
    )

    summary = _summary(snapshot)

    assert summary["state"] == "unknown"
    assert {"role_definitions_absent", "role_assignments_absent"} <= set(summary["reasons"])


def _states(snapshot: dict[str, Any]) -> dict[str, str]:
    return {row["source"]: row["state"] for row in _summary(snapshot)["sources"]}


_ERROR = {"error": "Forbidden", "error_class": "insufficient_permissions"}


@pytest.mark.parametrize(
    ("label", "identity_extra", "governance", "reason"),
    [
        ("assignments_blocked", {"roleAssignments": dict(_ERROR)}, None, "role_assignments_blocked"),
        ("assignments_truncated", {"roleAssignments": {"value": [], "collection_truncated": True}}, None, "role_assignments_truncated"),
        ("definitions_blocked", {"roleDefinitions": dict(_ERROR)}, None, "role_definitions_blocked"),
        ("eligibility_blocked", {}, {"roleAssignmentSchedules": {"value": []}, "roleEligibilitySchedules": dict(_ERROR)}, "role_eligibility_schedules_blocked"),
        ("active_schedules_truncated", {}, {"roleAssignmentSchedules": {"value": [], "collection_truncated": True}, "roleEligibilitySchedules": {"value": []}}, "role_assignment_schedules_truncated"),
        ("fanout_incomplete", {"roleAssignableGroupMembers": {"value": [], "fanout": {"fanout_complete": False}}}, None, "group_membership_fanout_truncated"),
        ("fanout_blocked", {"roleAssignableGroupMembers": dict(_ERROR)}, None, "group_membership_fanout_blocked"),
        (
            "fanout_cut",
            {"roleAssignableGroupMembers": {"value": [], "collection_truncated": True, "fanout": {"fanout_complete": True}}},
            None,
            "group_membership_fanout_truncated",
        ),
    ],
)
def test_a_blocked_or_truncated_source_makes_the_set_unknown_with_the_reason(
    label: str, identity_extra: dict[str, Any], governance: dict[str, Any] | None, reason: str
) -> None:
    identity = _identity(["u1"], [_assignment("u1")], extra=identity_extra)

    summary = _summary(_snapshot(identity, governance))

    assert summary["state"] == "unknown", label
    assert summary["reasons"] == [reason]
    assert all(row["state"] == "unknown" for row in _rows(_snapshot(identity, governance)).values())


def test_pim_schedules_that_were_never_collected_are_unknown_not_empty() -> None:
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads={"identity": _identity(["u1"], [_assignment("u1")])}
    )

    summary = _summary(snapshot)

    assert summary["state"] == "unknown"
    assert summary["reasons"] == ["role_assignment_schedules_absent", "role_eligibility_schedules_absent"]
    assert _states(snapshot)["role_assignments"] == "collected"


def test_a_tenant_without_pim_licences_has_no_schedules_to_hide() -> None:
    licence_error = {"error": "needs to have Microsoft Entra ID P2", "error_class": "license_required"}
    governance = {"roleAssignmentSchedules": dict(licence_error), "roleEligibilitySchedules": dict(licence_error)}

    snapshot = _snapshot(_identity(["u1"], [_assignment("u1")]), governance)

    assert _summary(snapshot)["state"] == "complete"
    assert _states(snapshot)["role_eligibility_schedules"] == "not_applicable"


def test_a_skipped_governance_collector_leaves_the_set_unknown() -> None:
    # Preflight skips a collector on a permission block, an exception or a missing raw file as well as on a
    # missing licence, and the skipped collector leaves no payload. Only a license_required refusal on the
    # schedule read itself proves the tenant has no PIM.
    identity = _identity(["u1"], [_assignment("u1")])
    skipped = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"identity": identity},
        result_rows=[{"name": "identity_governance", "status": "skipped"}],
    )
    never_run = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads={"identity": identity})

    assert _summary(skipped)["state"] == "unknown"
    assert _summary(skipped)["reasons"] == ["role_assignment_schedules_blocked", "role_eligibility_schedules_blocked"]
    assert _states(skipped)["role_assignment_schedules"] == "blocked"
    assert {row["detail"] for row in _summary(skipped)["sources"] if row["source"].endswith("_schedules")} == {"collector_skipped"}
    assert _summary(never_run)["reasons"] == ["role_assignment_schedules_absent", "role_eligibility_schedules_absent"]
    assert not _by_rule(skipped, "identity.global_admin_singleton")
    assert _by_rule(skipped, "identity.admin_set_unverified")


def test_group_expansion_that_was_never_run_is_unknown_only_when_a_group_holds_a_role() -> None:
    with_group = _snapshot(
        _identity(["u1"], [_assignment("g1")], groups=[{"id": "g1", "displayName": "G", "isAssignableToRole": True}])
    )
    without_group = _snapshot(_identity(["u1"], [_assignment("u1")]))

    assert _summary(with_group)["reasons"] == ["group_membership_fanout_absent"]
    assert _summary(without_group)["state"] == "complete" and _states(without_group)["group_membership_fanout"] == "not_needed"


def test_an_unknown_set_keeps_the_administrators_it_did_read() -> None:
    snapshot = _snapshot(_identity(["u1"], [_assignment("u1")], extra={"roleAssignableGroupMembers": dict(_ERROR)}))

    assert set(_rows(snapshot)) == {"u1"} and _summary(snapshot)["admin_count"] == 1


# --- licence flags ----------------------------------------------------------------------------------


def _licensing(sku_plans: dict[str, list[str]], users: dict[str, list[dict[str, Any]]], **sections: Any) -> dict[str, Any]:
    payload = {
        "subscribedSkus": {
            "value": [
                {
                    "skuId": sku,
                    "skuPartNumber": sku.upper(),
                    "servicePlans": [
                        {"servicePlanId": f"{sku}-{plan}", "servicePlanName": plan, "provisioningStatus": "Success"} for plan in plans
                    ],
                }
                for sku, plans in sku_plans.items()
            ]
        },
        "licensedUsers": {"value": [{"id": user, "assignedLicenses": licences} for user, licences in users.items()]},
    }
    payload.update(sections)
    return payload


def _licence_snapshot(licensing: dict[str, Any] | None, users: list[str] | None = None) -> dict[str, Any]:
    names = users or ["u1"]
    extra = {} if licensing is None else {"licensing": licensing}
    return _snapshot(_identity(names, [_assignment(name) for name in names]), **extra)


def test_licence_flags_come_from_the_service_plans_of_the_assigned_skus() -> None:
    licensing = _licensing(
        {"sku-mail": ["EXCHANGE_S_STANDARD", "AAD_PREMIUM"], "sku-apps": ["OFFICESUBSCRIPTION"], "sku-entra": ["AAD_PREMIUM"]},
        {
            "mail": [{"skuId": "sku-mail", "disabledPlans": []}],
            "apps": [{"skuId": "sku-apps"}],
            "entra": [{"skuId": "sku-entra"}],
            "none": [],
        },
    )

    rows = _rows(_licence_snapshot(licensing, ["mail", "apps", "entra", "none", "absent"]))

    assert (rows["mail"]["mailbox_licence"], rows["mail"]["productivity_licence"]) == (True, False)
    assert (rows["apps"]["mailbox_licence"], rows["apps"]["productivity_licence"]) == (False, True)
    assert (rows["entra"]["mailbox_licence"], rows["entra"]["productivity_licence"]) == (False, False)
    assert rows["entra"]["licence_sku_part_numbers"] == ["SKU-ENTRA"] and rows["entra"]["licence_state"] == "known"
    # In a complete list, an account that is not in it holds no licence.
    assert (rows["none"]["mailbox_licence"], rows["absent"]["mailbox_licence"]) == (False, False)


def test_a_disabled_service_plan_is_not_a_licence() -> None:
    licensing = _licensing(
        {"sku-mail": ["EXCHANGE_S_ENTERPRISE", "TEAMS1"]},
        {"u1": [{"skuId": "sku-mail", "disabledPlans": ["sku-mail-EXCHANGE_S_ENTERPRISE"]}]},
    )

    row = _rows(_licence_snapshot(licensing))["u1"]

    assert (row["mailbox_licence"], row["productivity_licence"]) == (False, True)


def test_government_and_education_plan_names_match_their_base_plan() -> None:
    licensing = _licensing(
        {"sku-gov": ["EXCHANGE_S_ENTERPRISE_GOV", "AAD_PREMIUM"], "sku-edu": ["SHAREPOINTENTERPRISE_EDU", "OFFICESUBSCRIPTION_GOV"], "sku-plain": ["AAD_PREMIUM_GOV"]},
        {"gov": [{"skuId": "sku-gov"}], "edu": [{"skuId": "sku-edu"}], "plain": [{"skuId": "sku-plain"}]},
    )

    rows = _rows(_licence_snapshot(licensing, ["gov", "edu", "plain"]))

    assert (rows["gov"]["mailbox_licence"], rows["gov"]["productivity_licence"]) == (True, False)
    assert (rows["edu"]["mailbox_licence"], rows["edu"]["productivity_licence"]) == (False, True)
    assert (rows["plain"]["mailbox_licence"], rows["plain"]["productivity_licence"]) == (False, False)


def test_a_sku_without_service_plans_falls_back_to_separate_mailbox_and_productivity_lists() -> None:
    skus = {"s-both": "ENTERPRISEPACK", "s-exo": "EXCHANGESTANDARD", "s-exo2": "EXCHANGEENTERPRISE", "s-apps": "O365_BUSINESS", "s-mystery": "MYSTERY_SKU"}
    licensing = {
        "subscribedSkus": {"value": [{"skuId": sku, "skuPartNumber": part} for sku, part in skus.items()]},
        "licensedUsers": {"value": [{"id": f"u-{sku}", "assignedLicenses": [{"skuId": sku}]} for sku in skus]},
    }

    rows = _rows(_licence_snapshot(licensing, [f"u-{sku}" for sku in skus]))

    flags = {sku: (rows[f"u-{sku}"].get("mailbox_licence"), rows[f"u-{sku}"].get("productivity_licence")) for sku in skus}
    assert flags["s-both"] == (True, True)
    # The standalone Exchange Online SKUs are a mailbox and nothing else; Apps for business has no mailbox.
    assert flags["s-exo"] == (True, False) and flags["s-exo2"] == (True, False)
    assert flags["s-apps"] == (False, True)
    assert flags["s-mystery"] == (None, None)
    assert rows["u-s-mystery"]["licence_state"] == "unknown" and rows["u-s-mystery"]["licence_reason"] == "sku_not_classifiable"


@pytest.mark.parametrize(
    ("label", "licensing", "reasons"),
    [
        ("not_collected", None, ["licence_skus_absent", "licensed_users_absent"]),
        ("users_truncated", _licensing({"s": ["TEAMS1"]}, {}, licensedUsers={"value": [], "collection_truncated": True}), ["licensed_users_truncated"]),
        ("skus_blocked", _licensing({"s": ["TEAMS1"]}, {}, subscribedSkus=dict(_ERROR)), ["licence_skus_blocked"]),
    ],
)
def test_licences_that_were_not_read_in_full_are_unknown_never_none(label: str, licensing: dict[str, Any] | None, reasons: list[str]) -> None:
    snapshot = _licence_snapshot(licensing)

    row, summary = _rows(snapshot)["u1"], _summary(snapshot)

    assert row["licence_state"] == "unknown" and "mailbox_licence" not in row, label
    assert summary["licence_state"] == "unknown" and summary["licence_reasons"] == reasons
    assert summary["state"] == "complete"


def test_the_plan_lists_name_real_exchange_and_office_plans_and_the_contract_lists_the_mailbox_plans() -> None:
    assert "EXCHANGE_S_STANDARD" in MAILBOX_SERVICE_PLANS and "EXCHANGE_S_FOUNDATION" not in MAILBOX_SERVICE_PLANS
    assert {"OFFICESUBSCRIPTION", "TEAMS1", "SHAREPOINTENTERPRISE"} <= PRODUCTIVITY_SERVICE_PLANS
    assert len(MAILBOX_SERVICE_PLANS) == 5
    contract = (REPO_ROOT / "docs" / "reference" / "output-contract.md").read_text(encoding="utf-8")
    assert all(plan in contract for plan in MAILBOX_SERVICE_PLANS)


def test_the_builder_is_pure_and_deterministic() -> None:
    evidence = AdminSetEvidence(**{name: Evidence("collected") for name in (
        "role_definitions", "role_assignments", "assignment_schedules", "eligibility_schedules", "group_fanout"
    )})
    inputs: dict[str, Any] = {
        "users": [{"id": "u1", "kind": "user"}],
        "groups": [],
        "service_principals": [],
        "role_definitions": [{"id": GLOBAL_ADMIN, "display_name": "Global Administrator"}],
        "role_assignments": [{"key": "role_assignment:r1", "id": "r1", "principal_id": "u1", "role_definition_id": GLOBAL_ADMIN}],
        "governance_objects": [],
        "membership_edges": [],
        "evidence": evidence,
    }

    assert build_effective_admin_set(**inputs) == build_effective_admin_set(**inputs)
    assert [row["kind"] for row in build_effective_admin_set(**inputs)] == ["effective_admin_set_summary", "effective_admin"]


# --- the Global Administrator rules read the set ----------------------------------------------------


def test_a_pim_tenant_with_one_permanent_and_three_eligible_administrators_is_not_a_singleton() -> None:
    names = ["perm", "e1", "e2", "e3"]
    snapshot = _snapshot(
        _identity(names, [_assignment("perm")]), _governance(eligible=[_schedule(name) for name in names[1:]])
    )

    rules = {row["rule_id"] for row in build_findings([], normalized_snapshot=snapshot)}

    assert _summary(snapshot)["global_admin_count"] == 4
    assert "identity.global_admin_singleton" not in rules and "identity.global_admin_sprawl" not in rules


def test_administrators_that_are_all_eligible_are_counted_and_one_alone_is_a_singleton() -> None:
    two = _snapshot(_identity(["e1", "e2"], []), _governance(eligible=[_schedule("e1"), _schedule("e2")]))
    one = _snapshot(_identity(["e1"], []), _governance(eligible=[_schedule("e1")]))

    assert _summary(two)["global_admin_count"] == 2
    assert not _by_rule(two, "identity.global_admin_singleton")
    [finding] = _by_rule(one, "identity.global_admin_singleton")
    assert finding["returned_value"]["global_admin_count"] == 1 and finding["returned_value"]["routes"] == ["pim_eligible"]
    assert finding["returned_value"]["admin_set_state"] == "complete"


def test_the_singleton_rule_stays_silent_on_an_unknown_set_and_the_diagnostic_is_raised() -> None:
    snapshot = _snapshot(_identity(["u1"], [_assignment("u1")]), governance={})

    rules = {row["rule_id"] for row in build_findings([], normalized_snapshot=snapshot)}

    assert _summary(snapshot)["state"] == "unknown"
    assert "identity.global_admin_singleton" not in rules
    [unverified] = _by_rule(snapshot, "identity.admin_set_unverified")
    assert unverified["id"] == "identity:admin_set:unverified" and unverified["severity"] == "medium"
    assert unverified["returned_value"]["state"] == "unknown"
    assert unverified["returned_value"]["reasons"] == ["role_assignment_schedules_absent", "role_eligibility_schedules_absent"]
    assert unverified["evidence"]["observed_global_admin_count"] == 1
    assert not unverified.get("framework_mappings", {}).get("cis_m365_v7")
    _assert_refs_resolve(snapshot, unverified)


def test_a_complete_set_raises_no_diagnostic() -> None:
    assert not _by_rule(_global_admins(3), "identity.admin_set_unverified")


@pytest.mark.parametrize("count", [2, 3, 4])
def test_two_to_four_global_administrators_raise_no_count_finding(count: int) -> None:
    snapshot = _global_admins(count)

    assert not _by_rule(snapshot, "identity.global_admin_sprawl") and not _by_rule(snapshot, "identity.global_admin_singleton")


@pytest.mark.parametrize("count", [5, 6, 8])
def test_five_to_eight_breach_the_cis_bound_only(count: int) -> None:
    snapshot = _global_admins(count)

    [finding] = _by_rule(snapshot, "identity.global_admin_sprawl")

    assert finding["severity"] == "low"
    thresholds = {row["framework"]: row for row in finding["framework_thresholds"]}
    assert thresholds["cis_m365_v7"] == {
        "framework": "cis_m365_v7", "control_ids": ["1.1.3"], "metric": "global_administrator_count",
        "observed": count, "minimum": 2, "maximum": 4, "breached": True,
    }
    assert thresholds["cisa_scuba"]["breached"] is False and thresholds["cisa_scuba"]["maximum"] == 8
    assert thresholds["cisa_scuba"]["control_ids"] == ["MS.AAD.7.1v1"]
    assert "more than 4 (CIS 1.1.3)" in finding["description"] and "more than 8" not in finding["description"]
    assert "2 to 4 (CIS 1.1.3)" in finding["expected_value"] and "2 to 8 (SCuBA MS.AAD.7.1v1)" in finding["expected_value"]
    _assert_refs_resolve(snapshot, finding)


def test_nine_or_more_breach_both_bounds() -> None:
    [finding] = _by_rule(_global_admins(9), "identity.global_admin_sprawl")

    assert finding["severity"] == "medium"
    assert all(row["breached"] for row in finding["framework_thresholds"])
    assert finding["returned_value"]["global_admin_count"] == 9 and len(finding["returned_value"]["principal_ids"]) == 9


def test_the_singleton_finding_states_the_minimum_each_framework_requires() -> None:
    [finding] = _by_rule(_snapshot(_identity(["u1"], [_assignment("u1")])), "identity.global_admin_singleton")

    assert {row["framework"]: row["minimum"] for row in finding["framework_thresholds"]} == {"cis_m365_v7": 2, "cisa_scuba": 2}
    assert all(row["breached"] and row["observed"] == 1 for row in finding["framework_thresholds"])


def test_groups_and_service_principals_do_not_count_towards_sprawl() -> None:
    names = [f"ga-{index}" for index in range(4)]
    snapshot = _snapshot(
        _identity(
            names,
            [_assignment(name) for name in names] + [_assignment(f"g{i}") for i in range(3)] + [_assignment("sp-1"), _assignment("sp-2")],
            groups=[{"id": f"g{i}", "displayName": f"g{i}", "isAssignableToRole": True} for i in range(3)],
            service_principals=[{"id": "sp-1", "displayName": "a"}, {"id": "sp-2", "displayName": "b"}],
            members=[{"groupId": f"g{i}", "displayName": f"g{i}", "members": []} for i in range(3)],
        )
    )

    assert _summary(snapshot)["global_admin_count"] == 4
    assert not _by_rule(snapshot, "identity.global_admin_sprawl")


def test_sprawl_still_fires_on_an_unknown_set_and_says_the_count_is_a_lower_bound() -> None:
    names = [f"ga-{index}" for index in range(5)]
    snapshot = _snapshot(_identity(names, [_assignment(name) for name in names]), governance={})

    [finding] = _by_rule(snapshot, "identity.global_admin_sprawl")

    assert finding["returned_value"]["lower_bound"] is True and finding["returned_value"]["admin_set_state"] == "unknown"
    assert finding["description"].startswith("At least 5")
    assert _by_rule(snapshot, "identity.admin_set_unverified")


def test_a_disabled_global_administrator_is_found_through_pim_and_through_a_group() -> None:
    members = [{"groupId": "g1", "displayName": "G", "members": [{"id": "u-group", "@odata.type": "#microsoft.graph.user"}]}]
    snapshot = _snapshot(
        _identity(
            user_rows=[_user("u-elig", accountEnabled=False), _user("u-group", accountEnabled=False), _user("u-ok")],
            assignments=[_assignment("g1"), _assignment("u-ok")],
            groups=[{"id": "g1", "displayName": "G", "isAssignableToRole": True}],
            members=members,
        ),
        _governance(eligible=[_schedule("u-elig")]),
    )

    findings = {row["id"]: row for row in _by_rule(snapshot, "identity.global_admin_disabled")}

    assert set(findings) == {"identity:global_admin_disabled:u-elig", "identity:global_admin_disabled:u-group"}
    assert findings["identity:global_admin_disabled:u-group"]["returned_value"]["routes"] == ["via_group"]
    keys = {ref["record_key"] for ref in findings["identity:global_admin_disabled:u-group"]["evidence_refs"]}
    assert {"effective_admin:u-group", "user:u-group"} <= keys
    assert "role_assignment:ra-g1-62e9" in keys and "group_membership_edge:member:g1:u-group" in keys
    for finding in findings.values():
        _assert_refs_resolve(snapshot, finding)


def test_a_stale_password_is_found_on_an_eligible_administrator() -> None:
    snapshot = _snapshot(
        _identity(user_rows=[_user("u-elig", lastPasswordChangeDateTime="2020-01-01T00:00:00Z")], assignments=[]),
        _governance(eligible=[_schedule("u-elig")]),
    )

    [finding] = _by_rule(snapshot, "identity.global_admin_stale_password")

    assert finding["affected_objects"] == ["u-elig@contoso.test"]
    _assert_refs_resolve(snapshot, finding)


def test_mfa_is_checked_for_eligible_and_group_administrators_and_not_duplicated() -> None:
    members = [{"groupId": "g1", "displayName": "G", "members": [{"id": "u-group", "@odata.type": "#microsoft.graph.user"}]}]
    registrations = [
        {"id": "u-elig", "userPrincipalName": "u-elig@contoso.test", "isMfaRegistered": False},
        {"id": "u-group", "userPrincipalName": "u-group@contoso.test", "isMfaRegistered": False},
        {"id": "u-exo", "userPrincipalName": "u-exo@contoso.test", "isMfaRegistered": False},
    ]
    snapshot = _snapshot(
        _identity(
            ["u-elig", "u-group", "u-exo"],
            [_assignment("g1"), _assignment("u-exo", EXCHANGE_ADMIN)],
            groups=[{"id": "g1", "displayName": "G", "isAssignableToRole": True}],
            members=members,
        ),
        _governance(eligible=[_schedule("u-elig")]),
        auth_methods={"userRegistrationDetails": {"value": registrations}},
    )

    critical = {row["affected_objects"][0] for row in _by_rule(snapshot, "identity.global_admin_mfa_not_registered")}
    privileged = _by_rule(snapshot, "identity.privileged_mfa_not_registered")

    assert critical == {"u-elig@contoso.test", "u-group@contoso.test"}
    assert [row["affected_objects"] for row in privileged] == [["u-exo@contoso.test"]]
    assert not _by_rule(snapshot, "identity.user_mfa_not_registered")
    for finding in _by_rule(snapshot, "identity.global_admin_mfa_not_registered"):
        _assert_refs_resolve(snapshot, finding)


def test_the_privileged_mfa_rule_records_the_group_a_role_comes_through() -> None:
    members = [{"groupId": "g1", "displayName": "G", "members": [{"id": "u-group", "@odata.type": "#microsoft.graph.user"}]}]
    snapshot = _snapshot(
        _identity(
            ["u-group"],
            [_assignment("g1", EXCHANGE_ADMIN)],
            groups=[{"id": "g1", "displayName": "G", "isAssignableToRole": True}],
            members=members,
        ),
        auth_methods={"userRegistrationDetails": {"value": [{"id": "u-group", "userPrincipalName": "u-group@contoso.test", "isMfaRegistered": False}]}},
    )

    [finding] = _by_rule(snapshot, "identity.privileged_mfa_not_registered")

    assert finding["evidence"]["privileged_roles"] == [{"role": "Exchange Administrator", "assignment": "group", "group_id": "g1"}]
    _assert_refs_resolve(snapshot, finding)


def test_a_privileged_stale_account_is_recognised_through_a_group() -> None:
    members = [{"groupId": "g1", "displayName": "G", "members": [{"id": "u-group", "@odata.type": "#microsoft.graph.user"}]}]
    snapshot = _snapshot(
        _identity(
            user_rows=[_user("u-group", createdDateTime="2024-01-01T00:00:00Z")],
            assignments=[_assignment("g1", EXCHANGE_ADMIN)],
            groups=[{"id": "g1", "displayName": "G", "isAssignableToRole": True}],
            members=members,
            extra={"userSignInActivity": {"value": [{"id": "u-group", "signInActivity": {"lastSuccessfulSignInDateTime": "2025-01-01T00:00:00Z"}}]}},
        )
    )

    [finding] = _by_rule(snapshot, "identity.privileged_stale_account")

    assert finding["evidence"]["privileged_roles"] == ["Exchange Administrator"]
    assert not _by_rule(snapshot, "identity.stale_enabled_account")
    _assert_refs_resolve(snapshot, finding)


def test_the_attack_path_finding_records_the_state_of_the_administrator_set() -> None:
    snapshot = _snapshot(
        _identity(
            ["u1", "u2"],
            [_assignment("u2")],
            groups=[],
        ),
        _governance(eligible=[_schedule("u1")]),
        auth_methods={"userRegistrationDetails": {"value": [{"id": "u1", "userPrincipalName": "u1@contoso.test", "isMfaRegistered": False}]}},
    )

    paths = _by_rule(snapshot, "attack_path.no_mfa_to_tier0")

    assert paths and all(row["evidence"]["effective_admin_set_state"] == "complete" for row in paths)


# --- baseline alignment -------------------------------------------------------------------------------


def test_five_global_administrators_fail_cis_and_pass_scuba() -> None:
    alignment = _alignment(_global_admins(5))

    assert _control(alignment, "cis_m365_v7", "1.1.3")["status"] == "fail"
    assert _rule_status(alignment, "cis_m365_v7", "1.1.3", "identity.global_admin_sprawl")["status"] == "fail"
    assert _control(alignment, "cisa_scuba", "MS.AAD.7.1v1")["status"] == "pass"
    assert _rule_status(alignment, "cisa_scuba", "MS.AAD.7.1v1", "identity.global_admin_sprawl") == {
        "rule_id": "identity.global_admin_sprawl", "status": "pass", "evaluated": True,
    }
    # A framework with no count of its own takes the finding as it is.
    assert _control(alignment, "mcsb", "PA-7")["status"] == "fail"


def test_nine_global_administrators_fail_both_frameworks() -> None:
    alignment = _alignment(_global_admins(9))

    assert _control(alignment, "cis_m365_v7", "1.1.3")["status"] == "fail"
    assert _control(alignment, "cisa_scuba", "MS.AAD.7.1v1")["status"] == "fail"


def test_four_global_administrators_pass_both_frameworks() -> None:
    alignment = _alignment(_global_admins(4))

    assert _control(alignment, "cis_m365_v7", "1.1.3")["status"] == "pass"
    assert _control(alignment, "cisa_scuba", "MS.AAD.7.1v1")["status"] == "pass"


def test_one_global_administrator_fails_both_minimums() -> None:
    alignment = _alignment(_global_admins(1))

    assert _control(alignment, "cis_m365_v7", "1.1.3")["status"] == "fail"
    assert _control(alignment, "cisa_scuba", "MS.AAD.7.1v1")["status"] == "fail"


def test_a_waived_sprawl_finding_is_accepted_risk_for_the_framework_it_breached() -> None:
    snapshot = _global_admins(5)
    findings = [{**row, "status": "accepted_risk"} for row in build_findings([], normalized_snapshot=snapshot)]

    alignment = build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=_ledger(*ALL_COLLECTORS))

    assert _control(alignment, "cis_m365_v7", "1.1.3")["status"] == "accepted_risk"
    assert _control(alignment, "cisa_scuba", "MS.AAD.7.1v1")["status"] == "pass"


@pytest.mark.parametrize(
    "rule_id",
    sorted(baselines._ADMIN_SET_RULES - {"identity.admin_holds_productivity_licence"}),
)
def test_every_administrator_set_rule_reads_not_assessed_when_the_set_is_unknown(rule_id: str) -> None:
    snapshot = _snapshot(_identity(["u1"], [_assignment("u1")]), governance={})
    ledger = _ledger(*ALL_COLLECTORS)
    summary = _summary(snapshot)

    row = baselines._rule_evaluation(rule_id, {}, {}, set(baselines._complete_collectors(ledger)), snapshot)

    assert summary["state"] == "unknown"
    assert row == {
        "rule_id": rule_id,
        "status": "not_assessed",
        "evaluated": False,
        "reason": "admin_set_unknown:role_assignment_schedules_absent,role_eligibility_schedules_absent",
    }


def test_the_same_rules_pass_when_the_set_is_complete_and_fail_when_they_have_a_finding() -> None:
    snapshot = _global_admins(3, signin=True)
    complete = set(baselines._complete_collectors(_ledger(*ALL_COLLECTORS)))

    for rule_id in baselines._ADMIN_SET_RULES - {"identity.admin_holds_productivity_licence"}:
        assert baselines._rule_evaluation(rule_id, {}, {}, complete, snapshot)["status"] == "pass", rule_id
        assert baselines._rule_evaluation(rule_id, {rule_id: ["f1"]}, {}, complete, snapshot)["status"] == "fail", rule_id


def test_a_finding_on_an_unknown_set_still_fails_its_rule() -> None:
    names = [f"ga-{index}" for index in range(5)]
    snapshot = _snapshot(_identity(names, [_assignment(name) for name in names]), governance={})

    alignment = _alignment(snapshot)

    assert _rule_status(alignment, "cis_m365_v7", "1.1.3", "identity.global_admin_sprawl")["status"] == "fail"
    assert _rule_status(alignment, "cis_m365_v7", "1.1.3", "identity.global_admin_singleton")["status"] == "not_assessed"
    assert _rule_status(alignment, "mcsb", "IM-6", "attack_path.no_mfa_to_tier0")["reason"].startswith("admin_set_unknown:")


def test_a_snapshot_without_the_section_is_not_assessed_not_passed() -> None:
    row = baselines._rule_evaluation(
        "identity.global_admin_singleton", {}, {}, {"identity"}, {"users": {"records": []}}
    )

    assert row["status"] == "not_assessed" and row["reason"] == "admin_set_not_collected"
    assert baselines._rule_evaluation("identity.global_admin_singleton", {}, {}, {"identity"}, None)["reason"] == "inputs_not_available"


def test_the_administrator_set_rules_are_the_rules_findings_builds_from_it() -> None:
    templates = json.loads((REPO_ROOT / "configs" / "finding-templates.json").read_text(encoding="utf-8"))
    mappings = json.loads((REPO_ROOT / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
    source = (REPO_ROOT / "src" / "azure_tenant_audit" / "findings.py").read_text(encoding="utf-8")

    assert baselines._ADMIN_SET_RULES <= set(templates) and baselines._ADMIN_SET_RULES <= set(mappings)
    for rule_id in baselines._ADMIN_SET_RULES - {"attack_path.no_mfa_to_tier0"}:
        assert f'"rule_id": "{rule_id}"' in source, rule_id
    # Every identity.global_admin_* rule is covered, and so is the no-MFA attack path.
    assert {rule for rule in templates if rule.startswith("identity.global_admin_")} <= baselines._ADMIN_SET_RULES
    assert "attack_path.no_mfa_to_tier0" in baselines._ADMIN_SET_RULES


# --- threshold configuration ----------------------------------------------------------------------------


_WORDS = {2: "two", 4: "four", 8: "eight"}


def test_the_thresholds_agree_with_the_catalog_and_with_what_each_rule_maps() -> None:
    mappings = json.loads((REPO_ROOT / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
    catalog = json.loads((REPO_ROOT / "configs" / "framework-catalog.json").read_text(encoding="utf-8"))["frameworks"]
    bounds = mappings["_rule_thresholds"]["global_administrator_count"]

    assert {row["framework"] for row in bounds} == {"cis_m365_v7", "cisa_scuba"}
    for bound in bounds:
        for control in bound["controls"]:
            title = catalog[bound["framework"]]["controls"][control].lower()
            assert f"{_WORDS[bound['minimum']]} to {_WORDS[bound['maximum']]}" in title or control == "MS.AAD.7.2v1", (control, title)
        # The bound lists exactly the controls each count rule maps for that framework.
        for rule_id in ("identity.global_admin_singleton", "identity.global_admin_sprawl"):
            assert sorted(bound["controls"]) == sorted(mappings[rule_id][bound["framework"]]), (rule_id, bound["framework"])
    # No count rule maps to the SCuBA ratio control, which a count cannot establish.
    assert "MS.AAD.7.2v1" not in {control for rule in mappings.values() if isinstance(rule, dict) for control in rule.get("cisa_scuba", [])}


# --- admin_holds_productivity_licence --------------------------------------------------------------------


def _licensed_admin_snapshot() -> dict[str, Any]:
    licensing = _licensing(
        {"sku-mail": ["EXCHANGE_S_STANDARD"], "sku-entra": ["AAD_PREMIUM"]},
        {"mail": [{"skuId": "sku-mail"}], "plain": [{"skuId": "sku-entra"}], "elig": [{"skuId": "sku-mail"}]},
    )
    return _snapshot(
        _identity(["mail", "plain", "elig", "bystander"], [_assignment("mail"), _assignment("plain", EXCHANGE_ADMIN)]),
        _governance(eligible=[_schedule("elig")]),
        licensing=licensing,
    )


def test_an_administrator_with_a_mailbox_or_productivity_licence_is_reported() -> None:
    snapshot = _licensed_admin_snapshot()

    findings = {row["affected_objects"][0]: row for row in _by_rule(snapshot, "identity.admin_holds_productivity_licence")}

    assert set(findings) == {"mail@contoso.test", "elig@contoso.test"}
    finding = findings["mail@contoso.test"]
    assert finding["severity"] == "medium" and finding["id"] == "identity:admin_holds_productivity_licence:mail"
    assert finding["evidence"] == {
        "mailbox_licence": True, "productivity_licence": False, "licence_sku_part_numbers": ["SKU-MAIL"],
        "role_names": ["Global Administrator"], "routes": ["direct_active"],
    }
    assert findings["elig@contoso.test"]["evidence"]["routes"] == ["pim_eligible"]
    assert finding["framework_mappings"]["cis_m365_v7"] == ["1.1.4"]
    assert finding["framework_mappings"]["cyber_essentials"] == ["ce.uac.separate_admin_accounts"]
    _assert_refs_resolve(snapshot, finding)


def test_the_licence_rule_stays_silent_when_licences_were_not_read() -> None:
    snapshot = _snapshot(_identity(["u1"], [_assignment("u1")]))

    assert not _by_rule(snapshot, "identity.admin_holds_productivity_licence")
    row = baselines._rule_evaluation(
        "identity.admin_holds_productivity_licence", {}, {}, {"identity", "licensing"}, snapshot
    )
    assert row["status"] == "not_assessed" and row["reason"] == "licence_data_unavailable:licence_skus_absent,licensed_users_absent"


def test_the_licence_rule_needs_the_licensing_collector_and_an_unambiguous_set() -> None:
    assert baselines.rule_evidence_collectors("identity.admin_holds_productivity_licence") == ("identity", "licensing")
    snapshot = _licensed_admin_snapshot()
    complete = {"identity", "licensing"}

    assert baselines._rule_evaluation("identity.admin_holds_productivity_licence", {}, {}, complete, snapshot)["status"] == "pass"
    assert baselines._rule_evaluation("identity.admin_holds_productivity_licence", {}, {}, {"identity"}, snapshot)["reason"] == (
        "collector_not_complete:licensing"
    )
    unknown_set = _snapshot(_identity(["u1"], [_assignment("u1")]), governance={}, licensing=_licensing({"s": ["TEAMS1"]}, {}))
    assert baselines._rule_evaluation("identity.admin_holds_productivity_licence", {}, {}, complete, unknown_set)["reason"].startswith(
        "admin_set_unknown:"
    )


def test_the_licence_rule_is_partial_evidence_for_separate_admin_accounts() -> None:
    snapshot = _licensed_admin_snapshot()
    alignment = _alignment(snapshot)

    row = next(
        item for item in alignment["frameworks"]["cyber_essentials"]["controls"] if item["control_id"] == "ce.uac.separate_admin_accounts"
    )

    assert row["requirement_status"] == "ce_plus_assessor_test" and row["status"] == "not_assessed"
    assert row["reason"] == "requirement_status:ce_plus_assessor_test"
    assert "identity.admin_holds_productivity_licence" in row["rule_ids"]
    (status,) = [item for item in row["rule_statuses"] if item["rule_id"] == "identity.admin_holds_productivity_licence"]
    assert status["status"] == "fail" and status["confidence"] == "partial"
    assert _control(alignment, "cis_m365_v7", "1.1.4")["status"] == "fail"


# --- guests ------------------------------------------------------------------------------------------------


def _days_ago(days: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _guest_snapshot(*, signin: list[dict[str, Any]] | None, assignments: list[dict[str, Any]] | None = None, **identity: Any) -> dict[str, Any]:
    users = [
        _user("g-old", userType="Guest", createdDateTime=_days_ago(500)),
        _user("g-100", userType="Guest", createdDateTime=_days_ago(500)),
        _user("g-recent", userType="Guest", createdDateTime=_days_ago(500)),
        _user("g-new", userType="Guest", createdDateTime=_days_ago(10)),
        _user("g-off", userType="Guest", createdDateTime=_days_ago(500), accountEnabled=False),
        _user("m-old", createdDateTime=_days_ago(500)),
    ]
    extra: dict[str, Any] = {}
    if signin is not None:
        extra["userSignInActivity"] = {"value": signin}
    extra.update(identity.pop("extra", {}))
    return _snapshot(_identity(user_rows=users, assignments=assignments or [], extra=extra, **identity))


def _signin(user: str, days: int | None) -> dict[str, Any]:
    return {"id": user, "signInActivity": {"lastSuccessfulSignInDateTime": _days_ago(days)} if days is not None else None}


_GUEST_SIGNIN = [
    _signin("g-old", 200), _signin("g-100", 100), _signin("g-recent", 5), _signin("g-new", None),
    _signin("g-off", 300), _signin("m-old", 300),
]


def test_a_guest_with_no_sign_in_for_the_default_ninety_days_is_stale() -> None:
    snapshot = _guest_snapshot(signin=_GUEST_SIGNIN)

    findings = {row["id"]: row for row in _by_rule(snapshot, "identity.stale_guest")}

    assert set(findings) == {"identity:stale_guest:g-old", "identity:stale_guest:g-100"}
    finding = findings["identity:stale_guest:g-old"]
    assert finding["severity"] == "medium" and finding["evidence"]["threshold_days"] == 90
    assert finding["title"] == "Guest account has not signed in successfully for over 90 days"
    assert finding["expected_value"] == "Guest accounts have signed in within 90 days or are removed."
    _assert_refs_resolve(snapshot, finding)


def test_a_stale_guest_is_not_also_a_stale_enabled_account() -> None:
    snapshot = _guest_snapshot(signin=_GUEST_SIGNIN)

    stale_accounts = {row["id"] for row in _by_rule(snapshot, "identity.stale_enabled_account")}

    assert stale_accounts == {"identity:stale_enabled_account:m-old"}


def test_the_stale_guest_threshold_is_configurable_by_argument_and_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = _guest_snapshot(signin=_GUEST_SIGNIN)

    assert {row["id"] for row in _by_rule(snapshot, "identity.stale_guest", stale_guest_days=150)} == {"identity:stale_guest:g-old"}
    monkeypatch.setenv("AUDITEX_STALE_GUEST_DAYS", "30")
    assert stale_guest_days() == 30
    assert {row["id"] for row in _by_rule(snapshot, "identity.stale_guest")} == {
        "identity:stale_guest:g-old", "identity:stale_guest:g-100",
    }
    # The argument wins over the environment.
    assert stale_guest_days(7) == 7 and stale_guest_days(None) == 30
    [finding] = [row for row in _by_rule(snapshot, "identity.stale_guest", stale_guest_days=150)]
    assert finding["evidence"]["threshold_days"] == 150 and "150 days" in finding["title"]


@pytest.mark.parametrize("value", ["", "abc", "0", "-5", "4000", "1.5"])
def test_an_unusable_threshold_falls_back_to_ninety_days(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("AUDITEX_STALE_GUEST_DAYS", value)

    assert stale_guest_days() == 90


def test_stale_guest_needs_sign_in_data_and_baselines_say_why_it_is_unknown() -> None:
    without = _guest_snapshot(signin=None)

    assert not _by_rule(without, "identity.stale_guest")
    row = baselines._rule_evaluation("identity.stale_guest", {}, {}, {"identity"}, without)
    assert row == {"rule_id": "identity.stale_guest", "status": "not_assessed", "evaluated": False, "reason": "signin_activity_unavailable"}
    with_data = _guest_snapshot(signin=_GUEST_SIGNIN)
    assert baselines._rule_evaluation("identity.stale_guest", {}, {}, {"identity"}, with_data)["status"] == "pass"
    assert baselines._rule_evaluation("identity.stale_guest", {"identity.stale_guest": ["f1"]}, {}, {"identity"}, with_data)["status"] == "fail"
    assert baselines._rule_evaluation("identity.stale_guest", {}, {}, {"identity"}, None)["reason"] == "inputs_not_available"


def test_a_tenant_with_no_guests_passes_the_stale_guest_rule_without_sign_in_data() -> None:
    snapshot = _snapshot(_identity(["m1"], []))

    assert baselines._rule_evaluation("identity.stale_guest", {}, {}, {"identity"}, snapshot)["status"] == "pass"


def test_a_guest_that_is_also_privileged_is_reported_once_by_the_privileged_stale_rule() -> None:
    snapshot = _guest_snapshot(signin=_GUEST_SIGNIN, assignments=[_assignment("g-old", EXCHANGE_ADMIN)])

    rules = {(row["rule_id"], row["affected_objects"][0]) for row in build_findings([], normalized_snapshot=snapshot)}

    assert ("identity.privileged_stale_account", "g-old@contoso.test") in rules
    assert ("identity.stale_guest", "g-old@contoso.test") not in rules
    assert ("identity.stale_guest", "g-100@contoso.test") in rules


def test_a_guest_holding_an_administrator_role_is_reported_by_every_route() -> None:
    members = [{"groupId": "g1", "displayName": "G", "members": [{"id": "guest-group", "@odata.type": "#microsoft.graph.user"}]}]
    snapshot = _snapshot(
        _identity(
            user_rows=[
                _user("guest-direct", userType="Guest"),
                _user("guest-elig", userType="Guest"),
                _user("guest-group", userType="Guest"),
                _user("guest-none", userType="Guest"),
                _user("member", userType="Member"),
            ],
            assignments=[_assignment("guest-direct", EXCHANGE_ADMIN), _assignment("g1"), _assignment("member")],
            groups=[{"id": "g1", "displayName": "G", "isAssignableToRole": True}],
            members=members,
        ),
        _governance(eligible=[_schedule("guest-elig", USER_ADMIN)]),
    )

    findings = {row["id"].rsplit(":", 1)[1]: row for row in _by_rule(snapshot, "identity.guest_with_privileged_role")}

    assert set(findings) == {"guest-direct", "guest-elig", "guest-group"}
    assert findings["guest-direct"]["severity"] == "high"
    assert findings["guest-direct"]["evidence"]["routes"] == ["direct_active"]
    assert findings["guest-elig"]["evidence"]["routes"] == ["pim_eligible"]
    assert findings["guest-group"]["evidence"]["global_administrator"] is True
    assert findings["guest-group"]["returned_value"]["roles"] == [{"role": "Global Administrator", "route": "via_group", "group_id": "g1"}]
    assert findings["guest-group"]["framework_mappings"]["cyber_essentials"] == ["ce.uac.special_access_privileges"]
    for finding in findings.values():
        _assert_refs_resolve(snapshot, finding)


def test_the_guest_role_rule_reads_the_administrator_set_state() -> None:
    unknown = _snapshot(_identity(user_rows=[_user("g", userType="Guest")], assignments=[]), governance={})

    row = baselines._rule_evaluation("identity.guest_with_privileged_role", {}, {}, {"identity"}, unknown)

    assert row["status"] == "not_assessed" and row["reason"].startswith("admin_set_unknown:")


# --- offline fixture ----------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fixture_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("admin-set")
    assert run_offline(FIXTURE, out, "fabrikam", "admin-set", auditor_profile="global-reader", plane="inventory") in {0, 1}
    return out / "fabrikam-admin-set"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_offline_fixture_resolves_every_route_and_validates(fixture_bundle: Path) -> None:
    section = _json(fixture_bundle / "normalized" / "effective_admin_set.json")
    rows = {row["principal_id"]: row for row in section["records"] if row["kind"] == "effective_admin"}
    (summary,) = [row for row in section["records"] if row["kind"] == "effective_admin_set_summary"]

    assert summary["state"] == "complete" and summary["licence_state"] == "known"
    assert summary["admin_count"] == 6 and summary["global_admin_count"] == 5 and summary["non_user_principal_count"] == 2
    assert {key: row["routes"] for key, row in rows.items() if row["counted"]} == {
        "effadm-user-01": ["direct_active"],
        "effadm-user-02": ["direct_active"],
        "effadm-user-03": ["pim_eligible"],
        "effadm-user-04": ["via_group"],
        "effadm-user-05": ["via_group"],
        "effadm-guest-01": ["pim_eligible"],
    }
    assert rows["effadm-group-admins"]["counted"] is False and rows["effadm-sp-01"]["counted"] is False
    assert rows["effadm-user-05"]["roles"][0]["nested_group"] is True
    assert _json(fixture_bundle / "validation.json")["valid"] is True
    assert build_validation_report(run_dir=fixture_bundle, read_only=True)["valid"] is True


def test_the_offline_fixture_raises_the_new_rules_and_every_reference_resolves(fixture_bundle: Path) -> None:
    findings = _json(fixture_bundle / "findings" / "findings.json")
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_rule.setdefault(finding["rule_id"], []).append(finding)

    assert {row["id"] for row in by_rule["identity.admin_holds_productivity_licence"]} == {
        "identity:admin_holds_productivity_licence:effadm-user-01",
        "identity:admin_holds_productivity_licence:effadm-user-03",
        "identity:admin_holds_productivity_licence:effadm-user-05",
    }
    assert [row["id"] for row in by_rule["identity.guest_with_privileged_role"]] == ["identity:guest_with_privileged_role:effadm-guest-01"]
    assert [row["id"] for row in by_rule["identity.stale_guest"]] == ["identity:stale_guest:effadm-guest-02"]
    assert [row["affected_objects"] for row in by_rule["identity.global_admin_mfa_not_registered"]] == [["cam.eligible@fabrikam.example"]]
    [sprawl] = by_rule["identity.global_admin_sprawl"]
    assert sprawl["returned_value"]["global_admin_count"] == 5 and sprawl["severity"] == "low"
    assert "identity.global_admin_singleton" not in by_rule and "identity.admin_set_unverified" not in by_rule
    index = EvidenceIndex(fixture_bundle)
    refs = [ref for finding in findings for ref in finding["evidence_refs"]]
    index.prime(refs)
    assert [(ref["artifact_path"], ref["record_key"]) for ref in refs if not index.resolve(ref).resolved] == []


def test_the_offline_fixture_reads_cis_failed_and_scuba_passed_for_five_administrators(fixture_bundle: Path) -> None:
    alignment = _json(fixture_bundle / "reports" / "report-pack.json")["baseline_alignment"]

    assert _control(alignment, "cis_m365_v7", "1.1.3")["status"] == "fail"
    assert _control(alignment, "cisa_scuba", "MS.AAD.7.1v1")["status"] == "pass"
    assert _control(alignment, "cis_m365_v7", "1.1.4")["status"] == "fail"


# --- privileged roles that do not say administrator, and the verdict's view of the set ---------------------


PARTNER_TIER2 = "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"
DIRECTORY_WRITERS = "9360feb5-f418-4baa-8175-e2a00bac4301"


def _with_extra_roles(*assignments: dict[str, Any], users: list[str]) -> dict[str, Any]:
    identity = _identity(users, list(assignments))
    identity["roleDefinitions"]["value"] += [
        {"id": PARTNER_TIER2, "displayName": "Partner Tier2 Support"},
        {"id": DIRECTORY_WRITERS, "displayName": "Directory Writers"},
    ]
    return _snapshot(identity)


def test_privileged_roles_without_administrator_in_the_name_make_their_holders_administrators() -> None:
    snapshot = _with_extra_roles(
        _assignment("u-partner", PARTNER_TIER2),
        _assignment("u-writer", DIRECTORY_WRITERS),
        _assignment("u-reader", "reader-role"),
        users=["u-partner", "u-writer", "u-reader"],
    )

    rows = _rows(snapshot)

    assert set(rows) == {"u-partner", "u-writer"}, "Global Reader is not a privileged role"
    assert rows["u-partner"]["role_names"] == ["Partner Tier2 Support"] and rows["u-partner"]["global_administrator"] is False
    assert _summary(snapshot)["admin_count"] == 2 and _summary(snapshot)["global_admin_count"] == 0


def test_the_administrator_scope_lists_enabled_counted_administrators_and_their_roles() -> None:
    from azure_tenant_audit.effective_admins import admin_scope

    users = [_user("ga-1"), _user("ga-2", accountEnabled=False), _user("u-exo")]
    identity = _identity(user_rows=users, assignments=[_assignment("ga-1"), _assignment("ga-2"), _assignment("u-exo", EXCHANGE_ADMIN)])
    snapshot = _snapshot(identity)

    scope = admin_scope(_records(snapshot), identity["roleDefinitions"]["value"])

    assert scope is not None and scope.complete is True
    assert scope.admin_principal_ids == frozenset({"ga-1", "u-exo"}), "a disabled administrator cannot sign in"
    assert scope.held_role_ids == frozenset({GLOBAL_ADMIN.lower(), EXCHANGE_ADMIN.lower()})
    assert GLOBAL_ADMIN.lower() in scope.privileged_role_ids and "reader-role" not in scope.privileged_role_ids
    assert scope.guest_admin_count == 0


def test_the_administrator_scope_is_incomplete_when_the_set_is_unknown_and_absent_without_one() -> None:
    from azure_tenant_audit.effective_admins import admin_scope

    snapshot = _snapshot(_identity(["u1"], [_assignment("u1")]), governance={})

    scope = admin_scope(_records(snapshot), [])

    assert scope is not None and scope.complete is False
    assert admin_scope([], []) is None
