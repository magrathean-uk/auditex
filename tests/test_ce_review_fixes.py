"""Cyber Essentials rows after the CE+ product review of 2026-10-22: supporting evidence, caveats, Google bundles, licence gates."""
from __future__ import annotations

from typing import Any

import pytest

from auditex import reporting
from auditex.explorer import _baselines as explorer_baselines
from azure_tenant_audit import baselines
from azure_tenant_audit.baselines import build_baseline_alignment
from azure_tenant_audit.cyber_essentials import CE_FRAMEWORK_KEY

CE = CE_FRAMEWORK_KEY


def _ledger(*collectors: str, status: str = "complete_exact_scope") -> list[dict[str, Any]]:
    return [{"collector": name, "coverage_status": status} for name in collectors]


def _row(alignment: dict[str, Any], requirement_id: str) -> dict[str, Any]:
    (row,) = [row for row in alignment["frameworks"][CE]["controls"] if row["control_id"] == requirement_id]
    return row


def _rule(row: dict[str, Any], rule_id: str) -> dict[str, Any]:
    (status,) = [item for item in row["rule_statuses"] if item["rule_id"] == rule_id]
    return status


def _finding(rule_id: str, **extra: Any) -> dict[str, Any]:
    return {"id": f"{rule_id}:1", "rule_id": rule_id, "status": "open", **extra}


def _admin_set(state: str = "complete") -> dict[str, Any]:
    summary = {"kind": "effective_admin_set_summary", "key": "effective_admin_set_summary:summary", "state": state, "licence_state": "known"}
    return {"effective_admin_set": {"records": [summary]}}


# ---- supporting evidence ----------------------------------------------------------------------------------


def test_intune_noncompliance_is_listed_for_patching_but_never_fails_it() -> None:
    alignment = build_baseline_alignment([_finding("intune.device_noncompliant")], coverage_ledger=_ledger("intune"))

    row = _row(alignment, "ce.sum.vulnerability_fixes_14_days")

    assert row["status"] != "fail", "a compliance state does not say which setting failed"
    assert _rule(row, "intune.device_noncompliant") == {
        "rule_id": "intune.device_noncompliant",
        "status": "fail",
        "evaluated": True,
        "confidence": "supporting",
    }
    assert row["finding_ids"] == ["intune.device_noncompliant:1"] and row["evidence"]["rules_supporting"] == 1


def test_a_device_that_has_not_synced_still_fails_the_patching_requirement() -> None:
    alignment = build_baseline_alignment([_finding("intune.device_stale_sync")], coverage_ledger=_ledger("intune"))

    row = _row(alignment, "ce.sum.vulnerability_fixes_14_days")

    assert row["status"] == "fail" and row["confidence"] == "partial"


@pytest.mark.parametrize(
    "rule_id",
    ["identity.global_admin_sprawl", "identity.global_admin_disabled", "identity.guest_with_privileged_role"],
)
def test_administrator_counts_disabled_and_guest_administrators_do_not_fail_special_access(rule_id: str) -> None:
    alignment = build_baseline_alignment([_finding(rule_id)], normalized_snapshot=_admin_set(), coverage_ledger=_ledger("identity"))

    row = _row(alignment, "ce.uac.special_access_privileges")

    assert row["status"] != "fail", rule_id
    assert _rule(row, rule_id)["confidence"] == "supporting" and _rule(row, rule_id)["status"] == "fail"


def test_a_privileged_account_that_is_no_longer_used_fails_special_access_with_partial_confidence() -> None:
    alignment = build_baseline_alignment([_finding("identity.privileged_stale_account")], coverage_ledger=_ledger("identity"))

    row = _row(alignment, "ce.uac.special_access_privileges")

    assert row["status"] == "fail" and row["confidence"] == "partial"
    assert _rule(row, "identity.privileged_stale_account")["confidence"] == "partial"


def test_a_requirement_mapped_only_to_supporting_rules_says_so() -> None:
    from azure_tenant_audit.cyber_essentials import build_cyber_essentials_section

    entry = {"controls": {"ce.test.row": {"title": "t", "theme": "x", "status": "partial", "citation": "c"}}}
    section = build_cyber_essentials_section(
        entry,
        {"ce.test.row": {"rule.a"}},
        evaluate=lambda rule_id: {"rule_id": rule_id, "status": "fail", "evaluated": True},
        open_by_rule={"rule.a": ["f1"]},
        control_status=baselines._control_status,
        status_order=baselines._STATUS_ORDER,
        confidence={"rule.a": {"ce.test.row": "supporting"}},
    )

    (row,) = section["controls"]
    assert row["status"] == "not_assessed" and row["reason"] == "supporting_evidence_only"
    assert row["finding_ids"] == ["f1"] and "confidence" not in row


def test_a_failure_rests_on_full_confidence_only_when_a_failing_rule_tests_the_named_condition() -> None:
    from azure_tenant_audit.cyber_essentials import build_cyber_essentials_section

    entry = {"controls": {"ce.test.row": {"title": "t", "theme": "x", "status": "partial", "citation": "c"}}}

    def build(confidence: dict[str, str]) -> dict[str, Any]:
        section = build_cyber_essentials_section(
            entry,
            {"ce.test.row": {"rule.a", "rule.b"}},
            evaluate=lambda rule_id: {"rule_id": rule_id, "status": "fail" if rule_id == "rule.a" else "pass", "evaluated": True},
            open_by_rule={"rule.a": ["f1"]},
            control_status=baselines._control_status,
            status_order=baselines._STATUS_ORDER,
            confidence={rule: {"ce.test.row": value} for rule, value in confidence.items()},
        )
        return section["controls"][0]

    assert build({"rule.a": "full", "rule.b": "partial"})["confidence"] == "full"
    assert build({"rule.a": "partial", "rule.b": "full"})["confidence"] == "partial", "the passing rule's confidence is irrelevant"


def test_a_row_with_no_evaluated_rule_names_the_reasons() -> None:
    alignment = build_baseline_alignment([], coverage_ledger=_ledger("identity", status="partial_success"))

    row = _row(alignment, "ce.uac.special_access_privileges")

    assert row["status"] == "not_assessed" and row["reason"] == "rules_not_evaluated"
    assert "collector_not_complete:identity" in row["not_assessed_reasons"]


# ---- the markdown report and the explorer carry the caveats ---------------------------------------------


def _markdown(alignment: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    reporting._append_baseline_alignment_markdown(lines, alignment)
    return lines


def test_the_markdown_table_carries_title_reason_confidence_limits_and_supporting_rules() -> None:
    findings = [_finding("ca.mfa_not_enforced"), _finding("intune.device_noncompliant")]
    snapshot = {
        "identity_control_verdicts": {
            "records": [{"kind": "identity_control_verdict", "control": "effective_mfa", "verdict": "not_enforced"}]
        }
    }
    alignment = build_baseline_alignment(
        findings, normalized_snapshot=snapshot, coverage_ledger=_ledger("conditional_access", "intune", "identity")
    )
    lines = _markdown(alignment)
    header = next(line for line in lines if line.startswith("| Requirement | Title |"))

    assert "| Confidence | Evidence limits |" in header
    mfa = next(line for line in lines if line.startswith("| ce.uac.mfa_cloud_services "))
    assert "| fail |" in mfa and "| partial |" in mfa, "a failure rests on partial confidence here"
    assert "Per-user (legacy) MFA states are not read" in mfa
    assert "MFA implemented where available" in mfa, "the requirement title is shown"
    assert "CE+ test: Test case 4: Check multi-factor authentication configuration." in mfa
    patching = next(line for line in lines if line.startswith("| ce.sum.vulnerability_fixes_14_days "))
    assert "intune.device_noncompliant (supporting)" in patching
    unevaluated = next(line for line in lines if line.startswith("| ce.uac.special_access_privileges "))
    assert "rules_not_evaluated:" in unevaluated and "verdict" not in unevaluated.split("rules_not_evaluated:")[0]


def test_the_markdown_reason_for_an_unevaluated_row_is_not_empty() -> None:
    alignment = build_baseline_alignment([], coverage_ledger=_ledger("identity", status="partial_success"))

    row = next(line for line in _markdown(alignment) if line.startswith("| ce.sc.unnecessary_accounts "))

    assert "rules_not_evaluated: collector_not_complete:identity" in row


def test_the_explorer_note_gives_the_actual_reasons_confidence_and_limits() -> None:
    findings = [_finding("identity.privileged_stale_account")]
    alignment = build_baseline_alignment(findings, coverage_ledger=_ledger("identity"))
    card = next(card for card in explorer_baselines(alignment)["frameworks"] if card["key"] == CE)
    controls = {control["id"]: control for control in card["controls"]}

    failed = controls["ce.uac.special_access_privileges"]
    assert failed["status"] == "fail"
    assert "proxy or a subset" in failed["note"] and "Only an administrator who has not signed in" in failed["note"]

    unevaluated_alignment = build_baseline_alignment([], coverage_ledger=_ledger("identity", status="partial_success"))
    unevaluated_card = next(card for card in explorer_baselines(unevaluated_alignment)["frameworks"] if card["key"] == CE)
    note = {control["id"]: control for control in unevaluated_card["controls"]}["ce.uac.special_access_privileges"]["note"]
    assert "No mapped rule could be evaluated: collector_not_complete:identity." in note
    assert "No collector in this run evidences this control" not in note


def test_benchmark_rows_in_the_explorer_also_say_why_they_were_not_evaluated() -> None:
    alignment = build_baseline_alignment([], coverage_ledger=_ledger("identity", status="partial_success"))
    card = next(card for card in explorer_baselines(alignment)["frameworks"] if card["key"] == "cis_m365_v7")

    note = {control["id"]: control for control in card["controls"]}["1.1.3"]["note"]

    assert note.startswith("No mapped rule could be evaluated: collector_not_complete:identity")


# ---- Google Workspace bundles ----------------------------------------------------------------------------


def _google_snapshot(*, truncated: tuple[str, ...] = (), two_step: str = "enforcing") -> dict[str, Any]:
    return {"snapshot": {"platform": "google_workspace", "truncated_sections": list(truncated), "two_step_policy_status": two_step}}


GOOGLE_LEDGER = _ledger("google_directory", "google_policies", "google_devices")


def test_a_google_bundle_lists_only_google_rules_and_shows_the_ones_that_ran_clean() -> None:
    alignment = build_baseline_alignment([], normalized_snapshot=_google_snapshot(), coverage_ledger=GOOGLE_LEDGER)

    mfa = _row(alignment, "ce.uac.mfa_cloud_services")

    assert all(rule.startswith("google.") for rule in mfa["rule_ids"])
    assert {"google.user_2sv_not_enforced", "google.admin_2sv_not_enforced", "google.org_2sv_policy_not_enforced"} <= set(mfa["rule_ids"])
    assert mfa["status"] == "not_assessed" and mfa["reason"] == "partial_requirement_no_gap_found"
    assert mfa["evidence"]["rules_evaluated"] == mfa["evidence"]["rules_passed"] == mfa["evidence"]["rules_mapped"] > 0
    antimalware = _row(alignment, "ce.mp.antimalware")
    assert antimalware["rule_ids"] == [] and antimalware["reason"] == "no_mapped_rules"
    assert not [row for row in alignment["frameworks"][CE]["controls"] if any(not rule.startswith("google.") for rule in row["rule_ids"])]


def test_a_google_rule_with_a_finding_fails_and_one_that_read_a_cut_list_is_not_assessed() -> None:
    findings = [_finding("google.user_2sv_not_enforced", framework_mappings={CE: ["ce.uac.mfa_cloud_services"]})]
    snapshot = _google_snapshot(truncated=("google_directory.users",))

    row = _row(build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=GOOGLE_LEDGER), "ce.uac.mfa_cloud_services")

    assert row["status"] == "fail" and _rule(row, "google.user_2sv_not_enforced")["confidence"] == "full"
    assert _rule(row, "google.admin_2sv_not_enforced") == {
        "rule_id": "google.admin_2sv_not_enforced",
        "status": "not_assessed",
        "evaluated": False,
        "reason": "users_truncated",
        "confidence": "full",
    }


def test_the_organisation_two_step_policy_rule_needs_a_known_policy_status() -> None:
    unknown = _row(
        build_baseline_alignment([], normalized_snapshot=_google_snapshot(two_step="unknown"), coverage_ledger=GOOGLE_LEDGER),
        "ce.uac.mfa_admin_accounts",
    )

    assert _rule(unknown, "google.org_2sv_policy_not_enforced")["reason"] == "two_step_policy_unknown"


def test_a_google_collector_that_did_not_complete_leaves_its_rules_not_assessed() -> None:
    ledger = _ledger("google_policies") + _ledger("google_directory", status="partial_success")

    row = _row(build_baseline_alignment([], normalized_snapshot=_google_snapshot(), coverage_ledger=ledger), "ce.uac.remove_unused_accounts")

    assert _rule(row, "google.stale_user")["reason"] == "collector_not_complete:google_directory"


def test_google_checks_google_reported_no_evidence_for_are_not_passed() -> None:
    unknown = {
        "id": "google.evidence_unknown:user_login_time",
        "rule_id": "google.evidence_unknown",
        "status": "open",
        "returned_value": {"check": "user_login_time", "rules_not_evaluated": ["google.stale_user", "google.never_logged_in_user"]},
    }

    row = _row(build_baseline_alignment([unknown], normalized_snapshot=_google_snapshot(), coverage_ledger=GOOGLE_LEDGER), "ce.uac.remove_unused_accounts")

    assert _rule(row, "google.stale_user")["reason"] == "evidence_not_returned:user_login_time"
    assert _rule(row, "google.admin_stale_login")["status"] == "pass"


def test_a_microsoft_bundle_never_lists_google_rules() -> None:
    finding = _finding("google.user_2sv_not_enforced", framework_mappings={CE: ["ce.uac.mfa_cloud_services"]})
    alignment = build_baseline_alignment([], normalized_snapshot={"snapshot": {"tenant_name": "acme"}}, coverage_ledger=_ledger("identity"))

    assert not [rule for row in alignment["frameworks"][CE]["controls"] for rule in row["rule_ids"] if rule.startswith("google.")]
    assert finding  # the finding exists only to show what a Microsoft bundle would never receive


# ---- licence-gated reads ---------------------------------------------------------------------------------


def _licensed_ledger(collector: str, *items: str, extra_error: str | None = None) -> list[dict[str, Any]]:
    """A ledger where ``collector`` is partial only because the given items were refused for want of a licence."""
    diagnostics = [{"collector": collector, "item": item, "status": "failed", "error_class": "license_required"} for item in items]
    if extra_error:
        diagnostics.append({"collector": collector, "item": "users", "status": "failed", "error_class": extra_error})
    row = {"collector": collector, "coverage_status": "partial_success", "diagnostics": diagnostics}
    others = [name for name in ("identity", "auth_methods", "identity_governance", "licensing") if name != collector]
    return [row, *_ledger(*others)]


def _users(*, signin: bool | None) -> dict[str, Any]:
    return {"users": {"records": [{"id": "u1", "enabled": True, "user_type": "member", "signin_data_available": signin}]}}


def test_a_refused_sign_in_read_does_not_stop_the_administrator_rules_being_evaluated() -> None:
    ledger = _licensed_ledger("identity", "userSignInActivity")
    snapshot = {**_admin_set(), **_users(signin=None)}

    alignment = build_baseline_alignment([], normalized_snapshot=snapshot, coverage_ledger=ledger)
    row = _row(alignment, "ce.uac.special_access_privileges")

    for rule_id in ("identity.global_admin_disabled", "identity.global_admin_sprawl", "identity.guest_with_privileged_role"):
        assert _rule(row, rule_id)["status"] == "pass", rule_id
    # The rules that read the refused section are still not assessed, and say why.
    stale = _rule(row, "identity.privileged_stale_account")
    assert stale["status"] == "not_assessed" and stale["reason"] == "collector_not_complete:identity"
    unnecessary = _row(alignment, "ce.sc.unnecessary_accounts")
    assert _rule(unnecessary, "identity.stale_enabled_account")["reason"] == "collector_not_complete:identity"


def test_a_refused_sign_in_read_is_a_gap_in_the_stale_rules_even_when_identity_counts_as_complete() -> None:
    snapshot = _users(signin=None)
    guest = {"users": {"records": [{"id": "g1", "enabled": True, "user_type": "guest", "signin_data_available": None}]}}

    for rule_id, rows in (("identity.stale_enabled_account", snapshot), ("identity.stale_guest", guest)):
        row = baselines._rule_evaluation(rule_id, {}, {}, {"identity"}, rows)
        assert row["reason"] == "signin_activity_unavailable", rule_id
    # A guest rule judges guests only: a member with no sign-in data is not its gap.
    assert baselines._rule_evaluation("identity.stale_guest", {}, {}, {"identity"}, snapshot)["status"] == "pass"
    with_data = baselines._rule_evaluation("identity.stale_enabled_account", {}, {}, {"identity"}, _users(signin=True))
    assert with_data["status"] == "pass"


def test_the_privileged_stale_rule_needs_sign_in_data_for_the_administrators_only() -> None:
    def snapshot(signin: bool | None) -> dict[str, Any]:
        admin = {"kind": "effective_admin", "principal_id": "ga-1", "counted": True, "key": "effective_admin:ga-1"}
        users = [
            {"id": "ga-1", "enabled": True, "user_type": "member", "signin_data_available": signin},
            {"id": "u-other", "enabled": True, "user_type": "member", "signin_data_available": None},
        ]
        return {"effective_admin_set": {"records": [_admin_set()["effective_admin_set"]["records"][0], admin]}, "users": {"records": users}}

    rule = "identity.privileged_stale_account"

    assert baselines._rule_evaluation(rule, {}, {}, {"identity"}, snapshot(True))["status"] == "pass"
    assert baselines._rule_evaluation(rule, {}, {}, {"identity"}, snapshot(None))["reason"] == "signin_activity_unavailable"


def test_a_collector_with_any_other_failure_is_not_treated_as_licence_limited() -> None:
    ledger = _licensed_ledger("identity", "userSignInActivity", extra_error="insufficient_permissions")

    row = _row(
        build_baseline_alignment([], normalized_snapshot={**_admin_set(), **_users(signin=None)}, coverage_ledger=ledger),
        "ce.uac.special_access_privileges",
    )

    assert _rule(row, "identity.global_admin_sprawl")["reason"] == "collector_not_complete:identity"


def test_a_refused_pim_schedule_read_does_not_stop_the_privileged_mfa_rule() -> None:
    ledger = _licensed_ledger("identity_governance", "roleAssignmentSchedules", "roleEligibilitySchedules")

    row = _row(build_baseline_alignment([], normalized_snapshot=_admin_set(), coverage_ledger=ledger), "ce.uac.mfa_admin_accounts")

    assert _rule(row, "identity.privileged_mfa_not_registered")["status"] == "pass"


def test_a_refused_pim_read_does_not_make_the_governance_rules_evaluated() -> None:
    ledger = _licensed_ledger("identity_governance", "roleAssignmentSchedules")

    row = baselines._rule_evaluation(
        "identity_governance.standing_privilege_only", {}, {}, baselines._complete_collectors(ledger), None, set(),
        baselines._licence_limited_collectors(ledger),
    )

    assert row["status"] == "not_assessed" and row["reason"] == "collector_not_complete:identity_governance"


def test_licence_limits_come_only_from_the_licence_gated_sections_of_the_listed_collectors() -> None:
    assert baselines._licence_limited_collectors(_licensed_ledger("identity", "userSignInActivity")) == {"identity"}
    assert baselines._licence_limited_collectors(_licensed_ledger("identity", "users")) == set()
    assert baselines._licence_limited_collectors(_licensed_ledger("auth_methods", "userRegistrationDetails")) == set()
    assert baselines._licence_limited_collectors(None) == set()


# ---- anonymous access and licence-refusal severity ---------------------------------------------------------


def test_anyone_links_and_public_sharing_are_supporting_evidence_for_user_authentication() -> None:
    findings = [
        _finding("sharepoint.external_sharing_broad"),
        _finding("google.drive_anyone_with_link", framework_mappings={CE: ["ce.sc.user_authentication"]}),
    ]
    microsoft = _row(build_baseline_alignment(findings[:1], coverage_ledger=_ledger("sharepoint_access")), "ce.sc.user_authentication")
    google = _row(
        build_baseline_alignment(
            findings[1:],
            normalized_snapshot=_google_snapshot(),
            coverage_ledger=GOOGLE_LEDGER + _ledger("google_drive_posture", "google_calendar_posture", "google_groups_settings"),
        ),
        "ce.sc.user_authentication",
    )

    for row in (microsoft, google):
        assert row["requirement_status"] == "manual" and row["status"] == "not_assessed"
        assert row["reason"] == "requirement_status:manual"
        assert row["evidence"]["rules_failed"] == 1
        assert row["evidence"]["rules_supporting"] == row["evidence"]["rules_mapped"]
    # The Google bundle also lists the other three public-sharing rules, which ran clean.
    assert microsoft["evidence"]["rules_mapped"] == 1 and google["evidence"]["rules_mapped"] == 4
    assert google["evidence"]["rules_passed"] == 3
    assert "No Auditex rule reads this" not in microsoft["evidence_limits"]


def test_only_anyone_links_are_anonymous_access_for_cyber_essentials() -> None:
    from azure_tenant_audit.external_sharing import grade_external_sharing

    anyone = grade_external_sharing({"sharing_capability": "externalUserAndGuestSharing"})
    guests = grade_external_sharing({"sharing_capability": "externalUserSharingOnly"})

    assert anyone is not None and anyone["breaches"]["cyber_essentials"] is True
    assert guests is not None and guests["breaches"]["cyber_essentials"] is False


def test_a_licence_refusal_is_a_medium_collector_issue_and_a_permission_block_stays_high() -> None:
    from azure_tenant_audit.findings import _severity_for

    assert _severity_for("license_required", "failed") == "medium"
    assert _severity_for("insufficient_permissions", "failed") == "high"
    assert _severity_for("client_error", "failed") == "high"


def test_the_member_stale_rule_ignores_guests_without_sign_in_data() -> None:
    snapshot = {
        "users": {
            "records": [
                {"id": "m1", "enabled": True, "user_type": "member", "signin_data_available": True},
                {"id": "g1", "enabled": True, "user_type": "guest", "signin_data_available": None},
            ]
        }
    }

    assert baselines._rule_evaluation("identity.stale_enabled_account", {}, {}, {"identity"}, snapshot)["status"] == "pass"
    assert baselines._rule_evaluation("identity.stale_guest", {}, {}, {"identity"}, snapshot)["reason"] == "signin_activity_unavailable"
