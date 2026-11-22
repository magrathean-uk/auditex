"""Integrate wave 1, repair round 1: review blockers B1 (R111) and B2 (R040)."""

from __future__ import annotations

from datetime import UTC, date, datetime

from azure_tenant_audit.baselines import BASELINE_FRAMEWORK_KEYS, build_baseline_alignment, rule_inputs_gap
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot


def _controls(alignment: dict) -> dict:
    return {
        (framework, control["control_id"]): control
        for framework, entry in alignment["frameworks"].items()
        for control in entry["controls"]
    }


# ---- B2 (R040): the unverified break-glass diagnostic claims no baseline control -----------------------------


def _break_glass_snapshot(exclude: dict) -> dict:
    payloads = {
        "identity": {
            "users": {"value": [{"id": "u-bg1", "displayName": "Emergency One", "userPrincipalName": "bg1@example.com"}]},
            "groups": {"value": [{"id": "g-ca-ex", "displayName": "CA Exclusions", "isAssignableToRole": False}]},
            "roleDefinitions": {"value": []},
            "roleAssignments": {"value": []},
        },
        "conditional_access": {"conditionalAccessPolicies": {"value": [{
            "id": "mfa-all",
            "displayName": "Policy mfa-all",
            "state": "enabled",
            "conditions": {"users": {"includeUsers": ["All"], **exclude}, "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["all"]},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        }]}},
    }
    return build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads=payloads, break_glass_accounts=["bg1@example.com"]
    )


def test_b2_a_group_exclusion_that_was_not_read_does_not_fail_the_zero_trust_identities_control() -> None:
    snapshot = _break_glass_snapshot({"excludeGroups": ["g-ca-ex"]})
    findings = build_findings([], normalized_snapshot=snapshot)
    assert any(item.get("rule_id") == "ca.break_glass_exclusion_unverified" for item in findings)
    alignment = build_baseline_alignment(
        findings,
        normalized_snapshot=snapshot,
        coverage_ledger=[
            {"collector": "identity", "coverage_status": "complete_exact_scope"},
            {"collector": "conditional_access", "coverage_status": "complete_exact_scope"},
        ],
    )
    controls = _controls(alignment)
    identities = controls[("ms_zero_trust", "identities")]
    rows = {row["rule_id"]: row for row in identities["rule_statuses"]}
    # The diagnostic says the exclusion was not assessed; it must not fail the control it cannot judge.
    assert "ca.break_glass_exclusion_unverified" not in rows, rows.get("ca.break_glass_exclusion_unverified")
    assert rows["ca.break_glass_exclusion_missing"]["status"] == "not_assessed"
    assert rows["ca.break_glass_exclusion_missing"]["reason"] == "break_glass_exclusion_unverified"
    for (framework, _control_id), control in controls.items():
        if framework in BASELINE_FRAMEWORK_KEYS:
            assert "ca.break_glass_exclusion_unverified" not in control["rule_ids"], (framework, _control_id)


def test_b2_the_missing_exclusion_rule_reads_not_assessed_while_the_group_is_unread() -> None:
    """The baselines.py change of R040: without it the missing-exclusion rule would read pass."""
    unverified = _break_glass_snapshot({"excludeGroups": ["g-ca-ex"]})
    assert rule_inputs_gap("ca.break_glass_exclusion_missing", unverified) == "break_glass_exclusion_unverified"
    assert rule_inputs_gap("ca.break_glass_exclusion_missing", _break_glass_snapshot({"excludeUsers": ["u-bg1"]})) is None
