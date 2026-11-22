"""Integrate wave 1, R040 outside part: an unverified break-glass exclusion is not a pass."""

from __future__ import annotations

from azure_tenant_audit.baselines import rule_inputs_gap
from azure_tenant_audit.normalize import build_normalized_snapshot


def _snapshot(exclude: dict) -> dict:
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


def test_i2_an_unverified_break_glass_exclusion_does_not_read_pass() -> None:
    unverified = _snapshot({"excludeGroups": ["g-ca-ex"]})
    assert rule_inputs_gap("ca.break_glass_exclusion_missing", unverified) == "break_glass_exclusion_unverified"
    assert rule_inputs_gap("ca.break_glass_exclusion_unverified", unverified) is None
    verified = _snapshot({"excludeUsers": ["u-bg1"]})
    assert rule_inputs_gap("ca.break_glass_exclusion_missing", verified) is None


def test_i9_duplicate_dmarc_records_fail_the_dmarc_controls() -> None:
    """R109: the duplicate-record finding decides the same DMARC controls as a missing record."""
    from azure_tenant_audit import dns_lookup
    from azure_tenant_audit.baselines import build_baseline_alignment
    from azure_tenant_audit.findings import build_findings

    posture = {
        "domain": "contoso.example",
        "dmarc": dns_lookup._summarize_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"]),
        "spf": {"present": True, "all_qualifier": "-"},
        "dkim": {"selectors_present": ["s"]},
        "mta_sts": {"dns_present": True},
    }
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"dns_posture": {"domains": {"value": []}, "domainPosture": {"value": [posture]}}},
    )
    findings = build_findings([], normalized_snapshot=snapshot)
    alignment = build_baseline_alignment(
        findings,
        normalized_snapshot=snapshot,
        coverage_ledger=[{"collector": "dns_posture", "coverage_status": "complete_exact_scope"}],
    )
    controls = {
        (framework, control["control_id"]): control
        for framework, entry in alignment["frameworks"].items()
        for control in entry["controls"]
    }
    assert controls[("cis_m365_v7", "2.1.10")]["status"] == "fail"
    assert "dns_posture.dmarc_multiple_records" in controls[("cis_m365_v7", "2.1.10")]["rule_ids"]
