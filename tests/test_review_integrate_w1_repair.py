"""Integrate wave 1, repair round 1: review blockers B1 (R111) and B2 (R040)."""

from __future__ import annotations

from datetime import UTC, date, datetime

from azure_tenant_audit.baselines import (
    BASELINE_FRAMEWORK_KEYS,
    build_baseline_alignment,
    rule_inputs_gap,
)
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


# ---- B1 (R111): only platforms known to be outside the table leave the end-of-life rule's scope -------------

_EOL_RULE = "intune.device_os_end_of_life"
_EOL_CONTROLS = (("ms_zero_trust", "endpoints"), ("mcsb", "PV-4"), ("cyber_essentials", "ce.sum.supported_software"))
_NOW = datetime(2026, 11, 22, 12, tzinfo=UTC)


def _device(device_id: str, system: str, version: str) -> dict:
    return {
        "id": device_id, "deviceName": device_id, "operatingSystem": system, "osVersion": version,
        "complianceState": "compliant", "isEncrypted": True, "lastSyncDateTime": "2026-11-21T00:00:00Z",
    }


def _eol_rows(devices: list[dict]) -> tuple[dict, list[dict]]:
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads={"intune": {"managedDevices": {"value": devices}}}
    )
    findings = build_findings([], normalized_snapshot=snapshot, now=_NOW)
    alignment = build_baseline_alignment(
        findings,
        normalized_snapshot=snapshot,
        coverage_ledger=[{"collector": "intune", "coverage_status": "complete_exact_scope"}],
    )
    controls = _controls(alignment)
    rows = []
    for key in _EOL_CONTROLS:
        (row,) = [item for item in controls[key]["rule_statuses"] if item["rule_id"] == _EOL_RULE]
        rows.append({"control": key, **row})
    return snapshot, rows


def _summary(devices: list[dict]) -> dict:
    from azure_tenant_audit import endpoint_posture

    return endpoint_posture.device_posture_summary(devices, read_state="collected", today=date(2026, 11, 22))


def test_b1_an_unrecognised_platform_is_unknown_not_outside_the_table() -> None:
    """Intune reports ``operatingSystem: "Unknown"`` for a device it cannot identify: that could be anything."""
    summary = _summary([{"platform": "Windows", "os_version": "10.0.26200.1000"}, {"platform": "Unknown", "os_version": "6.1.7601"}])
    assert summary["os_lifecycle_not_covered"] == 0
    assert summary["os_lifecycle_unknown"] == 1
    assert summary["os_lifecycle_unknown_reasons"] == [{"reason": "platform_unrecognised", "count": 1}]

    snapshot, rows = _eol_rows([_device("w11", "Windows", "10.0.26200.1000"), _device("w7", "Unknown", "6.1.7601")])
    assert rule_inputs_gap(_EOL_RULE, snapshot) == "os_lifecycle_unknown_for_1_devices"
    assert [row["status"] for row in rows] == ["not_assessed"] * 3, rows


def test_b1_named_platforms_outside_the_table_are_still_counted_apart() -> None:
    summary = _summary([
        {"platform": "Linux", "os_version": "6.1"},
        {"platform": "Windows Server 2019", "os_version": "10.0.17763.6000"},
        {"platform": "Windows Phone", "os_version": "8.1"},
    ])
    assert (summary["os_lifecycle_not_covered"], summary["os_lifecycle_unknown"]) == (3, 0)


def test_b1_no_device_in_the_tables_scope_is_not_a_pass() -> None:
    snapshot, rows = _eol_rows([_device("lx", "Linux", "6.1"), _device("srv", "Windows Server 2012 R2", "6.3.9600")])
    assert rule_inputs_gap(_EOL_RULE, snapshot) == "no_devices_in_os_lifecycle_scope"
    assert [row["status"] for row in rows] == ["not_assessed"] * 3, rows


def test_b1_a_windows_7_kernel_device_never_reads_pass() -> None:
    _snapshot, rows = _eol_rows([_device("w11", "Windows", "10.0.26200.1000"), _device("w7", "Windows", "6.1.7601")])
    assert "pass" not in [row["status"] for row in rows], rows


def test_b1_a_supported_fleet_beside_an_uncovered_platform_still_passes() -> None:
    snapshot, rows = _eol_rows([_device("w11", "Windows", "10.0.26200.1000"), _device("lx", "Linux", "6.1")])
    assert rule_inputs_gap(_EOL_RULE, snapshot) is None
    assert [row["status"] for row in rows] == ["pass"] * 3, rows
