"""Items handed over from the coverage and integrity work (CE+ product review of 2026-10-22).

* a blocked or cut beta update-profile list is "not read", never "no update profile" (the update ring rule);
* mailbox forwarding to a mail contact (``ForwardingAddress``) is forwarding, not only to an SMTP address;
* ``intune.device_noncompliant`` is not assessed while a device's compliance was never evaluated or is in its grace period.
"""
from __future__ import annotations

from typing import Any

import pytest

from azure_tenant_audit import endpoint_posture
from azure_tenant_audit.baselines import build_baseline_alignment, rule_inputs_gap
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

BLOCKED = {"error": "denied", "error_class": "insufficient_permissions"}
NOT_ASSIGNED = "intune_depth.update_ring_not_assigned"
DEFERRAL = "intune_depth.update_ring_deferral_excessive"
NONCOMPLIANT = "intune.device_noncompliant"


def _snapshot(**collectors: dict[str, Any]) -> dict[str, Any]:
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=collectors)


def _by_rule(snapshot: dict[str, Any], rule_id: str) -> list[dict[str, Any]]:
    return [row for row in build_findings([], normalized_snapshot=snapshot) if row.get("rule_id") == rule_id]


# ---- update profile lists ------------------------------------------------------------------------------------------


def _device(device_id: str, **fields: Any) -> dict[str, Any]:
    row = {
        "id": device_id,
        "deviceName": device_id,
        "operatingSystem": "Windows",
        "osVersion": "10.0.26200.1000",
        "complianceState": "compliant",
        "isEncrypted": True,
        "lastSyncDateTime": "2026-10-21T12:00:00Z",
    }
    row.update(fields)
    return {key: value for key, value in row.items() if value is not None}


def _updates(rings: list[dict[str, Any]], **depth: Any) -> dict[str, Any]:
    section = {"windowsUpdateRings": {"value": rings}, "windowsUpdateRingAssignments": {"value": []}, **depth}
    return _snapshot(intune={"managedDevices": {"value": [_device("w1")]}}, intune_depth=section)


def test_a_blocked_update_profile_list_is_not_read_as_no_profile() -> None:
    snapshot = _updates([], windowsQualityUpdateProfiles=dict(BLOCKED), windowsFeatureUpdateProfiles=dict(BLOCKED))

    assert not _by_rule(snapshot, NOT_ASSIGNED), "a refused beta list is not 'no update ring and no profile'"
    assert rule_inputs_gap(NOT_ASSIGNED, snapshot) == "update_profiles_blocked"


def test_profiles_with_unread_assignments_leave_the_rule_not_assessed() -> None:
    snapshot = _updates(
        [],
        windowsQualityUpdateProfiles={"value": [{"id": "q1", "displayName": "Quality"}]},
        windowsQualityUpdateProfileAssignments=dict(BLOCKED),
        windowsFeatureUpdateProfiles={"value": []},
        windowsFeatureUpdateProfileAssignments={"value": []},
    )

    assert not _by_rule(snapshot, NOT_ASSIGNED)
    assert rule_inputs_gap(NOT_ASSIGNED, snapshot) == "profile_assignments_blocked"


def test_profile_lists_read_in_full_still_let_the_rule_fire() -> None:
    snapshot = _updates(
        [],
        windowsQualityUpdateProfiles={"value": []},
        windowsFeatureUpdateProfiles={"value": []},
        windowsQualityUpdateProfileAssignments={"value": []},
        windowsFeatureUpdateProfileAssignments={"value": []},
    )

    assert _by_rule(snapshot, NOT_ASSIGNED)
    assert rule_inputs_gap(NOT_ASSIGNED, snapshot) is None


@pytest.mark.parametrize(
    "gap",
    [
        "update_profiles_blocked",
        "update_profiles_truncated",
        "profile_assignments_blocked",
        "profile_assignments_truncated",
        "profile_assignments_absent",
        "profile_assignments_unknown",
    ],
)
def test_every_update_profile_gap_is_the_reason_the_rule_is_not_assessed(gap: str) -> None:
    summary = {
        "kind": endpoint_posture.UPDATE_SUMMARY_KIND,
        "key": "update_management_summary:tenant",
        "rings_read_state": "collected",
        "ring_count": 0,
        "rings_assigned": 0,
        "devices_read_state": "collected",
        "windows_device_count": 3,
        "update_profiles_gap": gap,
    }
    snapshot = {endpoint_posture.UPDATE_SECTION: {"records": [summary]}}

    assert rule_inputs_gap(NOT_ASSIGNED, snapshot) == gap
    # The gap is taken first, ahead of the checks that follow it, and the finding stays quiet.
    assert rule_inputs_gap(NOT_ASSIGNED, {endpoint_posture.UPDATE_SECTION: {"records": [{**summary, "devices_read_state": "blocked"}]}}) == gap
    assert not _by_rule(snapshot, NOT_ASSIGNED)


def test_an_assigned_ring_makes_the_profile_gap_irrelevant_and_the_deferral_rule_never_reads_it() -> None:
    summary = {
        "kind": endpoint_posture.UPDATE_SUMMARY_KIND,
        "key": "update_management_summary:tenant",
        "rings_read_state": "collected",
        "ring_count": 1,
        "ring_assignments_read_state": "collected",
        "rings_assigned": 1,
        "devices_read_state": "collected",
        "windows_device_count": 3,
        "update_profiles_gap": "update_profiles_blocked",
    }
    ring = {"kind": endpoint_posture.UPDATE_RING_KIND, "assigned": True, "assignments_known": True, "key": "update_ring:r1"}
    snapshot = {endpoint_posture.UPDATE_SECTION: {"records": [summary, ring]}}

    assert rule_inputs_gap(NOT_ASSIGNED, snapshot) is None, "a ring is assigned whatever the profile lists say"
    unassigned = {**summary, "rings_assigned": 0, "ring_count": 0}
    assert rule_inputs_gap(DEFERRAL, {endpoint_posture.UPDATE_SECTION: {"records": [unassigned]}}) == "no_assigned_update_ring"


# ---- mailbox forwarding to a contact -------------------------------------------------------------------------------


def _forwarding(**fields: Any) -> dict[str, Any]:
    row = {"DisplayName": "Alice", "PrimarySmtpAddress": "alice@example.test", **fields}
    return _snapshot(exchange_policy={"mailboxForwarding": {"value": [row]}})


def test_forwarding_to_a_mail_contact_is_forwarding() -> None:
    (finding,) = _by_rule(_forwarding(ForwardingAddress="Contact B"), "exchange.mailbox_forwarding_configured")

    assert finding["severity"] == "high" and finding["affected_objects"] == ["Alice"]
    assert finding["returned_value"] == {"forwarding_address": "Contact B"}
    assert "mail contact" in finding["description"]


def test_forwarding_to_an_smtp_address_still_is_and_both_are_reported_together() -> None:
    (smtp,) = _by_rule(_forwarding(ForwardingSmtpAddress="smtp:x@example.net"), "exchange.mailbox_forwarding_configured")
    (both,) = _by_rule(
        _forwarding(ForwardingSmtpAddress="smtp:x@example.net", ForwardingAddress="Contact B"), "exchange.mailbox_forwarding_configured"
    )

    assert set(smtp["returned_value"]) == {"forwarding_smtp_address"}
    assert set(both["returned_value"]) == {"forwarding_smtp_address", "forwarding_address"}


def test_a_mailbox_with_no_forwarding_target_raises_nothing() -> None:
    assert not _by_rule(_forwarding(DeliverToMailboxAndForward=False), "exchange.mailbox_forwarding_configured")


# ---- device compliance never evaluated -----------------------------------------------------------------------------


def _devices(*rows: dict[str, Any]) -> dict[str, Any]:
    return _snapshot(intune={"managedDevices": {"value": list(rows)}})


def _noncompliant_status(snapshot: dict[str, Any]) -> dict[str, Any]:
    findings = build_findings([], normalized_snapshot=snapshot)
    alignment = build_baseline_alignment(
        findings,
        normalized_snapshot=snapshot,
        coverage_ledger=[{"collector": "intune", "coverage_status": "complete_exact_scope"}],
    )
    rows = [
        status
        for entry in alignment["frameworks"]["mcsb"]["controls"]
        for status in entry["rule_statuses"]
        if status["rule_id"] == NONCOMPLIANT
    ]
    assert rows, "the rule maps to MCSB PV-4"
    return rows[0]


@pytest.mark.parametrize("state", ["unknown", "inGracePeriod", "configManager", "", None])
def test_a_device_whose_compliance_was_never_evaluated_or_is_in_grace_is_not_assessed(state: str | None) -> None:
    snapshot = _devices(_device("w1"), _device("w2", complianceState=state))

    assert not _by_rule(snapshot, NONCOMPLIANT)
    assert rule_inputs_gap(NONCOMPLIANT, snapshot) == "compliance_unknown_for_1_devices"
    row = _noncompliant_status(snapshot)
    assert row["status"] == "not_assessed" and row["reason"] == "compliance_unknown_for_1_devices"


def test_every_device_compliant_passes_and_a_noncompliant_device_still_fails() -> None:
    clean = _devices(_device("w1"), _device("w2"))
    failing = _devices(_device("w1"), _device("w2", complianceState="noncompliant"), _device("w3", complianceState="unknown"))

    assert rule_inputs_gap(NONCOMPLIANT, clean) is None
    assert _noncompliant_status(clean)["status"] == "pass"
    assert [row["id"] for row in _by_rule(failing, NONCOMPLIANT)] == ["intune:w2:device_noncompliant"]
    assert _noncompliant_status(failing)["status"] == "fail", "a finding decides the rule whatever else is unknown"


@pytest.mark.parametrize("state", ["noncompliant", "error", "conflict"])
def test_the_decided_bad_states_raise_the_finding(state: str) -> None:
    assert len(_by_rule(_devices(_device("w1", complianceState=state)), NONCOMPLIANT)) == 1


def test_no_devices_is_not_a_pass_for_the_noncompliance_rule() -> None:
    snapshot = _devices()

    assert rule_inputs_gap(NONCOMPLIANT, snapshot) == "no_managed_devices"


def test_the_device_posture_summary_counts_the_devices_compliance_says_nothing_about() -> None:
    snapshot = _devices(
        _device("w1"),
        _device("w2", complianceState="inGracePeriod"),
        _device("w3", complianceState="unknown"),
        _device("w4", complianceState=None),
        _device("w5", complianceState="noncompliant"),
    )

    (summary,) = [row for row in snapshot["device_posture"]["records"] if row["kind"] == endpoint_posture.DEVICE_SUMMARY_KIND]

    assert summary["compliance_unknown"] == 3 and summary["compliance_in_grace_period"] == 1
