"""Normalization, findings and baseline status for the device, compliance, update and Defender rules.

Every rule here is judged from collector payloads through the real pipeline (normalize, findings, baseline
alignment). Dates are relative to a fixed ``NOW`` so no test depends on the day it runs.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit import endpoint_posture
from azure_tenant_audit.baselines import build_baseline_alignment, rule_inputs_gap
from azure_tenant_audit.findings import build_findings
from azure_tenant_audit.normalize import build_normalized_snapshot

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
ALL_DEVICES = {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}
GROUP = {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g1"}
BLOCKED = {"error": "denied", "error_class": "insufficient_permissions"}


@pytest.fixture(autouse=True)
def _fixed_day(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(endpoint_posture, "today_utc", lambda: NOW.date())
    monkeypatch.delenv(endpoint_posture.STALE_SYNC_DAYS_ENV, raising=False)


def _ago(days: float) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _device(device_id: str, system: str = "Windows", version: str = "10.0.26200.1000", **fields: Any) -> dict[str, Any]:
    row = {"id": device_id, "deviceName": device_id.upper(), "operatingSystem": system, "osVersion": version, "complianceState": "compliant",
           "isEncrypted": True, "lastSyncDateTime": _ago(1)}
    if system in {"iOS", "Android"}:
        row["jailBroken"] = "False"
    row.update(fields)
    return {key: value for key, value in row.items() if value is not None}


def _snapshot(**collectors: dict[str, Any]) -> dict[str, Any]:
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=collectors)


def _findings(snapshot: dict[str, Any], **kwargs: Any) -> list[dict[str, Any]]:
    return build_findings([], normalized_snapshot=snapshot, now=NOW, **kwargs)


def _by_rule(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [item for item in findings if item["rule_id"] == rule_id]


def _devices(*rows: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"intune": {"managedDevices": {"value": list(rows)}, **extra}}


def _record(snapshot: dict[str, Any], section: str, kind: str) -> dict[str, Any]:
    return next(row for row in snapshot[section]["records"] if row["kind"] == kind)


# ---- device posture ---------------------------------------------------------------------------------------


def test_device_rules_fire_once_per_device_with_their_documented_severity() -> None:
    snapshot = _snapshot(
        **_devices(
            _device("win-open", isEncrypted=False),
            _device("ios-open", "iOS", "18.5", isEncrypted=False, jailBroken="True"),
            _device("win10", version="10.0.19045.5371"),
            _device("android11", "Android", "11"),
            _device("old-mac", "macOS", "13.6", lastSyncDateTime=_ago(40)),
            _device("good"),
        )
    )
    findings = _findings(snapshot)

    encryption = {item["id"]: item["severity"] for item in _by_rule(findings, "intune.device_encryption_off")}
    assert encryption == {"intune:win-open:device_encryption_off": "high", "intune:ios-open:device_encryption_off": "medium"}
    jailbroken = _by_rule(findings, "intune.device_jailbroken")
    assert [(item["id"], item["severity"]) for item in jailbroken] == [("intune:ios-open:device_jailbroken", "high")]
    stale = _by_rule(findings, "intune.device_stale_sync")
    assert [item["id"] for item in stale] == ["intune:old-mac:device_stale_sync"]
    assert stale[0]["evidence"]["stale_after_days"] == 14 and "14 days" in stale[0]["description"]

    end_of_life = {item["id"]: item for item in _by_rule(findings, "intune.device_os_end_of_life")}
    assert set(end_of_life) == {"intune:win10:device_os_end_of_life", "intune:android11:device_os_end_of_life", "intune:old-mac:device_os_end_of_life"}
    windows = end_of_life["intune:win10:device_os_end_of_life"]
    # The paid Extended Security Updates window is still open, so the finding is medium and says so.
    assert windows["severity"] == "medium" and "2028-10-10" in windows["description"]
    assert windows["evidence"]["os_lifecycle"]["end_of_support"] == "2025-10-14"
    assert windows["evidence"]["os_lifecycle_table_verified_on"]
    assert end_of_life["intune:android11:device_os_end_of_life"]["severity"] == "medium"
    assert "good" not in {item["affected_objects"][0].lower() for item in findings if item["rule_id"].startswith("intune.device")}


def test_an_end_of_life_release_is_high_once_no_extended_programme_remains() -> None:
    findings = _findings(_snapshot(**_devices(_device("win11-old", version="10.0.22000.100"))))
    (item,) = _by_rule(findings, "intune.device_os_end_of_life")
    assert item["severity"] == "high" and item["evidence"]["os_lifecycle"]["confidence"] == "vendor_published"


def test_a_device_with_an_unknown_field_is_never_a_finding() -> None:
    snapshot = _snapshot(
        **_devices(
            _device("no-flags", "iOS", "18.5", isEncrypted=None, jailBroken="Unknown", lastSyncDateTime=None),
            _device("no-version", version="Unknown"),
            _device("linux", "Linux", "6.1"),
        )
    )
    findings = _findings(snapshot)
    assert not [item for item in findings if item["rule_id"].startswith("intune.device_") and item["rule_id"] != "intune.device_noncompliant"]


def test_the_summary_and_baseline_say_which_checks_were_unknown_instead_of_passing() -> None:
    snapshot = _snapshot(**_devices(_device("a"), _device("b", "iOS", "18.5", isEncrypted=None, jailBroken="Unknown", lastSyncDateTime=None)))
    summary = _record(snapshot, "device_posture", "device_posture_summary")
    assert (summary["encryption_unknown"], summary["jailbreak_unknown"], summary["last_sync_unknown"]) == (1, 1, 1)

    assert rule_inputs_gap("intune.device_encryption_off", snapshot) == "encryption_unknown_for_1_devices"
    assert rule_inputs_gap("intune.device_jailbroken", snapshot) == "jailbreak_unknown_for_1_devices"
    assert rule_inputs_gap("intune.device_stale_sync", snapshot) == "last_sync_unknown_for_1_devices"
    assert rule_inputs_gap("intune.device_os_end_of_life", snapshot) is None

    complete = _snapshot(**_devices(_device("a"), _device("b", "iOS", "18.5")))
    assert all(rule_inputs_gap(rule, complete) is None for rule in
               ("intune.device_encryption_off", "intune.device_jailbroken", "intune.device_stale_sync", "intune.device_os_end_of_life"))


def test_a_jailbreak_value_of_unknown_is_not_a_gap_on_a_laptop() -> None:
    snapshot = _snapshot(**_devices(_device("laptop", jailBroken="Unknown")))
    assert rule_inputs_gap("intune.device_jailbroken", snapshot) is None


def test_the_unknown_fields_are_absent_from_the_normalized_device_not_defaulted() -> None:
    snapshot = _snapshot(**_devices(_device("bare", isEncrypted=None, lastSyncDateTime=None)))
    (device,) = snapshot["devices"]["records"]
    assert "is_encrypted" not in device and "last_sync_at" not in device
    assert device["os_family"] == "windows"


def test_the_normalized_device_carries_the_posture_fields() -> None:
    snapshot = _snapshot(
        **_devices(_device("full", enrolledDateTime="2025-02-01T09:00:00Z", managedDeviceOwnerType="personal", deviceEnrollmentType="userEnrollment"))
    )
    (device,) = snapshot["devices"]["records"]
    assert device["is_encrypted"] is True and device["owner_type"] == "personal" and device["enrolled_at"] == "2025-02-01T09:00:00Z"
    assert device["enrollment_type"] == "userEnrollment" and device["os_family"] == "windows"


def test_the_stale_sync_threshold_is_configurable_and_defaults_to_14_days(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = _snapshot(**_devices(_device("ten", lastSyncDateTime=_ago(10)), _device("twenty", lastSyncDateTime=_ago(20)), _device("hundred", lastSyncDateTime=_ago(100))))

    def stale(**kwargs: Any) -> set[str]:
        return {item["affected_objects"][0] for item in _by_rule(_findings(snapshot, **kwargs), "intune.device_stale_sync")}

    assert stale() == {"TWENTY", "HUNDRED"}
    assert stale(stale_sync_days=7) == {"TEN", "TWENTY", "HUNDRED"}
    assert stale(stale_sync_days=30) == {"HUNDRED"}
    monkeypatch.setenv(endpoint_posture.STALE_SYNC_DAYS_ENV, "30")
    assert stale() == {"HUNDRED"}
    assert stale(stale_sync_days=7) == {"TEN", "TWENTY", "HUNDRED"}, "the option wins over the environment"
    monkeypatch.setenv(endpoint_posture.STALE_SYNC_DAYS_ENV, "never")
    assert stale() == {"TWENTY", "HUNDRED"}, "an invalid value is ignored"


def test_a_cut_device_list_still_flags_what_it_read_but_never_passes() -> None:
    cut = {"value": [_device("seen", isEncrypted=False)], "collection_truncated": True, "truncation_reason": "operator_limit"}
    snapshot = _snapshot(intune={"managedDevices": cut})

    assert [item["id"] for item in _by_rule(_findings(snapshot), "intune.device_encryption_off")] == ["intune:seen:device_encryption_off"]
    summary = _record(snapshot, "device_posture", "device_posture_summary")
    assert summary["read_state"] == "truncated"
    for rule in ("intune.device_encryption_off", "intune.device_stale_sync", "intune.device_os_end_of_life", "intune.device_jailbroken"):
        assert rule_inputs_gap(rule, snapshot) == "device_list_truncated", rule


def test_a_blocked_or_missing_device_list_is_not_assessed() -> None:
    blocked = _snapshot(intune={"managedDevices": BLOCKED})
    assert rule_inputs_gap("intune.device_encryption_off", blocked) == "device_list_blocked"
    assert not _by_rule(_findings(blocked), "intune.device_encryption_off")
    assert rule_inputs_gap("intune.device_encryption_off", _snapshot()) == "device_posture_not_collected"
    assert rule_inputs_gap("intune.device_encryption_off", _snapshot(**_devices())) == "no_managed_devices"
    assert rule_inputs_gap("intune.device_encryption_off", None) == "inputs_not_available"


def test_a_windows_build_whose_edition_decides_support_is_a_gap_not_a_finding_or_a_pass() -> None:
    # 24H2 on 2026-10-22: Home and Pro ended 2026-10-13, Enterprise and Education run to 2027-10-12.
    snapshot = _snapshot(**_devices(_device("w24h2", version="10.0.26100.6584")))
    assert not _by_rule(_findings(snapshot), "intune.device_os_end_of_life")
    assert rule_inputs_gap("intune.device_os_end_of_life", snapshot) == "os_edition_dependent_for_1_devices"
    assert _record(snapshot, "device_posture", "device_posture_summary")["os_lifecycle_edition_dependent"] == 1


def test_a_build_a_long_term_servicing_edition_shares_is_not_called_past_end_of_life() -> None:
    # 1809 and 21H2 builds are shared with LTSC 2019 and LTSC 2021 / IoT LTSC 2021, and 24H2 with LTSC 2024.
    snapshot = _snapshot(**_devices(_device("ltsc2019", version="10.0.17763.6000"), _device("ltsc2021", version="10.0.19044.4000"),
                                    _device("server", "Windows Server 2019", "10.0.17763.6000"), _device("ltsb2016", version="10.0.14393.7000")))
    findings = _by_rule(_findings(snapshot), "intune.device_os_end_of_life")

    # Only LTSB 2016, whose last update was 2026-10-13, is past end of life for every edition on its build.
    assert [item["id"] for item in findings] == ["intune:ltsb2016:device_os_end_of_life"]
    assert findings[0]["evidence"]["os_lifecycle"]["ltsc_end_of_support"] == "2026-10-13"
    summary = _record(snapshot, "device_posture", "device_posture_summary")
    assert summary["os_lifecycle_edition_dependent"] == 2
    # The server is not a Windows client: unknown, not judged against Windows 10.
    assert {row["reason"]: row["count"] for row in summary["os_lifecycle_unknown_reasons"]} == {"platform_not_covered": 1}
    assert rule_inputs_gap("intune.device_os_end_of_life", snapshot) == "os_lifecycle_unknown_for_1_devices"


def test_an_unlisted_release_is_unknown_for_the_end_of_life_rule() -> None:
    snapshot = _snapshot(**_devices(_device("future", version="10.0.99999.1"), _device("tux", "Linux", "6.1")))
    assert not _by_rule(_findings(snapshot), "intune.device_os_end_of_life")
    assert rule_inputs_gap("intune.device_os_end_of_life", snapshot) == "os_lifecycle_unknown_for_2_devices"
    reasons = {row["reason"] for row in _record(snapshot, "device_posture", "device_posture_summary")["os_lifecycle_unknown_reasons"]}
    assert reasons == {"release_not_in_table", "platform_not_covered"}


# ---- compliance policies ----------------------------------------------------------------------------------


def _policy(policy_id: str, odata_type: str, **settings: Any) -> dict[str, Any]:
    return {"id": policy_id, "displayName": policy_id, "@odata.type": f"#microsoft.graph.{odata_type}", **settings}


def _assignments(*rows: tuple[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {"value": [{"policyId": policy_id, "displayName": policy_id, "assignments": [{"id": f"{policy_id}-a{index}", "target": target} for index, target in enumerate(targets)]} for policy_id, targets in rows]}


def _compliance(devices: list[dict[str, Any]], policies: list[dict[str, Any]], assignments: dict[str, Any] | None) -> dict[str, Any]:
    section: dict[str, Any] = {"managedDevices": {"value": devices}, "deviceCompliancePolicies": {"value": policies}}
    if assignments is not None:
        section["deviceCompliancePolicyAssignments"] = assignments
    return _snapshot(intune=section)


def test_a_platform_with_devices_and_no_compliance_policy_is_a_finding() -> None:
    snapshot = _compliance(
        [_device("w1"), _device("i1", "iOS", "18.5"), _device("m1", "macOS", "15.1")],
        [_policy("win", "windows10CompliancePolicy", bitLockerEnabled=True)],
        _assignments(("win", [ALL_DEVICES])),
    )
    findings = _by_rule(_findings(snapshot), "intune.compliance_policy_missing_platform")

    assert {item["id"] for item in findings} == {"intune:compliance_policy:ios:missing", "intune:compliance_policy:macos:missing"}
    assert {item["evidence"]["reason"] for item in findings} == {"no_policy"}
    assert all(item["severity"] == "medium" for item in findings)
    assert "no ios device compliance policy exists" in findings[0]["description"] or "no macos" in findings[0]["description"]
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", snapshot) is None


def test_a_platform_whose_policies_are_all_unassigned_is_a_finding() -> None:
    snapshot = _compliance(
        [_device("a1", "Android", "14")],
        [_policy("android", "androidWorkProfileCompliancePolicy", passwordRequired=True)],
        _assignments(("android", [])),
    )
    (item,) = _by_rule(_findings(snapshot), "intune.compliance_policy_missing_platform")
    assert item["id"] == "intune:compliance_policy:android:missing" and item["evidence"]["reason"] == "no_assigned_policy"
    assert "none of the 1 android device compliance policies is assigned" in item["description"]

    exclusion_only = _compliance(
        [_device("a1", "Android", "14")],
        [_policy("android", "androidWorkProfileCompliancePolicy")],
        _assignments(("android", [{"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "g"}])),
    )
    assert _by_rule(_findings(exclusion_only), "intune.compliance_policy_missing_platform")


def test_an_assigned_policy_or_a_platform_without_devices_is_clean() -> None:
    assigned = _compliance([_device("w1")], [_policy("win", "windows10CompliancePolicy")], _assignments(("win", [GROUP])))
    assert not _by_rule(_findings(assigned), "intune.compliance_policy_missing_platform")
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", assigned) is None
    no_devices_on_platform = _compliance([_device("w1")], [_policy("win", "windows10CompliancePolicy")], _assignments(("win", [ALL_DEVICES])))
    assert not [item for item in _findings(no_devices_on_platform) if item["id"].endswith(":ios:missing")]


def test_assignments_that_were_not_read_never_count_as_unassigned() -> None:
    policies = [_policy("win", "windows10CompliancePolicy"), _policy("win2", "windows10CompliancePolicy")]
    # One policy's assignments are missing (a fan-out cut or a failed read): it may well be assigned.
    partial = _compliance([_device("w1")], policies, _assignments(("win", [])))
    assert not _by_rule(_findings(partial), "intune.compliance_policy_missing_platform")
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", partial) == "policy_assignments_not_read_for_every_policy"
    unread = _compliance([_device("w1")], policies, None)
    assert not _by_rule(_findings(unread), "intune.compliance_policy_missing_platform")
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", unread) == "policy_assignments_not_read_for_every_policy"
    failed = _snapshot(intune={"managedDevices": {"value": [_device("w1")]}, "deviceCompliancePolicies": {"value": policies},
                               "deviceCompliancePolicyAssignments": {"error": "x", "error_class": "incomplete_evidence"}})
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", failed) == "policy_assignments_not_read_for_every_policy"


def test_a_cut_or_blocked_policy_list_proves_no_absence() -> None:
    cut = _snapshot(intune={"managedDevices": {"value": [_device("w1")]},
                            "deviceCompliancePolicies": {"value": [], "collection_truncated": True, "truncation_reason": "operator_limit"}})
    assert not _by_rule(_findings(cut), "intune.compliance_policy_missing_platform")
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", cut) == "compliance_policies_truncated"
    blocked = _snapshot(intune={"managedDevices": {"value": [_device("w1")]}, "deviceCompliancePolicies": BLOCKED})
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", blocked) == "compliance_policies_blocked"
    cut_devices = _snapshot(intune={"managedDevices": {"value": [_device("w1")], "collection_truncated": True},
                                    "deviceCompliancePolicies": {"value": [_policy("win", "windows10CompliancePolicy")]}})
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", cut_devices) == "device_list_truncated"
    assert rule_inputs_gap("intune.compliance_policy_missing_platform", _snapshot()) == "compliance_policies_not_collected"


def test_the_normalized_policy_keeps_platform_settings_and_assignments() -> None:
    snapshot = _compliance(
        [_device("w1")],
        [_policy("win", "windows10CompliancePolicy", passwordRequired=True, passwordMinimumLength=12, bitLockerEnabled=True,
                 osMinimumVersion="10.0.22631", ownerNote="ignored")],
        _assignments(("win", [ALL_DEVICES, GROUP])),
    )
    policy = _record(snapshot, "compliance_policy_objects", "compliance_policy")
    assert policy["platform"] == "windows" and policy["policy_type"] == "windows10CompliancePolicy"
    assert policy["settings"] == {"passcode_required": True, "passcode_min_length": 12, "encryption_required": True, "min_os_version": "10.0.22631"}
    assert policy["assignments_known"] is True and policy["assigned"] is True and policy["assigned_to_all_devices"] is True
    assert policy["group_target_count"] == 1 and "g1" not in json.dumps(policy)
    assert "ownerNote" not in json.dumps(policy)
    summary = _record(snapshot, "compliance_policy_objects", "compliance_policy_summary")
    assert summary["policies_read_state"] == "collected" and summary["assignments_read_state"] == "collected"


# ---- update rings -----------------------------------------------------------------------------------------


def _ring(ring_id: str, deferral: int | None = 3, paused: bool | None = False, **fields: Any) -> dict[str, Any]:
    row = {"id": ring_id, "displayName": ring_id, "qualityUpdatesDeferralPeriodInDays": deferral, "qualityUpdatesPaused": paused, **fields}
    return {key: value for key, value in row.items() if value is not None}


def _updates(rings: list[dict[str, Any]], assignments: dict[str, Any] | None, devices: list[dict[str, Any]] | None = None, **depth: Any) -> dict[str, Any]:
    section = {"windowsUpdateRings": {"value": rings}, **depth}
    if assignments is not None:
        section["windowsUpdateRingAssignments"] = assignments
    return _snapshot(intune={"managedDevices": {"value": devices if devices is not None else [_device("w1")]}}, intune_depth=section)


def test_no_assigned_update_ring_is_a_finding_when_windows_devices_exist() -> None:
    for rings, assignments in (([], _assignments()), ([_ring("r1")], _assignments(("r1", [])))):
        snapshot = _updates(rings, assignments)
        (item,) = _by_rule(_findings(snapshot), "intune_depth.update_ring_not_assigned")
        assert item["id"] == "intune_depth:update_rings:none_assigned" and item["severity"] == "medium"
        assert item["evidence"]["rings_assigned"] == 0 and item["evidence"]["windows_device_count"] == 1
        assert rule_inputs_gap("intune_depth.update_ring_not_assigned", snapshot) is None


def test_a_ring_assigned_to_a_group_or_all_devices_satisfies_the_assignment_rule() -> None:
    for target in (GROUP, ALL_DEVICES):
        snapshot = _updates([_ring("r1")], _assignments(("r1", [target])))
        assert not _by_rule(_findings(snapshot), "intune_depth.update_ring_not_assigned")
        assert rule_inputs_gap("intune_depth.update_ring_not_assigned", snapshot) is None
    summary = _record(_updates([_ring("r1"), _ring("r2")], _assignments(("r1", [ALL_DEVICES]), ("r2", [GROUP]))), "update_management_objects", "update_management_summary")
    assert (summary["ring_count"], summary["rings_assigned"], summary["rings_assigned_to_all_devices"]) == (2, 2, 1)
    assert summary["update_profile_api_version"] == "beta" and "windowsUpdateForBusinessConfiguration" in summary["update_ring_source"]


def test_updates_managed_without_a_ring_are_not_called_unmanaged() -> None:
    quality = {"windowsQualityUpdateProfiles": {"value": [{"id": "q1", "displayName": "Expedite"}]},
               "windowsQualityUpdateProfileAssignments": _assignments(("q1", [ALL_DEVICES]))}
    with_profile = _updates([], _assignments(), **quality)
    assert not _by_rule(_findings(with_profile), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", with_profile) == "update_managed_by_other_means"
    summary = _record(with_profile, "update_management_objects", "update_management_summary")
    assert summary["profiles_assigned"] == 1 and summary["windows_comanaged_device_count"] == 0

    unassigned_profile = _updates([], _assignments(), windowsQualityUpdateProfiles=quality["windowsQualityUpdateProfiles"],
                                  windowsQualityUpdateProfileAssignments=_assignments(("q1", [])))
    assert _by_rule(_findings(unassigned_profile), "intune_depth.update_ring_not_assigned"), "a profile assigned to nobody manages nothing"

    # Configuration Manager co-management: its update settings and WSUS are not read.
    comanaged = _updates([], _assignments(), devices=[_device("w1", deviceEnrollmentType="windowsCoManagement")])
    assert not _by_rule(_findings(comanaged), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", comanaged) == "update_managed_by_other_means"
    assert _record(comanaged, "update_management_objects", "update_management_summary")["windows_comanaged_device_count"] == 1
    # A Mac enrolled the same way is not a Windows device.
    mac = _updates([], _assignments(), devices=[_device("w1"), _device("m1", "macOS", "15.1", deviceEnrollmentType="windowsCoManagement")])
    assert _by_rule(_findings(mac), "intune_depth.update_ring_not_assigned")


def test_the_deferral_rule_counts_the_deadline_and_the_restart_grace_period() -> None:
    snapshot = _updates(
        [_ring("slow-deadline", 7, False, deadlineForQualityUpdatesInDays=7, deadlineGracePeriodInDays=1),
         _ring("tight", 7, False, deadlineForQualityUpdatesInDays=7, deadlineGracePeriodInDays=0)],
        _assignments(("slow-deadline", [ALL_DEVICES]), ("tight", [GROUP])),
    )
    findings = {item["id"]: item for item in _by_rule(_findings(snapshot), "intune_depth.update_ring_deferral_excessive")}
    assert set(findings) == {"intune_depth:slow-deadline:update_ring_deferral"}
    evidence = findings["intune_depth:slow-deadline:update_ring_deferral"]["evidence"]
    assert evidence["reasons"] == ["quality_deferral_and_deadline_over_14_days"] and evidence["install_delay_days"] == 15


def test_update_ring_rules_need_windows_devices_and_readable_rings() -> None:
    no_windows = _updates([], _assignments(), devices=[_device("phone", "iOS", "18.5")])
    assert not _by_rule(_findings(no_windows), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", no_windows) == "no_windows_devices"

    unreadable = _snapshot(intune={"managedDevices": {"value": [_device("w1")]}}, intune_depth={"windowsUpdateRings": {"error": "x", "error_class": "incomplete_evidence"}})
    assert not _by_rule(_findings(unreadable), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", unreadable) == "update_rings_blocked"

    cut = _updates([_ring("r1")], _assignments(("r1", [])))
    cut["update_management_objects"]["records"] = [
        {**row, "rings_read_state": "truncated"} if row["kind"] == "update_management_summary" else row for row in cut["update_management_objects"]["records"]
    ]
    assert not _by_rule(_findings(cut), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", cut) == "update_rings_truncated"
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", _snapshot()) == "update_management_not_collected"


def test_a_ring_whose_assignments_were_not_read_never_reads_as_unassigned() -> None:
    unread = _updates([_ring("r1")], None)
    assert not _by_rule(_findings(unread), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", unread) == "ring_assignments_absent"
    failed_for_one = _updates([_ring("r1"), _ring("r2")], _assignments(("r1", [])))
    assert not _by_rule(_findings(failed_for_one), "intune_depth.update_ring_not_assigned")
    assert rule_inputs_gap("intune_depth.update_ring_not_assigned", failed_for_one) == "ring_assignments_not_read_for_every_ring"


def test_an_assigned_ring_that_defers_quality_updates_beyond_14_days_is_a_finding() -> None:
    snapshot = _updates(
        [_ring("slow", 30), _ring("edge", 14), _ring("paused", 3, True, qualityUpdatesPauseExpiryDateTime="2026-11-01T00:00:00Z"),
         _ring("old-pause", 3, True, qualityUpdatesPauseExpiryDateTime="2026-10-01T00:00:00Z"), _ring("unassigned-slow", 60)],
        _assignments(("slow", [ALL_DEVICES]), ("edge", [GROUP]), ("paused", [GROUP]), ("old-pause", [GROUP]), ("unassigned-slow", [])),
    )
    findings = {item["id"]: item for item in _by_rule(_findings(snapshot), "intune_depth.update_ring_deferral_excessive")}

    assert set(findings) == {"intune_depth:slow:update_ring_deferral", "intune_depth:paused:update_ring_deferral"}
    assert findings["intune_depth:slow:update_ring_deferral"]["evidence"]["reasons"] == ["quality_deferral_over_14_days"]
    assert findings["intune_depth:paused:update_ring_deferral"]["evidence"]["reasons"] == ["quality_updates_paused"]
    assert findings["intune_depth:slow:update_ring_deferral"]["evidence"]["deferral_limit_days"] == 14
    assert rule_inputs_gap("intune_depth.update_ring_deferral_excessive", snapshot) is None


def test_the_deferral_rule_is_not_assessed_without_an_assigned_ring_or_with_unread_settings() -> None:
    none_assigned = _updates([_ring("r1", 30)], _assignments(("r1", [])))
    assert not _by_rule(_findings(none_assigned), "intune_depth.update_ring_deferral_excessive")
    assert rule_inputs_gap("intune_depth.update_ring_deferral_excessive", none_assigned) == "no_assigned_update_ring"
    unread = _updates([_ring("r1", None, None)], _assignments(("r1", [GROUP])))
    assert not _by_rule(_findings(unread), "intune_depth.update_ring_deferral_excessive")
    assert rule_inputs_gap("intune_depth.update_ring_deferral_excessive", unread) == "ring_settings_not_returned"


def test_quality_and_feature_update_profiles_are_recorded_with_their_assignments_and_api_version() -> None:
    snapshot = _updates(
        [_ring("r1")],
        _assignments(("r1", [GROUP])),
        windowsQualityUpdateProfiles={"value": [{"id": "q1", "displayName": "Expedite", "expeditedUpdateSettings": {"daysUntilForcedReboot": 1}}]},
        windowsQualityUpdateProfileAssignments=_assignments(("q1", [ALL_DEVICES])),
        windowsFeatureUpdateProfiles={"value": [{"id": "f1", "displayName": "25H2", "featureUpdateVersion": "Windows 11, version 25H2"}]},
        windowsFeatureUpdateProfileAssignments={"error": "x", "error_class": "incomplete_evidence"},
    )
    profiles = {row["id"]: row for row in snapshot["update_management_objects"]["records"] if row["kind"] == "update_profile"}

    assert profiles["q1"]["profile_type"] == "quality" and profiles["q1"]["api_version"] == "beta"
    assert profiles["q1"]["assigned"] is True and profiles["q1"]["assigned_to_all_devices"] is True and profiles["q1"]["expedited"] is True
    assert profiles["f1"]["profile_type"] == "feature" and profiles["f1"]["feature_update_version"] == "Windows 11, version 25H2"
    assert profiles["f1"]["assignments_known"] is False
    summary = _record(snapshot, "update_management_objects", "update_management_summary")
    assert summary["profile_count"] == 2 and summary["feature_profile_assignments_read_state"] == "blocked"


# ---- Defender antivirus -----------------------------------------------------------------------------------


def _protection(*rows: dict[str, Any], **section: Any) -> dict[str, Any]:
    states = [{"read_status": "ok", **row} for row in rows]
    return {"value": states, "collection_truncated": False, **section}


def _av(rows: dict[str, Any], devices: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return _snapshot(intune={"managedDevices": {"value": devices if devices is not None else [_device("w1")]}, "windowsProtectionStates": rows})


def test_defender_rules_fire_per_device_from_state_that_was_read() -> None:
    snapshot = _av(
        _protection(
            {"deviceId": "off", "deviceName": "OFF", "malwareProtectionEnabled": False, "realTimeProtectionEnabled": False, "signatureUpdateOverdue": True},
            {"deviceId": "rtp", "deviceName": "RTP", "malwareProtectionEnabled": True, "realTimeProtectionEnabled": False, "signatureUpdateOverdue": False},
            {"deviceId": "sig", "deviceName": "SIG", "malwareProtectionEnabled": True, "realTimeProtectionEnabled": True, "productStatus": "avSignaturesOutOfDate"},
            {"deviceId": "ok", "deviceName": "OK", "malwareProtectionEnabled": True, "realTimeProtectionEnabled": True, "signatureUpdateOverdue": False},
        ),
        devices=[_device(name) for name in ("off", "rtp", "sig", "ok")],
    )
    findings = _findings(snapshot)

    def ids(rule: str) -> set[str]:
        return {item["id"] for item in _by_rule(findings, rule)}

    assert ids("intune.defender_av_off") == {"intune:off:defender_av_off"}
    assert ids("intune.defender_realtime_protection_off") == {"intune:off:defender_realtime_off", "intune:rtp:defender_realtime_off"}
    assert ids("intune.defender_signatures_stale") == {"intune:off:defender_signatures_stale", "intune:sig:defender_signatures_stale"}
    severities = {item["rule_id"]: item["severity"] for item in findings if item["rule_id"].startswith("intune.defender_")}
    assert severities == {"intune.defender_av_off": "high", "intune.defender_realtime_protection_off": "medium", "intune.defender_signatures_stale": "medium"}
    assert all(rule_inputs_gap(rule, snapshot) is None for rule in
               ("intune.defender_av_off", "intune.defender_realtime_protection_off", "intune.defender_signatures_stale"))


def test_a_device_with_no_defender_state_is_unknown_never_off() -> None:
    snapshot = _av(
        {"value": [{"deviceId": "w1", "deviceName": "W1", "read_status": "not_reported"}, {"deviceId": "w2", "deviceName": "W2", "read_status": "failed", "error_class": "graph_transient"}],
         "collection_truncated": False},
        devices=[_device("w1"), _device("w2")],
    )
    assert not [item for item in _findings(snapshot) if item["rule_id"].startswith("intune.defender_")]
    for rule in ("intune.defender_av_off", "intune.defender_realtime_protection_off", "intune.defender_signatures_stale"):
        assert rule_inputs_gap(rule, snapshot) == "defender_state_unavailable_for_2_devices", rule
    summary = _record(snapshot, "defender_av_objects", "defender_av_summary")
    assert (summary["state_not_reported"], summary["state_read_failed"], summary["state_read"]) == (1, 1, 0)


def test_a_field_missing_from_a_read_state_is_unknown_for_that_rule_only() -> None:
    snapshot = _av(_protection({"deviceId": "w1", "deviceName": "W1", "malwareProtectionEnabled": True}))
    assert rule_inputs_gap("intune.defender_av_off", snapshot) is None
    assert rule_inputs_gap("intune.defender_realtime_protection_off", snapshot) == "defender_realtime_state_unknown_for_1_devices"
    assert rule_inputs_gap("intune.defender_signatures_stale", snapshot) == "defender_signature_state_unknown_for_1_devices"


def test_a_cut_blocked_or_absent_defender_read_is_not_assessed() -> None:
    cut = _av(_protection({"deviceId": "w1", "deviceName": "W1", "malwareProtectionEnabled": False}, collection_truncated=True, truncation_reason="fanout_limit",
                          fanout={"fanout_omitted_count": 4}))
    # What was read still counts: the device it read with antivirus off is a finding, and the rest is a gap.
    assert [item["id"] for item in _by_rule(_findings(cut), "intune.defender_av_off")] == ["intune:w1:defender_av_off"]
    assert rule_inputs_gap("intune.defender_av_off", cut) == "defender_state_truncated"
    assert _record(cut, "defender_av_objects", "defender_av_summary")["devices_not_expanded"] == 4

    blocked = _av({"error": "The managed device list could not be read in full", "error_class": "incomplete_evidence"})
    assert rule_inputs_gap("intune.defender_av_off", blocked) == "defender_state_blocked"
    assert rule_inputs_gap("intune.defender_av_off", _snapshot(**_devices(_device("w1")))) == "defender_state_not_collected"
    assert rule_inputs_gap("intune.defender_av_off", _av(_protection(), devices=[_device("phone", "iOS", "18.5")])) == "no_windows_devices"
    cut_devices = _av(_protection({"deviceId": "w1", "deviceName": "W1", "malwareProtectionEnabled": True}), devices=[_device("w1")])
    cut_devices["device_posture"]["records"][0]["read_state"] = "truncated"
    for row in cut_devices["defender_av_objects"]["records"]:
        if row["kind"] == "defender_av_summary":
            row["devices_read_state"] = "truncated"
    assert rule_inputs_gap("intune.defender_av_off", cut_devices) == "device_list_truncated"


# ---- Cyber Essentials rows --------------------------------------------------------------------------------


def _ledger(*collectors: str) -> list[dict[str, str]]:
    return [{"collector": name, "coverage_status": "complete_exact_scope"} for name in collectors]


def _ce(snapshot: dict[str, Any], findings: list[dict[str, Any]], collectors: tuple[str, ...] = ("intune", "intune_depth", "exchange_policy")) -> dict[str, dict[str, Any]]:
    alignment = build_baseline_alignment(findings, normalized_snapshot=snapshot, coverage_ledger=_ledger(*collectors))
    return {row["control_id"]: row for row in alignment["frameworks"]["cyber_essentials"]["controls"]}


def test_update_and_malware_requirements_fail_on_evidence_and_never_pass_on_a_clean_run() -> None:
    clean = _snapshot(
        intune={"managedDevices": {"value": [_device("w1")]}, "windowsProtectionStates": _protection({"deviceId": "w1", "deviceName": "W1", "malwareProtectionEnabled": True, "realTimeProtectionEnabled": True, "signatureUpdateOverdue": False})},
        intune_depth={"windowsUpdateRings": {"value": [_ring("r1")]}, "windowsUpdateRingAssignments": _assignments(("r1", [ALL_DEVICES]))},
        exchange_policy={"malwareFilterPolicy": {"value": [{"Identity": "Default", "IsDefault": True, "EnableFileFilter": True, "ZapEnabled": True}]}},
    )
    rows = _ce(clean, _findings(clean))
    for requirement_id in ("ce.sum.supported_software", "ce.sum.automatic_updates", "ce.sum.vulnerability_fixes_14_days", "ce.mp.antimalware"):
        row = rows[requirement_id]
        assert row["requirement_status"] == "partial" and row["status"] == "not_assessed", requirement_id
        assert row["reason"] == "partial_requirement_no_gap_found", requirement_id
        assert row["open_finding_count"] == 0
    assert rows["ce.mp.app_allow_listing"]["status"] == "not_assessed" and rows["ce.mp.app_allow_listing"]["requirement_status"] == "manual"

    weak = _snapshot(
        intune={"managedDevices": {"value": [_device("w1", version="10.0.19045.1")]}, "windowsProtectionStates": _protection({"deviceId": "w1", "deviceName": "W1", "malwareProtectionEnabled": False})},
        intune_depth={"windowsUpdateRings": {"value": [_ring("r1", 30)]}, "windowsUpdateRingAssignments": _assignments(("r1", [ALL_DEVICES]))},
    )
    failing = _ce(weak, _findings(weak))
    assert failing["ce.sum.supported_software"]["status"] == "fail"
    assert failing["ce.sum.vulnerability_fixes_14_days"]["status"] == "fail"
    assert failing["ce.mp.antimalware"]["status"] == "fail"
    assert failing["ce.sum.automatic_updates"]["status"] == "not_assessed"


def test_update_and_malware_requirements_stay_not_assessed_when_nothing_was_collected() -> None:
    rows = _ce(_snapshot(), [], collectors=())
    for requirement_id in ("ce.sum.supported_software", "ce.sum.automatic_updates", "ce.sum.vulnerability_fixes_14_days", "ce.mp.antimalware"):
        assert rows[requirement_id]["status"] == "not_assessed" and rows[requirement_id]["evidence"]["rules_evaluated"] == 0, requirement_id
    # Collectors that ran but could not read the inputs are not assessed either, with the reason on the rule.
    blocked = _snapshot(intune={"managedDevices": BLOCKED})
    row = _ce(blocked, [])["ce.sum.supported_software"]
    assert row["status"] == "not_assessed"
    assert row["rule_statuses"][0] == {**row["rule_statuses"][0], "evaluated": False, "reason": "device_list_blocked"}


def test_the_mapped_rules_are_the_ones_the_requirements_name() -> None:
    mappings = json.loads((Path(__file__).resolve().parent.parent / "configs" / "control-mappings.json").read_text(encoding="utf-8"))
    ce = {rule: mapping["cyber_essentials"] for rule, mapping in mappings.items() if isinstance(mapping, dict) and mapping.get("cyber_essentials")}
    assert ce["intune.device_os_end_of_life"] == ["ce.sum.supported_software", "ce.sum.vulnerability_fixes_14_days"]
    assert ce["intune.device_stale_sync"] == ["ce.sum.vulnerability_fixes_14_days"]
    assert ce["intune_depth.update_ring_not_assigned"] == ["ce.sum.automatic_updates", "ce.sum.vulnerability_fixes_14_days"]
    assert ce["intune_depth.update_ring_deferral_excessive"] == ["ce.sum.vulnerability_fixes_14_days"]
    for rule in ("intune.defender_av_off", "intune.defender_realtime_protection_off", "intune.defender_signatures_stale", "exchange.malware_filter_weakened"):
        assert ce[rule] == ["ce.mp.antimalware"], rule
    assert "ce.sc.saas_configuration" in ce["exchange.smtp_auth_enabled_tenant_wide"]


def test_the_evaluation_date_alone_is_not_a_difference_between_two_runs(tmp_path: Path) -> None:
    from azure_tenant_audit.diffing import diff_run_directories

    snapshot = _snapshot(**_devices(_device("a")))
    summary = _record(snapshot, "device_posture", "device_posture_summary")
    for name, day in (("run-a", "2026-10-22"), ("run-b", "2026-10-23")):
        run = tmp_path / name
        (run / "normalized").mkdir(parents=True)
        (run / "run-manifest.json").write_text(json.dumps({"tenant_name": "acme", "run_id": name, "overall_status": "ok"}), encoding="utf-8")
        records = [{**summary, "os_lifecycle_evaluated_on": day}]
        (run / "normalized" / "device_posture.json").write_text(json.dumps({"kind": "device_posture", "records": records}), encoding="utf-8")

    diff = diff_run_directories(tmp_path / "run-a", tmp_path / "run-b")
    assert diff["summary"]["changed"] == 0
    assert diff["changes"]["device_posture"]["suppressed"][0]["changed_paths"] == ["os_lifecycle_evaluated_on"]
