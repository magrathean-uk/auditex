"""Parsing and thresholds behind the device, update and anti-malware rules (no tenant, no clock)."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest

from azure_tenant_audit import endpoint_posture as ep
from azure_tenant_audit.secret_hygiene import SENSITIVE_KEY_RE

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)


def _ago(days: float) -> str:
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- values -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (False, False), ("True", True), ("false", False), (" TRUE ", True), ("Unknown", None), ("", None), (None, None), (1, None), ("yes", None)],
)
def test_booleans_are_read_from_booleans_and_their_text_and_nothing_else(value: Any, expected: Any) -> None:
    assert ep.canonical_bool(value) is expected


def test_timestamps_are_utc_and_unparseable_ones_are_none() -> None:
    assert ep.parse_timestamp("2026-10-01T10:00:00Z") == datetime(2026, 10, 1, 10, tzinfo=timezone.utc)
    assert ep.parse_timestamp("2026-10-01T10:00:00+01:00") == datetime(2026, 10, 1, 9, tzinfo=timezone.utc)
    assert ep.parse_timestamp("2026-10-01T10:00:00") == datetime(2026, 10, 1, 10, tzinfo=timezone.utc)
    assert [ep.parse_timestamp(value) for value in ("", "yesterday", None, 5)] == [None] * 4


# ---- stale-sync threshold ---------------------------------------------------------------------------------


def test_the_stale_sync_threshold_defaults_to_the_cyber_essentials_14_days(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ep.STALE_SYNC_DAYS_ENV, raising=False)
    assert ep.DEFAULT_STALE_SYNC_DAYS == 14 and ep.stale_sync_days() == 14


def test_the_stale_sync_threshold_takes_the_argument_then_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ep.STALE_SYNC_DAYS_ENV, "30")
    assert ep.stale_sync_days() == 30
    assert ep.stale_sync_days(7) == 7 and ep.stale_sync_days("45") == 45


@pytest.mark.parametrize("bad", ["0", "-3", "3651", "soon", "", "1.5", True])
def test_an_invalid_stale_sync_threshold_is_ignored_never_half_applied(monkeypatch: pytest.MonkeyPatch, bad: Any) -> None:
    monkeypatch.setenv(ep.STALE_SYNC_DAYS_ENV, "21")
    # A bad argument falls through to the environment; a bad environment falls through to the default.
    assert ep.stale_sync_days(bad) == 21
    monkeypatch.setenv(ep.STALE_SYNC_DAYS_ENV, str(bad))
    assert ep.stale_sync_days(bad) == 14


# ---- managed devices --------------------------------------------------------------------------------------


def test_device_fields_read_the_v1_owner_field_and_fall_back_to_the_beta_one() -> None:
    v1 = ep.device_fields({"managedDeviceOwnerType": "Company", "isEncrypted": True, "jailBroken": "False", "operatingSystem": "iOS",
                           "enrolledDateTime": "2025-01-01T00:00:00Z", "deviceEnrollmentType": "appleBulkWithUser"})
    assert v1 == {"is_encrypted": True, "jail_broken": False, "owner_type": "company", "enrolled_at": "2025-01-01T00:00:00Z",
                  "enrollment_type": "appleBulkWithUser", "os_family": "ios"}
    assert ep.device_fields({"ownerType": "personal"})["owner_type"] == "personal"
    assert ep.device_fields({"managedDeviceOwnerType": "company", "ownerType": "personal"})["owner_type"] == "company"
    blank = ep.device_fields({"isEncrypted": None, "jailBroken": "Unknown", "managedDeviceOwnerType": "corporate"})
    assert blank["is_encrypted"] is None and blank["jail_broken"] is None and blank["owner_type"] is None and blank["os_family"] is None


def test_every_device_check_is_three_valued() -> None:
    assert [ep.encryption_state({"is_encrypted": value}) for value in (True, False, None)] == ["on", "off", "unknown"]
    assert ep.encryption_state({}) == "unknown"
    ios = {"platform": "iOS"}
    assert ep.jailbreak_state({**ios, "jail_broken": True}) == "jailbroken"
    assert ep.jailbreak_state({**ios, "jail_broken": False}) == "clean"
    assert ep.jailbreak_state(ios) == "unknown"
    assert ep.jailbreak_state({"os_family": "android"}) == "unknown"
    # Intune reports jailBroken for iOS and Android only; Unknown on a laptop is not a gap.
    assert ep.jailbreak_state({"platform": "Windows"}) == "not_applicable"
    assert ep.jailbreak_state({"platform": "macOS", "jail_broken": True}) == "not_applicable"


def test_sync_state_is_stale_only_beyond_the_threshold() -> None:
    assert ep.sync_state({"last_sync_at": _ago(14)}, 14, NOW) == "current"
    assert ep.sync_state({"last_sync_at": _ago(14.01)}, 14, NOW) == "stale"
    assert ep.sync_state({"last_sync_at": _ago(1)}, 14, NOW) == "current"
    assert ep.sync_state({"last_sync_at": _ago(10)}, 7, NOW) == "stale"
    assert ep.sync_state({"last_sync_at": "0001-01-01T00:00:00Z"}, 14, NOW) == "stale", "a device that never synced is stale"
    assert ep.sync_state({}, 14, NOW) == ep.sync_state({"last_sync_at": "not a date"}, 14, NOW) == "unknown"


def test_the_device_summary_counts_what_each_check_cannot_judge() -> None:
    devices = [
        {"platform": "Windows", "os_version": "10.0.19045.1", "os_family": "windows", "is_encrypted": True, "last_sync_at": _ago(1)},
        {"platform": "Windows", "os_version": "10.0.26100.1", "os_family": "windows", "is_encrypted": False, "last_sync_at": _ago(1)},
        {"platform": "iOS", "os_version": "18.5", "os_family": "ios", "is_encrypted": True, "jail_broken": True, "last_sync_at": _ago(1)},
        {"platform": "Android", "os_version": "Unknown", "os_family": "android"},
        {"platform": "Linux", "os_version": "6.1"},
    ]
    summary = ep.device_posture_summary(devices, read_state="collected", today=date(2026, 10, 22))

    assert summary["device_count"] == 5 and summary["read_state"] == "collected"
    assert (summary["encryption_on"], summary["encryption_off"], summary["encryption_unknown"]) == (2, 1, 2)
    assert (summary["jailbreak_jailbroken"], summary["jailbreak_clean"], summary["jailbreak_unknown"], summary["jailbreak_not_applicable"]) == (1, 0, 1, 3)
    assert summary["last_sync_unknown"] == 2
    assert summary["os_lifecycle_unknown"] == 2
    assert summary["os_lifecycle_unknown_reasons"] == [{"reason": "os_version_missing", "count": 1}, {"reason": "platform_not_covered", "count": 1}]
    # 24H2 is between its Home/Pro and Enterprise/Education dates on 2026-10-22: the edition is not in the data.
    assert summary["os_lifecycle_edition_dependent"] == 1 and summary["os_lifecycle_evaluated_on"] == "2026-10-22"
    assert summary["platform_counts"] == {"android": 1, "ios": 1, "other": 1, "windows": 2}


# ---- compliance policies ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("odata_type", "platform"),
    [
        ("#microsoft.graph.windows10CompliancePolicy", "windows"),
        ("#microsoft.graph.iosCompliancePolicy", "ios"),
        ("#microsoft.graph.macOSCompliancePolicy", "macos"),
        ("#microsoft.graph.androidWorkProfileCompliancePolicy", "android"),
        ("#microsoft.graph.androidDeviceOwnerCompliancePolicy", "android"),
        ("#microsoft.graph.windowsPhone81CompliancePolicy", "windows_phone"),
        ("#microsoft.graph.somethingNew", None),
        (None, None),
    ],
)
def test_a_compliance_policy_type_maps_to_its_platform(odata_type: Any, platform: Any) -> None:
    assert ep.compliance_platform(odata_type) == platform


def test_compliance_settings_keep_the_ones_that_matter_and_leave_absent_ones_unknown() -> None:
    windows = ep.compliance_settings(
        {"passwordRequired": True, "passwordMinimumLength": 12, "bitLockerEnabled": False, "storageRequireEncryption": True,
         "osMinimumVersion": "10.0.22631", "secureBootEnabled": True}
    )
    assert windows["passcode_required"] is True and windows["passcode_min_length"] == 12
    assert windows["encryption_required"] is True, "either BitLocker or storage encryption required counts"
    assert windows["min_os_version"] == "10.0.22631" and windows["secure_boot_required"] is True
    # Graph v1.0 does not return Defender settings for a Windows policy: unknown, not "not required".
    assert windows["defender_required"] is None and windows["jailbreak_blocked"] is None

    ios = ep.compliance_settings({"passcodeRequired": True, "passcodeMinimumLength": "6", "securityBlockJailbrokenDevices": False, "osMinimumVersion": ""})
    assert ios["passcode_required"] is True and ios["passcode_min_length"] == 6
    assert ios["jailbreak_blocked"] is False and ios["min_os_version"] is None
    assert ep.compliance_settings({"rtpEnabled": False, "antivirusRequired": False})["defender_required"] is False
    assert ep.compliance_settings({"rtpEnabled": False, "antivirusRequired": True})["defender_required"] is True
    assert ep.compliance_settings({"firewallEnabled": True})["firewall_required"] is True


def test_compliance_setting_names_are_not_redacted_by_the_bundle() -> None:
    settings = ep.compliance_settings({})
    assert not [key for key in settings if SENSITIVE_KEY_RE.search(key)]


def test_assignment_summary_tells_all_devices_all_users_groups_and_exclusions_apart() -> None:
    all_devices = {"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"}}
    all_users = {"target": {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"}}
    group = {"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "g1"}}
    exclusion = {"target": {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "g2"}}
    bare_group = {"target": {"groupId": "g3"}}

    summary = ep.assignment_summary([all_devices, all_users, group, exclusion, bare_group, "junk"])
    assert summary == {"assignment_count": 5, "assigned_to_all_devices": True, "assigned_to_all_users": True,
                       "group_target_count": 2, "exclusion_count": 1, "assigned": True}
    assert ep.assignment_summary([])["assigned"] is False
    assert ep.assignment_summary([exclusion])["assigned"] is False, "an exclusion on its own assigns nobody"
    assert "g1" not in str(summary), "group ids are not kept"


def test_platform_coverage_counts_devices_policies_and_assignment_knowledge() -> None:
    devices = [{"os_family": "windows"}, {"os_family": "windows"}, {"os_family": "ios"}, {"platform": "Android"}]
    policies = [
        {"platform": "windows", "assignments_known": True, "assigned": True},
        {"platform": "windows", "assignments_known": True, "assigned": False},
        {"platform": "ios", "assignments_known": False},
    ]
    rows = {row["platform"]: row for row in ep.compliance_platform_coverage(devices, policies)}

    assert rows["windows"] == {"platform": "windows", "device_count": 2, "policy_count": 2, "assigned_policy_count": 1,
                               "unassigned_policy_count": 1, "assignments_unknown_count": 0}
    assert rows["ios"]["policy_count"] == 1 and rows["ios"]["assignments_unknown_count"] == 1 and rows["ios"]["assigned_policy_count"] == 0
    assert rows["android"]["device_count"] == 1 and rows["android"]["policy_count"] == 0
    assert rows["macos"]["device_count"] == 0
    assert list(rows) == ["windows", "macos", "ios", "android"]


# ---- update rings -----------------------------------------------------------------------------------------


def test_only_windows_update_for_business_configurations_are_update_rings() -> None:
    assert ep.is_update_ring({"@odata.type": "#microsoft.graph.windowsUpdateForBusinessConfiguration"})
    assert not ep.is_update_ring({"@odata.type": "#microsoft.graph.windows10GeneralConfiguration"})
    assert not ep.is_update_ring({})


def test_a_ring_projection_keeps_only_the_named_fields() -> None:
    raw = {"id": "r1", "displayName": "Ring", "qualityUpdatesDeferralPeriodInDays": 3, "omaSettings": [{"value": "secret"}], "@odata.type": "x"}
    assert ep.project(raw, ep.UPDATE_RING_FIELDS) == {"id": "r1", "displayName": "Ring", "qualityUpdatesDeferralPeriodInDays": 3}


def test_ring_fields_read_deferral_deadline_and_pause() -> None:
    fields = ep.update_ring_fields(
        {"qualityUpdatesDeferralPeriodInDays": "7", "featureUpdatesDeferralPeriodInDays": 30, "deadlineForQualityUpdatesInDays": 2,
         "qualityUpdatesPaused": "False", "qualityUpdatesPauseExpiryDateTime": "2026-11-01T00:00:00Z", "automaticUpdateMode": "windowsDefault"}
    )
    assert fields["quality_deferral_days"] == 7 and fields["feature_deferral_days"] == 30 and fields["quality_deadline_days"] == 2
    assert fields["quality_paused"] is False and fields["automatic_update_mode"] == "windowsDefault"
    assert ep.update_ring_fields({})["quality_deferral_days"] is None


def test_a_ring_that_delays_quality_updates_beyond_14_days_or_pauses_them_is_flagged() -> None:
    def reasons(**ring: Any) -> list[str]:
        return ep.ring_delay_reasons({"quality_paused": False, **ring}, NOW)

    assert reasons(quality_deferral_days=14) == [] and reasons(quality_deferral_days=0) == []
    assert reasons(quality_deferral_days=15) == ["quality_deferral_over_14_days"]
    future, past = "2026-10-30T00:00:00Z", "2026-10-01T00:00:00Z"
    assert reasons(quality_deferral_days=3, quality_paused=True, quality_pause_expires_at=future) == ["quality_updates_paused"]
    assert reasons(quality_deferral_days=3, quality_paused=True, quality_pause_expires_at=past) == []
    assert reasons(quality_deferral_days=3, quality_paused=True) == ["quality_updates_paused"], "no readable expiry: treat as paused"
    assert reasons(quality_deferral_days=30, quality_paused=True) == ["quality_deferral_over_14_days", "quality_updates_paused"]
    # An unread setting is neither a delay nor a pass.
    assert ep.ring_delay_reasons({}, NOW) == []
    assert ep.ring_settings_known({"quality_deferral_days": 3, "quality_paused": False})
    assert not ep.ring_settings_known({"quality_deferral_days": 3}) and not ep.ring_settings_known({"quality_paused": False})


def test_the_install_delay_adds_the_deadline_and_restart_grace_only_when_a_deadline_is_set() -> None:
    def delay(**ring: Any) -> int | None:
        return ep.ring_install_delay_days(ring)

    assert delay(quality_deferral_days=7, quality_deadline_days=7) == 14
    assert delay(quality_deferral_days=7, quality_deadline_days=5, deadline_grace_days=2) == 14
    assert delay(quality_deferral_days=7, quality_deadline_days=7, deadline_grace_days=1) == 15
    # A grace period without a deadline forces nothing; the deferral alone decides.
    assert delay(quality_deferral_days=7, deadline_grace_days=7) == 7
    assert delay(quality_deferral_days=0) == 0
    assert delay(quality_deadline_days=7) is None, "an unread deferral is unknown, not zero"

    def reasons(**ring: Any) -> list[str]:
        return ep.ring_delay_reasons({"quality_paused": False, **ring}, NOW)

    assert reasons(quality_deferral_days=7, quality_deadline_days=7) == []
    assert reasons(quality_deferral_days=7, quality_deadline_days=7, deadline_grace_days=1) == ["quality_deferral_and_deadline_over_14_days"]
    assert reasons(quality_deferral_days=15, quality_deadline_days=2) == ["quality_deferral_over_14_days"], "the deferral alone is reported once"
    assert reasons(quality_deferral_days=3, quality_deadline_days=30, quality_paused=True,
                   quality_pause_expires_at="2026-11-01T00:00:00Z") == ["quality_deferral_and_deadline_over_14_days", "quality_updates_paused"]
    assert ep.update_ring_fields({"deadlineGracePeriodInDays": "2", "deadlineForQualityUpdatesInDays": 5})["deadline_grace_days"] == 2


def test_profile_fields_distinguish_quality_and_feature_profiles() -> None:
    assert ep.update_profile_fields({"featureUpdateVersion": "Windows 11, version 25H2", "endOfSupportDate": "2027-10-12T00:00:00Z"}, "feature") == {
        "profile_type": "feature", "feature_update_version": "Windows 11, version 25H2", "end_of_support_at": "2027-10-12T00:00:00Z"}
    assert ep.update_profile_fields({"expeditedUpdateSettings": {"daysUntilForcedReboot": 1}}, "quality") == {"profile_type": "quality", "expedited": True}
    assert ep.update_profile_fields({}, "quality")["expedited"] is None


# ---- Defender antivirus -----------------------------------------------------------------------------------


def _row(**fields: Any) -> dict[str, Any]:
    return {"deviceId": "d1", "deviceName": "PC", "read_status": "ok", **fields}


def test_defender_state_reads_each_signal_from_the_booleans_and_the_product_status_flags() -> None:
    healthy = ep.defender_states(_row(malwareProtectionEnabled=True, realTimeProtectionEnabled=True, signatureUpdateOverdue=False, productStatus="noStatus"))
    assert healthy == {"av_state": "on", "realtime_state": "on", "signature_state": "current"}

    off = ep.defender_states(_row(malwareProtectionEnabled=False, realTimeProtectionEnabled=False, signatureUpdateOverdue=True))
    assert off == {"av_state": "off", "realtime_state": "off", "signature_state": "stale"}

    flagged = ep.defender_states(_row(productStatus="serviceNotRunning, avSignaturesOutOfDate", malwareProtectionEnabled=True))
    assert flagged["av_state"] == "off" and flagged["signature_state"] == "stale", "the product status flags override a stale boolean"
    assert ep.defender_states(_row(productStatus="serviceStartedWithoutMalwareProtection"))["av_state"] == "off"


def test_defender_state_is_unknown_when_the_device_state_was_not_read_or_a_field_is_absent() -> None:
    unknown = {"av_state": "unknown", "realtime_state": "unknown", "signature_state": "unknown"}
    assert ep.defender_states(_row()) == unknown
    assert ep.defender_states(_row(malwareProtectionEnabled="Unknown", productStatus="noStatus")) == unknown
    for status in (ep.READ_NOT_REPORTED, ep.READ_FAILED):
        assert ep.defender_states(_row(read_status=status, malwareProtectionEnabled=False)) == unknown


def test_defender_state_fields_keep_a_fixed_set_of_normalized_names() -> None:
    fields = ep.defender_state_fields(
        _row(malwareProtectionEnabled=True, realTimeProtectionEnabled=False, tamperProtectionEnabled=True, productStatus="noStatus",
             signatureVersion="1.2.3", lastReportedDateTime="2026-10-20T00:00:00Z", deviceState="clean")
    )
    assert fields["device_name"] == "PC" and fields["read_status"] == "ok"
    assert fields["malware_protection_enabled"] is True and fields["real_time_protection_enabled"] is False
    assert fields["signature_version"] == "1.2.3" and fields["last_reported_at"] == "2026-10-20T00:00:00Z"
    assert fields["realtime_state"] == "off" and fields["device_health_state"] == "clean"
