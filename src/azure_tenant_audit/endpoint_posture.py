"""Device, update and anti-malware evidence, read the way the endpoint rules need it.

Cyber Essentials asks whether devices are encrypted, supported, patched and protected against malware.
A tenant audit can see part of that through Intune, and only for the devices Intune manages. This module
turns the Intune reads into small, explicit records and never guesses:

* every check on a device is three-valued (``on``/``off``/``unknown``, ``current``/``stale``/``unknown``):
  a field that is absent, ``Unknown`` or unparseable is ``unknown``, never a pass and never a failure;
* a list that was blocked, cut or never collected makes the checks that read it ``unknown`` as a whole;
* nothing here performs I/O or reads the clock: callers pass ``now`` and ``today``.

Read states reuse the identity-control vocabulary: ``collected``, ``truncated``, ``blocked``, ``absent``.
"""
from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any

from . import os_lifecycle

DEVICE_SECTION = "device_posture"
DEVICE_SUMMARY_KIND = "device_posture_summary"
COMPLIANCE_SECTION = "compliance_policy_objects"
COMPLIANCE_POLICY_KIND = "compliance_policy"
COMPLIANCE_PLATFORM_KIND = "compliance_platform_coverage"
COMPLIANCE_SUMMARY_KIND = "compliance_policy_summary"
UPDATE_SECTION = "update_management_objects"
UPDATE_RING_KIND = "update_ring"
UPDATE_PROFILE_KIND = "update_profile"
UPDATE_SUMMARY_KIND = "update_management_summary"
DEFENDER_SECTION = "defender_av_objects"
DEFENDER_STATE_KIND = "defender_av_state"
DEFENDER_SUMMARY_KIND = "defender_av_summary"

# Cyber Essentials: critical and high-risk updates are installed within 14 days of release, so a device
# that has not checked in for 14 days cannot be shown to have received them.
STALE_SYNC_DAYS_ENV = "AUDITEX_STALE_SYNC_DAYS"
DEFAULT_STALE_SYNC_DAYS = 14
STALE_SYNC_DAYS_MAX = 3650
UPDATE_DEFERRAL_LIMIT_DAYS = 14

# Platforms that have a classic Intune compliance policy template (the ones the missing-policy rule judges).
COMPLIANCE_PLATFORMS = (os_lifecycle.FAMILY_WINDOWS, os_lifecycle.FAMILY_MACOS, os_lifecycle.FAMILY_IOS, os_lifecycle.FAMILY_ANDROID)

STATE_ON = "on"
STATE_OFF = "off"
STATE_UNKNOWN = "unknown"
STATE_CURRENT = "current"
STATE_STALE = "stale"
STATE_NOT_APPLICABLE = "not_applicable"
STATE_CLEAN = "clean"
STATE_JAILBROKEN = "jailbroken"

READ_OK = "ok"
READ_NOT_REPORTED = "not_reported"
READ_FAILED = "failed"


def canonical_bool(value: Any) -> bool | None:
    """``True``/``False`` for a boolean or its text ("True", "false"); anything else, including "Unknown", is ``None``."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return None


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def parse_timestamp(value: Any) -> datetime | None:
    """A timezone-aware UTC datetime from an ISO 8601 string, or ``None``."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def stale_sync_days(days: int | str | None = None) -> int:
    """Days without an Intune check-in after which a managed device is stale.

    The argument wins, then ``AUDITEX_STALE_SYNC_DAYS``, then the 14 days Cyber Essentials uses for
    installing updates. A value that is not a whole number from 1 to 3650 is ignored, never half-applied.
    """
    for candidate in (days, os.environ.get(STALE_SYNC_DAYS_ENV)):
        if candidate is None or isinstance(candidate, bool):
            continue
        try:
            value = int(str(candidate).strip())
        except ValueError:
            continue
        if 1 <= value <= STALE_SYNC_DAYS_MAX:
            return value
    return DEFAULT_STALE_SYNC_DAYS


def _first(item: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = item.get(name)
        if value is not None and value != "":
            return value
    return None


# ---- managed devices ------------------------------------------------------------------------------------


def canonical_owner_type(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    return text if text in {"company", "personal", "unknown"} else None


def device_fields(item: Mapping[str, Any]) -> dict[str, Any]:
    """The posture fields of one Intune ``managedDevice`` row; absent or unreadable ones are ``None``.

    Graph v1.0 names the owner field ``managedDeviceOwnerType``; the beta ``ownerType`` is read as a fallback.
    """
    return {
        "is_encrypted": canonical_bool(item.get("isEncrypted")),
        "jail_broken": canonical_bool(item.get("jailBroken")),
        "owner_type": canonical_owner_type(_first(item, "managedDeviceOwnerType", "ownerType")),
        "enrolled_at": item.get("enrolledDateTime"),
        "enrollment_type": item.get("deviceEnrollmentType"),
        "os_family": os_lifecycle.os_family(item.get("operatingSystem")),
    }


def _family(device: Mapping[str, Any]) -> str | None:
    return device.get("os_family") or os_lifecycle.os_family(device.get("platform"))


def encryption_state(device: Mapping[str, Any]) -> str:
    value = device.get("is_encrypted")
    if not isinstance(value, bool):
        return STATE_UNKNOWN
    return STATE_ON if value else STATE_OFF


def jailbreak_state(device: Mapping[str, Any]) -> str:
    """Jailbreak and root detection exists on iOS and Android; Intune does not report it for the rest."""
    if _family(device) not in os_lifecycle.MOBILE_FAMILIES:
        return STATE_NOT_APPLICABLE
    value = device.get("jail_broken")
    if not isinstance(value, bool):
        return STATE_UNKNOWN
    return STATE_JAILBROKEN if value else STATE_CLEAN


# Compliance states Intune has decided. ``unknown``, ``inGracePeriod`` (not compliant, but access is still granted),
# ``configManager`` (decided outside Intune) and a missing value say nothing about whether the device is compliant.
COMPLIANCE_DECIDED_STATES = frozenset({"compliant", "noncompliant", "error", "conflict"})
COMPLIANCE_IN_GRACE_PERIOD = "ingraceperiod"


def compliance_state(device: Mapping[str, Any]) -> str:
    """The device's Intune compliance state, lower-case; empty when the payload carries none."""
    return str(device.get("compliance_state") or "").strip().lower()


def sync_state(device: Mapping[str, Any], days: int, now: datetime) -> str:
    last = parse_timestamp(device.get("last_sync_at"))
    if last is None:
        return STATE_UNKNOWN
    return STATE_STALE if (now - last).total_seconds() > days * 86400 else STATE_CURRENT


def lifecycle(device: Mapping[str, Any], today: date) -> os_lifecycle.Lifecycle:
    return os_lifecycle.classify(device.get("platform"), device.get("os_version"), today)


def today_utc() -> date:
    return datetime.now(tz=timezone.utc).date()


def device_posture_summary(
    devices: Sequence[Mapping[str, Any]], *, read_state: str, read_detail: str | None = None, today: date | None = None
) -> dict[str, Any]:
    """Counts of the devices each check says nothing about.

    Whether a device can be judged at all is fixed here: a device with no last-sync time, or an OS the
    table does not describe, is unknown whatever day it is. The one date-dependent unknown, a Windows build
    whose Home/Pro end of support has passed but whose Enterprise/Education date has not, is counted as of
    ``os_lifecycle_evaluated_on`` because the edition is not in the data.
    """
    today = today or today_utc()
    encryption = Counter(encryption_state(device) for device in devices)
    jailbreak = Counter(jailbreak_state(device) for device in devices)
    platforms = Counter(str(_family(device) or "other") for device in devices)
    sync_unknown = sum(1 for device in devices if parse_timestamp(device.get("last_sync_at")) is None)
    compliance_unknown = sum(1 for device in devices if compliance_state(device) not in COMPLIANCE_DECIDED_STATES)
    in_grace_period = sum(1 for device in devices if compliance_state(device) == COMPLIANCE_IN_GRACE_PERIOD)
    lifecycle_reasons: Counter[str] = Counter()
    edition_dependent = 0
    for device in devices:
        _family_name, release, reason = os_lifecycle.lookup(device.get("platform"), device.get("os_version"))
        if release is None:
            lifecycle_reasons[str(reason)] += 1
        elif os_lifecycle.classify(device.get("platform"), device.get("os_version"), today).state == os_lifecycle.STATE_EDITION_DEPENDENT:
            edition_dependent += 1
    return {
        "read_state": read_state,
        "read_detail": read_detail,
        "device_count": len(devices),
        "platform_counts": {name: platforms[name] for name in sorted(platforms)},
        "encryption_on": encryption[STATE_ON],
        "encryption_off": encryption[STATE_OFF],
        "encryption_unknown": encryption[STATE_UNKNOWN],
        "jailbreak_clean": jailbreak[STATE_CLEAN],
        "jailbreak_jailbroken": jailbreak[STATE_JAILBROKEN],
        "jailbreak_unknown": jailbreak[STATE_UNKNOWN],
        "jailbreak_not_applicable": jailbreak[STATE_NOT_APPLICABLE],
        "last_sync_unknown": sync_unknown,
        "compliance_unknown": compliance_unknown,
        "compliance_in_grace_period": in_grace_period,
        "os_lifecycle_unknown": sum(lifecycle_reasons.values()),
        "os_lifecycle_unknown_reasons": [{"reason": name, "count": lifecycle_reasons[name]} for name in sorted(lifecycle_reasons)],
        "os_lifecycle_edition_dependent": edition_dependent,
        "os_lifecycle_evaluated_on": today.isoformat(),
        "os_lifecycle_table_verified_on": os_lifecycle.table_verified_on(),
    }


# ---- compliance policies --------------------------------------------------------------------------------

_COMPLIANCE_TYPES = {
    "windows10compliancepolicy": os_lifecycle.FAMILY_WINDOWS,
    "windows81compliancepolicy": os_lifecycle.FAMILY_WINDOWS,
    "windowsphone81compliancepolicy": "windows_phone",
    "ioscompliancepolicy": os_lifecycle.FAMILY_IOS,
    "macoscompliancepolicy": os_lifecycle.FAMILY_MACOS,
    "androidcompliancepolicy": os_lifecycle.FAMILY_ANDROID,
    "androidworkprofilecompliancepolicy": os_lifecycle.FAMILY_ANDROID,
    "androiddeviceownercompliancepolicy": os_lifecycle.FAMILY_ANDROID,
    "aospdeviceownercompliancepolicy": os_lifecycle.FAMILY_ANDROID,
}


def _type_name(odata_type: Any) -> str:
    return str(odata_type or "").rsplit(".", 1)[-1].strip().lower()


def compliance_platform(odata_type: Any) -> str | None:
    """The platform a compliance policy's ``@odata.type`` belongs to, or ``None`` for an unfamiliar type."""
    return _COMPLIANCE_TYPES.get(_type_name(odata_type))


def _any_flag(item: Mapping[str, Any], *names: str) -> bool | None:
    """``True`` when any named setting is on, ``False`` when some are present and all off, ``None`` when none is present."""
    values = [canonical_bool(item[name]) for name in names if name in item]
    values = [value for value in values if value is not None]
    if not values:
        return None
    return any(values)


def compliance_settings(item: Mapping[str, Any]) -> dict[str, Any]:
    """The settings that matter for a device assertion; ``None`` where the policy type has no such setting.

    Key names avoid the word "password" (the bundle redacts such keys). Graph v1.0 does not expose
    Defender settings on a Windows policy, so ``defender_required`` is usually ``None`` (unknown) there.
    """
    minimum = _first(item, "osMinimumVersion")
    return {
        "passcode_required": _any_flag(item, "passwordRequired", "passcodeRequired"),
        "passcode_min_length": _integer(_first(item, "passwordMinimumLength", "passcodeMinimumLength")),
        "encryption_required": _any_flag(item, "storageRequireEncryption", "bitLockerEnabled"),
        "min_os_version": str(minimum) if minimum else None,
        "jailbreak_blocked": _any_flag(item, "securityBlockJailbrokenDevices"),
        "defender_required": _any_flag(item, "defenderEnabled", "rtpEnabled", "antivirusRequired", "antiSpywareRequired"),
        "firewall_required": _any_flag(item, "firewallEnabled", "activeFirewallRequired"),
        "threat_protection_required": _any_flag(item, "deviceThreatProtectionEnabled"),
        "secure_boot_required": _any_flag(item, "secureBootEnabled"),
    }


def assignment_summary(assignments: Iterable[Any]) -> dict[str, Any]:
    """What an assignment list targets: all devices, all users, groups, and exclusions. Group ids are not kept."""
    rows = [row for row in assignments if isinstance(row, Mapping)]
    all_devices = all_users = False
    groups = exclusions = 0
    for row in rows:
        target = row.get("target") if isinstance(row.get("target"), Mapping) else {}
        kind = _type_name(target.get("@odata.type"))
        if kind == "alldevicesassignmenttarget":
            all_devices = True
        elif kind == "alllicensedusersassignmenttarget":
            all_users = True
        elif kind == "exclusiongroupassignmenttarget":
            exclusions += 1
        elif kind == "groupassignmenttarget" or target.get("groupId"):
            groups += 1
    return {
        "assignment_count": len(rows),
        "assigned_to_all_devices": all_devices,
        "assigned_to_all_users": all_users,
        "group_target_count": groups,
        "exclusion_count": exclusions,
        # An exclusion on its own assigns the policy to nobody.
        "assigned": (len(rows) - exclusions) > 0,
    }


def compliance_platform_coverage(devices: Sequence[Mapping[str, Any]], policies: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Per platform: enrolled devices and the compliance policies of that platform, with how many are assigned.

    ``policies`` are normalized ``compliance_policy`` records. A policy whose assignments were not read has
    ``assignments_known`` false and counts as neither assigned nor unassigned.
    """
    devices_by_platform = Counter(str(_family(device) or "other") for device in devices)
    rows: list[dict[str, Any]] = []
    for platform in COMPLIANCE_PLATFORMS:
        platform_policies = [policy for policy in policies if policy.get("platform") == platform]
        known = [policy for policy in platform_policies if policy.get("assignments_known") is True]
        rows.append(
            {
                "platform": platform,
                "device_count": devices_by_platform[platform],
                "policy_count": len(platform_policies),
                "assigned_policy_count": sum(1 for policy in known if policy.get("assigned") is True),
                "unassigned_policy_count": sum(1 for policy in known if policy.get("assigned") is not True),
                "assignments_unknown_count": len(platform_policies) - len(known),
            }
        )
    return rows


# ---- Windows Update for Business ------------------------------------------------------------------------

UPDATE_RING_TYPE = "windowsupdateforbusinessconfiguration"
UPDATE_RING_FIELDS = (
    "id",
    "displayName",
    "lastModifiedDateTime",
    "qualityUpdatesDeferralPeriodInDays",
    "featureUpdatesDeferralPeriodInDays",
    "deadlineForQualityUpdatesInDays",
    "deadlineForFeatureUpdatesInDays",
    "deadlineGracePeriodInDays",
    "qualityUpdatesPaused",
    "featureUpdatesPaused",
    "qualityUpdatesPauseExpiryDateTime",
    "featureUpdatesPauseExpiryDateTime",
    "automaticUpdateMode",
    "microsoftUpdateServiceAllowed",
    "businessReadyUpdatesOnly",
    "driversExcluded",
    "userPauseAccess",
)
QUALITY_PROFILE_FIELDS = ("id", "displayName", "lastModifiedDateTime", "expeditedUpdateSettings", "releaseDateDisplayName")
FEATURE_PROFILE_FIELDS = ("id", "displayName", "lastModifiedDateTime", "featureUpdateVersion", "rolloutSettings", "endOfSupportDate")


def is_update_ring(item: Mapping[str, Any]) -> bool:
    return _type_name(item.get("@odata.type")) == UPDATE_RING_TYPE


def project(item: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    """Only the named fields of a raw row, so nothing else in a policy object is kept."""
    return {name: item[name] for name in fields if name in item}


def update_ring_fields(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "quality_deferral_days": _integer(item.get("qualityUpdatesDeferralPeriodInDays")),
        "feature_deferral_days": _integer(item.get("featureUpdatesDeferralPeriodInDays")),
        "quality_deadline_days": _integer(item.get("deadlineForQualityUpdatesInDays")),
        "feature_deadline_days": _integer(item.get("deadlineForFeatureUpdatesInDays")),
        "deadline_grace_days": _integer(item.get("deadlineGracePeriodInDays")),
        "quality_paused": canonical_bool(item.get("qualityUpdatesPaused")),
        "feature_paused": canonical_bool(item.get("featureUpdatesPaused")),
        "quality_pause_expires_at": item.get("qualityUpdatesPauseExpiryDateTime"),
        "automatic_update_mode": item.get("automaticUpdateMode"),
        "microsoft_update_service_allowed": canonical_bool(item.get("microsoftUpdateServiceAllowed")),
    }


def quality_pause_active(ring: Mapping[str, Any], now: datetime) -> bool | None:
    """Whether quality updates are paused now: ``None`` when the pause flag was not read."""
    paused = ring.get("quality_paused")
    if not isinstance(paused, bool):
        return None
    if not paused:
        return False
    expiry = parse_timestamp(ring.get("quality_pause_expires_at"))
    # A pause with no readable expiry is taken as still in force; one that has expired is not.
    return expiry is None or expiry > now


def ring_install_delay_days(ring: Mapping[str, Any]) -> int | None:
    """The longest a quality update can wait: the deferral, plus the deadline and the restart grace period when a deadline is set.

    Windows installs an update once the deferral ends; the deadline is how many days after that it is forced, and the
    grace period how many days after the deadline a restart is forced. Without a deadline nothing is forced and the
    deferral alone decides. ``None`` when the deferral was not returned.
    """
    deferral = ring.get("quality_deferral_days")
    if not isinstance(deferral, int):
        return None
    deadline = ring.get("quality_deadline_days")
    if not isinstance(deadline, int):
        return deferral
    grace = ring.get("deadline_grace_days")
    return deferral + deadline + (grace if isinstance(grace, int) else 0)


def ring_delay_reasons(ring: Mapping[str, Any], now: datetime) -> list[str]:
    """Why an assigned ring delays quality updates beyond the 14 days Cyber Essentials allows."""
    reasons: list[str] = []
    deferral = ring.get("quality_deferral_days")
    delay = ring_install_delay_days(ring)
    if isinstance(deferral, int) and deferral > UPDATE_DEFERRAL_LIMIT_DAYS:
        reasons.append("quality_deferral_over_14_days")
    elif delay is not None and delay > UPDATE_DEFERRAL_LIMIT_DAYS:
        reasons.append("quality_deferral_and_deadline_over_14_days")
    if quality_pause_active(ring, now):
        reasons.append("quality_updates_paused")
    return reasons


def ring_settings_known(ring: Mapping[str, Any]) -> bool:
    """Both settings the delay rule reads are present on the ring."""
    return isinstance(ring.get("quality_deferral_days"), int) and isinstance(ring.get("quality_paused"), bool)


def update_profile_fields(item: Mapping[str, Any], profile_type: str) -> dict[str, Any]:
    fields: dict[str, Any] = {"profile_type": profile_type}
    if profile_type == "feature":
        fields["feature_update_version"] = item.get("featureUpdateVersion")
        fields["end_of_support_at"] = item.get("endOfSupportDate")
    else:
        fields["expedited"] = isinstance(item.get("expeditedUpdateSettings"), Mapping) or None
    return fields


# ---- Defender antivirus state -----------------------------------------------------------------------------

PROTECTION_FIELDS = (
    "malwareProtectionEnabled",
    "realTimeProtectionEnabled",
    "networkInspectionSystemEnabled",
    "signatureUpdateOverdue",
    "quickScanOverdue",
    "fullScanOverdue",
    "rebootRequired",
    "fullScanRequired",
    "tamperProtectionEnabled",
    "isVirtualMachine",
    "productStatus",
    "deviceState",
    "engineVersion",
    "signatureVersion",
    "antiMalwareVersion",
    "lastQuickScanDateTime",
    "lastFullScanDateTime",
    "lastReportedDateTime",
)
_AV_OFF_STATUS = frozenset({"servicenotrunning", "servicestartedwithoutmalwareprotection"})
_SIGNATURE_STALE_STATUS = frozenset({"avsignaturesoutofdate", "assignaturesoutofdate"})


def _product_flags(value: Any) -> set[str]:
    """``productStatus`` is a flags enum; Graph returns the set bits as comma-separated names."""
    return {part.strip().lower() for part in str(value or "").split(",") if part.strip()}


def defender_states(row: Mapping[str, Any]) -> dict[str, str]:
    """Antivirus, real-time protection and signature state of one device, each ``on``/``off``/``stale``/``unknown``."""
    if row.get("read_status") != READ_OK:
        return {"av_state": STATE_UNKNOWN, "realtime_state": STATE_UNKNOWN, "signature_state": STATE_UNKNOWN}
    flags = _product_flags(row.get("productStatus") if "productStatus" in row else row.get("product_status"))
    protection = canonical_bool(_first(row, "malwareProtectionEnabled", "malware_protection_enabled"))
    realtime = canonical_bool(_first(row, "realTimeProtectionEnabled", "real_time_protection_enabled"))
    overdue = canonical_bool(_first(row, "signatureUpdateOverdue", "signature_update_overdue"))
    if flags & _AV_OFF_STATUS or protection is False:
        av = STATE_OFF
    elif protection is True:
        av = STATE_ON
    else:
        av = STATE_UNKNOWN
    if overdue is True or flags & _SIGNATURE_STALE_STATUS:
        signatures = STATE_STALE
    elif overdue is False:
        signatures = STATE_CURRENT
    else:
        signatures = STATE_UNKNOWN
    return {
        "av_state": av,
        "realtime_state": STATE_UNKNOWN if realtime is None else (STATE_ON if realtime else STATE_OFF),
        "signature_state": signatures,
    }


def defender_state_fields(row: Mapping[str, Any]) -> dict[str, Any]:
    """The normalized fields of one ``windowsProtectionState`` read."""
    states = defender_states(row)
    return {
        "device_name": row.get("deviceName"),
        "read_status": row.get("read_status"),
        "read_error_class": row.get("error_class"),
        "malware_protection_enabled": canonical_bool(row.get("malwareProtectionEnabled")),
        "real_time_protection_enabled": canonical_bool(row.get("realTimeProtectionEnabled")),
        "signature_update_overdue": canonical_bool(row.get("signatureUpdateOverdue")),
        "quick_scan_overdue": canonical_bool(row.get("quickScanOverdue")),
        "full_scan_overdue": canonical_bool(row.get("fullScanOverdue")),
        "tamper_protection_enabled": canonical_bool(row.get("tamperProtectionEnabled")),
        "product_status": row.get("productStatus"),
        "device_health_state": row.get("deviceState"),
        "signature_version": row.get("signatureVersion"),
        "last_reported_at": row.get("lastReportedDateTime"),
        **states,
    }
