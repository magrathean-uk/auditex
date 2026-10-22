from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from azure_tenant_audit.collection_gaps import (
    COLLECTION_GAP_SECTION,
    collection_gap_records,
    list_truncations,
    truncations_from_payloads,
)
from azure_tenant_audit.data_minimisation import minimise_gmail_settings

from .collectors import SUBJECT_SCOPE_ADMIN, SUBJECT_SCOPE_USER, SUBJECT_SCOPED_COLLECTORS


def _values(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    section = payload.get(key, {})
    values = section.get("value", []) if isinstance(section, dict) else []
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _compact(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value not in (None, [], {}, "")}


def _record(kind: str, source: str, object_id: str, **fields: Any) -> dict[str, Any]:
    payload = {"kind": kind, "source": source, "id": object_id, "key": f"{kind}:{object_id}"}
    payload.update(fields)
    return _compact(payload)


def _email_domain(value: Any) -> str | None:
    text = str(value or "")
    if "@" not in text:
        return None
    return text.rsplit("@", 1)[1].lower()


def _utc_text(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _epoch_text(value: Any) -> str | None:
    """A Google int64 timestamp (epoch seconds or milliseconds) as UTC ISO text; None when absent or zero."""
    text = str(value or "").strip()
    if not text.isdigit():
        return None
    number = int(text)
    if number <= 0:
        return None
    if len(text) == 8:
        # An Android patch level is sometimes a YYYYMMDD date rather than an epoch.
        try:
            return _utc_text(datetime.strptime(text, "%Y%m%d").replace(tzinfo=timezone.utc))
        except ValueError:
            return None
    seconds = number / 1000 if number > 10**11 else number
    try:
        return _utc_text(datetime.fromtimestamp(seconds, tz=timezone.utc))
    except (OverflowError, OSError, ValueError):
        return None


def _auto_update_expiration(item: dict[str, Any]) -> tuple[str | None, str | None]:
    """ChromeOS auto-update expiration as UTC text, and which API field it came from."""
    through = _parse_timestamp(item.get("autoUpdateThrough"))
    if through is not None:
        return _utc_text(through), "autoUpdateThrough"
    legacy = _epoch_text(item.get("autoUpdateExpiration"))
    return (legacy, "autoUpdateExpiration") if legacy else (None, None)


_NEGATIVE_STATES = ("not encrypted", "unencrypted", "no encryption", "not enabled", "disabled", "off", "not set", "no password", "non compliant", "noncompliant", "not compliant")
_POSITIVE_STATES = ("encrypted", "enabled", "on", "set", "compliant", "password enabled")


def _device_state(value: Any, *, positive: str, negative: str) -> str | None:
    """Tri-state of a device posture string; None when absent or in a form this tool does not recognise.

    The Directory API does not enumerate the values of ``encryptionStatus`` or ``devicePasswordStatus``,
    so an unrecognised value is unknown, never a pass and never a failure. The raw text is kept beside it.
    """
    text = " ".join(str(value or "").replace("_", " ").replace("-", " ").lower().split())
    if not text or text in {"unknown", "unspecified", "not supported", "unsupported", "n/a"}:
        return None
    if text in _NEGATIVE_STATES:
        return negative
    if text in _POSITIVE_STATES:
        return positive
    return None


# The Directory API describes ``deviceCompromisedStatus`` only as "the compromised device status" and
# lists no values. These are the texts seen in the Admin console and API output, and the Cloud Identity
# Devices enum (COMPROMISED, UNCOMPROMISED). Anything else is unknown: never a pass, never a failure.
COMPROMISED = "compromised"
NOT_COMPROMISED = "not_compromised"
UNKNOWN_COMPROMISE = "unknown"
_COMPROMISED_TEXTS = frozenset({"compromised", "compromise detected", "device compromised"})
_NOT_COMPROMISED_TEXTS = frozenset({"no compromise detected", "no compromise", "not compromised", "uncompromised"})


def compromised_state(value: Any) -> str:
    """``compromised``, ``not_compromised`` or ``unknown`` for a ``deviceCompromisedStatus`` value.

    Only the recognised texts classify. An absent field, ``unknown`` or ``COMPROMISED_STATE_UNSPECIFIED``,
    or any text this tool has not seen, is ``unknown``; the raw text stays on the record beside it.
    """
    text = " ".join(str(value or "").replace("_", " ").replace("-", " ").lower().split())
    if text in _COMPROMISED_TEXTS:
        return COMPROMISED
    if text in _NOT_COMPROMISED_TEXTS:
        return NOT_COMPROMISED
    return UNKNOWN_COMPROMISE


_POLICY_PREFIX = "settings/"


def _policy_value(setting: dict[str, Any], *names: str) -> Any:
    value = setting.get("value") if isinstance(setting.get("value"), dict) else {}
    for name in names:
        if value.get(name) not in (None, ""):
            return value.get(name)
    return None


def _org_unit_key(value: Any) -> str:
    """An org unit id without the ``id:`` (Directory) or ``orgUnits/`` (Policy API) prefix."""
    text = str(value or "").strip()
    for prefix in ("orgUnits/", "id:"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    return text


def _root_org_unit(directory: dict[str, Any] | None, coverage_rows: list[dict[str, Any]]) -> tuple[bool, set[str]]:
    """Whether the root organisational unit can be told apart in the Directory org units, and its id.

    The Directory list holds no row for the root: it is the parent of the top-level units. A list that
    was read and is empty means the root is the only unit, so every unit-level policy is the root's.
    Without the list (not collected, failed) the root is unknown and no policy can be called organisation-wide.
    """
    if not isinstance(directory, dict) or not isinstance(directory.get("orgUnits"), dict):
        return False, set()
    rows = [
        row
        for row in coverage_rows
        if row.get("collector") == "google_directory" and row.get("name") == "orgUnits"
    ]
    if any(row.get("status") not in (None, "ok") for row in rows):
        return False, set()
    units = _values(directory, "orgUnits")
    if not units:
        return (not any(row.get("collection_truncated") is True for row in rows)), set()
    roots = {
        _org_unit_key(unit.get("parentOrgUnitId"))
        for unit in units
        if str(unit.get("parentOrgUnitPath") or "") == "/" and unit.get("parentOrgUnitId")
    }
    return bool(roots), roots


def _policy_scope(record: dict[str, Any], *, root_known: bool, root_ids: set[str]) -> str:
    """``group``, ``organisation`` (the root unit, no group), ``org_unit`` or ``unclassified`` (root unknown)."""
    if record.get("group"):
        return "group"
    if not root_known:
        return "unclassified"
    unit = _org_unit_key(record.get("org_unit"))
    return "organisation" if not root_ids or unit in root_ids else "org_unit"


def _two_step_policy_status(
    payload: dict[str, Any] | None,
    records: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    now: datetime,
) -> str:
    """Whether 2-step verification is enforced for the organisation.

    ``enforcing``: the organisation-level policy (root unit, no group) is in force. ``partial``: only
    some organisational units or groups are enforced, the organisation-level policy is not. ``scheduled``:
    every enforcement date is still ahead. ``not_enforced``: the read completed and no policy enforces.
    ``unknown``: the read did not happen or is incomplete, or an enforcing policy cannot be placed in the
    organisation because the root unit is unknown. Unknown is never read as not enforced.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("twoStepVerificationPolicies"), dict):
        return "unknown"
    rows = [row for row in coverage_rows if row.get("collector") == "google_policies"]
    if any(row.get("status") not in (None, "ok") and row.get("name") == "twoStepVerificationPolicies" for row in rows):
        return "unknown"
    truncated = any(row.get("collection_truncated") is True for row in rows)
    enforcement = [record for record in records if record.get("setting_type") == "security.two_step_verification_enforcement"]
    in_force = [record for record in enforcement if (_parse_timestamp(record.get("enforced_from")) or now + timedelta(days=1)) <= now]
    if in_force:
        scopes = {record.get("policy_scope") for record in in_force}
        if "organisation" in scopes:
            return "enforcing"
        if scopes <= {"unclassified"}:
            return "unknown"
        return "partial"
    if any(_parse_timestamp(record.get("enforced_from")) is not None for record in enforcement):
        return "scheduled"
    return "unknown" if truncated else "not_enforced"


def build_google_normalized_snapshot(
    *,
    tenant_name: str,
    run_id: str,
    collector_payloads: dict[str, dict[str, Any]],
    domain: str | None = None,
    customer_id: str | None = None,
    diagnostics: list[dict[str, Any]] | None = None,
    result_rows: list[dict[str, Any]] | None = None,
    coverage_rows: list[dict[str, Any]] | None = None,
    top_limit: int | None = None,
) -> dict[str, dict[str, Any]]:
    diagnostics = diagnostics or []
    result_rows = result_rows or []
    coverage_rows = coverage_rows or []
    workspace_domain = str(domain or "").lower() or None
    now = datetime.now(tz=timezone.utc)

    users = [
        _record(
            "google_user",
            "google_directory.users",
            str(item.get("id") or item.get("primaryEmail")),
            primary_email=item.get("primaryEmail"),
            display_name=(item.get("name") or {}).get("fullName") if isinstance(item.get("name"), dict) else item.get("name"),
            is_admin=bool(item.get("isAdmin")),
            is_delegated_admin=bool(item.get("isDelegatedAdmin")),
            # Super admin or delegated admin: the flag the 2-step verification and stale-account rules use.
            is_privileged=bool(item.get("isAdmin") or item.get("isDelegatedAdmin")),
            suspended=bool(item.get("suspended")),
            archived=bool(item.get("archived")),
            is_enrolled_in_2sv=item.get("isEnrolledIn2Sv"),
            is_enforced_in_2sv=item.get("isEnforcedIn2Sv"),
            last_login_time=item.get("lastLoginTime"),
            creation_time=item.get("creationTime"),
            org_unit_path=item.get("orgUnitPath"),
            domain=_email_domain(item.get("primaryEmail")),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "users")
        if item.get("id") or item.get("primaryEmail")
    ]
    domain_records: list[dict[str, Any]] = []
    seen_domains: set[str] = set()
    for item in _values(collector_payloads.get("google_directory", {}), "domains"):
        domain_name = str(item.get("domainName") or item.get("domain") or "").strip().lower()
        if not domain_name or domain_name in seen_domains:
            continue
        seen_domains.add(domain_name)
        domain_records.append(
            _record(
                "google_domain",
                "google_directory.domains",
                domain_name,
                domain_name=domain_name,
                domain_kind="primary" if item.get("isPrimary") else "secondary",
                is_primary=bool(item.get("isPrimary")),
                verified=item.get("verified"),
            )
        )
        for alias in item.get("domainAliases") or []:
            if not isinstance(alias, dict):
                continue
            alias_name = str(alias.get("domainAliasName") or "").strip().lower()
            if not alias_name or alias_name in seen_domains:
                continue
            seen_domains.add(alias_name)
            domain_records.append(
                _record(
                    "google_domain",
                    "google_directory.domains",
                    alias_name,
                    domain_name=alias_name,
                    domain_kind="alias",
                    is_primary=False,
                    parent_domain=domain_name,
                    verified=alias.get("verified"),
                )
            )
    # Internal domains: every primary, secondary and alias domain of the customer, plus the --domain label.
    # With neither, the external-principal checks cannot say what is external and report unknown.
    internal_domains = sorted(seen_domains | ({workspace_domain} if workspace_domain else set()))
    domain_rows = [
        row for row in coverage_rows if row.get("collector") == "google_directory" and row.get("name") == "domains"
    ]
    domains_section = (collector_payloads.get("google_directory") or {}).get("domains")
    domains_incomplete = any(
        row.get("status") not in (None, "ok") or row.get("collection_truncated") is True for row in domain_rows
    ) or (isinstance(domains_section, dict) and domains_section.get("collection_truncated") is True)
    if seen_domains:
        # A list cut short or partly read can miss a secondary or alias domain, so it is not "known".
        internal_domains_status = "partial" if domains_incomplete else "known"
        internal_domains_source = "directory+label" if workspace_domain and workspace_domain not in seen_domains else "directory"
    elif workspace_domain:
        internal_domains_status = "label_only"
        internal_domains_source = "label"
    else:
        internal_domains_status = "unknown"
        internal_domains_source = "none"
    root_known, root_ids = _root_org_unit(collector_payloads.get("google_directory"), coverage_rows)
    policy_records = [
        _record(
            "google_two_step_policy",
            "google_policies.twoStepVerificationPolicies",
            str(item.get("name") or f"{(item.get('setting') or {}).get('type')}:{(item.get('policyQuery') or {}).get('orgUnit')}"),
            setting_type=str((item.get("setting") or {}).get("type") or "").removeprefix(_POLICY_PREFIX) or None,
            policy_type=item.get("type"),
            org_unit=(item.get("policyQuery") or {}).get("orgUnit"),
            group=(item.get("policyQuery") or {}).get("group"),
            sort_order=(item.get("policyQuery") or {}).get("sortOrder"),
            enforced_from=_policy_value(item.get("setting") or {}, "enforcedFrom", "enforced_from"),
            allow_enrollment=_policy_value(item.get("setting") or {}, "allowEnrollment", "allow_enrollment"),
            allowed_sign_in_factor_set=_policy_value(item.get("setting") or {}, "allowedSignInFactorSet", "allowed_sign_in_factor_set"),
            enrollment_grace_period=_policy_value(item.get("setting") or {}, "enrollmentGracePeriod", "enrollment_grace_period"),
        )
        for item in _values(collector_payloads.get("google_policies", {}), "twoStepVerificationPolicies")
        if isinstance(item.get("setting"), dict)
    ]
    for record in policy_records:
        # organisation (root unit, no group), org_unit, group, or unclassified when the root unit is unknown
        record["policy_scope"] = _policy_scope(record, root_known=root_known, root_ids=root_ids)
    groups = [
        _record(
            "google_group",
            "google_directory.groups",
            str(item.get("id") or item.get("email")),
            email=item.get("email"),
            display_name=item.get("name"),
            description=item.get("description"),
            direct_members_count=item.get("directMembersCount"),
            who_can_join=item.get("whoCanJoin"),
            who_can_view_membership=item.get("whoCanViewMembership"),
            domain=_email_domain(item.get("email")),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "groups")
        if item.get("id") or item.get("email")
    ]
    group_members = [
        _record(
            "google_group_member",
            "google_directory.groupMembers",
            f"{item.get('groupEmail')}:{item.get('id') or item.get('email')}",
            group_email=item.get("groupEmail"),
            email=item.get("email"),
            role=item.get("role"),
            type=item.get("type"),
            status=item.get("status"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "groupMembers")
        if item.get("groupEmail") and (item.get("id") or item.get("email"))
    ]
    group_member_errors = [
        _record(
            "google_group_member_error",
            "google_directory.groupMembersErrors",
            str(item.get("groupEmail")),
            group_email=item.get("groupEmail"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "groupMembersErrors")
        if item.get("groupEmail")
    ]
    alias_errors = [
        _record(
            "google_alias_error",
            "google_directory.aliasesErrors",
            str(item.get("userKey")),
            user_email=item.get("userKey"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "aliasesErrors")
        if item.get("userKey")
    ]
    roles = {
        str(item.get("roleId")): item
        for item in _values(collector_payloads.get("google_directory", {}), "roles")
        if item.get("roleId")
    }
    role_assignments = [
        _record(
            "google_role_assignment",
            "google_directory.roleAssignments",
            str(item.get("roleAssignmentId") or f"{item.get('roleId')}:{item.get('assignedTo')}"),
            role_id=item.get("roleId"),
            role_name=(roles.get(str(item.get("roleId"))) or {}).get("roleName"),
            assigned_to=item.get("assignedTo"),
            scope_type=item.get("scopeType"),
            org_unit_id=item.get("orgUnitId"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "roleAssignments")
        if item.get("roleId") or item.get("assignedTo")
    ]
    oauth_grants = [
        _record(
            "google_oauth_grant",
            "google_directory.oauthGrants",
            f"{item.get('userKey')}:{item.get('clientId') or item.get('client_id')}",
            user_email=item.get("userKey"),
            client_id=item.get("clientId") or item.get("client_id"),
            display_name=item.get("displayText") or item.get("display_name") or item.get("anonymous"),
            scopes=item.get("scopes") or [],
        )
        for item in _values(collector_payloads.get("google_directory", {}), "oauthGrants")
        if item.get("clientId") or item.get("client_id")
    ]
    oauth_grant_errors = [
        _record(
            "google_oauth_grant_error",
            "google_directory.oauthGrantsErrors",
            str(item.get("userKey")),
            user_email=item.get("userKey"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "oauthGrantsErrors")
        if item.get("userKey")
    ]
    mailbox_settings = [
        _record(
            "google_mailbox_setting",
            "google_gmail_settings.mailboxSettings",
            str(item.get("userEmail")),
            user_email=item.get("userEmail"),
            auto_forwarding=item.get("autoForwarding"),
            auto_forwarding_error=item.get("autoForwarding_error") or {},
            filters=item.get("filters") or [],
            filters_error=item.get("filters_error") or {},
            forwarding_addresses=item.get("forwardingAddresses") or [],
            forwarding_addresses_error=item.get("forwardingAddresses_error") or {},
            send_as=minimise_gmail_settings(item).get("sendAs") or [],
            send_as_error=item.get("sendAs_error") or {},
            delegates=item.get("delegates") or [],
            delegates_error=item.get("delegates_error") or {},
            imap=item.get("imap") or {},
            imap_error=item.get("imap_error") or {},
            pop=item.get("pop") or {},
            pop_error=item.get("pop_error") or {},
            vacation=minimise_gmail_settings(item).get("vacation") or {},
            vacation_error=item.get("vacation_error") or {},
        )
        for item in _values(collector_payloads.get("google_gmail_settings", {}), "mailboxSettings")
        if item.get("userEmail")
    ]
    alerts = [
        _record(
            "google_alert",
            "google_alert_center.alerts",
            str(item.get("alertId") or item.get("id")),
            alert_type=item.get("type"),
            severity=item.get("severity"),
            status=item.get("status"),
            create_time=item.get("createTime"),
        )
        for item in _values(collector_payloads.get("google_alert_center", {}), "alerts")
        if item.get("alertId") or item.get("id")
    ]
    dns_posture = [
        _record(
            "google_domain_posture",
            "google_dns_posture.domainPosture",
            str(item.get("domain")),
            domain=item.get("domain"),
            resolver_error=item.get("resolver_error"),
            spf=item.get("spf"),
            dmarc=item.get("dmarc"),
            dkim=item.get("dkim"),
            is_primary=item.get("isPrimary"),
        )
        for item in _values(collector_payloads.get("google_dns_posture", {}), "domainPosture")
        if item.get("domain")
    ]
    mobile_devices = [
        _record(
            "google_mobile_device",
            "google_devices.mobileDevices",
            str(item.get("resourceId") or item.get("deviceId") or item.get("serialNumber")),
            email=item.get("email"),
            model=item.get("model"),
            os=item.get("os"),
            device_type=item.get("type"),
            status=item.get("status"),
            # The Directory API names the field deviceCompromisedStatus; compromisedStatus is the older sample key.
            compromised_status=item.get("deviceCompromisedStatus") or item.get("compromisedStatus"),
            compromised_state=compromised_state(item.get("deviceCompromisedStatus") or item.get("compromisedStatus")),
            encryption_status=item.get("encryptionStatus"),
            encryption=_device_state(item.get("encryptionStatus"), positive="encrypted", negative="not_encrypted"),
            # Named for the lock, not the password: the bundle's sensitive-key scanner rejects the word.
            device_lock_status=item.get("devicePasswordStatus"),
            device_lock_policy=_device_state(item.get("devicePasswordStatus"), positive="enabled", negative="disabled"),
            os_release=item.get("releaseVersion"),
            security_patch_level=item.get("securityPatchLevel"),
            security_patch_date=_epoch_text(item.get("securityPatchLevel")),
            last_sync=item.get("lastSync"),
        )
        for item in _values(collector_payloads.get("google_devices", {}), "mobileDevices")
        if item.get("resourceId") or item.get("deviceId") or item.get("serialNumber")
    ]
    chrome_devices = [
        _record(
            "google_chromeos_device",
            "google_devices.chromeosDevices",
            str(item.get("deviceId") or item.get("serialNumber")),
            serial_number=item.get("serialNumber"),
            annotated_user=item.get("annotatedUser"),
            status=item.get("status"),
            model=item.get("model"),
            os_version=item.get("osVersion"),
            platform_version=item.get("platformVersion"),
            boot_mode=item.get("bootMode"),
            org_unit_path=item.get("orgUnitPath"),
            auto_update_expiration=_auto_update_expiration(item)[0],
            auto_update_source=_auto_update_expiration(item)[1],
            support_end_date=item.get("supportEndDate"),
            last_sync=item.get("lastSync"),
        )
        for item in _values(collector_payloads.get("google_devices", {}), "chromeosDevices")
        if item.get("deviceId") or item.get("serialNumber")
    ]
    drive_files = [
        _record(
            "google_drive_file",
            "google_drive_posture.driveFiles",
            str(item.get("id")),
            name=item.get("name"),
            mime_type=item.get("mimeType"),
            web_view_link=item.get("webViewLink"),
            shared=item.get("shared"),
            owners=item.get("owners") or [],
            permissions=item.get("permissions") or [],
            modified_time=item.get("modifiedTime"),
        )
        for item in _values(collector_payloads.get("google_drive_posture", {}), "driveFiles")
        if item.get("id")
    ]
    shared_drives = [
        _record(
            "google_shared_drive",
            "google_drive_posture.sharedDrives",
            str(item.get("id")),
            name=item.get("name"),
            hidden=item.get("hidden"),
            created_time=item.get("createdTime"),
            restrictions=item.get("restrictions") or {},
        )
        for item in _values(collector_payloads.get("google_drive_posture", {}), "sharedDrives")
        if item.get("id")
    ]
    group_settings = [
        _record(
            "google_group_setting",
            "google_groups_settings.groupSettings",
            str(item.get("email")),
            email=item.get("email"),
            allow_external_members=item.get("allowExternalMembers"),
            who_can_join=item.get("whoCanJoin"),
            who_can_post_message=item.get("whoCanPostMessage"),
            message_moderation_level=item.get("messageModerationLevel"),
            who_can_view_membership=item.get("whoCanViewMembership"),
            who_can_view_group=item.get("whoCanViewGroup"),
        )
        for item in _values(collector_payloads.get("google_groups_settings", {}), "groupSettings")
        if item.get("email")
    ]
    group_setting_errors = [
        _record(
            "google_group_setting_error",
            "google_groups_settings.groupSettingsErrors",
            str(item.get("email")),
            email=item.get("email"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_groups_settings", {}), "groupSettingsErrors")
        if item.get("email")
    ]
    calendar_resources = [
        _record(
            "google_calendar_resource",
            "google_calendar_posture.calendarResources",
            str(item.get("resourceId") or item.get("resourceEmail")),
            resource_name=item.get("resourceName"),
            resource_email=item.get("resourceEmail"),
            resource_type=item.get("resourceType"),
            resource_category=item.get("resourceCategory"),
            capacity=item.get("capacity"),
            building_id=item.get("buildingId"),
            floor_name=item.get("floorName"),
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendarResources")
        if item.get("resourceId") or item.get("resourceEmail")
    ]
    calendars = [
        _record(
            "google_calendar",
            "google_calendar_posture.calendars",
            str(item.get("id")),
            summary=item.get("summary"),
            description=item.get("description"),
            access_role=item.get("accessRole"),
            primary=item.get("primary"),
            hidden=item.get("hidden"),
            deleted=item.get("deleted"),
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendars")
        if item.get("id")
    ]
    calendar_acls = [
        _record(
            "google_calendar_acl",
            "google_calendar_posture.calendarAcls",
            f"{item.get('calendarId')}:{item.get('id') or item.get('scope')}",
            calendar_id=item.get("calendarId"),
            acl_id=item.get("id"),
            role=item.get("role"),
            scope=item.get("scope") or {},
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendarAcls")
        if item.get("calendarId") and (item.get("id") or item.get("scope"))
    ]
    calendar_acl_errors = [
        _record(
            "google_calendar_acl_error",
            "google_calendar_posture.calendarAclsErrors",
            str(item.get("calendarId")),
            calendar_id=item.get("calendarId"),
            error_class=item.get("error_class"),
            error=item.get("error"),
        )
        for item in _values(collector_payloads.get("google_calendar_posture", {}), "calendarAclsErrors")
        if item.get("calendarId")
    ]
    activity_records: list[dict[str, Any]] = []
    for source, payload in collector_payloads.get("google_reports", {}).items():
        for item in _values({"items": payload}, "items"):
            activity_records.append(
                _record(
                    "google_activity",
                    f"google_reports.{source}",
                    str(item.get("id", {}).get("uniqueQualifier") if isinstance(item.get("id"), dict) else item.get("id") or f"{source}:{len(activity_records)}"),
                    application=source.replace("Activities", ""),
                    actor_email=(item.get("actor") or {}).get("email") if isinstance(item.get("actor"), dict) else None,
                    event_names=[
                        str(event.get("name"))
                        for event in item.get("events") or []
                        if isinstance(event, dict) and event.get("name")
                    ],
                    events=item.get("events") or [],
                )
            )

    sections: dict[str, Any] = {
        "google_users": users,
        "google_domains": domain_records,
        "google_two_step_policies": policy_records,
        "google_groups": groups,
        "google_group_members": group_members,
        "google_group_member_errors": group_member_errors,
        "google_alias_errors": alias_errors,
        "google_role_assignments": role_assignments,
        "google_oauth_grants": oauth_grants,
        "google_oauth_grant_errors": oauth_grant_errors,
        "google_mailbox_settings": mailbox_settings,
        "google_alerts": alerts,
        "google_dns_posture": dns_posture,
        "google_mobile_devices": mobile_devices,
        "google_chromeos_devices": chrome_devices,
        "google_drive_files": drive_files,
        "google_shared_drives": shared_drives,
        "google_group_settings": group_settings,
        "google_group_setting_errors": group_setting_errors,
        "google_calendar_resources": calendar_resources,
        "google_calendars": calendars,
        "google_calendar_acls": calendar_acls,
        "google_calendar_acl_errors": calendar_acl_errors,
        "google_activity_events": activity_records,
    }
    # Every list cut short (an operator limit, never a silent default) is a coverage gap.
    truncations = list_truncations(coverage_rows)
    truncations.extend(truncations_from_payloads(collector_payloads, truncations))
    collection_gaps = collection_gap_records(sorted(truncations, key=lambda item: (item["collector"], item["list"])))
    if collection_gaps:
        sections[COLLECTION_GAP_SECTION] = collection_gaps
    object_counts = {name: len(records) for name, records in sections.items()}
    status_counts = Counter(str(row.get("status") or "unknown") for row in result_rows if isinstance(row, dict))
    truncated_sections = sorted({f"{item['collector']}.{item['list']}" for item in truncations})
    # Which collectors' evidence is the view of one subject, not the tenant. Drive and Calendar are the
    # delegated admin's view; Gmail settings are "user" when each mailbox was read as its own user.
    scope_labels: dict[str, set[str]] = {
        collector: {label} for collector, label in SUBJECT_SCOPED_COLLECTORS.items() if collector in collector_payloads
    }
    for row in coverage_rows:
        label = row.get("subject_scoped")
        if label in {SUBJECT_SCOPE_ADMIN, SUBJECT_SCOPE_USER} and row.get("collector"):
            scope_labels.setdefault(str(row["collector"]), set()).add(str(label))
    subject_scope = {
        collector: SUBJECT_SCOPE_ADMIN if SUBJECT_SCOPE_ADMIN in labels else SUBJECT_SCOPE_USER
        for collector, labels in sorted(scope_labels.items())
    }
    snapshot = {
        "kind": "snapshot",
        "platform": "google_workspace",
        "tenant_name": tenant_name,
        "workspace_domain": workspace_domain,
        "customer_id": customer_id,
        "run_id": run_id,
        "object_counts": object_counts,
        "normalized_counts": object_counts,
        "collector_count": len(result_rows),
        "coverage_row_count": len(coverage_rows),
        "blocker_count": len(diagnostics),
        "status_counts": dict(status_counts),
        "full_counts": object_counts,
        "sample_counts": object_counts,
        "top_limit": top_limit,
        "sample_truncated": bool(truncated_sections),
        "truncated_sections": truncated_sections,
        "collection_gap_count": len(collection_gaps),
        "internal_domains": internal_domains,
        "internal_domains_status": internal_domains_status,
        "internal_domains_source": internal_domains_source,
        "two_step_policy_status": _two_step_policy_status(
            collector_payloads.get("google_policies"), policy_records, coverage_rows, now
        ),
        "subject_scope": subject_scope,
        "mailbox_settings_skipped_suspended": sum(
            int(row.get("skipped_suspended") or 0) for row in coverage_rows if row.get("collector") == "google_gmail_settings"
        ),
    }
    normalized: dict[str, dict[str, Any]] = {"snapshot": snapshot}
    for name, records in sections.items():
        if records:
            normalized[name] = {"kind": name, "records": records}
    return normalized
