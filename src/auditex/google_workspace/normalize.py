from __future__ import annotations

from collections import Counter
from typing import Any


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

    users = [
        _record(
            "google_user",
            "google_directory.users",
            str(item.get("id") or item.get("primaryEmail")),
            primary_email=item.get("primaryEmail"),
            display_name=(item.get("name") or {}).get("fullName") if isinstance(item.get("name"), dict) else item.get("name"),
            is_admin=bool(item.get("isAdmin")),
            is_delegated_admin=bool(item.get("isDelegatedAdmin")),
            suspended=bool(item.get("suspended")),
            is_enrolled_in_2sv=item.get("isEnrolledIn2Sv"),
            is_enforced_in_2sv=item.get("isEnforcedIn2Sv"),
            last_login_time=item.get("lastLoginTime"),
            org_unit_path=item.get("orgUnitPath"),
            domain=_email_domain(item.get("primaryEmail")),
        )
        for item in _values(collector_payloads.get("google_directory", {}), "users")
        if item.get("id") or item.get("primaryEmail")
    ]
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
            send_as=item.get("sendAs") or [],
            send_as_error=item.get("sendAs_error") or {},
            delegates=item.get("delegates") or [],
            delegates_error=item.get("delegates_error") or {},
            imap=item.get("imap") or {},
            imap_error=item.get("imap_error") or {},
            pop=item.get("pop") or {},
            pop_error=item.get("pop_error") or {},
            vacation=item.get("vacation") or {},
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
            status=item.get("status"),
            compromised_status=item.get("compromisedStatus"),
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
            os_version=item.get("osVersion"),
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
    object_counts = {name: len(records) for name, records in sections.items()}
    status_counts = Counter(str(row.get("status") or "unknown") for row in result_rows if isinstance(row, dict))
    truncated_sections = sorted(
        str(row.get("name"))
        for row in result_rows
        if top_limit is not None and str(row.get("name") or "") and int(row.get("item_count") or 0) >= top_limit
    )
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
    }
    normalized: dict[str, dict[str, Any]] = {"snapshot": snapshot}
    for name, records in sections.items():
        if records:
            normalized[name] = {"kind": name, "records": records}
    return normalized
