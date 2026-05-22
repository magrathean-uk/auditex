from __future__ import annotations

import time
from typing import Any, Callable

from azure_tenant_audit.collectors.base import CollectorResult, normalize_collection_limit
from azure_tenant_audit.dns_lookup import DEFAULT_DOH_ENDPOINT, DohClient, DohError, collect_domain_posture

from .client import classify_google_error


AuditLogger = Callable[[str, str, dict[str, Any] | None], None]


def _context_limit(context: dict[str, Any], default: int = 100) -> int | None:
    return normalize_collection_limit(context.get("top"), default=default)


def _coverage(
    collector: str,
    name: str,
    *,
    status: str,
    item_count: int,
    duration_ms: float,
    surface_type: str = "google",
    endpoint: str | None = None,
    error_class: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    row = {
        "collector": collector,
        "type": surface_type,
        "name": name,
        "endpoint": endpoint or name,
        "status": status,
        "item_count": item_count,
        "duration_ms": duration_ms,
    }
    if error_class:
        row["error_class"] = error_class
    if error:
        row["error"] = error
    return row


def _call(
    *,
    collector: str,
    name: str,
    coverage: list[dict[str, Any]],
    log_event: AuditLogger | None,
    func: Callable[[], list[dict[str, Any]]],
    endpoint: str | None = None,
) -> list[dict[str, Any]]:
    start = time.perf_counter()
    try:
        rows = func()
        status = "ok"
        error_class = None
        error = None
    except Exception as exc:  # noqa: BLE001
        rows = []
        status = "failed"
        error_class, error = classify_google_error(exc)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    coverage.append(
        _coverage(
            collector,
            name,
            status=status,
            item_count=len(rows),
            duration_ms=duration_ms,
            endpoint=endpoint,
            error_class=error_class,
            error=error,
        )
    )
    if log_event:
        log_event(
            "collector.endpoint.finished",
            "Google Workspace endpoint request completed",
            {
                "collector": collector,
                "endpoint_name": name,
                "status": status,
                "item_count": len(rows),
                "duration_ms": duration_ms,
                "error_class": error_class,
            },
        )
    return rows


class GoogleDirectoryCollector:
    name = "google_directory"
    description = "Google Workspace Directory users, groups, roles, domains, and OAuth grants."
    required_scopes = (
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
        "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.security",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        domain = context.get("domain")
        log_event: AuditLogger | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])

        users = _call(
            collector=self.name,
            name="users",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.users.list",
            func=lambda: client.list_directory("users", top=top, domain=domain),
        )
        groups = _call(
            collector=self.name,
            name="groups",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.groups.list",
            func=lambda: client.list_directory("groups", top=top, domain=domain),
        )
        domains = _call(
            collector=self.name,
            name="domains",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.domains.list",
            func=lambda: client.list_directory("domains", top=top),
        )
        org_units = _call(
            collector=self.name,
            name="orgUnits",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.orgunits.list",
            func=lambda: client.list_directory("orgUnits", top=top),
        )
        roles = _call(
            collector=self.name,
            name="roles",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.roles.list",
            func=lambda: client.list_directory("roles", top=top),
        )
        role_assignments = _call(
            collector=self.name,
            name="roleAssignments",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.roleAssignments.list",
            func=lambda: client.list_directory("roleAssignments", top=top),
        )

        group_members: list[dict[str, Any]] = []
        for group in groups[:top]:
            group_email = str(group.get("email") or group.get("id") or "")
            if not group_email:
                continue
            members = _call(
                collector=self.name,
                name=f"groupMembers:{group_email}",
                coverage=coverage,
                log_event=log_event,
                endpoint="admin.directory.members.list",
                func=lambda group_email=group_email: client.list_group_members(group_email, top=top),
            )
            for member in members:
                group_members.append({"groupEmail": group_email, **member})

        aliases: list[dict[str, Any]] = []
        oauth_grants: list[dict[str, Any]] = []
        for user in users[:top]:
            user_key = str(user.get("primaryEmail") or user.get("email") or user.get("id") or "")
            if not user_key:
                continue
            if hasattr(client, "list_user_aliases"):
                for alias in _call(
                    collector=self.name,
                    name=f"aliases:{user_key}",
                    coverage=coverage,
                    log_event=log_event,
                    endpoint="admin.directory.users.aliases.list",
                    func=lambda user_key=user_key: client.list_user_aliases(user_key, top=top),
                ):
                    aliases.append({"userKey": user_key, **alias})
            if hasattr(client, "list_user_tokens"):
                for token in _call(
                    collector=self.name,
                    name=f"oauthGrants:{user_key}",
                    coverage=coverage,
                    log_event=log_event,
                    endpoint="admin.directory.tokens.list",
                    func=lambda user_key=user_key: client.list_user_tokens(user_key, top=top),
                ):
                    oauth_grants.append({"userKey": user_key, **token})

        payload = {
            "users": {"value": users},
            "aliases": {"value": aliases},
            "groups": {"value": groups},
            "groupMembers": {"value": group_members},
            "orgUnits": {"value": org_units},
            "domains": {"value": domains},
            "roles": {"value": roles},
            "roleAssignments": {"value": role_assignments},
            "oauthGrants": {"value": oauth_grants},
        }
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            payload,
            sum(int(row.get("item_count") or 0) for row in coverage),
            "Google Directory collector partially completed" if partial else "",
            coverage=coverage,
        )


class GoogleReportsCollector:
    name = "google_reports"
    description = "Google Workspace Reports audit and usage events."
    required_scopes = (
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    )
    applications = ("admin", "login", "token", "drive", "mobile", "groups", "chrome")

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        since = context.get("since")
        until = context.get("until")
        log_event: AuditLogger | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        payload: dict[str, Any] = {}
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        for application in self.applications:
            key = f"{application}Activities"
            rows = _call(
                collector=self.name,
                name=key,
                coverage=coverage,
                log_event=log_event,
                endpoint=f"admin.reports.activities.{application}",
                func=lambda application=application: client.list_report_activities(application, top=top, start_time=since, end_time=until),
            )
            payload[key] = {"value": rows}
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(self.name, "partial" if partial else "ok", payload, sum(len(v["value"]) for v in payload.values()), coverage=coverage)


class GoogleAlertCenterCollector:
    name = "google_alert_center"
    description = "Google Workspace Alert Center active alerts."
    required_scopes = ("https://www.googleapis.com/auth/apps.alerts",)

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        coverage: list[dict[str, Any]] = []
        log_event: AuditLogger | None = context.get("audit_logger")
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        alerts = _call(
            collector=self.name,
            name="alerts",
            coverage=coverage,
            log_event=log_event,
            endpoint="alertcenter.alerts.list",
            func=lambda: client.list_alerts(top=top),
        )
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(self.name, "partial" if partial else "ok", {"alerts": {"value": alerts}}, len(alerts), coverage=coverage)


class GoogleGmailSettingsCollector:
    name = "google_gmail_settings"
    description = "Gmail forwarding, filters, aliases, send-as, and delegates."
    required_scopes = (
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.settings.sharing",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        domain = context.get("domain")
        coverage: list[dict[str, Any]] = []
        log_event: AuditLogger | None = context.get("audit_logger")
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        users = context.get("users")
        if not isinstance(users, list):
            users = _call(
                collector=self.name,
                name="users",
                coverage=coverage,
                log_event=log_event,
                endpoint="admin.directory.users.list",
                func=lambda: client.list_directory("users", top=top, domain=domain),
            )
        rows: list[dict[str, Any]] = []
        for user in users[:top]:
            user_email = str(user.get("primaryEmail") or user.get("email") or "")
            if not user_email:
                continue
            start = time.perf_counter()
            try:
                rows.append(client.get_gmail_settings_for_user(user_email))
                status = "ok"
                error_class = None
                error = None
            except Exception as exc:  # noqa: BLE001
                status = "failed"
                error_class, error = classify_google_error(exc)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            coverage.append(
                _coverage(
                    self.name,
                    f"mailboxSettings:{user_email}",
                    status=status,
                    item_count=1 if status == "ok" else 0,
                    duration_ms=duration_ms,
                    endpoint="gmail.users.settings",
                    error_class=error_class,
                    error=error,
                )
            )
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(self.name, "partial" if partial else "ok", {"mailboxSettings": {"value": rows}}, len(rows), coverage=coverage)


class GoogleDevicesCollector:
    name = "google_devices"
    description = "Google Workspace mobile and ChromeOS inventory."
    required_scopes = (
        "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
        "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        coverage: list[dict[str, Any]] = []
        log_event: AuditLogger | None = context.get("audit_logger")
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        mobile = _call(
            collector=self.name,
            name="mobileDevices",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.mobiledevices.list",
            func=lambda: client.list_devices("mobile", top=top),
        )
        chromeos = _call(
            collector=self.name,
            name="chromeosDevices",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.chromeosdevices.list",
            func=lambda: client.list_devices("chromeos", top=top),
        )
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {"mobileDevices": {"value": mobile}, "chromeosDevices": {"value": chromeos}},
            len(mobile) + len(chromeos),
            coverage=coverage,
        )


class GoogleDnsPostureCollector:
    name = "google_dns_posture"
    description = "Google Workspace DNS and email authentication posture."
    required_scopes = ("https://www.googleapis.com/auth/admin.directory.domain.readonly",)

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        domain = context.get("domain")
        resolver = context.get("dns_resolver") or DohClient(endpoint=context.get("doh_endpoint", DEFAULT_DOH_ENDPOINT))
        log_event: AuditLogger | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        domains: list[dict[str, Any]] = []
        if domain:
            domains.append({"domainName": domain, "verified": True, "isPrimary": True})
        elif client is not None:
            domains = _call(
                collector=self.name,
                name="domains",
                coverage=coverage,
                log_event=log_event,
                endpoint="admin.directory.domains.list",
                func=lambda: client.list_directory("domains", top=top),
            )
        else:
            row = _coverage(self.name, "domains", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {"domains": {"value": []}, "domainPosture": {"value": []}}, 0, "Google client unavailable", coverage=[row])

        assessments: list[dict[str, Any]] = []
        for entry in domains[:top]:
            domain_name = str(entry.get("domainName") or entry.get("domain") or "").strip()
            if not domain_name:
                continue
            start = time.perf_counter()
            try:
                posture = collect_domain_posture(
                    domain_name,
                    resolver,
                    dkim_selectors=("google",),
                    dkim_fallback_selectors=("s1", "s2", "default", "k1", "mail"),
                )
                posture["isPrimary"] = entry.get("isPrimary")
                status = "ok"
                error_class = None
                error = None
            except DohError as exc:
                posture = {
                    "domain": domain_name,
                    "resolver_error": str(exc),
                    "spf": {"present": False},
                    "dmarc": {"present": False},
                    "dkim": {"selectors_present": [], "selectors_missing": ["google"]},
                }
                status = "failed"
                error_class = "dns_resolver_error"
                error = str(exc)
            assessments.append(posture)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            coverage.append(
                _coverage(
                    self.name,
                    f"posture:{domain_name}",
                    status=status,
                    item_count=1,
                    duration_ms=duration_ms,
                    surface_type="dns",
                    endpoint=f"doh://{domain_name}",
                    error_class=error_class,
                    error=error,
                )
            )
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {"domains": {"value": domains}, "domainPosture": {"value": assessments}},
            len(domains) + len(assessments),
            coverage=coverage,
        )


class GoogleDrivePostureCollector:
    name = "google_drive_posture"
    description = "Google Drive metadata, shared drive inventory, and sharing exposure. Does not read file content."
    required_scopes = (
        "https://www.googleapis.com/auth/drive.metadata.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        coverage: list[dict[str, Any]] = []
        log_event: AuditLogger | None = context.get("audit_logger")
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        drive_files = _call(
            collector=self.name,
            name="driveFiles",
            coverage=coverage,
            log_event=log_event,
            endpoint="drive.files.list",
            func=lambda: client.list_drive_files(top=top),
        )
        shared_drives = _call(
            collector=self.name,
            name="sharedDrives",
            coverage=coverage,
            log_event=log_event,
            endpoint="drive.drives.list",
            func=lambda: client.list_shared_drives(top=top),
        )
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {"driveFiles": {"value": drive_files}, "sharedDrives": {"value": shared_drives}},
            len(drive_files) + len(shared_drives),
            coverage=coverage,
        )


class GoogleGroupsSettingsCollector:
    name = "google_groups_settings"
    description = "Google Groups settings exposure such as external membership and public posting."
    required_scopes = (
        "https://www.googleapis.com/auth/apps.groups.settings",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        domain = context.get("domain")
        coverage: list[dict[str, Any]] = []
        log_event: AuditLogger | None = context.get("audit_logger")
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        groups = context.get("groups")
        if not isinstance(groups, list):
            groups = _call(
                collector=self.name,
                name="groups",
                coverage=coverage,
                log_event=log_event,
                endpoint="admin.directory.groups.list",
                func=lambda: client.list_directory("groups", top=top, domain=domain),
            )
        settings_rows: list[dict[str, Any]] = []
        for group in groups[:top]:
            group_email = str(group.get("email") or group.get("id") or "")
            if not group_email:
                continue
            settings = _call(
                collector=self.name,
                name=f"groupSettings:{group_email}",
                coverage=coverage,
                log_event=log_event,
                endpoint="groupssettings.groups.get",
                func=lambda group_email=group_email: [client.get_group_settings(group_email)],
            )
            for row in settings:
                settings_rows.append({"email": group_email, **row})
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {"groupSettings": {"value": settings_rows}},
            len(settings_rows),
            coverage=coverage,
        )


class GoogleCalendarPostureCollector:
    name = "google_calendar_posture"
    description = "Google Calendar resource inventory and ACL sharing posture. Does not read event content."
    required_scopes = (
        "https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly",
        "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
        "https://www.googleapis.com/auth/calendar.acls.readonly",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
        coverage: list[dict[str, Any]] = []
        log_event: AuditLogger | None = context.get("audit_logger")
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])

        resources = _call(
            collector=self.name,
            name="calendarResources",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.resources.calendars.list",
            func=lambda: client.list_calendar_resources(top=top),
        )
        calendars = _call(
            collector=self.name,
            name="calendars",
            coverage=coverage,
            log_event=log_event,
            endpoint="calendar.calendarList.list",
            func=lambda: client.list_calendar_list(top=top),
        )
        calendar_ids: list[str] = []
        for calendar in calendars[:top]:
            calendar_id = str(calendar.get("id") or "")
            if calendar_id and calendar_id not in calendar_ids:
                calendar_ids.append(calendar_id)
        for resource in resources[:top]:
            calendar_id = str(resource.get("resourceEmail") or resource.get("id") or resource.get("resourceId") or "")
            if calendar_id and calendar_id not in calendar_ids:
                calendar_ids.append(calendar_id)

        acl_rows: list[dict[str, Any]] = []
        for calendar_id in calendar_ids[:top]:
            acls = _call(
                collector=self.name,
                name=f"calendarAcls:{calendar_id}",
                coverage=coverage,
                log_event=log_event,
                endpoint="calendar.acl.list",
                func=lambda calendar_id=calendar_id: client.list_calendar_acl(calendar_id, top=top),
            )
            for acl in acls:
                acl_rows.append({"calendarId": calendar_id, **acl})

        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {
                "calendarResources": {"value": resources},
                "calendars": {"value": calendars},
                "calendarAcls": {"value": acl_rows},
            },
            len(resources) + len(calendars) + len(acl_rows),
            coverage=coverage,
        )


REGISTRY = {
    "google_directory": GoogleDirectoryCollector(),
    "google_reports": GoogleReportsCollector(),
    "google_alert_center": GoogleAlertCenterCollector(),
    "google_gmail_settings": GoogleGmailSettingsCollector(),
    "google_devices": GoogleDevicesCollector(),
    "google_dns_posture": GoogleDnsPostureCollector(),
    "google_drive_posture": GoogleDrivePostureCollector(),
    "google_groups_settings": GoogleGroupsSettingsCollector(),
    "google_calendar_posture": GoogleCalendarPostureCollector(),
}

DEFAULT_ORDER = tuple(REGISTRY.keys())

PRESETS = {
    "core-security": (
        "google_directory",
        "google_reports",
        "google_alert_center",
        "google_gmail_settings",
        "google_devices",
        "google_dns_posture",
    ),
    "everything": tuple(REGISTRY.keys()),
    "identity": ("google_directory", "google_reports", "google_alert_center"),
    "mail": ("google_directory", "google_gmail_settings", "google_dns_posture"),
    "collaboration": ("google_directory", "google_drive_posture", "google_groups_settings", "google_calendar_posture"),
}
