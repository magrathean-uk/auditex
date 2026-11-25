from __future__ import annotations

import json
import math
import re
import sys
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from azure_tenant_audit.collection_gaps import (
    REASON_OPERATOR_LIMIT,
    REASON_PAGINATION_FAILED,
    fanout_gap_row,
    section_was_cut,
)
from azure_tenant_audit.collectors.base import (
    CollectorResult,
    context_limit,
    record_truncation,
)
from azure_tenant_audit.data_minimisation import (
    minimise_policy_section,
    minimise_policy_settings,
    minimise_policy_value,
)
from azure_tenant_audit.dns_lookup import (
    DNS_POSTURE_COLLECTORS,
    DohClient,
    DohError,
    collect_domain_posture,
    doh_resolver_display,
    resolve_doh_endpoint,
    safe_resolver_diagnostic,
    unknown_posture,
)
from azure_tenant_audit.offline_replay import OFFLINE_ROW_TYPE

from .auth import POLICIES_SCOPE
from .client import (
    POLICY_MALFORMED_ERROR_CLASS,
    POLICY_TYPE_ALLOWED,
    classify_google_error,
    classify_page_error,
    gmail_settings_status,
    minimise_gmail_settings,
    policy_malformed_error,
)

AuditLogger = Callable[[str, str, dict[str, Any] | None], None]


# Rows kept per event log or file crawl when the operator sets no row limit: a sample by design,
# since an unbounded read of a large domain's audit events or Drive files is not practical.
# Narrow the logs with --since/--until. An explicit --top below this is recorded as a coverage gap.
STREAM_SAMPLE_LIMIT = 500

# Subject scope of a collector's evidence, recorded as ``subject_scoped`` on its coverage rows,
# capability row and findings so evidence is never read as tenant-wide when it is not.
#   "admin": every call acts as the one delegated admin (or the signed-in user), so the data is what
#            that subject can see. Drive files and calendar ACLs have no cheap tenant-wide read in the
#            Admin SDK, so they stay admin-scoped and say so.
#   "user":  every user's own settings were read by acting as that user (domain-wide delegation).
SUBJECT_SCOPE_ADMIN = "admin"
SUBJECT_SCOPE_USER = "user"
SUBJECT_SCOPED_COLLECTORS: dict[str, str] = {
    "google_drive_posture": SUBJECT_SCOPE_ADMIN,
    "google_calendar_posture": SUBJECT_SCOPE_ADMIN,
}

# Mailboxes read per run when the operator sets no ``--top``. Each is eight settings calls plus a
# delegated token, so an unbounded default would be 160,000 calls for 20,000 users. A domain larger
# than this records a fan-out coverage gap; ``--top`` above the user count raises the bound.
MAILBOX_FANOUT_LIMIT = 500


def _context_limit(context: dict[str, Any]) -> int | None:
    """The operator's row limit; without one every directory list is paged to its last row."""
    return context_limit(context)


def _stream_limit(top: int | None) -> tuple[int, bool]:
    """Limit for an event log or file crawl, and whether it is the built-in sample bound.

    The sample bound is a ceiling: ``--top`` at or above it does not raise it (as on Microsoft 365),
    so only a ``--top`` below it is an operator limit whose cut is a coverage gap.
    """
    if not top:
        return STREAM_SAMPLE_LIMIT, True
    return min(top, STREAM_SAMPLE_LIMIT), top >= STREAM_SAMPLE_LIMIT


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
    subject_scoped: str | None = None,
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
        row["error"] = safe_resolver_diagnostic(error) if collector in DNS_POSTURE_COLLECTORS else error
    if subject_scoped:
        row["subject_scoped"] = subject_scoped
    return row


def _call(
    *,
    collector: str,
    name: str,
    coverage: list[dict[str, Any]],
    log_event: AuditLogger | None,
    func: Callable[[], list[dict[str, Any]]],
    endpoint: str | None = None,
    bounded_sample: bool = False,
    subject_scoped: str | None = None,
) -> list[dict[str, Any]]:
    """Run one list read and record it on the coverage ledger.

    A list the client reports as cut short (``truncated``) is a coverage gap: its row is
    ``partial`` and carries the truncation reason, so the collector and the run are not ``ok``.
    ``bounded_sample`` marks a cut at a bound the collector chose, which is recorded but is not a gap.
    """
    start = time.perf_counter()
    truncated = False
    result_limit: int | None = None
    page_error: Exception | None = None
    try:
        rows = func()
        status = "ok"
        error_class = None
        error = None
        truncated = bool(getattr(rows, "truncated", False))
        result_limit = getattr(rows, "result_limit", None)
        page_error = getattr(rows, "page_error", None)
        if page_error is not None:
            # A later page failed: the rows read before it are kept, and the list is a partial read.
            status = "partial"
            error_class, error = classify_page_error(page_error)
    except Exception as exc:  # noqa: BLE001
        rows = []
        status = "failed"
        error_class, error = classify_google_error(exc)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    row = _coverage(
        collector,
        name,
        status=status,
        item_count=len(rows),
        duration_ms=duration_ms,
        endpoint=endpoint,
        error_class=error_class,
        error=error,
        subject_scoped=subject_scoped,
    )
    if status != "failed":
        # The read completed on the collector's token: evidence of its scopes, independent of the row count.
        row["authenticated_read"] = True
    if result_limit:
        row["result_limit"] = result_limit
    if page_error is not None:
        record_truncation(row, list_name=name, rows=len(rows), limit=result_limit, reason=REASON_PAGINATION_FAILED)
    elif truncated and bounded_sample:
        row["bounded_sample"] = True
        row["collection_truncated"] = False
    elif truncated:
        reason = getattr(rows, "truncation_reason", None) or REASON_OPERATOR_LIMIT
        record_truncation(row, list_name=name, rows=len(rows), limit=result_limit, reason=reason)
    elif status == "ok":
        row["collection_truncated"] = False
    coverage.append(row)
    if log_event:
        log_event(
            "collector.endpoint.finished",
            "Google Workspace endpoint request completed",
            {
                "collector": collector,
                "endpoint_name": name,
                "status": row["status"],
                "item_count": len(rows),
                "duration_ms": duration_ms,
                "error_class": row.get("error_class"),
                "collection_truncated": bool(row.get("collection_truncated")),
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
        log_event: AuditLogger | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])

        # Users and groups are listed for the whole customer (my_customer): the domain flag is a label,
        # so secondary and alias domains are never left out of the lists.
        users = _call(
            collector=self.name,
            name="users",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.users.list",
            func=lambda: client.list_directory("users", top=top),
        )
        groups = _call(
            collector=self.name,
            name="groups",
            coverage=coverage,
            log_event=log_event,
            endpoint="admin.directory.groups.list",
            func=lambda: client.list_directory("groups", top=top),
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
        group_member_errors: list[dict[str, Any]] = []
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
            coverage_row = next((row for row in reversed(coverage) if row.get("name") == f"groupMembers:{group_email}"), None)
            if isinstance(coverage_row, dict) and coverage_row.get("status") != "ok":
                group_member_errors.append(
                    {
                        "groupEmail": group_email,
                        "error_class": coverage_row.get("error_class"),
                        "error": coverage_row.get("error"),
                    }
                )
            for member in members:
                group_members.append({"groupEmail": group_email, **member})

        aliases: list[dict[str, Any]] = []
        alias_errors: list[dict[str, Any]] = []
        oauth_grants: list[dict[str, Any]] = []
        oauth_grant_errors: list[dict[str, Any]] = []
        for user in users[:top]:
            user_key = str(user.get("primaryEmail") or user.get("email") or user.get("id") or "")
            if not user_key:
                continue
            if hasattr(client, "list_user_aliases"):
                user_aliases = _call(
                    collector=self.name,
                    name=f"aliases:{user_key}",
                    coverage=coverage,
                    log_event=log_event,
                    endpoint="admin.directory.users.aliases.list",
                    func=lambda user_key=user_key: client.list_user_aliases(user_key, top=top),
                )
                coverage_row = next((row for row in reversed(coverage) if row.get("name") == f"aliases:{user_key}"), None)
                if isinstance(coverage_row, dict) and coverage_row.get("status") != "ok":
                    alias_errors.append(
                        {
                            "userKey": user_key,
                            "error_class": coverage_row.get("error_class"),
                            "error": coverage_row.get("error"),
                        }
                    )
                for alias in user_aliases:
                    aliases.append({"userKey": user_key, **alias})
            if hasattr(client, "list_user_tokens"):
                tokens = _call(
                    collector=self.name,
                    name=f"oauthGrants:{user_key}",
                    coverage=coverage,
                    log_event=log_event,
                    endpoint="admin.directory.tokens.list",
                    func=lambda user_key=user_key: client.list_user_tokens(user_key, top=top),
                )
                coverage_row = next((row for row in reversed(coverage) if row.get("name") == f"oauthGrants:{user_key}"), None)
                if isinstance(coverage_row, dict) and coverage_row.get("status") != "ok":
                    oauth_grant_errors.append(
                        {
                            "userKey": user_key,
                            "error_class": coverage_row.get("error_class"),
                            "error": coverage_row.get("error"),
                        }
                    )
                for token in tokens:
                    oauth_grants.append({"userKey": user_key, **token})

        payload = {
            "users": {"value": users},
            "aliases": {"value": aliases},
            "aliasesErrors": {"value": alias_errors},
            "groups": {"value": groups},
            "groupMembers": {"value": group_members},
            "groupMembersErrors": {"value": group_member_errors},
            "orgUnits": {"value": org_units},
            "domains": {"value": domains},
            "roles": {"value": roles},
            "roleAssignments": {"value": role_assignments},
            "oauthGrants": {"value": oauth_grants},
            "oauthGrantsErrors": {"value": oauth_grant_errors},
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
        log_limit, sampled = _stream_limit(top)
        for application in self.applications:
            key = f"{application}Activities"
            rows = _call(
                collector=self.name,
                name=key,
                coverage=coverage,
                log_event=log_event,
                endpoint=f"admin.reports.activities.{application}",
                func=lambda application=application: client.list_report_activities(application, top=log_limit, start_time=since, end_time=until),
                bounded_sample=sampled,
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
    description = (
        "Gmail forwarding, filters, aliases, send-as, and delegates, read per mailbox "
        "(as each user under domain-wide delegation; the signed-in mailbox only otherwise)."
    )
    required_scopes = (
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
    )

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        top = _context_limit(context)
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
                func=lambda: client.list_directory("users", top=top),
            )
        # A client that cannot act as other users (OAuth) reads only the signed-in mailbox; a fake or a
        # delegated client reads every user's own settings.
        per_user = bool(getattr(client, "per_user_delegation", True))
        subject_scope = SUBJECT_SCOPE_USER if per_user else SUBJECT_SCOPE_ADMIN

        emails: list[str] = []
        skipped_inactive = 0
        for user in users:
            user_email = str(user.get("primaryEmail") or user.get("email") or "")
            if not user_email:
                continue
            if user.get("suspended") or user.get("archived"):
                skipped_inactive += 1
                continue
            emails.append(user_email)

        if per_user:
            limit = top or MAILBOX_FANOUT_LIMIT
            targets = emails[:limit]
            if len(emails) > len(targets):
                coverage.append(
                    fanout_gap_row(
                        self.name,
                        "mailboxSettingsFanout",
                        total=len(emails),
                        expanded=len(targets),
                        limit=limit,
                        scope="Gmail settings, one delegated read per user",
                    )
                )
        else:
            targets = ["me"]
            if emails:
                coverage.append(
                    _coverage(
                        self.name,
                        "mailboxSettingsScope",
                        status="partial",
                        item_count=0,
                        duration_ms=0,
                        endpoint="gmail.users.settings",
                        error_class="subject_scope",
                        error=(
                            f"Gmail settings were read for the signed-in mailbox only; the other {len(emails)} users were "
                            "not read because these credentials cannot act as another user, and mailbox delegates "
                            "can be listed only under domain-wide delegation. Use domain-wide delegation for per-user "
                            "evidence."
                        ),
                        subject_scoped=SUBJECT_SCOPE_ADMIN,
                    )
                )
        if skipped_inactive:
            skipped_row = _coverage(
                self.name,
                "mailboxSettingsSkipped",
                status="ok",
                item_count=0,
                duration_ms=0,
                endpoint="gmail.users.settings",
                subject_scoped=subject_scope,
            )
            skipped_row["skipped_suspended"] = skipped_inactive
            skipped_row["note"] = (
                f"{skipped_inactive} suspended or archived mailboxes were not read: delegation does not act as an inactive account."
            )
            coverage.append(skipped_row)

        rows: list[dict[str, Any]] = []
        for user_email in targets:
            start = time.perf_counter()
            try:
                settings = minimise_gmail_settings(client.get_gmail_settings_for_user(user_email))
                rows.append(settings)
                # The client keeps each failed settings read as ``<name>_error``: all failing fails the mailbox.
                status, error_class, error = gmail_settings_status(settings)
            except Exception as exc:  # noqa: BLE001
                status = "failed"
                error_class, error = classify_google_error(exc)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            coverage.append(
                _coverage(
                    self.name,
                    f"mailboxSettings:{user_email}",
                    status=status,
                    item_count=0 if status == "failed" else 1,
                    duration_ms=duration_ms,
                    endpoint="gmail.users.settings",
                    error_class=error_class,
                    error=error,
                    subject_scoped=subject_scope,
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


# The 2-step verification setting types, kept in today's ``twoStepVerificationPolicies`` shape.
TWO_STEP_SETTING_PREFIX = "settings/security.two_step_verification_"
# The two payloads of the one Policy API read, in the order they are written.
POLICY_SECTIONS = ("twoStepVerificationPolicies", "policySettings")

# ---- Policy API row validation -------------------------------------------------------------------------------
#
# Every field the collector and the normaliser read from a Policy API policy, and what makes it unreadable. A row
# with any problem is never complete or unconditional evidence: the collector and a replay mark the read partial,
# the normaliser leaves the affected setting out (``unusable_scopes`` or ``unusable_sections``) and the read
# incomplete, and the 2-step verification status becomes unknown. ``""`` is proto3 JSON's unset string, so an empty
# ``orgUnit``, ``group`` or ``query`` is the field left out.
#
# | field                       | absent              | null / wrong type | blank, malformed or out of range           |
# |-----------------------------|---------------------|-------------------|--------------------------------------------|
# | policy                      | -                   | policy_invalid    | -                                          |
# | name, customer (dropped)    | fine                | name_invalid      | -                                          |
# | type                        | fine (unspecified)  | policy_type_invalid | not ADMIN or SYSTEM                      |
# | setting                     | setting_invalid     | setting_invalid   | -                                          |
# | setting.type                | setting_type_invalid| same              | not ``settings/<a>.<b>``; outside the filter: setting_type_not_requested |
# | setting.value               | value_missing       | value_invalid     | an address list whose counts are unknown: value_unreadable |
# | policyQuery                 | query_object_invalid| same              | -                                          |
# | policyQuery.orgUnit, group  | fine (one required: target_missing) | org_unit_invalid / group_invalid | not ``orgUnits/<id>`` / ``groups/<id>`` |
# | policyQuery.sortOrder       | fine (proto3 0)     | sort_order_invalid| NaN, infinite or outside the double range  |
# | policyQuery.query           | fine (targets only) | query_invalid     | longer than POLICY_QUERY_MAX; CEL that the targets cannot represent is unsupported scope (normaliser) |
# | 2SV enforcedFrom            | fine (not enforced) | two_step_value_invalid | blank or not an RFC 3339 timestamp    |
# | 2SV allowEnrollment         | fine                | two_step_value_invalid | not a Boolean                         |
# | 2SV allowedSignInFactorSet  | fine                | two_step_value_invalid | not an upper-case enum name           |
# | 2SV enrollmentGracePeriod   | fine                | two_step_value_invalid | not a ``<seconds>s`` duration         |
# | 2SV camelCase vs snake_case | -                   | -                 | both present and different: two_step_value_conflict |

POLICY_UNIT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
POLICY_SETTING_TYPE = re.compile(r"settings/[a-z0-9_]+(?:\.[a-z0-9_]+)+")
POLICY_QUERY_MAX = 4_096
POLICY_TYPES = ("ADMIN", "SYSTEM")
_DOUBLE_MAX = sys.float_info.max
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})")
_DURATION = re.compile(r"\d{1,12}(?:\.\d{1,9})?s")
_ENUM = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def finite_number(value: Any) -> bool:
    """A JSON number that is not a Boolean, NaN or infinite and fits the API's double (``sortOrder``).

    A JSON integer is checked by comparison, never converted: ``1`` followed by 400 zeroes is out of range, not an
    ``OverflowError``.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, int):
        return -_DOUBLE_MAX <= value <= _DOUBLE_MAX
    return math.isfinite(value)


def policy_timestamp(value: Any) -> bool:
    """An RFC 3339 timestamp with a zone, as the Policy API writes ``enforcedFrom``."""
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


# The 2-step verification value fields the normaliser reads: (camelCase, snake_case, check).
TWO_STEP_VALUE_FIELDS: tuple[tuple[str, str, Callable[[Any], bool]], ...] = (
    ("enforcedFrom", "enforced_from", policy_timestamp),
    ("allowEnrollment", "allow_enrollment", lambda value: isinstance(value, bool)),
    ("allowedSignInFactorSet", "allowed_sign_in_factor_set", lambda value: isinstance(value, str) and bool(_ENUM.fullmatch(value))),
    ("enrollmentGracePeriod", "enrollment_grace_period", lambda value: isinstance(value, str) and bool(_DURATION.fullmatch(value))),
)


def policy_target(value: Any, prefix: str) -> str | None | bool:
    """A policy target's bare id; ``None`` when unset (absent or ``""``); ``False`` when not ``<prefix><id>``."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not value.startswith(prefix):
        return False
    bare = value[len(prefix) :]
    return bare if POLICY_UNIT_ID.fullmatch(bare) else False


def policy_value_unreadable(value: Any) -> bool:
    """Whether a minimised value holds a part the minimiser could not read (an address list with unknown counts)."""
    if isinstance(value, list):
        return any(policy_value_unreadable(item) for item in value)
    if not isinstance(value, dict):
        return False
    if "emailAddressList" in value and not isinstance(value["emailAddressList"], list):
        return True
    if ("entry_count" in value or "domain_entry_count" in value) and (
        value.get("entry_count") is None or value.get("domain_entry_count") is None
    ):
        return True
    return any(policy_value_unreadable(item) for item in value.values())


def _two_step_value_problems(value: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for camel, snake, check in TWO_STEP_VALUE_FIELDS:
        present = [value[name] for name in (camel, snake) if name in value]
        if any(not check(item) for item in present):
            problems.append("two_step_value_invalid")
        elif len(present) == 2 and present[0] != present[1]:
            problems.append("two_step_value_conflict")
    return problems


def policy_problems(policy: Any) -> tuple[str, ...]:
    """The fixed problem codes of one Policy API policy (raw or minimised); ``()`` when every read field is sound.

    See the table above. The CEL ``query`` is only checked for type and length here; whether the targets can
    represent it is the normaliser's scope check.
    """
    if not isinstance(policy, dict):
        return ("policy_invalid",)
    problems: list[str] = []
    if any(key in policy and not isinstance(policy[key], str) for key in ("name", "customer")):
        problems.append("name_invalid")
    if "type" in policy and policy["type"] not in POLICY_TYPES:
        problems.append("policy_type_invalid")
    setting = policy.get("setting")
    if not isinstance(setting, dict):
        problems.append("setting_invalid")
    else:
        setting_type = setting.get("type")
        if not isinstance(setting_type, str) or not POLICY_SETTING_TYPE.fullmatch(setting_type):
            problems.append("setting_type_invalid")
        elif not POLICY_TYPE_ALLOWED.fullmatch(setting_type):
            problems.append("setting_type_not_requested")
        if "value" not in setting:
            problems.append("value_missing")
        elif not isinstance(setting["value"], dict):
            problems.append("value_invalid")
        else:
            value = setting["value"]
            if policy_value_unreadable(minimise_policy_value(setting_type, value)):
                problems.append("value_unreadable")
            if isinstance(setting_type, str) and setting_type.startswith(TWO_STEP_SETTING_PREFIX):
                problems.extend(_two_step_value_problems(value))
    query = policy.get("policyQuery")
    if not isinstance(query, dict):
        problems.append("query_object_invalid")
    else:
        org_unit = policy_target(query.get("orgUnit"), "orgUnits/")
        group = policy_target(query.get("group"), "groups/")
        if org_unit is False:
            problems.append("org_unit_invalid")
        if group is False:
            problems.append("group_invalid")
        if org_unit is None and group is None:
            problems.append("target_missing")
        if "sortOrder" in query and not finite_number(query["sortOrder"]):
            problems.append("sort_order_invalid")
        text = query.get("query")
        if text is not None and (not isinstance(text, str) or len(text) > POLICY_QUERY_MAX):
            problems.append("query_invalid")
    return tuple(sorted(set(problems)))


# Problems that leave a policy's setting section unknown, and ones that leave its targets unknown.
POLICY_SECTION_PROBLEMS = frozenset({"policy_invalid", "setting_invalid", "setting_type_invalid", "setting_type_not_requested"})
POLICY_TARGET_PROBLEMS = frozenset({"query_object_invalid", "org_unit_invalid", "group_invalid", "target_missing"})


def policy_row_readable(policy: Any) -> bool:
    """Whether one Policy API policy has every field its readers rely on (see :func:`policy_problems`)."""
    return not policy_problems(policy)


def _is_two_step_policy(policy: Any) -> bool:
    setting = policy.get("setting") if isinstance(policy, dict) else None
    return isinstance(setting, dict) and isinstance(setting.get("type"), str) and setting["type"].startswith(TWO_STEP_SETTING_PREFIX)


def _requested(policy: Any) -> Any:
    """A policy whose setting type the filter did not ask for keeps only a sound type, never its value."""
    setting = policy.get("setting") if isinstance(policy, dict) else None
    if not isinstance(setting, dict):
        return policy
    setting_type = setting.get("type")
    if isinstance(setting_type, str) and POLICY_TYPE_ALLOWED.fullmatch(setting_type):
        return policy
    kept = {"type": setting_type} if isinstance(setting_type, str) and POLICY_SETTING_TYPE.fullmatch(setting_type) else {}
    return {**policy, "setting": kept}


def _malformed_policy_error(bad: int, total: int) -> str:
    return f"{bad} of {total} policies returned by the read cannot be read; the settings they hold are unknown."


def replay_policy_payload(collector: str, payload: Any) -> Any:
    """A replayed ``google_policies`` payload with only fixed vocabulary in its markers and no unrequested content.

    Only the two policy sections are kept. A section that is not an object becomes ``null`` (a failed read, see
    :func:`policy_replay_rows`). A section's error text, class and cut markers are reduced to fixed values (see
    :func:`minimise_policy_section`), so a sample cannot carry a customer id or a path into the bundle through them.
    Any other collector's payload is returned as it is.
    """
    if collector != "google_policies" or not isinstance(payload, dict):
        return payload
    result: dict[str, Any] = {}
    for name in POLICY_SECTIONS:
        if name not in payload:
            continue
        section = payload[name]
        if not isinstance(section, dict):
            result[name] = None
            continue
        section = minimise_policy_section(name, section)
        if isinstance(section.get("value"), list):
            section["value"] = [_requested(policy) for policy in section["value"]]
        result[name] = section
    return result


def two_step_subset_differs(payload: dict[str, Any]) -> bool:
    """Whether a payload holding both sections has a 2-step verification list that is not the widened read's subset."""
    two_step, settings = payload.get("twoStepVerificationPolicies"), payload.get("policySettings")
    if not isinstance(two_step, dict) or not isinstance(settings, dict):
        return False
    listed, read = two_step.get("value"), settings.get("value")
    if not isinstance(listed, list) or not isinstance(read, list):
        return False

    def canonical(rows: list[Any]) -> list[str]:
        return sorted(json.dumps(row, sort_keys=True) for row in minimise_policy_settings(rows))

    return canonical(listed) != canonical([row for row in read if _is_two_step_policy(row)])


def policy_replay_rows(collector: str, payload: Any) -> list[dict[str, Any]]:
    """Coverage rows for a replayed ``google_policies`` payload whose sections cannot be read.

    A section present under its name but not an object with a ``value`` list (``null``, a list, a string) is a failed
    read, and so is a ``policySettings`` list with no policies (every read of the allow-listed types returns some). A
    section with policies that cannot be read (:func:`policy_problems`), or a 2-step verification list that is not the
    subset of the widened read, is a partial read. A section the sample leaves out is the older shape and gets no row
    here, and a section that carries an error or a cut marker is already replayed from that marker.
    """
    if collector != "google_policies" or not isinstance(payload, dict):
        return []
    rows: list[dict[str, Any]] = []
    for name in POLICY_SECTIONS:
        if name not in payload:
            continue
        section = payload[name]
        if isinstance(section, dict) and (section.get("error") or section.get("error_class") or section_was_cut(section)):
            continue
        values = section.get("value") if isinstance(section, dict) else None
        if not isinstance(values, list) or (name == "policySettings" and not values):
            status, item_count, error = "failed", 0, f"google_policies.{name}: the offline sample holds no readable policies in this section."
        else:
            bad = sum(1 for policy in values if not policy_row_readable(policy))
            if bad:
                status, item_count, error = "partial", len(values), _malformed_policy_error(bad, len(values))
            elif name == "twoStepVerificationPolicies" and two_step_subset_differs(payload):
                status, item_count = "partial", len(values)
                error = "google_policies.twoStepVerificationPolicies: the list is not the 2-step verification part of policySettings."
            else:
                continue
        rows.append(
            {
                "collector": collector,
                "type": OFFLINE_ROW_TYPE,
                "name": name,
                "status": status,
                "item_count": item_count,
                "error_class": POLICY_MALFORMED_ERROR_CLASS,
                "error": error,
                "message": "Replayed from an offline sample whose policies section cannot be read.",
            }
        )
    return rows


def _policy_sections(policies: list[Any], markers: dict[str, Any]) -> dict[str, Any]:
    """The two payloads of one read, each carrying the read's outcome so a replay of the raw evidence keeps it.

    Both drop ``customer`` and ``name`` (a customer id and a raw policy id); the SCuBA payload also reduces Gmail
    address lists to counts. A policy of a type the filter did not ask for keeps no value. The 2-step verification
    subset keeps its shape otherwise.
    """
    policies = [_requested(policy) for policy in policies]
    two_step = minimise_policy_settings([policy for policy in policies if _is_two_step_policy(policy)])
    settings = minimise_policy_settings(list(policies))
    sections: dict[str, Any] = {}
    for name, values in (("twoStepVerificationPolicies", two_step), ("policySettings", settings)):
        section: dict[str, Any] = {"value": values}
        for key, item in markers.items():
            section[key] = len(values) if key == "item_count" else item
        sections[name] = section
    return sections


class GooglePoliciesCollector:
    name = "google_policies"
    description = (
        "Google Workspace Cloud Identity policies: the setting types the SCuBA baselines read, "
        "including the organisation's 2-step verification enforcement."
    )
    required_scopes = (POLICIES_SCOPE,)

    def run(self, context: dict[str, Any]) -> CollectorResult:
        client = context.get("client")
        log_event: AuditLogger | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        if client is None:
            row = _coverage(self.name, "client", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {}, 0, "Google client unavailable", coverage=[row])
        # One read of every allow-listed setting type, never bounded by the operator's ``--top`` (the client's own
        # bounds stop a runaway read). Its coverage row (``policySettings``) is the completeness signal for both
        # payloads: a failed or unreadable first page or no policies (failed), a cut at a bound or a later page error
        # or unreadable page (partial, cut), or policies that cannot be read (partial) make it not ok, and the
        # failure or cut is written on both raw sections so a replay cannot read the evidence as complete.
        policies = _call(
            collector=self.name,
            name="policySettings",
            coverage=coverage,
            log_event=log_event,
            endpoint="cloudidentity.policies.list",
            func=lambda: client.list_policies(),
        )
        row = coverage[-1]
        if row.get("status") == "ok" and not policies:
            # The client raises on an empty read; any other source of an empty list has read nothing either.
            row.update(status="failed", error_class=POLICY_MALFORMED_ERROR_CLASS, error=str(policy_malformed_error(later_page=False)))
            row.pop("collection_truncated", None)
        markers: dict[str, Any] = {}
        if row.get("status") == "failed":
            markers = {"error_class": row.get("error_class"), "error": row.get("error")}
        elif row.get("collection_truncated") is True:
            markers = {"collection_truncated": True, "truncation_reason": row.get("truncation_reason"), "item_count": None}
            if row.get("result_limit"):
                markers["result_limit"] = row["result_limit"]
        bad = sum(1 for policy in policies if not policy_row_readable(policy))
        if bad and row.get("status") == "ok":
            row.update(status="partial", error_class=POLICY_MALFORMED_ERROR_CLASS, error=_malformed_policy_error(bad, len(policies)))
        partial = any(item.get("status") != "ok" for item in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            _policy_sections(list(policies), markers),
            len(policies),
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
        resolver = context.get("dns_resolver")
        endpoint = context.get("doh_endpoint")
        if resolver is None:
            # The run's resolver: an explicit endpoint, else AUDITEX_DOH_ENDPOINT, else Cloudflare.
            try:
                endpoint = resolve_doh_endpoint(endpoint)
                resolver = DohClient(endpoint=endpoint)
            except ValueError as exc:
                row = _coverage(self.name, "dohEndpoint", status="failed", item_count=0, duration_ms=0,
                                surface_type="dns", endpoint="doh", error_class="config_error", error=str(exc))
                return CollectorResult(self.name, "partial", {"domains": {"value": []}, "domainPosture": {"value": []}}, 0,
                                       "DNS-over-HTTPS endpoint is not valid", coverage=[row])
        else:
            endpoint = getattr(resolver, "endpoint", endpoint)
        resolver_origin = doh_resolver_display(endpoint)
        log_event: AuditLogger | None = context.get("audit_logger")
        coverage: list[dict[str, Any]] = []
        domains: list[dict[str, Any]] = []
        if client is not None:
            domains = _call(
                collector=self.name,
                name="domains",
                coverage=coverage,
                log_event=log_event,
                endpoint="admin.directory.domains.list",
                func=lambda: client.list_directory("domains", top=top),
            )
        elif not domain:
            row = _coverage(self.name, "domains", status="failed", item_count=0, duration_ms=0, error_class="unauthenticated", error="google client unavailable")
            return CollectorResult(self.name, "partial", {"domains": {"value": []}, "domainPosture": {"value": []}}, 0, "Google client unavailable", coverage=[row])
        # Every verified domain of the customer is assessed. The --domain label stands in only when the
        # directory list could not be read, so a secondary domain is not skipped when it can be listed.
        domains = [entry for entry in domains if entry.get("verified") is not False]
        if domain and not domains:
            domains.append({"domainName": domain, "verified": True, "isPrimary": True})

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
                if posture.get("resolver_error"):
                    status = "failed"
                    error_class = "dns_resolver_error"
                    error = posture["resolver_error"]
            except DohError as exc:
                error = safe_resolver_diagnostic(exc)
                posture = {
                    "domain": domain_name,
                    "resolver_error": error,
                    **unknown_posture(("google",)),
                }
                status = "failed"
                error_class = "dns_resolver_error"
            assessments.append(posture)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            row = _coverage(
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
            if resolver_origin and error_class == "dns_resolver_error":
                row["doh_endpoint"] = resolver_origin
            coverage.append(row)
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {"domains": {"value": domains}, "domainPosture": {"value": assessments}},
            len(domains) + len(assessments),
            coverage=coverage,
        )


def _record_drive_permission_reads(collector: str, drive_files: Any, coverage: list[dict[str, Any]]) -> None:
    """A coverage row for the files whose permissions had to be read one by one, failing where they could not be."""
    errors = [item for item in getattr(drive_files, "permission_errors", None) or [] if isinstance(item, dict)]
    reads = int(getattr(drive_files, "permission_reads", 0) or 0)
    if not errors and not reads:
        return
    error_class = error = None
    status = "ok"
    if errors:
        classes = [str(item.get("error_class") or "client_error") for item in errors]
        error_class = max(set(classes), key=classes.count)
        status = "failed" if not reads else "partial"
        # Error classes only: a request error names the file's id and the request URL.
        error = (
            f"Sharing of {len(errors)} of {len(errors) + reads} Drive files (shared-drive items or files the subject "
            f"cannot share) could not be read, so their exposure is unknown ({', '.join(sorted(set(classes)))})."
        )
    coverage.append(
        _coverage(
            collector,
            "drivePermissions",
            status=status,
            item_count=reads,
            duration_ms=0,
            endpoint="drive.permissions.list",
            error_class=error_class,
            error=error,
            subject_scoped=SUBJECT_SCOPE_ADMIN,
        )
    )


class GoogleDrivePostureCollector:
    name = "google_drive_posture"
    description = (
        "Google Drive metadata, shared drive inventory, and sharing exposure as the delegated admin subject "
        "sees it (not tenant-wide). Does not read file content."
    )
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
        file_limit, sampled = _stream_limit(top)
        drive_files = _call(
            collector=self.name,
            name="driveFiles",
            coverage=coverage,
            log_event=log_event,
            endpoint="drive.files.list",
            func=lambda: client.list_drive_files(top=file_limit),
            bounded_sample=sampled,
            subject_scoped=SUBJECT_SCOPE_ADMIN,
        )
        _record_drive_permission_reads(self.name, drive_files, coverage)
        shared_drives = _call(
            collector=self.name,
            name="sharedDrives",
            coverage=coverage,
            log_event=log_event,
            endpoint="drive.drives.list",
            func=lambda: client.list_shared_drives(top=top),
            subject_scoped=SUBJECT_SCOPE_ADMIN,
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
                func=lambda: client.list_directory("groups", top=top),
            )
        settings_rows: list[dict[str, Any]] = []
        settings_errors: list[dict[str, Any]] = []
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
            coverage_row = next((row for row in reversed(coverage) if row.get("name") == f"groupSettings:{group_email}"), None)
            if isinstance(coverage_row, dict) and coverage_row.get("status") != "ok":
                settings_errors.append(
                    {
                        "email": group_email,
                        "error_class": coverage_row.get("error_class"),
                        "error": coverage_row.get("error"),
                    }
                )
            for row in settings:
                settings_rows.append({"email": group_email, **row})
        partial = any(row.get("status") != "ok" for row in coverage)
        return CollectorResult(
            self.name,
            "partial" if partial else "ok",
            {"groupSettings": {"value": settings_rows}, "groupSettingsErrors": {"value": settings_errors}},
            len(settings_rows) + len(settings_errors),
            coverage=coverage,
        )


class GoogleCalendarPostureCollector:
    name = "google_calendar_posture"
    description = (
        "Google Calendar resource inventory (tenant-wide) and calendar ACL sharing posture as the delegated admin "
        "subject sees it (not tenant-wide). Does not read event content."
    )
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
            subject_scoped=SUBJECT_SCOPE_ADMIN,
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
        acl_errors: list[dict[str, Any]] = []
        for calendar_id in calendar_ids[:top]:
            acls = _call(
                collector=self.name,
                name=f"calendarAcls:{calendar_id}",
                coverage=coverage,
                log_event=log_event,
                endpoint="calendar.acl.list",
                func=lambda calendar_id=calendar_id: client.list_calendar_acl(calendar_id, top=top),
                subject_scoped=SUBJECT_SCOPE_ADMIN,
            )
            coverage_row = next((row for row in reversed(coverage) if row.get("name") == f"calendarAcls:{calendar_id}"), None)
            if isinstance(coverage_row, dict) and coverage_row.get("status") != "ok":
                acl_errors.append(
                    {
                        "calendarId": calendar_id,
                        "error_class": coverage_row.get("error_class"),
                        "error": coverage_row.get("error"),
                    }
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
                "calendarAclsErrors": {"value": acl_errors},
            },
            len(resources) + len(calendars) + len(acl_rows) + len(acl_errors),
            coverage=coverage,
        )


# The sections each collector's live run records: what an offline replay checks a sample against, so a collector the
# sample holds but delivered none of (``{}``, ``null``, a list) replays as the failed read it is and not as ``ok``.
COLLECTOR_SECTIONS: dict[str, tuple[str, ...]] = {
    "google_directory": ("users", "groups", "domains", "roles", "roleAssignments", "groupMembers", "orgUnits", "oauthGrants"),
    "google_reports": ("loginActivities", "adminActivities"),
    "google_alert_center": ("alerts",),
    "google_policies": ("twoStepVerificationPolicies", "policySettings"),
    "google_gmail_settings": ("mailboxSettings",),
    "google_devices": ("mobileDevices", "chromeosDevices"),
    "google_dns_posture": ("domains", "domainPosture"),
    "google_drive_posture": ("driveFiles", "sharedDrives"),
    "google_groups_settings": ("groupSettings",),
    "google_calendar_posture": ("calendarResources", "calendars", "calendarAcls"),
}

REGISTRY = {
    "google_directory": GoogleDirectoryCollector(),
    "google_reports": GoogleReportsCollector(),
    "google_alert_center": GoogleAlertCenterCollector(),
    "google_policies": GooglePoliciesCollector(),
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
        "google_policies",
        "google_gmail_settings",
        "google_devices",
        "google_dns_posture",
    ),
    "everything": tuple(REGISTRY.keys()),
    "identity": ("google_directory", "google_reports", "google_alert_center", "google_policies"),
    "mail": ("google_directory", "google_gmail_settings", "google_dns_posture"),
    "collaboration": ("google_directory", "google_drive_posture", "google_groups_settings", "google_calendar_posture"),
}
