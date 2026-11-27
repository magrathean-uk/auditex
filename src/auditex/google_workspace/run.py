from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from azure_tenant_audit.ai_context import build_privacy_block
from azure_tenant_audit.assurance import build_live_readiness_summary
from azure_tenant_audit.auth_runtime import local_path_argument
from azure_tenant_audit.capability_gate import enrich_capability_row
from azure_tenant_audit.collector_runner import (
    CollectorRunContext,
    CollectorRunHooks,
    CollectorRunner,
)
from azure_tenant_audit.dns_lookup import (
    DOH_ENDPOINT_ENV,
    doh_resolver_disclosure,
    resolve_doh_endpoint,
    sanitise_resolver_fields,
)
from azure_tenant_audit.offline_replay import (
    absent_section_rows,
    fixture_provenance_for_bundle,
    replay_collector_status,
    replay_coverage_rows,
    replay_source,
)
from azure_tenant_audit.output import AuditWriter, validate_bundle_name
from azure_tenant_audit.provider_runtime import (
    ProviderFinalizePlan,
    write_provider_bundle,
)
from azure_tenant_audit.rule_parameters import google_rule_parameters
from azure_tenant_audit.run import build_coverage_ledger
from azure_tenant_audit.secret_hygiene import redact_argv
from azure_tenant_audit.utils import parse_csv_list
from azure_tenant_audit.waivers import WaiverFileError, apply_waivers, load_waivers

from .auth import (
    ISOLATED_GOOGLE_SCOPES,
    GoogleAuthConfig,
    build_google_credentials,
    google_dependency_status,
    granted_scopes,
    read_service_account_summary,
    safe_auth_summary,
)
from .client import (
    GMAIL_NOT_APPLICABLE_REASON,
    GoogleWorkspaceClient,
    classify_google_error,
    classify_page_error,
    gmail_mail_service_not_enabled,
    gmail_mailbox_identifier,
    gmail_settings_status,
    is_token_refusal,
    minimise_gmail_settings,
)
from .collectors import (
    COLLECTOR_SECTIONS,
    DEFAULT_ORDER,
    PRESETS,
    REGISTRY,
    SUBJECT_SCOPE_ADMIN,
    SUBJECT_SCOPE_USER,
    SUBJECT_SCOPED_COLLECTORS,
    mark_incomplete_sections,
    policy_replay_rows,
    replay_policy_payload,
    replay_scuba_payload,
    scuba_probe_rows,
)
from .customer_id import (
    CustomerIds,
    bundle_customer_id,
    collect_customer_ids,
    withheld_coverage_row,
)
from .drive_scope import DOMAIN_SCOPE, read_tenant_domains
from .findings import (
    DEFAULT_STALE_DEVICE_DAYS,
    DEFAULT_STALE_USER_DAYS,
    build_google_findings,
)
from .normalize import (
    build_google_normalized_snapshot,
    org_unit_read_malformed,
    unplaced_policy_count,
)

LOG = logging.getLogger("auditex.google_workspace")
_OFFLINE_SAMPLE_METADATA_KEYS = frozenset({"_fixture_provenance"})


def _merged_fixture_provenance(
    sample_fixture_provenance: dict[str, Any] | None,
    fixture_provenance_override: dict[str, Any] | None,
) -> dict[str, Any] | None:
    merged: dict[str, Any] = {}
    if isinstance(sample_fixture_provenance, dict):
        merged.update(sample_fixture_provenance)
    if isinstance(fixture_provenance_override, dict):
        for key, value in fixture_provenance_override.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
    return fixture_provenance_for_bundle(merged) or None
# --doh-endpoint: a DoH resolver URL path can carry an account token.
# ``--customer-id`` is not a secret, but no customer id may enter a bundle (PRIV-CUSTOMER-ID).
_SENSITIVE_COMMAND_FLAGS = {"--sensitive-users", "--partner-domains", "--service-account-key", "--oauth-client", "--token-cache",
                            "--doh-endpoint", "--customer-id"}


@dataclass(frozen=True)
class GoogleRunConfig:
    tenant_name: str
    out: Path
    domain: str | None = None
    customer_id: str | None = None
    run_name: str | None = None
    auth: str = "domain-delegation"
    subject: str | None = None
    service_account_key: Path | None = None
    oauth_client: Path | None = None
    token_cache: Path | None = None
    collector_preset: str | None = "core-security"
    collectors: str | None = None
    exclude: str | None = None
    top: int | None = None
    page_size: int = 100
    since: str | None = None
    until: str | None = None
    offline: bool = False
    sample: Path | None = None
    fixture_provenance: dict[str, Any] | None = None
    # Accepted-risk waivers, read before any API call (see azure_tenant_audit.waivers).
    waiver_file: Path | None = None
    stale_user_days: int = DEFAULT_STALE_USER_DAYS
    stale_device_days: int = DEFAULT_STALE_DEVICE_DAYS
    # The DNS-over-HTTPS resolver for google_dns_posture: this option, else AUDITEX_DOH_ENDPOINT, else Cloudflare.
    doh_endpoint: str | None = None


def _validate_google_labels(tenant_name: str, run_name: str | None, ids: CustomerIds) -> bool:
    try:
        validate_bundle_name(tenant_name, "tenant name")
        validate_bundle_name(run_name, "run name")
    except ValueError as exc:
        LOG.error("%s", ids.text(str(exc)))
        return False
    return True


def _output_config(config: GoogleRunConfig, ids: CustomerIds) -> GoogleRunConfig:
    return replace(
        config,
        tenant_name=ids.text(config.tenant_name, "customer-id-withheld"),
        run_name=ids.text(config.run_name, "customer-id-withheld") if config.run_name is not None else None,
        domain=ids.scrub(config.domain),
        collectors=ids.scrub(config.collectors),
        since=ids.scrub(config.since),
        until=ids.scrub(config.until),
        waiver_file=Path(ids.text(local_path_argument(str(config.waiver_file)))) if config.waiver_file else None,
    )


def scrub_google_command_line(command_line: list[str]) -> list[str]:
    """The command line as the run bundle records it: secret-bearing values redacted and every absolute path of the
    operator's machine (``--out /home/...``) reduced to ``<local-path>/<name>``."""
    return [local_path_argument(item) for item in redact_argv(command_line, sensitive_flags=_SENSITIVE_COMMAND_FLAGS)]


def _selected_collectors(config: GoogleRunConfig) -> list[str]:
    selected = parse_csv_list(config.collectors) or []
    if not selected:
        selected = list(PRESETS.get(config.collector_preset or "core-security", DEFAULT_ORDER))
    excluded = set(parse_csv_list(config.exclude) or [])
    return [name for name in selected if name in REGISTRY and name not in excluded]


def scopes_for_collectors(selected: list[str], *, auth_mode: str = "domain-delegation") -> tuple[str, ...]:
    """Every scope the run asks for: the selected collectors' required scopes, then (delegation only) optional ones.

    Under domain-wide delegation an optional scope (``optional_scopes``, such as the Drive collector's read-only
    Directory domains scope) is never on its collector's own token (``_collector_client`` narrows to
    ``required_scopes``): it is read on a token of its own, so a delegation that leaves it out fails only that read.
    An OAuth sign-in asks only for the union of the required scopes (LIVE-FIX-7): every token comes from that one
    sign-in, a grant must hold all of it, and no scope that is only optional is ever requested, cached or refreshed.
    """
    attributes = ("required_scopes",) if auth_mode == "oauth" else ("required_scopes", "optional_scopes")
    scopes: list[str] = []
    for attribute in attributes:
        for name in selected:
            for scope in getattr(REGISTRY.get(name), attribute, ()):
                if scope not in scopes:
                    scopes.append(scope)
    return tuple(scopes)


def drive_domain_read_mode(selected: list[str], auth_mode: str, scopes: tuple[str, ...]) -> str | None:
    """How the Drive collector may read the tenant's domains in this run (``drive_domain_read`` in the auth context);
    ``None`` when Drive is not selected.

    ``delegation_own_token`` under domain-wide delegation (on a token of its own); ``oauth_required_scope`` under OAuth
    when the domain scope is in the requested (required) set because another selected collector requires it;
    otherwise ``not_requested``: it is neither asked for nor read.
    """
    if "google_drive_posture" not in selected:
        return None
    if auth_mode == "domain-delegation":
        return "delegation_own_token"
    if auth_mode == "oauth" and DOMAIN_SCOPE in scopes:
        return "oauth_required_scope"
    return "not_requested"


def tenant_domain_read_allowed(auth_config: GoogleAuthConfig, credentials: Any) -> bool:
    """Whether the client may read the Directory domains list for Drive: delegation, or an OAuth grant holding it.

    Under OAuth the scope must be in this run's requested set (another selected collector requires it) and in the
    grant the credentials carry; a scope only asked for, or not asked for, is never used.
    """
    if auth_config.auth_mode == "domain-delegation":
        return True
    if auth_config.auth_mode == "oauth":
        return DOMAIN_SCOPE in auth_config.scopes and DOMAIN_SCOPE in granted_scopes(credentials)
    return False


def subject_scope_for_collectors(selected: list[str], *, per_user_delegation: bool) -> dict[str, str]:
    """``subject_scoped`` of each selected collector whose evidence is one subject's view, not the tenant's.

    Drive and Calendar are always the delegated admin's view. Gmail settings are each user's own when
    domain-wide delegation lets the run act as that user, and the signed-in mailbox's otherwise.
    """
    scope = {name: label for name, label in SUBJECT_SCOPED_COLLECTORS.items() if name in selected}
    if "google_gmail_settings" in selected:
        scope["google_gmail_settings"] = SUBJECT_SCOPE_USER if per_user_delegation else SUBJECT_SCOPE_ADMIN
    return scope


def build_google_auth_context_payload(config: GoogleRunConfig, auth_config: GoogleAuthConfig) -> dict[str, Any]:
    auth_summary = safe_auth_summary(auth_config)
    return {
        "platform": "google_workspace",
        "auth_mode": auth_config.auth_mode,
        "auth_type": auth_config.auth_mode,
        "per_user_delegation": auth_summary["per_user_delegation"],
        "subject_scope": subject_scope_for_collectors(
            _selected_collectors(config), per_user_delegation=auth_summary["per_user_delegation"]
        ),
        "subject": auth_config.subject,
        "workspace_domain": config.domain,
        "customer_id": bundle_customer_id(config.customer_id),
        "scope_count": len(auth_config.scopes),
        "scopes": list(auth_config.scopes),
        **_drive_domain_read_field(_selected_collectors(config), auth_config.auth_mode, auth_config.scopes),
        "service_account_key_present": auth_summary["service_account_key_present"],
        "oauth_client_present": auth_summary["oauth_client_present"],
        "token_cache_present": auth_summary["token_cache_present"],
    }


def _drive_domain_read_field(selected: list[str], auth_mode: str, scopes: tuple[str, ...]) -> dict[str, str]:
    mode = drive_domain_read_mode(selected, auth_mode, scopes)
    return {} if mode is None else {"drive_domain_read": mode}


def _authenticated_google_read(row: dict[str, Any]) -> bool:
    """Whether a coverage row is a Google read that completed on the collector's token, whatever its row count.

    Every collector reads through one token asking for all of its scopes (see ``_collector_client``), so a completed
    read proves that token carries them. A DNS lookup uses no Google token, and a row with no read behind it (a
    skipped-mailbox note) proves nothing. Rows recorded before the explicit marker count only when they hold data.
    """
    if str(row.get("type") or "google") != "google" or row.get("status") not in {"ok", "partial"}:
        return False
    return bool(row.get("authenticated_read")) or int(row.get("item_count") or 0) > 0


def build_google_capability_rows(
    selected: list[str],
    *,
    auth_mode: str,
    dependency_status: dict[str, Any],
    coverage_rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    coverage_rows = coverage_rows or []
    failures_by_collector: dict[str, list[dict[str, Any]]] = {}
    seen_by_collector: dict[str, list[dict[str, Any]]] = {}
    for row in coverage_rows:
        seen_by_collector.setdefault(str(row.get("collector") or ""), []).append(row)
        if row.get("status") != "ok":
            failures_by_collector.setdefault(str(row.get("collector") or ""), []).append(row)
    status = "supported" if dependency_status.get("available") else "blocked"
    reason = "google_dependencies_available" if status == "supported" else "missing_google_dependencies"
    scope_by_collector = {name: label for name, label in SUBJECT_SCOPED_COLLECTORS.items() if name in selected}
    for row in coverage_rows:
        label = row.get("subject_scoped")
        if label in {SUBJECT_SCOPE_ADMIN, SUBJECT_SCOPE_USER} and row.get("collector") in selected:
            # Admin wins over user: one admin-scoped read makes the collector's evidence admin-scoped.
            if scope_by_collector.get(str(row["collector"])) != SUBJECT_SCOPE_ADMIN:
                scope_by_collector[str(row["collector"])] = str(label)
    rows: list[dict[str, Any]] = []
    for name in selected:
        required = list(getattr(REGISTRY.get(name), "required_scopes", ()))
        failures = failures_by_collector.get(name, [])
        row_status = status
        row_reason = reason
        missing_permissions: list[str] = []
        scopes_proven = any(_authenticated_google_read(item) for item in seen_by_collector.get(name, []))
        if not failures and scopes_proven and status == "supported":
            row_status = "supported_exact_scope"
            row_reason = "runtime_preflight_ok"
        elif failures:
            # Only a read refused outright is a scope block; a read that partly succeeded proves the scopes work.
            classes = {str(item.get("error_class") or "") for item in failures if item.get("status") == "failed"}
            # A completed Google read of this collector, even an empty one, proves its token carries the collector's
            # scopes, so another read refused beside it is a role limit, not a missing scope.
            if classes & {"insufficient_permissions", "unauthenticated"} and not scopes_proven:
                row_status = "blocked_by_scope"
                row_reason = "runtime_permission_block"
                # A refused token whose scopes were checked one by one names only the ones actually missing.
                named = [
                    str(scope)
                    for item in failures
                    if isinstance(item.get("missing_permissions"), list)
                    for scope in item["missing_permissions"]
                ]
                missing_permissions = list(dict.fromkeys(named)) or required
            else:
                row_status = "partial"
                row_reason = (
                    "runtime_permission_block"
                    if classes & {"insufficient_permissions", "unauthenticated"}
                    else "runtime_endpoint_block"
                )
        seen = seen_by_collector.get(name, [])
        if seen and not failures and all(item.get("live_read") is False for item in seen):
            # Only a DNS readiness note: nothing was looked up and no Google request was made.
            row_reason = "dns_only_not_verified"
        if auth_mode == "offline" and not failures:
            # A replay observed nothing on a tenant: it is an offline sample, not an exact-scope read.
            row_status = "offline_sample"
            row_reason = "offline_bundle"
        capability: dict[str, Any] = {
            "collector": name,
            "status": row_status,
            "reason": row_reason,
            "required_permissions": required,
            "missing_permissions": missing_permissions,
            "observed_permissions": [],
            "delegated_roles": [],
            "minimum_role_hints": ["Google Workspace super admin or delegated admin"],
            "scopes_proven": scopes_proven,
            "notes": f"Google Workspace {auth_mode} auth.",
            "endpoint_statuses": [
                {
                    "name": item.get("name"),
                    "status": item.get("status"),
                    "error_class": item.get("error_class"),
                    "error": item.get("error"),
                }
                for item in failures
            ],
        }
        scope = scope_by_collector.get(name)
        if scope:
            capability["subject_scoped"] = scope
            capability["notes"] = (
                f"Google Workspace {auth_mode} auth. "
                + (
                    "Evidence is each user's own settings, read by acting as that user."
                    if scope == SUBJECT_SCOPE_USER
                    else "Evidence is limited to what the delegated admin subject can see; it is not tenant-wide."
                )
            )
        rows.append(enrich_capability_row(capability))
    return rows


def _capability_rows(
    selected: list[str],
    *,
    auth_mode: str,
    dependency_status: dict[str, Any],
    coverage_rows: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    return build_google_capability_rows(
        selected,
        auth_mode=auth_mode,
        dependency_status=dependency_status,
        coverage_rows=coverage_rows,
    )


def build_google_live_readiness(
    selected: list[str], capability_rows: list[dict[str, Any]], *, dependency_available: bool = True,
    coverage_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return build_live_readiness_summary(
        selected_collectors=selected,
        capability_rows=capability_rows,
        dependency_available=dependency_available,
        coverage_rows=coverage_rows,
    )


def build_google_toolchain_readiness(dependency_status: dict[str, Any]) -> dict[str, Any]:
    available = bool(dependency_status.get("available"))
    missing = [str(item) for item in dependency_status.get("missing") or []]
    return {
        "google_workspace_libraries": {
            "name": "google_workspace_libraries",
            "status": "supported" if available else "blocked",
            "item_count": 0 if available else len(missing),
            "message": "Google client libraries available" if available else dependency_status.get("install_hint", "Google client libraries missing"),
            "missing": missing,
            "install_hint": dependency_status.get("install_hint", ""),
        }
    }


def _collector_client(client: Any, collector: str) -> Any:
    """``client`` narrowed to the collector's own scopes, so a scope left out of the delegation fails only it."""
    for_scopes = getattr(client, "for_scopes", None)
    if for_scopes is None:
        return client
    return for_scopes(tuple(getattr(REGISTRY.get(collector), "required_scopes", ()) or ()))


def name_missing_scopes(client: Any, coverage_rows: list[dict[str, Any]]) -> None:
    """Add ``missing_permissions`` to each row whose token was refused, naming only the scopes the delegation lacks.

    One token exchange per scope of each refused collector; nothing is changed when that cannot be told.
    """
    checker = getattr(client, "unauthorised_scopes", None)
    if checker is None:
        return
    refused: dict[str, list[dict[str, Any]]] = {}
    for row in coverage_rows:
        if row.get("status") == "failed" and is_token_refusal(row.get("error")):
            refused.setdefault(str(row.get("collector") or ""), []).append(row)
    for collector, rows in refused.items():
        required = tuple(getattr(REGISTRY.get(collector), "required_scopes", ()) or ())
        if not required:
            continue
        try:
            missing = checker(required)
        except Exception:  # noqa: BLE001 - the capability row then lists every required scope, as before
            missing = None
        if missing:
            for row in rows:
                row["missing_permissions"] = list(missing)


def _preflight_call(collector: str, name: str, func: Any) -> dict[str, Any]:
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
    page_error = getattr(rows, "page_error", None)
    if status == "ok" and isinstance(page_error, Exception):
        # A later page failed after its retries: what was read is real, but the list is cut short.
        status = "partial"
        error_class, error = classify_page_error(page_error)
    permission_errors = [item for item in getattr(rows, "permission_errors", None) or [] if isinstance(item, dict)]
    if status == "ok" and permission_errors:
        # Drive files whose sharing could not be read: their exposure is unknown, so the read is not complete.
        classes = [str(item.get("error_class") or "client_error") for item in permission_errors]
        status = "partial"
        error_class = max(set(classes), key=classes.count)
        error = f"Sharing of {len(permission_errors)} Drive files could not be read ({', '.join(sorted(set(classes)))})."
    row = {
        "collector": collector,
        "type": "google",
        "name": name,
        "status": status,
        "item_count": len(rows) if isinstance(rows, list) else 1,
        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
        "error_class": error_class,
        "error": error,
    }
    if status != "failed":
        row["authenticated_read"] = True
    return row


def _gmail_preflight_status(row: dict[str, Any], check: Any) -> dict[str, Any]:
    """A probe read that returned settings whose every read failed is not ready; some failing is partial.

    A probed mailbox whose user has no Gmail service (:func:`gmail_mail_service_not_enabled`) read no settings: the
    row keeps status ``ok`` with ``item_count`` 0 and ``not_applicable``, and it proves no scope
    (``authenticated_read`` false), so the capability matrix never reports an exact-scope proof from it.
    """
    if row.get("status") != "ok":
        return {}
    payloads = [payload for payload in getattr(check, "payloads", None) or [] if isinstance(payload, dict)]
    if not payloads:
        # No mailbox was sampled (an empty Directory sample): nothing was read, so no scope is proven.
        return {"item_count": 0, "authenticated_read": False}
    for payload in payloads:
        status, error_class, error = gmail_settings_status(payload)
        if status != "ok":
            update = {"status": status, "error_class": error_class, "error": error}
            if status == "failed":
                update["item_count"] = 0
            return update
    read = [payload for payload in payloads if not gmail_mail_service_not_enabled(payload)]
    if payloads and not read:
        return {"item_count": 0, "not_applicable": GMAIL_NOT_APPLICABLE_REASON, "authenticated_read": False}
    if payloads and len(read) < len(payloads):
        return {"item_count": len(read)}
    return {}


def build_google_preflight_rows(
    client: Any,
    selected: list[str],
    *,
    domain: str | None,
    top: int = 1,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for collector in selected:
        rows.extend(_collector_preflight_rows(_collector_client(client, collector), collector, domain=domain, top=top))
    name_missing_scopes(client, rows)
    return rows


def _collector_preflight_rows(client: Any, collector: str, *, domain: str | None, top: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if collector == "google_directory":
        rows.append(_preflight_call(collector, "users", lambda: client.list_directory("users", top=top)))
    elif collector == "google_reports":
        rows.append(_preflight_call(collector, "loginActivities", lambda: client.list_report_activities("login", top=top)))
    elif collector == "google_alert_center":
        rows.append(_preflight_call(collector, "alerts", lambda: client.list_alerts(top=top)))
    elif collector == "google_policies":
        rows.append(_preflight_call(collector, "policySettings", lambda: client.list_policies(limit=top)))
    elif collector == "google_setting_events":
        event_name = "CHANGE_APPLICATION_SETTING"
        rows.append(_preflight_call(collector, "settingEvents", lambda: scuba_probe_rows(
            client.list_admin_setting_events(event_name, limit=top), collector, event_name=event_name,
        )))
    elif collector == "google_sso_assignments":
        rows.append(_preflight_call(collector, "inboundSsoAssignments", lambda: scuba_probe_rows(
            client.list_inbound_sso_assignments(limit=top), collector,
        )))
    elif collector == "google_gmail_settings":
        def gmail_check() -> list[dict[str, Any]]:
            # Without delegation only the signed-in mailbox can be read, so that is what the probe tries.
            if not getattr(client, "per_user_delegation", True):
                gmail_check.payloads = [client.get_gmail_settings_for_user("me")]  # type: ignore[attr-defined]
                return gmail_check.payloads  # type: ignore[attr-defined]
            users = client.list_directory("users", top=1)
            if not users:
                return []
            email = str(users[0].get("primaryEmail") or users[0].get("email") or "")
            gmail_check.payloads = [client.get_gmail_settings_for_user(email)] if email else []  # type: ignore[attr-defined]
            return gmail_check.payloads  # type: ignore[attr-defined]

        row = _preflight_call(collector, "mailboxSettings", gmail_check)
        row.update(_gmail_preflight_status(row, gmail_check))
        rows.append(row)
    elif collector == "google_devices":
        rows.append(_preflight_call(collector, "mobileDevices", lambda: client.list_devices("mobile", top=top)))
    elif collector == "google_dns_posture":
        # Only the run's resolver is ready to look the domain up; no Google token is used, so no Google scope is proven.
        # The row is a readiness note with no lookup behind it (``live_read`` false): it verifies nothing.
        rows.append({"collector": collector, "type": "dns", "name": "dns", "status": "ok", "item_count": 1 if domain else 0, "duration_ms": 0, "error_class": None, "error": None, "live_read": False})
    elif collector == "google_drive_posture":
        rows.append(_preflight_call(collector, "driveFiles", lambda: client.list_drive_files(
            top=top, tenant_domains=lambda: read_tenant_domains(client))))
        rows.append(_preflight_call(collector, "sharedDrives", lambda: client.list_shared_drives(top=top)))
    elif collector == "google_groups_settings":
        def group_settings_check() -> list[dict[str, Any]]:
            groups = client.list_directory("groups", top=1)
            if not groups:
                return []
            email = str(groups[0].get("email") or groups[0].get("id") or "")
            return [client.get_group_settings(email)] if email else []

        rows.append(_preflight_call(collector, "groupSettings", group_settings_check))
    elif collector == "google_calendar_posture":
        rows.append(_preflight_call(collector, "calendarResources", lambda: client.list_calendar_resources(top=top)))
    return rows


def _write_google_bundle(
    *,
    writer: AuditWriter,
    config: GoogleRunConfig,
    collector_payloads: dict[str, dict[str, Any]],
    result_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
    capability_rows: list[dict[str, Any]],
    diagnostics: list[dict[str, Any]],
    duration: float,
    mode: str,
    auth_context_path: Path | None = None,
    command_line: list[str] | None = None,
    waiver_rows: list[dict[str, Any]] | None = None,
    replay: dict[str, Any] | None = None,
    as_of: datetime | None = None,
    data_handling_notices: list[str] | None = None,
    doh_endpoint: str | None = None,
) -> int:
    evaluated_at = as_of or datetime.now(UTC)
    normalized_snapshot = build_google_normalized_snapshot(
        tenant_name=config.tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        domain=config.domain,
        customer_id=bundle_customer_id(config.customer_id),
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        top_limit=config.top or None,
        as_of=evaluated_at,
    )
    findings = build_google_findings(
        normalized_snapshot,
        diagnostics=diagnostics,
        stale_user_days=config.stale_user_days,
        stale_device_days=config.stale_device_days,
        now=evaluated_at,
    )
    if waiver_rows:
        # Same semantics as Microsoft 365: AND matching, finding_id or rule_id required, expired rows ignored.
        findings = apply_waivers(findings, waiver_rows)
    if findings:
        writer.write_findings(findings)
    coverage_ledger = build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe(
        "run_summary",
        {
            "platform": "google_workspace",
            "tenant_name": config.tenant_name,
            "workspace_domain": config.domain,
            "customer_id": bundle_customer_id(config.customer_id),
            "run_id": writer.run_id,
            "finding_count": len(findings),
            "collector_count": len(result_rows),
        },
    )
    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        "ai_safe/run_summary.json",
    ]
    if findings:
        evidence_paths.append("findings/findings.json")
    if diagnostics:
        evidence_paths.append("blockers/blockers.json")
    if auth_context_path is not None:
        evidence_paths.append(str(auth_context_path.relative_to(writer.run_dir)))
    evidence_paths.extend(f"normalized/{name}.json" for name in ["capability_matrix", "coverage_ledger", *normalized_snapshot.keys()])
    overall_status = "partial" if diagnostics or any(str(row.get("status")) not in {"ok", "skipped"} for row in result_rows) else "ok"
    privacy = build_privacy_block(safe_for_external_llm=False)
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=config.tenant_name,
            tenant_id=None,
            executed_by="auditex_google_workspace",
            selected_collectors=[row["name"] for row in result_rows],
            overall_status=overall_status,
            duration_seconds=duration,
            mode=mode,
            auditor_profile="google-workspace",
            plane="inventory",
            findings=findings,
            blockers=diagnostics,
            evidence_paths=evidence_paths,
            normalized_snapshot=normalized_snapshot,
            capability_rows=capability_rows,
            coverage_ledger=coverage_ledger,
            privacy=privacy,
            bundle_metadata={
                "fixture_provenance": config.fixture_provenance,
                "as_of": evaluated_at.isoformat().replace("+00:00", "Z"),
                "since": config.since,
                "until": config.until,
                "platform": "google_workspace",
                "workspace_domain": config.domain,
                "customer_id": bundle_customer_id(config.customer_id),
                "auth_context_path": str(auth_context_path.relative_to(writer.run_dir)) if auth_context_path is not None else None,
                "command_line": command_line or [],
                "coverage_count": len(coverage_rows),
                "waiver_path": str(config.waiver_file) if config.waiver_file else None,
                "top_limit": config.top or None,
                "rule_parameters": google_rule_parameters(
                    stale_user_days=config.stale_user_days, stale_device_days=config.stale_device_days
                ),
                "replay_source": replay,
                "sample_truncated": bool((normalized_snapshot.get("snapshot") or {}).get("sample_truncated")),
                "truncated_sections": (normalized_snapshot.get("snapshot") or {}).get("truncated_sections", []),
                "data_handling_notices": list(data_handling_notices or []),
            },
            as_of=as_of,
            doh_endpoint=doh_endpoint,
        ),
    )
    return 1 if overall_status == "partial" else 0


def _replay_gmail_payload(collector: str, payload: Any) -> Any:
    """A sample's Gmail mailbox rows as the live collector keeps them (:func:`minimise_gmail_settings`): a
    ``userEmail`` naming no readable mailbox is replaced before any raw, coverage or normalised copy is written."""
    section = payload.get("mailboxSettings") if collector == "google_gmail_settings" and isinstance(payload, dict) else None
    if not isinstance(section, dict) or not isinstance(section.get("value"), list):
        return payload
    rows = [minimise_gmail_settings(row) if isinstance(row, dict) else row for row in section["value"]]
    return {**payload, "mailboxSettings": {**section, "value": rows}}


def _replayed_mailbox_rows(collector: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Mailboxes in a sample whose Gmail settings reads failed replay as the failed or partial reads they were."""
    if collector != "google_gmail_settings":
        return []
    section = payload.get("mailboxSettings")
    mailboxes = section.get("value") if isinstance(section, dict) else None
    rows: list[dict[str, Any]] = []
    for mailbox in mailboxes if isinstance(mailboxes, list) else []:
        if not isinstance(mailbox, dict):
            mailbox = {}
        status, error_class, error = gmail_settings_status(mailbox)
        if status == "ok":
            continue
        rows.append(
            {
                "collector": collector,
                "type": "google",
                "name": f"mailboxSettings:{mailbox['userEmail'] if gmail_mailbox_identifier(mailbox.get('userEmail')) else 'unknown'}",
                "endpoint": "gmail.users.settings",
                "status": status,
                "item_count": 0 if status == "failed" else 1,
                "duration_ms": 0,
                "error_class": error_class,
                "error": error,
            }
        )
    return rows


def _record_policy_placement(
    writer: AuditWriter,
    collector_payloads: dict[str, dict[str, Any]],
    result_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Partial coverage rows for a malformed Directory OU read and for OU targets absent from a complete one."""
    new_rows: list[tuple[str, dict[str, Any]]] = []
    if org_unit_read_malformed(collector_payloads.get("google_directory")):
        new_rows.append(
            (
                "google_directory",
                {
                    "collector": "google_directory",
                    "type": "derived",
                    "name": "orgUnits",
                    "status": "partial",
                    "item_count": 0,
                    "error_class": "malformed_response",
                    "error": "The Directory organisational unit read is present but malformed.",
                },
            )
        )
    if count := unplaced_policy_count(collector_payloads, coverage_rows):
        new_rows.append(
            (
                "google_policies",
                {
                    "collector": "google_policies",
                    "type": "derived",
                    "name": "policyPlacement",
                    "status": "partial",
                    "item_count": 0,
                    "error_class": "malformed_response",
                    "error": f"{count} policies target organisational units absent from the complete Directory read.",
                    "policy_row_validation": True,
                },
            )
        )
    for collector, row in new_rows:
        coverage_rows.append(row)
        summary = next((item for item in result_rows if item["name"] == collector), None)
        if summary is None:
            continue
        if summary["status"] == "ok":
            summary["status"] = "partial"
        summary["coverage_rows"] += 1
        writer.write_checkpoint(collector, summary)
    return [row for _, row in new_rows]


def run_google_offline(
    *,
    sample_path: Path,
    out: Path,
    tenant_name: str,
    run_name: str | None,
    domain: str | None,
    customer_id: str | None,
    fixture_provenance_override: dict[str, Any] | None = None,
    waiver_file: Path | None = None,
    stale_user_days: int = DEFAULT_STALE_USER_DAYS,
    stale_device_days: int = DEFAULT_STALE_DEVICE_DAYS,
    as_of: datetime | None = None,
) -> int:
    """Replay a Google Workspace sample. ``as_of`` pins the instant date-derived findings are judged at."""
    ids = CustomerIds(customer_id)
    if not _validate_google_labels(tenant_name, run_name, ids):
        return 2
    from azure_tenant_audit.resources import (
        read_selected_resource,
        selected_resource_record,
    )

    sample_default = "examples/google_workspace_sample.json"
    # The run log names the file actually read (an operator's local copy, not the shipped sample of the same name),
    # and never by an absolute workstation path.
    sample_record = selected_resource_record(sample_path, default=sample_default)
    try:
        sample_bytes = read_selected_resource(sample_path, default=sample_default, field="sample")
        sample = json.loads(sample_bytes.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        LOG.error("Unable to load Google sample bundle.")
        return 2
    if not isinstance(sample, dict):
        LOG.error("Google sample bundle must be a JSON object.")
        return 2
    # Resolver diagnostics in the sample are untrusted (a full resolver URL may carry user info, a path token or a
    # query): every copy below (raw payloads, coverage, diagnostics, normalised records) sees only the safe form.
    sample = sanitise_resolver_fields(sample)
    ids.learn(sample)
    sample_record = ids.scrub(sample_record)
    # A value used to identify evidence (for example an OU path) can become unusable after masking.
    withheld_collectors: set[str] = set()
    safe_sample: dict[str, Any] = {}
    for key, value in sample.items():
        safe_key = ids.text(key, "customer-id-withheld")
        if key not in _OFFLINE_SAMPLE_METADATA_KEYS:
            value = _replay_gmail_payload(key, replay_scuba_payload(key, replay_policy_payload(key, value)))
        safe_sample[safe_key], changed = ids.evidence(value)
        if changed or safe_key != key:
            withheld_collectors.add(safe_key)
    sample = safe_sample
    fixture_provenance = ids.scrub(_merged_fixture_provenance(
        sample.get("_fixture_provenance") if isinstance(sample.get("_fixture_provenance"), dict) else None,
        fixture_provenance_override,
    ))
    try:
        waiver_rows = load_waivers(waiver_file) if waiver_file else []
    except WaiverFileError as exc:
        LOG.error("%s", ids.text(str(exc)))
        return 2
    config = _output_config(GoogleRunConfig(
        tenant_name=tenant_name,
        out=out,
        domain=domain,
        customer_id=customer_id,
        run_name=run_name,
        offline=True,
        sample=sample_path,
        fixture_provenance=fixture_provenance,
        waiver_file=waiver_file,
        stale_user_days=stale_user_days,
        stale_device_days=stale_device_days,
    ), ids)
    writer = AuditWriter(out, tenant_name=config.tenant_name, run_name=config.run_name)
    writer.log_event(
        "run.started",
        "Google Workspace offline run started",
        {"mode": "offline", "platform": "google_workspace", **sample_record},
    )
    # ``null``, a list or an empty object under a collector's name is a collector that delivered nothing, not one that is
    # absent from the sample: it stays in the run, with every section it should have carried recorded as absent.
    sample_collectors = {key: value for key, value in sample.items() if key not in _OFFLINE_SAMPLE_METADATA_KEYS}
    collector_payloads = {name: value for name, value in sample_collectors.items() if isinstance(value, dict)}
    result_rows: list[dict[str, Any]] = []
    # A sample section that carries an error or a cut-list marker replays as the failed or partial read it was,
    # with the same blocker a live run raises, so the replay cannot read complete over it.
    coverage_rows: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for name, held in sample_collectors.items():
        if name not in COLLECTOR_SECTIONS and not isinstance(held, dict):
            continue
        payload = held if isinstance(held, dict) else {}
        item_count = 0
        for section_name, section in payload.items():
            # ``twoStepVerificationPolicies`` is a subset of the one policies read in ``policySettings``: count it once.
            if name == "google_policies" and section_name == "twoStepVerificationPolicies" and "policySettings" in payload:
                continue
            if isinstance(section, dict) and isinstance(section.get("value"), list):
                item_count += len(section["value"])
        replayed = [
            *replay_coverage_rows(name, payload),
            *absent_section_rows(name, held, COLLECTOR_SECTIONS.get(name, ())),
            *_replayed_mailbox_rows(name, payload),
            *policy_replay_rows(name, payload),
            *([withheld_coverage_row(name)] if name in withheld_collectors else []),
        ]
        coverage_rows.extend(replayed)
        diagnostics.extend(dict(row) for row in replayed if row.get("status") != "ok")
        row = {
            "name": name,
            "status": replay_collector_status(replayed),
            "item_count": item_count,
            "message": "offline simulation"
            if not replayed
            else f"offline simulation; {len(replayed)} section(s) recorded as failed, absent or cut short",
            "coverage_rows": len(replayed),
        }
        result_rows.append(row)
        writer.write_checkpoint(name, row)
        writer.write_raw(name, payload)
    diagnostics.extend(_record_policy_placement(writer, collector_payloads, result_rows, coverage_rows))
    for row in result_rows:
        writer.write_summary(row)
    writer.write_index_records(coverage_rows)
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
    capability_rows = _capability_rows(
        [row["name"] for row in result_rows], auth_mode="offline", dependency_status={"available": True}, coverage_rows=coverage_rows
    )
    return _write_google_bundle(
        writer=writer,
        config=config,
        collector_payloads=collector_payloads,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        capability_rows=capability_rows,
        diagnostics=diagnostics,
        duration=0,
        mode="offline",
        command_line=[],
        waiver_rows=ids.scrub(waiver_rows),
        replay=replay_source(sample_record["sample"], data=sample_bytes),
        as_of=as_of,
    )


def _resolver_label(doh_endpoint: str) -> str:
    """The resolver as the notice and run log name it: a configured one by host only, since a path can hold a profile id."""
    return doh_resolver_disclosure(doh_endpoint)


def google_dns_notice(doh_endpoint: str) -> str:
    """The data-handling notice for the Google DNS posture lookups, with how to turn them off."""
    return (
        "Selected Google DNS posture collection sends the customer's verified domain and alias names, "
        "and may send their parent DNS names for DMARC, to "
        f"{_resolver_label(doh_endpoint)}. Only domain names, no user data, are sent to the resolver. "
        "Deselect it with --exclude google_dns_posture (the identity and collaboration presets omit it); "
        f"use --doh-endpoint or set {DOH_ENDPOINT_ENV} to use another DNS-over-HTTPS resolver."
    )


def _auth_config(config: GoogleRunConfig, selected: list[str]) -> GoogleAuthConfig:
    scopes = scopes_for_collectors(selected, auth_mode=config.auth)
    return GoogleAuthConfig(
        auth_mode=config.auth,
        scopes=scopes,
        subject=config.subject,
        service_account_key=config.service_account_key,
        oauth_client=config.oauth_client,
        token_cache=config.token_cache,
        isolated_scopes=tuple(scope for scope in scopes if scope in ISOLATED_GOOGLE_SCOPES),
    )


def run_google_live(config: GoogleRunConfig, *, command_line: list[str] | None = None) -> int:
    ids = CustomerIds(config.customer_id)
    if not _validate_google_labels(config.tenant_name, config.run_name, ids):
        return 2
    # Read the waiver file once, before any API call: a file that cannot be trusted must not let the run
    # finish with no waivers applied. The rows loaded here are the ones applied later.
    try:
        waiver_rows = load_waivers(config.waiver_file) if config.waiver_file else []
    except WaiverFileError as exc:
        LOG.error("%s", ids.text(str(exc)))
        return 2
    dependency_status = google_dependency_status()
    if not dependency_status["available"]:
        print(json.dumps({"error": "missing_google_dependencies", **dependency_status}, indent=2), file=sys.stderr)
        return 2
    selected = _selected_collectors(config)
    # A resolver that cannot be used stops the run before any sign-in or call, as a bad option would.
    doh_endpoint: str | None = None
    if "google_dns_posture" in selected:
        try:
            doh_endpoint = resolve_doh_endpoint(config.doh_endpoint)
        except ValueError as exc:
            print(json.dumps({"error": "invalid_doh_endpoint", "message": ids.text(str(exc))}, indent=2), file=sys.stderr)
            return 2
    auth_config = _auth_config(config, selected)
    try:
        credentials = build_google_credentials(auth_config)
    except (RuntimeError, ValueError, OSError) as exc:
        message = ids.failure_text(str(exc))
        print(json.dumps({"error": "google_auth_failed", "message": message}, indent=2), file=sys.stderr)
        return 2
    client = GoogleWorkspaceClient(
        credentials,
        customer_id=config.customer_id,
        page_size=config.page_size,
        delegated=auth_config.supports_user_delegation,
        tenant_domain_read=tenant_domain_read_allowed(auth_config, credentials),
    )
    # One collector can disclose the ID of a customer another already mentioned in free text.
    # Buffer the runner's events and results in memory until all reads have supplied their IDs.
    events: list[tuple[str, str, dict[str, Any] | None]] = []
    hooks = CollectorRunHooks(audit_logger=lambda event, message, details: events.append((event, message, details)))
    start = time.time()
    runner = CollectorRunner()
    with collect_customer_ids(ids):
        outputs = [
            runner.run(
                REGISTRY[name],
                CollectorRunContext(
                    client=_collector_client(client, name),
                    top=config.top,
                    page_size=config.page_size,
                    plane="inventory",
                    since=config.since,
                    until=config.until,
                    hooks=hooks,
                    extra={"domain": config.domain, "customer_id": config.customer_id, "doh_endpoint": doh_endpoint},
                ),
                name=name,
            )
            for name in selected
        ]
    for output in outputs:
        ids.learn(output.result.payload)
        ids.learn(output.coverage_rows)
    ids.learn([detail for _, _, detail in events])

    config = _output_config(config, ids)
    writer = AuditWriter(config.out, tenant_name=config.tenant_name, run_name=config.run_name)
    auth_context_path = writer.write_json_artifact(
        "auth-context.json", ids.scrub(build_google_auth_context_payload(config, auth_config)),
    )
    writer.log_event(
        "run.started",
        "Google Workspace live run started",
        ids.scrub({
            "platform": "google_workspace", "domain": config.domain,
            "customer_id": bundle_customer_id(config.customer_id), "auth": safe_auth_summary(auth_config),
        }),
    )
    notices = []
    if doh_endpoint is not None:
        notice = ids.text(google_dns_notice(doh_endpoint))
        notices.append(notice)
        LOG.info("%s", notice)
        print(f"Collection notice: {notice}", file=sys.stderr)
        writer.log_event("run.notice", notice, {"collector": "google_dns_posture", "resolver": ids.text(_resolver_label(doh_endpoint))})
    for event, message, detail in events:
        writer.log_event(event, ids.text(message), ids.scrub(detail))
    result_rows: list[dict[str, Any]] = []
    coverage_rows: list[dict[str, Any]] = []
    collector_payloads: dict[str, dict[str, Any]] = {}
    for name, output in zip(selected, outputs, strict=True):
        # A list read that failed, was cut or held unreadable rows is marked on its raw section too, so an offline
        # replay, compare or drift of the raw evidence sees the same gap as this run (LIVE-FIX-6 B1a).
        payload, changed = ids.evidence(mark_incomplete_sections(name, output.result.payload, output.coverage_rows))
        payload = writer.valid_text(payload)
        rows = writer.valid_text(ids.scrub(output.coverage_rows))
        row = writer.valid_text(ids.scrub(dict(output.result_row)))
        if changed:
            rows.append(withheld_coverage_row(name))
            row["coverage_rows"] = len(rows)
            if row["status"] == "ok":
                row["status"] = "partial"
        if rows:
            writer.write_index_records(rows)
        if not output.crashed or payload:
            writer.write_raw(name, payload)
        writer.write_checkpoint(name, row)
        result_rows.append(row)
        coverage_rows.extend(rows)
        collector_payloads[name] = payload
    if placement := _record_policy_placement(writer, collector_payloads, result_rows, coverage_rows):
        writer.write_index_records(placement)
    for row in result_rows:
        writer.write_summary(row)
    name_missing_scopes(client, coverage_rows)
    diagnostics = [dict(row) for row in coverage_rows if row.get("status") != "ok"]
    capability_rows = _capability_rows(
        selected,
        auth_mode=config.auth,
        dependency_status=dependency_status,
        coverage_rows=coverage_rows,
    )
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
    return _write_google_bundle(
        writer=writer,
        config=config,
        collector_payloads=collector_payloads,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        capability_rows=capability_rows,
        diagnostics=diagnostics,
        duration=round(time.time() - start, 2),
        mode=config.auth,
        auth_context_path=auth_context_path,
        command_line=ids.scrub(scrub_google_command_line(command_line or [])),
        waiver_rows=ids.scrub(waiver_rows),
        data_handling_notices=notices,
        doh_endpoint=ids.scrub(doh_endpoint),
    )


def google_doctor(config: GoogleRunConfig | None = None) -> dict[str, Any]:
    dependency_status = google_dependency_status()
    payload: dict[str, Any] = {
        "platform": "google_workspace",
        "dependencies": dependency_status,
        "collectors": sorted(REGISTRY),
        "presets": sorted(PRESETS),
    }
    if config is not None:
        selected = _selected_collectors(config)
        scopes = list(scopes_for_collectors(selected, auth_mode=config.auth))
        payload["auth"] = {
            "mode": config.auth,
            "subject": config.subject,
            "scope_count": len(scopes),
            "scopes": scopes,
            "scopes_csv": ",".join(scopes),
            "per_user_delegation": config.auth == "domain-delegation",
            "isolated_scopes": [scope for scope in scopes if scope in ISOLATED_GOOGLE_SCOPES],
            **_drive_domain_read_field(selected, config.auth, tuple(scopes)),
            "subject_scope": subject_scope_for_collectors(selected, per_user_delegation=config.auth == "domain-delegation"),
            "service_account": read_service_account_summary(config.service_account_key),
            "oauth_client_present": bool(config.oauth_client and config.oauth_client.expanduser().exists()),
            "token_cache_present": bool(config.token_cache and config.token_cache.expanduser().exists()),
        }
        # The console and MCP copies carry no customer id either (PRIV-CUSTOMER-ID).
        payload["target"] = {"domain": config.domain, "customer_id": bundle_customer_id(config.customer_id)}
        payload["selected_collectors"] = selected
        payload["live_readiness"] = build_google_live_readiness(
            selected,
            [],
            dependency_available=bool(dependency_status.get("available")),
        )
    return CustomerIds(config.customer_id).scrub(payload) if config is not None else payload


def _google_probe_summary_rows(selected: list[str], preflight_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows_by_collector: dict[str, list[dict[str, Any]]] = {}
    for row in preflight_rows:
        rows_by_collector.setdefault(str(row.get("collector") or ""), []).append(row)
    summary_rows: list[dict[str, Any]] = []
    for collector in selected:
        rows = rows_by_collector.get(collector, [])
        failures = [row for row in rows if row.get("status") != "ok"]
        item_count = sum(int(row.get("item_count") or 0) for row in rows)
        summary = {
            "name": collector,
            "status": "failed" if failures else "ok",
            "item_count": item_count,
            "message": "preflight ok" if not failures else "preflight blocked",
            "coverage_rows": len(rows),
        }
        if rows and not failures and all(row.get("live_read") is False for row in rows):
            # Only a readiness note, no lookup or Google request: the probe verified nothing for this collector.
            summary.update({
                "live_read": False,
                "reason": "dns_only_not_verified",
                "message": "DNS-only readiness; nothing was looked up or verified",
            })
        summary_rows.append(summary)
    return summary_rows


def _write_google_probe_bundle(
    *,
    writer: AuditWriter,
    config: GoogleRunConfig,
    selected: list[str],
    auth_config: GoogleAuthConfig,
    payload: dict[str, Any],
    dependency_status: dict[str, Any],
    command_line: list[str] | None,
) -> None:
    ids = CustomerIds(config.customer_id)
    preflight_rows = [dict(row) for row in payload.get("preflight", []) if isinstance(row, dict)]
    capability_rows = [dict(row) for row in payload.get("capability_matrix", []) if isinstance(row, dict)]
    if not capability_rows:
        capability_rows = build_google_capability_rows(
            selected,
            auth_mode=config.auth,
            dependency_status=dependency_status,
            coverage_rows=preflight_rows,
        )
        payload["capability_matrix"] = capability_rows
    live_readiness = payload.get("live_readiness")
    if not isinstance(live_readiness, dict):
        live_readiness = build_google_live_readiness(
            selected,
            capability_rows,
            dependency_available=bool(dependency_status.get("available")),
            coverage_rows=preflight_rows,
        )
        payload["live_readiness"] = live_readiness

    writer.log_event(
        "probe.started",
        "Google Workspace probe started",
        {"platform": "google_workspace", "domain": config.domain, "customer_id": bundle_customer_id(config.customer_id)},
    )
    for row in _google_probe_summary_rows(selected, preflight_rows):
        writer.write_summary(row)
    auth_context_path = writer.write_json_artifact("auth-context.json", ids.scrub(build_google_auth_context_payload(config, auth_config)))
    preflight_path = writer.write_json_artifact("preflight.json", preflight_rows)
    writer.write_index_records(preflight_rows)
    capability_path = writer.write_json_artifact("capability-matrix.json", capability_rows)
    toolchain_path = writer.write_json_artifact("toolchain-readiness.json", build_google_toolchain_readiness(dependency_status))
    live_readiness_path = writer.write_json_artifact("live-readiness.json", live_readiness)
    probe_result_path = writer.write_json_artifact("probe-result.json", payload)
    coverage_ledger = build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=writer.summary.get("collectors", []),
        diagnostics=[row for row in preflight_rows if row.get("status") != "ok"],
    )
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    writer.write_normalized(
        "snapshot",
        {
            "kind": "google_workspace_probe_snapshot",
            "tenant_name": config.tenant_name,
            "run_id": writer.run_id,
            "workspace_domain": config.domain,
            "customer_id": bundle_customer_id(config.customer_id),
            "collector_count": len(selected),
            "coverage_row_count": len(preflight_rows),
            "blocker_count": sum(1 for row in preflight_rows if row.get("status") != "ok"),
            "object_counts": {"preflight_rows": len(preflight_rows), "collectors": len(selected)},
            "normalized_counts": {"preflight_rows": len(preflight_rows), "collectors": len(selected)},
            "sample_truncated": False,
            "truncated_sections": [],
        },
    )
    blockers = [row for row in preflight_rows if row.get("status") != "ok"]
    if blockers:
        writer.write_diagnostics(blockers)
        writer.write_blockers(blockers)

    overall_status = "partial" if blockers or payload.get("preflight_error") or not dependency_status.get("available") else "ok"
    privacy = build_privacy_block(safe_for_external_llm=False)
    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        str(auth_context_path.relative_to(writer.run_dir)),
        str(preflight_path.relative_to(writer.run_dir)),
        str(capability_path.relative_to(writer.run_dir)),
        str(toolchain_path.relative_to(writer.run_dir)),
        str(live_readiness_path.relative_to(writer.run_dir)),
        str(probe_result_path.relative_to(writer.run_dir)),
        "normalized/capability_matrix.json",
        "normalized/coverage_ledger.json",
        "normalized/snapshot.json",
    ]
    if blockers:
        evidence_paths.append("blockers/blockers.json")
    evidence_index = {"artifacts": sorted(set(writer.artifact_paths() + ["run-manifest.json", "summary.json", "summary.md"]))}
    evidence_index_path = writer.write_json_artifact("evidence-index.json", evidence_index)
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=config.tenant_name,
            tenant_id=None,
            executed_by="auditex_google_probe",
            selected_collectors=selected,
            overall_status=overall_status,
            duration_seconds=0,
            mode=config.auth,
            auditor_profile="google-workspace",
            plane="inventory",
            findings=[],
            blockers=blockers,
            evidence_paths=evidence_paths,
            normalized_snapshot={
                "snapshot": {
                    "normalized_counts": {"preflight_rows": len(preflight_rows), "collectors": len(selected)},
                    "collector_count": len(selected),
                    "coverage_row_count": len(preflight_rows),
                    "blocker_count": len(blockers),
                    "sample_truncated": False,
                    "truncated_sections": [],
                }
            },
            capability_rows=capability_rows,
            coverage_ledger=coverage_ledger,
            privacy=privacy,
            bundle_metadata={
                "since": config.since,
                "until": config.until,
                "command_line": command_line or [],
                "probe_mode": config.auth,
                "probe_surface": config.collectors or config.collector_preset or "",
                "capability_matrix_path": str(capability_path.relative_to(writer.run_dir)),
                "toolchain_readiness_path": str(toolchain_path.relative_to(writer.run_dir)),
                "live_readiness_path": str(live_readiness_path.relative_to(writer.run_dir)),
                "preflight_path": str(preflight_path.relative_to(writer.run_dir)),
                "evidence_index_path": str(evidence_index_path.relative_to(writer.run_dir)),
                "auth_context_path": str(auth_context_path.relative_to(writer.run_dir)),
                "platform": "google_workspace",
                "workspace_domain": config.domain,
                "customer_id": bundle_customer_id(config.customer_id),
                "collector_preset": config.collector_preset,
                "top_limit": config.top,
            },
        ),
    )
    writer.log_event(
        "probe.completed",
        "Google Workspace probe completed",
        {"probe_mode": config.auth, "blockers": len(blockers)},
    )


def run_google_probe(config: GoogleRunConfig, *, command_line: list[str] | None = None) -> int:
    ids = CustomerIds(config.customer_id)
    if not _validate_google_labels(config.tenant_name, config.run_name, ids):
        return 2
    dependency_status = google_dependency_status()
    selected = _selected_collectors(config)
    payload = google_doctor(config)
    auth_config = _auth_config(config, selected)
    exit_code = 2
    if dependency_status["available"]:
        try:
            with collect_customer_ids(ids):
                credentials = build_google_credentials(auth_config)
                client = GoogleWorkspaceClient(
                    credentials,
                    customer_id=config.customer_id,
                    page_size=config.page_size,
                    delegated=auth_config.supports_user_delegation,
                    tenant_domain_read=tenant_domain_read_allowed(auth_config, credentials),
                )
                preflight_rows = build_google_preflight_rows(
                    client, selected, domain=config.domain, top=5 if config.top is None else max(1, min(config.top, 5)),
                )
            exit_code = 0 if all(row.get("status") == "ok" for row in preflight_rows) else 1
        except Exception as exc:  # noqa: BLE001
            with collect_customer_ids(ids):
                error_class, message = classify_google_error(exc)
            if isinstance(exc, OSError):
                message = exc.strerror or type(exc).__name__
            preflight_rows = [
                {
                    "collector": name,
                    "name": "probe",
                    "status": "failed",
                    "item_count": 0,
                    "duration_ms": 0,
                    "error_class": error_class,
                    "error": message,
                }
                for name in selected
            ]
            payload["preflight_error"] = {"error": "google_probe_failed", "message": message}
        payload["preflight"] = preflight_rows
        ids.learn(preflight_rows)
    payload["capability_matrix"] = build_google_capability_rows(
        selected,
        auth_mode=config.auth,
        dependency_status=dependency_status,
        coverage_rows=payload.get("preflight"),
    )
    payload["live_readiness"] = build_google_live_readiness(
        selected,
        payload["capability_matrix"],
        dependency_available=bool(dependency_status.get("available")),
        coverage_rows=payload.get("preflight"),
    )
    payload = ids.scrub(payload)
    config = _output_config(config, ids)
    writer = AuditWriter(config.out, tenant_name=config.tenant_name, run_name=config.run_name)
    _write_google_probe_bundle(
        writer=writer,
        config=config,
        selected=selected,
        auth_config=replace(auth_config, subject=ids.scrub(auth_config.subject)),
        payload=payload,
        dependency_status=ids.scrub(dependency_status),
        command_line=ids.scrub(scrub_google_command_line(command_line or [])),
    )
    print(json.dumps(payload, indent=2))
    return exit_code
