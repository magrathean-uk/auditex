from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Collection, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import auth_context
from . import run as run_core
from .ai_context import build_privacy_block
from .auth_runtime import (
    acquire_azure_cli_access_token as _acquire_azure_cli_access_token,
)
from .auth_runtime import (
    build_auth_context_payload as _build_auth_context_payload,
)
from .auth_runtime import (
    capture_signed_in_context as _capture_signed_in_context,
)
from .auth_runtime import (
    inspect_access_token as _inspect_access_token,
)
from .auth_runtime import (
    scrub_command_line as _scrub_command_line,
)
from .break_glass import load_accounts_argument as load_break_glass_accounts
from .capability_gate import relabel_intune_license_blockers
from .cli_guard import admit_sensitive_env, guarded_cli, parse_guarded
from .collection_gaps import NON_FATAL_COLLECTORS
from .collector_runner import (
    AuditWriterCollectorAdapter,
    CollectorRunContext,
    CollectorRunner,
    CollectorRunOptions,
    CollectorRunOutput,
)
from .collectors import REGISTRY
from .collectors.base import normalize_collection_limit
from .config import AuthConfig, CollectorConfig
from .data_handling import collector_activity_notices
from .data_minimisation import minimise_user_text
from .diagnostics import build_diagnostics as _build_diagnostics
from .diagnostics import load_permission_hints as _load_permission_hints
from .endpoint_posture import STALE_SYNC_DAYS_MAX
from .findings import build_findings
from .graph import GraphClient
from .guarded_io import current_context
from .normalize import (
    build_ai_safe_summary,
    build_normalization_diagnostics,
    build_normalized_snapshot,
)
from .offline_replay import (
    absent_section_rows,
    planned_sections,
    replay_collector_status,
    replay_coverage_rows,
    replay_source,
)
from .output import AuditWriter
from .partner_domains import PartnerDomains, PartnerDomainsError, load_partner_domains
from .presets import load_collector_presets
from .profiles import get_profile, profile_choices
from .provider_runtime import ProviderFinalizePlan, write_provider_bundle
from .resources import resolve_resource_path
from .rule_parameters import effective_rule_parameters
from .secret_hygiene import build_argument_parser
from .sensitive_users import SensitiveUsers, SensitiveUsersError, load_sensitive_users
from .utils import load_env_file
from .versioning import package_version_line
from .waivers import WaiverFileError, apply_waivers, load_waivers

LOG = logging.getLogger("azure_tenant_audit")

PLANE_CHOICES = ("inventory", "full", "export")
_OFFLINE_SAMPLE_METADATA_KEYS = frozenset({"_fixture_provenance"})


def _partial_workload_notice(collectors: Collection[str]) -> str | None:
    """Describe non-fatal gaps using only the fixed collector names, never diagnostic text."""
    names = sorted(NON_FATAL_COLLECTORS.intersection(collectors))
    if not names:
        return None
    return f"Partial: {', '.join(names)} did not finish; run status partial, exit 0; see diagnostics"


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
    return merged or None


def _offline_item_count(payload: Any) -> int:
    """Count records in a flat ``{"value": [...]}`` or nested ``{section: {"value": [...]}}`` sample payload."""
    if not isinstance(payload, dict):
        return 0
    if isinstance(payload.get("value"), list):
        return len(payload["value"])
    return sum(
        len(section["value"])
        for section in payload.values()
        if isinstance(section, dict) and isinstance(section.get("value"), list)
    )


def _stale_sync_days(value: str) -> int:
    """argparse type for ``--stale-sync-days``: a whole number of days from 1 to 3650."""
    try:
        days = int(value)
    except ValueError:
        days = 0
    if not 1 <= days <= STALE_SYNC_DAYS_MAX:
        raise argparse.ArgumentTypeError(f"must be a whole number of days from 1 to {STALE_SYNC_DAYS_MAX}")
    return days


_AS_OF_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
# Every date-derived check survives this window: the widest offset is a 3650-day stale-sync window back and one
# day forward, far from the datetime limits that 0001-01-01 and 9999-12-31 overflow.
AS_OF_EARLIEST = "1970-01-01"
AS_OF_LATEST = "2999-12-31"
AS_OF_HELP = (
    "Offline runs only: judge end of support, credential expiry, stale sync and the other date-derived checks "
    f"at 12:00 UTC on this date (YYYY-MM-DD, from {AS_OF_EARLIEST} to {AS_OF_LATEST}) instead of now. "
    "A live run refuses it."
)


def parse_as_of(value: str) -> datetime:
    """``--as-of YYYY-MM-DD`` as 12:00 UTC on that day; any other text or a date outside the window is a usage error."""
    try:
        if not _AS_OF_PATTERN.fullmatch(value) or not AS_OF_EARLIEST <= value <= AS_OF_LATEST:
            raise ValueError(value)
        day = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"--as-of needs a calendar date written YYYY-MM-DD, from {AS_OF_EARLIEST} to {AS_OF_LATEST}"
        ) from exc
    return day.replace(hour=12, tzinfo=UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = build_argument_parser(allow_abbrev=False, description="Run Microsoft tenant audit collection.")
    parser.add_argument("--version", action="version", version=package_version_line("azure-tenant-audit"))
    parser.add_argument("--tenant-name", default="tenant", help="Label for the output folder.")
    parser.add_argument("--tenant-id", default=None, help="Entra tenant ID.")
    parser.add_argument("--client-id", default=None, help="App registration ID.")
    parser.add_argument("--client-secret", default=None, help="App secret.")
    parser.add_argument("--access-token", default=None, help="Optional preissued Graph access token.")
    parser.add_argument("--auth-context", default=None, help="Optional saved Auditex auth context name.")
    parser.add_argument(
        "--use-azure-cli-token",
        action="store_true",
        help="Use an existing Azure CLI Graph token if available (no app credentials required).",
    )
    parser.add_argument("--authority", default="https://login.microsoftonline.com/", help="Identity authority URL.")
    parser.add_argument("--graph-scope", default="https://graph.microsoft.com/.default", help="Graph scope.")
    parser.add_argument("--interactive", action="store_true", help="Use delegated browser login.")
    parser.add_argument("--scopes", default=None, help="Comma-separated delegated Graph scopes for interactive login.")
    parser.add_argument("--browser-command", default="firefox", help="Browser command used by interactive auth.")
    parser.add_argument("--out", default="audit-output", help="Base output directory.")
    parser.add_argument("--config", default="configs/collector-definitions.json", help="Collector configuration file.")
    parser.add_argument(
        "--collector-preset",
        default=None,
        help="Optional named collector preset from configs/collector-presets.json.",
    )
    parser.add_argument(
        "--waiver-file",
        default=None,
        help="Optional JSON waiver file for accepted findings.",
    )
    parser.add_argument(
        "--break-glass-accounts",
        default=None,
        help=(
            "Emergency-access accounts for the Conditional Access exclusion check: comma-separated object IDs, "
            "user principal names or group names, or @file with one per line. List the group your policies exclude "
            "when the accounts are excluded through it. Without a list the accounts are inferred from names and the "
            "Global Administrator role (weaker evidence, rated medium at most). Also read from AUDITEX_BREAK_GLASS_ACCOUNTS."
        ),
    )
    parser.add_argument(
        "--stale-sync-days",
        type=_stale_sync_days,
        default=None,
        help=(
            "Days without an Intune check-in after which a managed device is stale (1 to 3650). Default 14, the Cyber "
            "Essentials window for installing updates. Also read from AUDITEX_STALE_SYNC_DAYS."
        ),
    )
    parser.add_argument("--collectors", default=None, help="Comma-separated collectors to run.")
    parser.add_argument("--exclude", default=None, help="Comma-separated collectors to skip.")
    parser.add_argument("--include-exchange", action="store_true", help="Enable optional exchange collectors.")
    parser.add_argument(
        "--top",
        type=int,
        default=None,
        help=(
            "Explicit per-list row limit for very large tenants. Without it, lists are paged to the last row "
            "except identity.users, which stops at 250,000 users with an explicit pagination_not_followed gap if more remain. "
            "A list cut by this limit is recorded as a coverage gap and the run is partial."
        ),
    )
    parser.add_argument("--page-size", type=int, default=100, help="Per-request page size for paged Graph endpoints.")
    parser.add_argument(
        "--throttle-mode",
        choices=("fast", "safe", "ultra-safe"),
        default="safe",
        help="Graph pacing mode used to reduce bursts and retry more carefully.",
    )
    parser.add_argument("--probe-first", dest="probe_first", action="store_true", default=False, help="Run a low-volume preflight; Exchange policy and DNS reads run once during collection.")
    parser.add_argument("--no-probe-first", dest="probe_first", action="store_false", help="Skip the low-volume preflight step.")
    parser.add_argument("--include-blocked", action="store_true", help="Run collectors even if preflight marks them as known blocked.")
    parser.add_argument("--run-name", default=None, help="Optional run subfolder identifier.")
    parser.add_argument(
        "--resume-from",
        default=None,
        help="Resume into an existing run directory and skip already completed collectors.",
    )
    parser.add_argument(
        "--plane",
        default="inventory",
        choices=PLANE_CHOICES,
        help="Run plane: inventory (default), full, or export. Full and export both run export collectors.",
    )
    parser.add_argument("--since", default=None, help="Optional ISO8601 lower bound for time-windowed collectors.")
    parser.add_argument("--until", default=None, help="Optional ISO8601 upper bound for time-windowed collectors.")
    parser.add_argument(
        "--auditor-profile",
        default="auto",
        choices=profile_choices(),
        help="Named audit profile for expected permission shape and escalation guidance.",
    )
    parser.add_argument("--offline", action="store_true", help="Use offline sample bundle.")
    parser.add_argument("--as-of", type=parse_as_of, default=None, metavar="YYYY-MM-DD", help=AS_OF_HELP)
    parser.add_argument("--sensitive-users", metavar="FILE", help="Local sensitive-user list (else AUDITEX_SENSITIVE_USERS_FILE); never uploaded or logged.")
    parser.add_argument("--partner-domains", metavar="FILE", help="Local partner-domain list (else AUDITEX_PARTNER_DOMAINS_FILE); never uploaded or logged.")
    parser.add_argument("--sample", default="examples/sample_audit_bundle/sample_result.json", help="Sample bundle path when offline.")
    parser.add_argument(
        "--permission-hints",
        default="configs/collector-permissions.json",
        help="Optional collector-permission matrix file for diagnostics.",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logs.")
    parser.add_argument("--env", default=None, help="Optional .env-like file to load.")
    return parser


def run_offline(
    sample_path: Path,
    out: Path,
    tenant_name: str,
    run_name: str | None,
    *,
    auditor_profile: str = "auto",
    plane: str = "inventory",
    since: str | None = None,
    until: str | None = None,
    fixture_provenance_override: dict[str, Any] | None = None,
    break_glass_accounts: Sequence[str] | None = None,
    stale_sync_days: int | None = None,
    as_of: datetime | None = None,
    sensitive_users: SensitiveUsers | None = None,
    partner_domains: PartnerDomains | None = None,
) -> int:
    """Replay an offline sample. ``as_of`` pins the instant that stale sync and operating-system end of life are judged at."""
    sensitive_users = sensitive_users if sensitive_users is not None else SensitiveUsers()
    partner_domains = partner_domains if partner_domains is not None else PartnerDomains()
    selected_sample = sample_path
    sample_path = resolve_resource_path(sample_path)
    try:
        from .resources import read_selected_resource
        sample_bytes = read_selected_resource(selected_sample, default="examples/sample_audit_bundle/sample_result.json", field="sample")
        sample = json.loads(sample_bytes.decode("utf-8"))
    except (ValueError, OSError):
        LOG.error("Unable to load sample bundle.")
        return 2
    writer = AuditWriter(out, tenant_name=tenant_name, run_name=run_name)
    try:
        sensitive_binding = writer.write_sensitive_users(sensitive_users)
        writer.write_partner_domains(partner_domains)
    except (SensitiveUsersError, PartnerDomainsError) as exc:
        LOG.error("%s", exc)
        return 2
    # The anti-phish target lists in the sample are summarised under this run's binding and dropped in memory, before
    # the replay copy and before any collector replays; nothing later reads the original sample object again.
    from .collectors.targeted_users_coverage import sanitise_sample, strip_targets
    sample = sanitise_sample(sample, sensitive_users, sensitive_binding)
    # Provenance is persisted separately in the manifest and report pack. Derive it only from the sanitised
    # sample, and give an explicit override the same boundary before it can bypass the replay-copy boundary.
    fixture_provenance = strip_targets(_merged_fixture_provenance(
        sample.get("_fixture_provenance") if isinstance(sample.get("_fixture_provenance"), dict) else None,
        fixture_provenance_override,
    ))
    writer.log_event(
        "run.started",
        "Offline run started",
        {
            "mode": "offline",
            "sample": str(sample_path),
            "auditor_profile": auditor_profile,
            "plane": plane,
            "since": since,
            "until": until,
        },
    )

    collector_payloads: dict[str, dict[str, Any]] = {}
    result_rows: list[dict[str, Any]] = []
    # A sample section that carries an error or a cut-list marker replays as the failed or partial read it was.
    coverage_rows: list[dict[str, Any]] = []
    # The replay input is copied into the bundle: mailbox text a live run would have dropped is dropped here too.
    from .private_io import write_private_text
    write_private_text(writer.raw_dir / "sample_input.json", json.dumps(minimise_user_text(sample), indent=2))
    writer.record_artifact(writer.raw_dir / "sample_input.json")
    for key, value in sample.items():
        if key in _OFFLINE_SAMPLE_METADATA_KEYS:
            continue
        if isinstance(value, dict):
            collector_payloads[str(key)] = value
        replayed = [
            *(replay_coverage_rows(str(key), value) if isinstance(value, dict) else []),
            # A collector that delivered none of its sections has no evidence: it replays as the failed read it is.
            *absent_section_rows(str(key), value, planned_sections(str(key))),
        ]
        coverage_rows.extend(replayed)
        row: dict[str, Any] = {
            "name": str(key),
            "status": replay_collector_status(replayed),
            "item_count": _offline_item_count(value),
            "message": (
                "offline simulation"
                if not replayed
                else f"offline simulation; {len(replayed)} section(s) recorded as failed, absent or cut short"
            ),
            "coverage_rows": len(replayed),
        }
        result_rows.append(row)
        writer.write_summary(row)
        writer.write_checkpoint(str(key), row)
        writer.log_event("collector.synthetic", "Offline collector simulated", {"name": key, "item_count": row["item_count"]})

    writer.write_index_records(coverage_rows)
    # The same blockers a live run would raise for those rows: the ledger, manifest gaps and gate read them.
    diagnostics: list[dict[str, Any]] = _build_diagnostics(
        result_rows=result_rows, coverage_rows=coverage_rows, permission_hints={}, auditor_profile=auditor_profile
    )
    capability_rows = [
        {
            "collector": row["name"],
            "status": "offline_sample",
            "reason": "offline_bundle",
            "required_permissions": [],
            "missing_permissions": [],
            "observed_permissions": [],
            "delegated_roles": [],
            "minimum_role_hints": [],
            "notes": "Offline sample run; no tenant auth exercised.",
        }
        for row in result_rows
    ]
    normalized_snapshot = build_normalized_snapshot(
        tenant_name=tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        run_dir=writer.run_dir,
        break_glass_accounts=break_glass_accounts,
        as_of=as_of,
    )
    diagnostics.extend(build_normalization_diagnostics(normalized_snapshot))
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
    coverage_ledger = run_core.build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    findings = build_findings(diagnostics, normalized_snapshot=normalized_snapshot, stale_sync_days=stale_sync_days, now=as_of)
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe("run_summary", build_ai_safe_summary(normalized_snapshot, findings=findings))
    if findings:
        writer.write_findings(findings)

    evidence_paths = [
        "run-manifest.json",
        "summary.json",
        "reports/report-pack.json",
        "index/evidence.sqlite",
        "ai_context.json",
        "validation.json",
        "ai_safe/run_summary.json",
    ]
    if coverage_rows:
        evidence_paths.append("coverage.json")
    if findings:
        evidence_paths.append("findings/findings.json")
    if diagnostics:
        evidence_paths.append("blockers/blockers.json")
    evidence_paths.extend(f"normalized/{name}.json" for name in ["capability_matrix", "coverage_ledger", *normalized_snapshot.keys()])
    privacy = build_privacy_block(safe_for_external_llm=False)
    exit_code = 1 if any(row.get("collector") not in NON_FATAL_COLLECTORS for row in diagnostics) else 0
    partial_notice = _partial_workload_notice([row.get("collector") for row in diagnostics]) if not exit_code else None
    if partial_notice:
        writer.summary["partial_workload_notice"] = partial_notice
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=tenant_name,
            tenant_id=None,
            executed_by="azure_tenant_audit",
            selected_collectors=[row["name"] for row in result_rows],
            overall_status="partial" if diagnostics else "ok",
            duration_seconds=0,
            mode="offline",
            auditor_profile=auditor_profile,
            plane=plane,
            findings=findings,
            blockers=diagnostics,
            evidence_paths=evidence_paths,
            normalized_snapshot=normalized_snapshot,
            capability_rows=capability_rows,
            coverage_ledger=coverage_ledger,
            privacy=privacy,
            bundle_metadata={
                "fixture_provenance": fixture_provenance,
                "since": since,
                "until": until,
                "command_line": [],
                "coverage_count": len(coverage_rows),
                "platform": "m365",
                "rule_parameters": effective_rule_parameters(
                    stale_sync_days=stale_sync_days, break_glass_accounts=break_glass_accounts
                ),
                "replay_source": replay_source(sample_path, data=sample_bytes),
            },
            as_of=as_of,
        ),
    )
    LOG.info("Offline sample written to %s", writer.run_dir)
    if partial_notice:
        print(partial_notice, file=sys.stderr)
    return exit_code


# A collector the preflight probe skipped as known blocked is not a collector that finished: it is recorded
# with this error class so that a resumed run re-probes it instead of treating it as complete.
_PREFLIGHT_BLOCKED = "preflight_blocked"
_PREFLIGHT_SKIP_MESSAGE = "Collector skipped after preflight marked it as known blocked."


def _is_preflight_skip(state: dict[str, Any]) -> bool:
    return state.get("error_class") == _PREFLIGHT_BLOCKED or state.get("message") == _PREFLIGHT_SKIP_MESSAGE


def _window_changed(state: dict[str, Any], since: str | None, until: str | None) -> bool:
    """Whether a checkpoint was read over another time window than this session's.

    A checkpoint written before windows were recorded has no ``since`` or ``until`` key: its window is unknown,
    which only a session with no window of its own can accept.
    """
    if "since" not in state and "until" not in state:
        return bool(since or until)
    return (state.get("since") or None) != (since or None) or (state.get("until") or None) != (until or None)


def _resume_carried_collectors(
    writer: AuditWriter,
    checkpoint_state: dict[str, dict[str, Any]],
    *,
    windowed: Collection[str] = (),
    since: str | None = None,
    until: str | None = None,
) -> dict[str, dict[str, Any]]:
    """The checkpointed collectors a resumed run keeps as they were: ``{name: raw payload}``.

    Only a collector that finished is carried forward. That is ``ok`` (with its raw payload still on disk),
    or ``skipped`` because the tenant cannot have the data (a licence or capability skip, which carries no
    payload). A ``partial`` or ``failed`` collector, a collector the preflight skipped as blocked, and an
    ``ok`` collector whose raw payload is gone are all re-run: carrying them forward as finished would let
    the resumed run read ``ok`` over evidence that was never complete. A ``windowed`` collector (one that reads
    events between ``since`` and ``until``) that was read over another window is re-run too: the bundle records
    one time window, so carried evidence from a different one would be mislabelled.
    """
    carried: dict[str, dict[str, Any]] = {}
    for name, state in checkpoint_state.items():
        if name in windowed and _window_changed(state, since, until):
            continue
        status = state.get("status")
        if status == "ok":
            payload = writer._safe_load_json(writer.raw_dir / f"{name}.json")
            if isinstance(payload, dict):
                carried[name] = payload
        elif status == "skipped" and not _is_preflight_skip(state):
            carried[name] = {}
    return carried


def _resume_exchange_binding(
    carried: dict[str, dict[str, Any]],
    selected: Collection[str],
    *,
    sensitive_users: SensitiveUsers,
    binding: Any,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Carry ``exchange_policy`` forward only while its SS 2.1 summaries stand for this session's operator input.

    The old raw summaries are compared with the binding the writer just returned for the current canonical tuple
    under the run's retained key (so case, order, duplicates and ``name;email`` forms that normalise alike still
    match). A changed, cleared or newly supplied list, a missing, unknown or mismatched summary, or stale literal
    targets end the carry: the collector re-runs when this session selected it. If it cannot re-run, the rest of its
    evidence is kept in memory with every anti-phish summary ``not_collected``, so it proves no membership. The
    stored raw file and its HMAC are never rewritten or rebound, and no replacement key is ever made.

    Returns ``(carried, retained)``. ``retained`` holds that same minimised copy for a collector that re-runs (empty
    otherwise): the re-run is staged and publishes it for every operation it cannot replace (see _publish_staged_rerun).
    """
    from .collectors.targeted_users_coverage import COLLECTOR, resume_payload

    if COLLECTOR not in carried:
        return carried, {}
    payload, reusable = resume_payload(carried[COLLECTOR], sensitive_users, binding)
    carried = dict(carried)
    if not reusable and COLLECTOR in selected and COLLECTOR in REGISTRY:
        del carried[COLLECTOR]
        return carried, {COLLECTOR: payload}
    carried[COLLECTOR] = payload
    return carried, {}


# The markers a projection refuses an operation section for (auditex.scuba_projection), plus a non-ok ``status``.
_UNHEALTHY_SECTION_KEYS = (
    "error", "error_class", "collection_truncated", "bounded_sample", "@odata.nextLink", "truncation_reason",
    "incomplete", "partial",
)


def _healthy_section(section: Any) -> bool:
    """Whether an operation envelope is a complete, error-free read."""
    return (
        isinstance(section, dict)
        and not any(section.get(key) for key in _UNHEALTHY_SECTION_KEYS)
        and section.get("status", "ok") in {"ok", "success", "collected"}
    )


def _publish_staged_rerun(output: CollectorRunOutput, retained: dict[str, Any]) -> dict[str, Any]:
    """The raw payload a binding-invalidated re-run publishes, given the earlier session's minimised copy.

    A re-run that finished ``ok`` replaces the earlier evidence outright. Any other outcome (a crash, failed or partial
    operations) is not a replacement: each healthy operation it did read replaces its earlier copy, the earlier
    minimised copy is kept for every operation it could not read cleanly (anti-phish membership ``not_collected``, no
    target literal, the old proof neither kept nor rebound), and its own failure envelope or crash marker is kept
    where nothing healthy is retained. The re-run's status, checkpoint and coverage rows are left as they are, so a
    retained section sits under failed coverage and is never admitted as a fresh read.
    """
    fresh = output.result.payload if isinstance(output.result.payload, dict) else {}
    if output.result.status == "ok" and not output.crashed:
        return fresh
    published = dict(retained)
    for key, section in fresh.items():
        if key not in published or _healthy_section(section) or not _healthy_section(published[key]):
            published[key] = section
    return published


def _collector_extra(
    name: str, collector_payloads: dict[str, dict[str, Any]], sensitive_users: SensitiveUsers, binding: Any,
) -> dict[str, Any]:
    """Run-scoped private context: accepted domains for ``dns_posture``; SensitiveUsers and its opaque writer binding
    for ``exchange_policy`` only (never the key, a session, an event or a checkpoint)."""
    if name == "dns_posture":
        return {"exchange_accepted_domains": collector_payloads.get("exchange_policy", {}).get("acceptedDomains")}
    if name == "exchange_policy":
        from .collectors.targeted_users_coverage import CONTEXT_BINDING, CONTEXT_USERS
        return {CONTEXT_USERS: sensitive_users, CONTEXT_BINDING: binding}
    return {}


def _resumed_row(name: str, state: dict[str, Any], coverage_rows: list[dict[str, Any]]) -> dict[str, object]:
    """The result row of a collector carried over from the checkpoint, with the status it finished with."""
    previous_message = str(state.get("message") or "").strip()
    return {
        "name": name,
        "status": str(state.get("status")),
        "item_count": state.get("item_count") or 0,
        "message": f"Resumed from checkpoint ({state.get('status')})" + (f": {previous_message}" if previous_message else ""),
        "error": state.get("error"),
        "error_class": state.get("error_class"),
        "coverage_rows": sum(1 for row in coverage_rows if row.get("collector") == name),
    }


def run_live(
    args: argparse.Namespace, event_listener: Callable[[dict[str, Any]], None] | None = None,
    *, sensitive_users: SensitiveUsers | None = None, partner_domains: PartnerDomains | None = None,
) -> int:
    try:
        sensitive_users = sensitive_users if sensitive_users is not None else load_sensitive_users(getattr(args, "sensitive_users", None))
        partner_domains = partner_domains if partner_domains is not None else load_partner_domains(getattr(args, "partner_domains", None))
    except (SensitiveUsersError, PartnerDomainsError) as exc:
        LOG.error("%s", exc)
        return 2
    # Read the waiver file once, before any tenant call. A file that cannot be trusted must not
    # let the run finish with no waivers applied (or the wrong ones), and the rows loaded here
    # are the ones applied later, so a file edited mid-run cannot fail the run after collection.
    try:
        waiver_rows = load_waivers(Path(args.waiver_file)) if getattr(args, "waiver_file", None) else []
    except WaiverFileError as exc:
        LOG.error("%s", exc)
        return 2
    try:
        break_glass_list = load_break_glass_accounts(getattr(args, "break_glass_accounts", None))
    except (OSError, UnicodeError) as exc:
        LOG.error("Unable to read the break-glass accounts file: %s", exc)
        return 2
    out = Path(args.out).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)

    saved_auth_context: dict[str, Any] | None = None
    if args.auth_context:
        saved_auth_context = auth_context.resolve_auth_context(args.auth_context)
        args.access_token = args.access_token or saved_auth_context.get("token")
        args.tenant_id = args.tenant_id or saved_auth_context.get("tenant_id")

    try:
        config = CollectorConfig.from_path(Path(args.config))
        permission_hints = _load_permission_hints(Path(args.permission_hints))
        plan = run_core.build_live_run_plan(
            args,
            output_dir=out,
            collector_config=config,
            permission_hints=permission_hints,
            profile=get_profile(args.auditor_profile),
            collector_presets=load_collector_presets(),
        )
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    run_cfg = plan.run_config
    selected = plan.selected_collectors
    for notice in [*plan.selection_notices, *collector_activity_notices(selected, "live")]:
        LOG.info("%s", notice)
    if NON_FATAL_COLLECTORS.intersection(selected):
        LOG.info("Exchange/DNS failures leave overall status partial, process exit 0 when these are the only failures; "
                 "coverage gates reject partial runs unless --allow-partial is supplied.")
    execution_plane = plan.execution_plane
    auth_scopes = plan.auth_scopes

    resume_from = Path(args.resume_from).expanduser().resolve() if args.resume_from else None
    writer = AuditWriter(
        run_cfg.output_dir,
        run_cfg.tenant_name,
        run_name=run_cfg.run_name,
        run_dir=resume_from,
        event_listener=event_listener,
    )
    completed_state = writer.load_checkpoint_state() if resume_from else {}
    try:
        sensitive_binding = writer.write_sensitive_users(sensitive_users)
        writer.write_partner_domains(partner_domains)
    except (SensitiveUsersError, PartnerDomainsError) as exc:
        LOG.error("%s", exc)
        return 2
    collector_checkpoint_state = writer.load_collector_checkpoint_state() if resume_from else {}
    operation_checkpoint_state = writer.load_operation_checkpoint_state() if resume_from else {}
    # Collectors that finished are carried forward with the status they finished with; every other
    # checkpointed collector is re-run (see _resume_carried_collectors).
    windowed_collectors = {name for name, collector in REGISTRY.items() if getattr(collector, "time_windowed", False)}
    carried_payloads = (
        _resume_carried_collectors(
            writer,
            collector_checkpoint_state,
            windowed=windowed_collectors,
            since=run_cfg.since,
            until=run_cfg.until,
        )
        if resume_from
        else {}
    )
    # A collector that must re-run because its carried evidence no longer stands: {name: earlier minimised payload}.
    retained_payloads: dict[str, dict[str, Any]] = {}
    if resume_from:
        # After this session's operator input is written: SS 2.1 summaries are carried only under the same binding.
        carried_payloads, retained_payloads = _resume_exchange_binding(
            carried_payloads, selected, sensitive_users=sensitive_users, binding=sensitive_binding,
        )
    completed_collectors = set(carried_payloads)
    if resume_from:
        # Every collector that finished in an earlier session is part of this run's evidence, whatever this session
        # selected: the run folder holds its raw data, and dropping it would leave the report, the findings and the
        # normalized sections describing half a bundle (or leave the earlier session's behind).
        selected = [*selected, *(name for name in carried_payloads if name not in selected and name in REGISTRY)]
    if resume_from:
        writer.log_event(
            "run.resume",
            "Resuming from existing run state",
            {
                "resume_from": str(resume_from),
                "checkpoint_entries": len(completed_state.get("collectors", {})),
                "completed_collectors": sorted(completed_collectors),
                "rerun_collectors": sorted(
                    name for name in collector_checkpoint_state if name not in completed_collectors
                ),
            },
        )

    if args.use_azure_cli_token:
        if not args.access_token:
            try:
                args.access_token = _acquire_azure_cli_access_token(args.tenant_id, log_event=writer.log_event)
                writer.log_event(
                    "auth.cli.token.selected",
                    "Using Azure CLI cached token for Graph authentication.",
                    {"tenant_id": args.tenant_id or "organizations"},
                )
                LOG.info("Using Azure CLI cached Graph token.")
            except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                writer.log_event(
                    "auth.cli.token.rejected",
                    "Azure CLI token could not be used.",
                    {"tenant_id": args.tenant_id or "organizations", "error": str(exc)},
                )
                LOG.error("Unable to use Azure CLI token: %s", exc)
                return 2

    has_token_source = bool(args.access_token or args.use_azure_cli_token)
    if args.interactive and not args.client_id and not has_token_source:
        LOG.warning(
            "Interactive mode requested without --client-id. Falling back to Azure CLI token mode. "
            "Run `az login` first; this avoids creating an app registration."
        )
        args.interactive = False
        args.use_azure_cli_token = True
        has_token_source = True
    if not args.interactive and not has_token_source:
        if not args.client_id:
            LOG.error("client-id is required for app authentication.")
            return 2
        if not args.client_secret:
            LOG.error("client-id and client-secret are required for app auth. Use --interactive or --use-azure-cli-token.")
            return 2
        if not args.tenant_id:
            LOG.error("tenant-id is required for app authentication.")
            return 2
    if args.interactive and not args.tenant_id:
        args.tenant_id = "organizations"

    tenant_id = args.tenant_id or "organizations"

    auth_mode = "interactive" if args.interactive else "azure_cli" if args.use_azure_cli_token else "access_token" if args.access_token else "app"

    auth = AuthConfig(
        tenant_id=tenant_id,
        client_id=args.client_id,
        auth_mode=auth_mode,
        client_secret=args.client_secret,
        access_token=args.access_token,
        authority=args.authority,
        graph_scope=args.graph_scope,
        interactive_scopes=auth_scopes,
        throttle_mode=args.throttle_mode,
    )
    client = GraphClient(auth, audit_event=writer.log_event)
    session_context: dict[str, Any] = {}
    if auth_mode in {"azure_cli", "interactive"}:
        session_context = _capture_signed_in_context(client, log_event=writer.log_event)
    token_claims: dict[str, Any] = {}
    if args.access_token:
        try:
            token_claims = _inspect_access_token(args.access_token)
        except Exception as exc:  # noqa: BLE001
            writer.log_event(
                "auth.token.inspect_failed",
                "Access token could not be decoded locally.",
                {"error": str(exc)},
            )
            token_claims = {}
    elif hasattr(client, "token_claims"):
        token_claims = client.token_claims()
    auth_context_payload = _build_auth_context_payload(
        auth_mode=auth_mode,
        tenant_id=tenant_id,
        token_claims=token_claims,
        session_context=session_context,
        saved_context=saved_auth_context,
    )
    capability_rows = run_core.build_capability_matrix_rows(
        auth_context=auth_context_payload,
        selected_collectors=selected,
        auditor_profile=run_cfg.auditor_profile,
        collector_config=config,
        permission_hints=permission_hints,
    )
    selected_before_preflight = list(selected)
    preflight_rows: list[dict[str, Any]] = []
    preflight_path: str | None = None
    if args.probe_first:
        selected, preflight_rows, preflight_path = run_core.run_preflight_probe(
            selected_collectors=selected_before_preflight,
            completed_collectors=completed_collectors,
            client=client,
            run_cfg=run_cfg,
            writer=writer,
            include_blocked=args.include_blocked,
            registry=REGISTRY,
        )
        if not selected and set(selected_before_preflight).difference(NON_FATAL_COLLECTORS):
            writer.log_event(
                "run.aborted",
                "No runnable collectors remained after preflight.",
                {"preflight_path": preflight_path},
            )
            writer.write_bundle(
                {
                    "executed_by": "azure_tenant_audit",
                    "collectors": [],
                    "overall_status": "partial",
                    "duration_seconds": 0,
                    "mode": auth_mode,
                    "auditor_profile": run_cfg.auditor_profile,
                    "plane": run_cfg.plane,
                    "since": run_cfg.since,
                    "until": run_cfg.until,
                    "session_context": session_context,
                    "command_line": _scrub_command_line(list(getattr(args, "_command_line", sys.argv))),
                    "coverage_count": 0,
                    "throttle_mode": args.throttle_mode,
                    "preflight_path": preflight_path,
                }
            )
            return 1
    command_line = _scrub_command_line(list(getattr(args, "_command_line", sys.argv)))
    writer.log_event(
        "run.started",
        "Live run started",
        {
            "tenant_id": args.tenant_id,
            "collectors": selected,
            "top": run_cfg.top_items,
            "page_size": run_cfg.page_size,
            "include_exchange": args.include_exchange,
            "mode": auth_mode,
            "auditor_profile": run_cfg.auditor_profile,
            "plane": run_cfg.plane,
            "since": run_cfg.since,
            "until": run_cfg.until,
            "session_context": session_context,
            "auth_context": auth_context_payload,
            "command_line": command_line,
            "throttle_mode": args.throttle_mode,
            "preflight_path": preflight_path,
        },
    )
    start = time.time()
    result_rows: list[dict[str, object]] = []
    failures = 0
    required_failures = 0
    incomplete_collectors: set[str] = set()
    summary_rows: list[dict[str, object]] = []
    coverage_rows: list[dict[str, Any]] = list(writer.coverage) if resume_from else []
    collector_payloads: dict[str, dict[str, Any]] = {}
    preflight_skipped = {
        row["collector"]: row
        for row in preflight_rows
        if row.get("decision") == "skip" and row.get("collector")
    }
    collector_pause_seconds = run_core.collector_pause_seconds(args.throttle_mode)
    writer_adapter = AuditWriterCollectorAdapter(writer)
    collector_runner = CollectorRunner(writer_adapter)

    for name, skip in preflight_skipped.items():
        skip_row: dict[str, object] = {
            "name": name,
            "status": "skipped",
            "item_count": 0,
            "message": _PREFLIGHT_SKIP_MESSAGE,
            "error": skip.get("error"),
            "error_class": _PREFLIGHT_BLOCKED,
            # What the preflight read: the error class of the first read that failed (a 403 is ``insufficient_permissions``).
            "cause_error_class": skip.get("cause_error_class"),
            "coverage_rows": 0,
        }
        result_rows.append(skip_row)
        summary_rows.append(skip_row)
        writer.write_checkpoint(name, skip_row)
        writer.log_event(
            "collector.skipped",
            "Collector skipped after preflight",
            {
                "collector": name,
                "reason": skip.get("reason"),
            },
        )

    for name in run_core.collector_execution_order(selected):
        collector = REGISTRY.get(name)
        if collector is None:
            LOG.warning("Unknown collector requested: %s", name)
            continue

        if resume_from and name in completed_collectors:
            previous_state = collector_checkpoint_state.get(name, {})
            # The collector finished in the earlier session: keep its status, error and coverage rows. Marking
            # it ``skipped`` here would read as "not applicable" in the ledger and hide a gap the checkpoint holds.
            carried_row = _resumed_row(name, previous_state, coverage_rows)
            result_rows.append(carried_row)
            if not any(
                isinstance(item, dict) and item.get("name") == name for item in writer.summary.get("collectors", [])
            ):
                # An interrupted session never wrote summary.json: the carried collector is added to this one.
                summary_rows.append(carried_row)
            if previous_state.get("status") == "ok":
                collector_payloads[name] = carried_payloads[name]
            writer.log_event(
                "collector.resumed",
                "Collector carried forward from the checkpoint",
                {
                    "collector": name,
                    "resume_from": str(resume_from),
                    "previous_status": previous_state.get("status"),
                    "item_count": previous_state.get("item_count", 0),
                },
            )
            continue

        if resume_from and name in collector_checkpoint_state:
            # Re-run: this observation replaces the earlier partial or failed one everywhere it was recorded.
            writer.summary["collectors"] = [
                row for row in writer.summary.get("collectors", []) if not (isinstance(row, dict) and row.get("name") == name)
            ]
            writer.coverage = [row for row in writer.coverage if row.get("collector") != name]
            coverage_rows = [row for row in coverage_rows if row.get("collector") != name]

        staged = name in retained_payloads
        output = collector_runner.run(
            collector,
            CollectorRunContext(
                client=client,
                top=run_cfg.top_items,
                page_size=run_cfg.page_size,
                plane=execution_plane,
                since=run_cfg.since,
                until=run_cfg.until,
                collector_checkpoint_state=collector_checkpoint_state.get(name, {}),
                operation_checkpoint_state=operation_checkpoint_state.get(name, {}),
                hooks=writer_adapter.hooks(),
                # Only completed evidence from this run (including a validated resume),
                # never another tenant read or an arbitrary raw artefact from disk.
                extra=_collector_extra(name, collector_payloads, sensitive_users, sensitive_binding),
            ),
            name=name,
            # A staged re-run writes no raw file or checkpoint of its own: its raw evidence is published below once
            # it is known whether it replaced the earlier session's, and the checkpoint is written after it.
            options=CollectorRunOptions(write_raw=False, write_checkpoint=False) if staged else None,
        )
        coverage_rows.extend(output.coverage_rows)
        payload = output.result.payload
        if staged:
            payload = _publish_staged_rerun(output, retained_payloads[name])
            writer_adapter.write_raw(name, payload)
        # The window this collector was read over, so a resume under another window re-runs it (see _window_changed).
        writer.write_checkpoint(name, {**output.result_row, "since": run_cfg.since, "until": run_cfg.until})
        if output.result.status != "ok":
            failures += 1
            incomplete_collectors.add(name)
            if name not in NON_FATAL_COLLECTORS:
                required_failures += 1
        if output.result.error:
            LOG.warning("%s collector error: %s", name, output.result.error)
        collector_payloads[name] = payload
        result_rows.append(dict(output.result_row))
        summary_rows.append(result_rows[-1])

        if collector_pause_seconds > 0:
            writer.log_event(
                "run.collector.pause",
                "Pausing before next collector",
                {"collector": name, "delay_seconds": collector_pause_seconds},
            )
            time.sleep(collector_pause_seconds)

    duration = round(time.time() - start, 2)
    # A collector that was checkpointed incomplete and is not part of this session keeps the run partial:
    # its gap is in the bundle's coverage rows and summary, so the headline status must not read ok over it.
    selected_names = set(selected)
    # A checkpointed collector that is not part of this session is carried when it finished; any other is a gap: partial,
    # failed, skipped by the preflight, an ``ok`` whose raw payload is gone, or one read over another time window.
    resumed_incomplete = sorted(
        name for name in collector_checkpoint_state if name not in selected_names and name not in carried_payloads
    )
    if resumed_incomplete:
        writer.log_event(
            "run.resume.incomplete",
            "Earlier collectors outside this session did not finish",
            {"collectors": resumed_incomplete},
        )
    for row in summary_rows:
        writer.write_summary(row)
    # Intune Forbidden means "missing scope" or "no licence"; use subscribedSkus to tell them apart.
    coverage_rows = relabel_intune_license_blockers(coverage_rows, collector_payloads)
    diagnostics = _build_diagnostics(
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        permission_hints=permission_hints,
        auditor_profile=run_cfg.auditor_profile,
    )
    capability_rows = run_core.reconcile_capability_matrix_rows(
        capability_rows,
        result_rows,
        coverage_rows=coverage_rows,
        collector_payloads=collector_payloads,
    )
    normalized_snapshot = build_normalized_snapshot(
        tenant_name=run_cfg.tenant_name,
        run_id=writer.run_id,
        collector_payloads=collector_payloads,
        diagnostics=diagnostics,
        result_rows=result_rows,
        coverage_rows=coverage_rows,
        run_dir=writer.run_dir,
        break_glass_accounts=break_glass_list,
    )
    normalization_diagnostics = build_normalization_diagnostics(normalized_snapshot)
    diagnostics.extend(normalization_diagnostics)
    # A resumed run rewrites diagnostics, blockers and findings whatever this session found: a collector that succeeded
    # this time must not keep the blocker an earlier session wrote. With nothing left to report the files are removed,
    # as a fresh run that has nothing to report never writes them.
    if diagnostics:
        writer.write_diagnostics(diagnostics)
        writer.write_blockers(diagnostics)
    elif resume_from:
        writer.clear_result_file("diagnostics.json", "diagnostics_path", "diagnostics_count")
        writer.clear_result_file("blockers/blockers.json", "blockers_path", "blocker_count")
    if diagnostics:
        writer.log_event(
            "run.diagnostics.generated",
            "Failure diagnostics generated",
            {"count": len(diagnostics)},
        )
    coverage_ledger = run_core.build_coverage_ledger(
        capability_rows=capability_rows,
        result_rows=result_rows,
        diagnostics=diagnostics,
    )
    # Waivers are the last step build_findings would take; applying the rows read at the start of
    # the run keeps the file from being read a second time after the tenant calls.
    findings = build_findings(
        diagnostics, normalized_snapshot=normalized_snapshot, stale_sync_days=getattr(args, "stale_sync_days", None)
    )
    if waiver_rows:
        findings = apply_waivers(findings, waiver_rows)
    if resume_from:
        # Sections an earlier session normalized and this one did not (a collector that was dropped, a section that
        # no longer has rows) would describe evidence this run no longer holds.
        writer.prune_normalized({"auth_context", "capability_matrix", "coverage_ledger", *normalized_snapshot})
    writer.write_normalized("auth_context", auth_context_payload)
    writer.write_normalized("capability_matrix", {"kind": "capability_matrix", "records": capability_rows})
    writer.write_normalized("coverage_ledger", {"kind": "coverage_ledger", "records": coverage_ledger})
    if findings:
        writer.write_findings(findings)
    elif resume_from:
        writer.clear_result_file("findings/findings.json", "findings_path", "findings_count")
    for name, payload in normalized_snapshot.items():
        writer.write_normalized(name, payload)
    writer.write_ai_safe("run_summary", build_ai_safe_summary(normalized_snapshot, findings=findings))
    evidence_paths = ["run-manifest.json", "summary.json"]
    if coverage_rows:
        evidence_paths.append("coverage.json")
    if diagnostics:
        evidence_paths.append("blockers/blockers.json")
    if findings:
        evidence_paths.append("findings/findings.json")
    evidence_paths.extend(f"normalized/{name}.json" for name in normalized_snapshot)
    evidence_paths.extend(["ai_context.json", "validation.json"])
    overall_status = (
        "partial" if failures or preflight_skipped or resumed_incomplete or normalization_diagnostics else "ok"
    )
    # Optional Exchange/DNS gaps remain partial and visible to gates, but do not fail collection.
    required_gaps = (
        required_failures
        or set(preflight_skipped).difference(NON_FATAL_COLLECTORS)
        or set(resumed_incomplete).difference(NON_FATAL_COLLECTORS)
        or any(row.get("collector") not in NON_FATAL_COLLECTORS for row in normalization_diagnostics)
    )
    exit_code = 1 if required_gaps else 0
    incomplete_collectors.update(preflight_skipped, resumed_incomplete)
    incomplete_collectors.update(row["collector"] for row in normalization_diagnostics)
    partial_notice = _partial_workload_notice(incomplete_collectors) if overall_status == "partial" and not exit_code else None
    if partial_notice:
        writer.summary["partial_workload_notice"] = partial_notice
    privacy = build_privacy_block(safe_for_external_llm=False)
    writer.log_event(
        "run.complete",
        "Live run completed",
        {"failures": failures, "collectors": len(result_rows), "coverage_rows": len(coverage_rows)},
    )
    write_provider_bundle(
        writer=writer,
        plan=ProviderFinalizePlan(
            tenant_name=run_cfg.tenant_name,
            tenant_id=args.tenant_id,
            executed_by="azure_tenant_audit",
            selected_collectors=selected,
            overall_status=overall_status,
            duration_seconds=duration,
            mode=auth_mode,
            auditor_profile=run_cfg.auditor_profile,
            plane=run_cfg.plane,
            findings=findings,
            blockers=diagnostics,
            evidence_paths=evidence_paths,
            normalized_snapshot=normalized_snapshot,
            capability_rows=capability_rows,
            coverage_ledger=coverage_ledger,
            privacy=privacy,
            trust_selected_collectors=selected_before_preflight,
            bundle_metadata={
                "collector_preset": args.collector_preset,
                "waiver_path": args.waiver_file,
                "since": run_cfg.since,
                "until": run_cfg.until,
                "session_context": session_context,
                "auth_context_path": "normalized/auth_context.json",
                "capability_matrix_path": "normalized/capability_matrix.json",
                "coverage_ledger_path": "normalized/coverage_ledger.json",
                "command_line": command_line,
                "coverage_count": len(coverage_rows),
                "throttle_mode": args.throttle_mode,
                "preflight_path": preflight_path,
                "top_limit": normalize_collection_limit(run_cfg.top_items, default=None),
                "platform": "m365",
                "rule_parameters": effective_rule_parameters(
                    stale_sync_days=getattr(args, "stale_sync_days", None), break_glass_accounts=break_glass_list
                ),
            },
        ),
    )
    LOG.info("Completed in %.2fs. Output in %s", duration, writer.run_dir)
    if partial_notice:
        print(partial_notice, file=sys.stderr)
    return exit_code


@guarded_cli
def main(
    argv: list[str] | None = None, event_listener: Callable[[dict[str, Any]], None] | None = None,
    *, sensitive_users: SensitiveUsers | None = None, partner_domains: PartnerDomains | None = None,
) -> int:
    parser = build_parser()
    parsed_argv = list(argv if argv is not None else sys.argv[1:])
    args = parse_guarded(parser, parsed_argv)
    args._command_line = ["azure-tenant-audit", *parsed_argv]
    if args.as_of is not None and not args.offline:
        parser.error_prevalidated("--as-of applies only to offline runs (--offline)")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    if args.env:
        load_env_file(Path(args.env), guarded=True)

    if sensitive_users is None:
        admit_sensitive_env(current_context(), args.sensitive_users)

    try:
        sensitive_users = sensitive_users if sensitive_users is not None else load_sensitive_users(args.sensitive_users)
        partner_domains = partner_domains if partner_domains is not None else load_partner_domains(args.partner_domains)
    except (SensitiveUsersError, PartnerDomainsError) as exc:
        parser.error_prevalidated(str(exc))

    args.tenant_id = args.tenant_id or None
    args.client_id = args.client_id or None
    args.client_secret = args.client_secret or None
    args.access_token = args.access_token or None

    if args.tenant_id is None:
        args.tenant_id = __import__("os").environ.get("AZURE_TENANT_ID")
    if args.client_id is None:
        args.client_id = __import__("os").environ.get("AZURE_CLIENT_ID")
    if args.client_secret is None:
        args.client_secret = __import__("os").environ.get("AZURE_CLIENT_SECRET")
    if args.access_token is None and __import__("os").environ.get("AZURE_ACCESS_TOKEN") is not None:
        LOG.warning(
            "Ignoring AZURE_ACCESS_TOKEN environment variable. "
            "Pass --access-token explicitly or use a saved auth context."
        )
    if args.authority is None:
        args.authority = __import__("os").environ.get("AZURE_AUTHORITY", args.authority)
    if args.graph_scope is None:
        args.graph_scope = __import__("os").environ.get("AZURE_GRAPH_SCOPE", args.graph_scope)
    if args.interactive and args.browser_command:
        os.environ["BROWSER"] = args.browser_command
    if args.scopes:
        args.scopes = args.scopes.strip()
    if args.offline:
        try:
            offline_break_glass = load_break_glass_accounts(args.break_glass_accounts)
        except (OSError, UnicodeError) as exc:
            LOG.error("Unable to read the break-glass accounts file: %s", exc)
            return 2
        return run_offline(
            Path(args.sample),
            Path(args.out),
            args.tenant_name,
            args.run_name,
            auditor_profile=args.auditor_profile,
            plane=args.plane,
            since=args.since,
            until=args.until,
            break_glass_accounts=offline_break_glass,
            stale_sync_days=args.stale_sync_days,
            as_of=args.as_of,
            sensitive_users=sensitive_users,
            partner_domains=partner_domains,
        )
    return run_live(args, event_listener=event_listener, sensitive_users=sensitive_users, partner_domains=partner_domains)


if __name__ == "__main__":
    raise SystemExit(main())
