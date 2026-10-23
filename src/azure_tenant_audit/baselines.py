"""Baseline alignment and Microsoft Secure Score reconciliation.

The report pack carries a ``baseline_alignment`` section built from the
shipped control mappings (``configs/control-mappings.json``), the framework
catalog (``configs/framework-catalog.json``), the run's findings, and the
collector coverage ledger. It answers two reviewer questions:

* Which benchmark controls did this run touch, and did they pass, fail, or go
  unassessed? A rule passes only when it was actually evaluated: every collector
  that feeds it completed and the inputs it reads were present. Absence of a
  finding is never treated as evidence on its own.
* Where does Microsoft Secure Score agree or disagree with Auditex?

Everything here is derived from local bundle data. Nothing calls a tenant.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Collection, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import break_glass, endpoint_posture, exchange_protection
from .collection_gaps import bounded_sample_gap
from .cyber_essentials import CE_FRAMEWORK_KEY, build_cyber_essentials_section
from .effective_admins import (
    SECTION as _ADMIN_SET_SECTION,
    STATE_COMPLETE as _ADMIN_SET_COMPLETE,
    SUMMARY_KIND as _ADMIN_SUMMARY_KIND,
)
from .identity_controls import (
    CONTROL_ADMIN_MFA,
    CONTROL_EFFECTIVE_MFA,
    CONTROL_LEGACY_AUTH,
    CONTROL_USER_CONSENT,
    SECTION as _IDENTITY_CONTROL_SECTION,
)
from .external_sharing import FEDERATION_UNKNOWN, SETTING_RULES, setting_inputs_gap
from .resources import resolve_resource_path
from .waivers import has_matching_waiver, is_accepted_status

BASELINE_ALIGNMENT_SCHEMA_VERSION = "2026-10-20"
BASELINE_FRAMEWORK_KEYS = ("cis_m365_v7", "cisa_scuba", "ms_secure_score", "ms_zero_trust", "mcsb", CE_FRAMEWORK_KEY)
SECURE_SCORE_LOW_THRESHOLD_PERCENT = 50.0

_FRAMEWORK_CATALOG_PATH = Path("configs/framework-catalog.json")
_CONTROL_MAPPINGS_PATH = Path("configs/control-mappings.json")

# The collectors whose successful run means a rule was evaluated. Rules are
# looked up by exact id first (every collector listed must be complete), then
# by namespace (the text before the first dot). Add new namespaces here when a
# new rule family ships; unknown namespaces report ``not_assessed`` unless a
# finding fails. Rules that read evidence from a different collector than their
# namespace suggests (detection signals, attack paths) are listed by id.
# Google Workspace rules that reach a Cyber Essentials requirement, and the collector each reads. Google rules have no
# namespace in ``_NAMESPACE_COLLECTORS`` (the Microsoft collector map), so each is listed by id.
_GOOGLE_RULE_COLLECTORS = {
    "google.admin_2sv_not_enforced": ("google_directory",),
    "google.admin_2sv_not_enrolled": ("google_directory",),
    "google.user_2sv_not_enforced": ("google_directory",),
    "google.user_2sv_not_enrolled": ("google_directory",),
    "google.org_2sv_policy_not_enforced": ("google_policies",),
    "google.stale_user": ("google_directory",),
    "google.never_logged_in_user": ("google_directory",),
    "google.admin_stale_login": ("google_directory",),
    "google.suspended_admin": ("google_directory",),
    "google.super_admin_sprawl": ("google_directory",),
    "google.chromeos_device_past_aue": ("google_devices",),
    "google.drive_anyone_with_link": ("google_drive_posture",),
    "google.drive_public_discoverable": ("google_drive_posture",),
    "google.calendar_public_acl": ("google_calendar_posture",),
    "google.group_public_view": ("google_groups_settings",),
}
# The coverage list each Google rule reads, so a clean result over a list that was cut short is not a pass.
_GOOGLE_RULE_LISTS = {
    "google_directory": "google_directory.users",
    "google_devices": "google_devices.chromeosDevices",
}
GOOGLE_PLATFORM = "google_workspace"
_RULE_COLLECTORS = {
    **_GOOGLE_RULE_COLLECTORS,
    # Registration comes from auth_methods; who is a Global Administrator or holds an
    # administrator role comes from the identity collector's role assignments.
    "identity.global_admin_mfa_not_registered": ("auth_methods", "identity"),
    "identity.privileged_mfa_not_registered": ("auth_methods", "identity"),
    "identity.user_mfa_not_registered": ("auth_methods",),
    "attack_path.no_mfa_to_tier0": ("identity", "auth_methods"),
    # The graph these paths walk is built from more than the role assignments: application and service principal
    # ownership and grants (app_consent), group membership and application owners (directory_relationships) and
    # PIM-eligible assignments (identity_governance). A path hidden by a gap in any of them is not a clean result.
    "attack_path.app_owner_to_tier0": ("identity", "app_consent", "directory_relationships"),
    "attack_path.privilege_escalation": ("identity", "app_consent", "directory_relationships"),
    # The licence flags of an administrator come from the licensing collector.
    "identity.admin_holds_productivity_licence": ("identity", "licensing"),
    "detection.unified_audit_log_disabled": ("exchange_policy",),
    "detection.mailbox_audit_disabled": ("exchange_policy",),
    "detection.mailbox_audit_bypass": ("exchange_policy",),
    "detection.no_alert_policies": ("exchange_policy",),
    "detection.no_risk_based_policies": ("conditional_access",),
    "detection.signin_logs_unavailable": ("security",),
    # An external principal is one outside the tenant's own domains, which domains_hybrid reads.
    "sharepoint.external_principal": ("sharepoint_access", "domains_hybrid"),
}
# Collectors a rule also needs, where "complete" or "not_applicable" (skipped because the tenant
# cannot have the data, for example no licence) both mean the evidence is as complete as it can be.
# A collector that was blocked, partial, failed or never ran is still a gap.
_RULE_COLLECTORS_NOT_APPLICABLE_OK = {
    # PIM-eligible administrators come from identity governance.
    "identity.privileged_mfa_not_registered": ("identity_governance",),
    # The attack-path graph reads PIM-eligible assignments from identity governance too.
    "attack_path.app_owner_to_tier0": ("identity_governance",),
    "attack_path.privilege_escalation": ("identity_governance",),
}
_NAMESPACE_COLLECTORS = {
    "app_consent": "app_consent",
    "attack_path": "identity",
    "app_credentials": "app_credentials",
    "ca": "conditional_access",
    "consent_policy": "consent_policy",
    "cross_tenant_access": "cross_tenant_access",
    "dns_posture": "dns_posture",
    "exchange": "exchange_policy",
    "exposure": "dns_posture",
    "external_identity": "external_identity",
    "identity": "identity",
    "identity_governance": "identity_governance",
    "intune": "intune",
    "intune_depth": "intune_depth",
    "mailbox_forwarding": "mailbox_forwarding",
    "onedrive": "onedrive_posture",
    "reports_usage": "reports_usage",
    "secure_score": "defender",
    "security": "security",
    "service_health": "service_health",
    "sharepoint": "sharepoint_access",
    "teams": "teams_policy",
}
# Detection rule -> detection signal that decides whether it was evaluated. Mirrors
# ``_DETECTION_SIGNAL_RULES`` in findings.py (a test keeps the two in step).
_DETECTION_RULE_SIGNALS = {
    "detection.unified_audit_log_disabled": "unified_audit_log",
    "detection.mailbox_audit_disabled": "mailbox_audit_default",
    "detection.mailbox_audit_bypass": "mailbox_audit_bypass_clear",
    "detection.no_alert_policies": "alert_policies",
    "detection.no_risk_based_policies": "risk_based_conditional_access",
    "detection.signin_logs_unavailable": "signin_logs",
}
# Rules decided by a tenant-level identity control verdict -> the verdict controls that must be
# known (not ``unknown``) for the rule to count as evaluated. ``ca.enforcement_unverified`` is the
# diagnostic an ``unknown`` MFA or legacy-authentication verdict raises, so it is clean only when
# both verdicts are known. Mirrors ``_UNVERIFIED_CONTROL_RULES`` in findings.py (a test keeps them in step).
_RULE_VERDICT_CONTROLS = {
    "ca.mfa_not_enforced": (CONTROL_EFFECTIVE_MFA,),
    "ca.mfa_split_across_policies": (CONTROL_EFFECTIVE_MFA,),
    "ca.admin_mfa_not_enforced": (CONTROL_ADMIN_MFA,),
    "ca.admin_phishing_resistant_mfa_not_enforced": (CONTROL_ADMIN_MFA,),
    "ca.admin_mfa_role_set_incomplete": (CONTROL_ADMIN_MFA,),
    "ca.legacy_auth_not_blocked": (CONTROL_LEGACY_AUTH,),
    "ca.enforcement_unverified": (CONTROL_EFFECTIVE_MFA, CONTROL_ADMIN_MFA, CONTROL_LEGACY_AUTH),
    "consent_policy.user_consent_unrestricted": (CONTROL_USER_CONSENT,),
    "consent_policy.user_consent_limited": (CONTROL_USER_CONSENT,),
    "consent_policy.user_consent_unverified": (CONTROL_USER_CONSENT,),
}
# Rules that read the effective administrator set (``normalized/effective_admin_set.json``). Each is
# evaluated only when the set is ``complete``: a role-assignment, PIM-schedule or group-membership read
# that was blocked, truncated or not run can hide an administrator, so a clean result is not a pass.
# ``identity.admin_set_unverified`` is the diagnostic an ``unknown`` set raises. Mirrors the rules in
# findings.py that call ``_effective_admins`` (a test keeps them in step).
_ADMIN_SET_RULES = frozenset(
    {
        "identity.global_admin_singleton",
        "identity.global_admin_sprawl",
        "identity.global_admin_disabled",
        "identity.global_admin_stale_password",
        "identity.global_admin_mfa_not_registered",
        "identity.privileged_mfa_not_registered",
        "identity.privileged_stale_account",
        "identity.admin_holds_productivity_licence",
        "identity.guest_with_privileged_role",
        "identity.service_principal_privileged_role",
        "identity.admin_set_unverified",
        "attack_path.no_mfa_to_tier0",
    }
)
_ADMIN_LICENCE_RULE = "identity.admin_holds_productivity_licence"
_STALE_GUEST_RULE = "identity.stale_guest"
# Rules that read user sign-in activity, which needs Microsoft Entra ID P1 or P2 (``userSignInActivity``).
_SIGNIN_ACTIVITY_RULES = frozenset(
    {"identity.stale_enabled_account", "identity.privileged_stale_account", _STALE_GUEST_RULE}
)
# Sections a licence can refuse (error class ``license_required``) without the rest of the collector failing.
# A collector that is partial for no other reason still evidences every rule that does not read the section:
# ``identity`` for everything but the sign-in rules, ``identity_governance`` (PIM schedules, which the
# effective administrator set already reads as "no PIM") for the rules that tolerate it.
_LICENCE_GATED_SECTIONS = {
    "identity": frozenset({"userSignInActivity"}),
    "identity_governance": frozenset({"roleAssignmentSchedules", "roleEligibilitySchedules"}),
}
_MTA_STS_POLICY_RULES = frozenset({"dns_posture.mta_sts_policy_invalid", "dns_posture.mta_sts_testing_mode"})
# Rules judged on the rows they read, not on whether their whole collector completed. ``exchange_policy`` runs a dozen
# commands and is partial whenever one of them is not available (``Get-ProtectionAlert`` needs a Security & Compliance
# session that app-only runs never open), which would keep these rules, and CIS 2.1.9 and SCuBA MS.EXO.3.1v1 with them,
# from ever reading ``pass``. Each rule's own command rows are checked by ``exchange_protection.inputs_gap``.
INPUT_JUDGED_RULES = frozenset(exchange_protection.RULES)
_NOT_ASSESSED = "not_assessed"
_STATUS_ORDER = ("fail", "accepted_risk", "pass", _NOT_ASSESSED)


def rule_judged_on_inputs(rule_id: str) -> bool:
    """Whether ``rule_id`` is judged on its own input rows instead of its collector's overall status."""
    return rule_id in INPUT_JUDGED_RULES


def _read_json(path: Path) -> Any:
    try:
        return json.loads(resolve_resource_path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return {}


@lru_cache(maxsize=1)
def load_framework_catalog() -> dict[str, Any]:
    payload = _read_json(_FRAMEWORK_CATALOG_PATH)
    return payload if isinstance(payload, dict) else {}


@lru_cache(maxsize=1)
def _shipped_control_mappings() -> dict[str, dict[str, list[str]]]:
    payload = _read_json(_CONTROL_MAPPINGS_PATH)
    if not isinstance(payload, Mapping):
        return {}
    return {
        str(rule_id): {str(key): [str(item) for item in value] for key, value in mapping.items() if isinstance(value, list)}
        for rule_id, mapping in payload.items()
        if isinstance(rule_id, str) and not rule_id.startswith("_") and isinstance(mapping, Mapping)
    }


@lru_cache(maxsize=1)
def _shipped_cyber_essentials_confidence() -> dict[str, dict[str, str]]:
    """``rule id -> requirement id -> full|partial`` from the shipped control mappings."""
    payload = _read_json(_CONTROL_MAPPINGS_PATH)
    table = payload.get("_cyber_essentials_confidence") if isinstance(payload, Mapping) else None
    if not isinstance(table, Mapping):
        return {}
    return {
        str(rule_id): {str(requirement): str(value) for requirement, value in requirements.items()}
        for rule_id, requirements in table.items()
        if isinstance(requirements, Mapping)
    }


@lru_cache(maxsize=1)
def _shipped_verdict_basis_requirements() -> dict[str, dict[str, Any]]:
    """``rule id -> {control, requires, frameworks}`` from ``_verdict_basis_requirements`` in the control mappings.

    A benchmark control listed here is met only when the rule's identity control verdict rests on ``requires`` (a
    qualifying Conditional Access policy), not on security defaults alone: CIS 5.2.2.x and the SCuBA Conditional
    Access controls audit a policy, and security defaults are not one. Cyber Essentials, Zero Trust and Secure Score
    are not listed and keep reading the verdict as it is.
    """
    payload = _read_json(_CONTROL_MAPPINGS_PATH)
    table = payload.get("_verdict_basis_requirements") if isinstance(payload, Mapping) else None
    if not isinstance(table, Mapping):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for rule_id, spec in table.items():
        if not isinstance(spec, Mapping) or not spec.get("control") or not spec.get("requires"):
            continue
        frameworks = spec.get("frameworks")
        result[str(rule_id)] = {
            "control": str(spec["control"]),
            "requires": str(spec["requires"]),
            "frameworks": {
                str(framework): [str(item) for item in controls]
                for framework, controls in (frameworks.items() if isinstance(frameworks, Mapping) else ())
                if isinstance(controls, list)
            },
        }
    return result


def _basis_requirement_gap(
    rule_id: str,
    framework: str,
    control_id: str,
    snapshot: Mapping[str, Any] | None,
    requirements: Mapping[str, Mapping[str, Any]],
) -> str | None:
    """Why a passing rule does not meet this benchmark control: its verdict rests on a basis the control does not accept."""
    requirement = requirements.get(rule_id)
    if requirement is None or control_id not in (requirement["frameworks"].get(framework) or []) or snapshot is None:
        return None
    verdict = next(
        (record for record in _records(snapshot, _IDENTITY_CONTROL_SECTION) if record.get("control") == requirement["control"]),
        None,
    )
    if verdict is None:
        return None
    basis = [str(item) for item in verdict.get("basis") or []]
    if requirement["requires"] in basis:
        return None
    return f"{requirement['requires']}_required:basis_{'+'.join(basis) or 'none'}"


def framework_entry(framework: str) -> dict[str, Any]:
    frameworks = load_framework_catalog().get("frameworks")
    entry = frameworks.get(framework) if isinstance(frameworks, Mapping) else None
    return dict(entry) if isinstance(entry, Mapping) else {}


def framework_control_title(framework: str, control_id: str) -> str | None:
    controls = framework_entry(framework).get("controls")
    if not isinstance(controls, Mapping):
        return None
    value = controls.get(control_id)
    if isinstance(value, Mapping):
        title = value.get("title")
        return str(title) if title else None
    return str(value) if value else None


def rule_evidence_collectors(rule_id: str) -> tuple[str, ...]:
    """Every collector that must complete before ``rule_id`` counts as evaluated.

    Collectors that may also be ``not_applicable`` (see ``unmet_rule_collectors``) come last.
    """
    if rule_id in _RULE_COLLECTORS:
        required: tuple[str, ...] = _RULE_COLLECTORS[rule_id]
    else:
        collector = _NAMESPACE_COLLECTORS.get(rule_id.split(".", 1)[0])
        required = (collector,) if collector else ()
    if not required:
        return ()
    return (*required, *_RULE_COLLECTORS_NOT_APPLICABLE_OK.get(rule_id, ()))


def unmet_rule_collectors(
    rule_id: str, *, complete: Collection[str], not_applicable: Collection[str] = ()
) -> list[str]:
    """The collectors ``rule_id`` needs that neither completed nor (where allowed) were not applicable."""
    if rule_id in INPUT_JUDGED_RULES:
        return []
    tolerant = _RULE_COLLECTORS_NOT_APPLICABLE_OK.get(rule_id, ())
    return [
        collector
        for collector in rule_evidence_collectors(rule_id)
        if collector not in complete and not (collector in tolerant and collector in not_applicable)
    ]


def rule_evidence_collector(rule_id: str) -> str | None:
    collectors = rule_evidence_collectors(rule_id)
    return collectors[0] if collectors else None


def _records(snapshot: Mapping[str, Any] | None, section: str) -> list[dict[str, Any]]:
    if not isinstance(snapshot, Mapping):
        return []
    payload = snapshot.get(section)
    rows = payload.get("records") if isinstance(payload, Mapping) else None
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def latest_secure_score(normalized_snapshot: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return the newest usable ``security_scores`` record with its percentage."""
    candidates = []
    for record in _records(normalized_snapshot, "security_scores"):
        current = _number(record.get("current_score"))
        maximum = _number(record.get("max_score"))
        if current is None or maximum is None or maximum <= 0:
            continue
        candidates.append((str(record.get("created") or ""), str(record.get("id") or ""), record, current, maximum))
    if not candidates:
        return None
    _, _, record, current, maximum = max(candidates, key=lambda item: (item[0], item[1]))
    return {
        "record": record,
        "id": record.get("id"),
        "created": record.get("created"),
        "current_score": current,
        "max_score": maximum,
        "percentage": round(current / maximum * 100, 1),
    }


def _finding_state(finding: Mapping[str, Any]) -> str:
    """``open``, ``accepted`` or ``closed``. An unknown status counts as open (fail closed).

    ``closed`` and ``resolved`` are never written by the engine, so one without the waiver that stands behind it
    is an edit and the finding stays open, as in the gate (``auditex.gate``).
    """
    status = str(finding.get("status") or "open").strip().lower()
    if is_accepted_status(status):
        return "accepted"
    if status in {"resolved", "closed"}:
        return "closed" if has_matching_waiver(finding) else "open"
    return "open"


def _threshold_exemptions(findings: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Framework -> ids of findings whose bound for that framework was not breached.

    A count rule states, per framework, the bound it tested (``framework_thresholds``). A finding
    raised for CIS's two-to-four Global Administrators while SCuBA allows up to eight must fail only
    the CIS controls. A framework the finding does not list has no bound of its own and takes the
    finding as it is.
    """
    exempt: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        thresholds = finding.get("framework_thresholds")
        if not isinstance(thresholds, list):
            continue
        for entry in thresholds:
            if isinstance(entry, Mapping) and entry.get("framework") and entry.get("breached") is False:
                exempt[str(entry["framework"])].add(str(finding.get("id") or ""))
    return exempt


def _open_findings_by_rule(
    findings: list[dict[str, Any]], *, exempt_ids: Collection[str] = ()
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    open_by_rule: dict[str, list[str]] = defaultdict(list)
    accepted_by_rule: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if not rule_id or str(finding.get("id") or "") in exempt_ids:
            continue
        state = _finding_state(finding)
        if state == "closed":
            continue
        target = open_by_rule if state == "open" else accepted_by_rule
        target[rule_id].append(str(finding.get("id") or rule_id))
    return open_by_rule, accepted_by_rule


def unmapped_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Findings that carry no ``rule_id``, so no baseline control can see them.

    They never reach a control row. Counting them here keeps them visible next to
    the per-framework roll-ups instead of letting a control read ``pass`` while
    an open finding in the same area exists.
    """
    rows = [row for row in findings if isinstance(row, Mapping) and not str(row.get("rule_id") or "").strip()]
    states = [_finding_state(row) for row in rows]
    collectors = _count(str(row.get("collector") or "unknown") for row in rows)
    return {
        "count": len(rows),
        "open_count": states.count("open"),
        "accepted_count": states.count("accepted"),
        # A list, not a mapping: collector names such as ``app_credentials`` would trip the
        # bundle's sensitive-key scan if used as object keys.
        "collectors": [{"collector": name, "count": count} for name, count in sorted(collectors.items())],
        "finding_ids": sorted({str(row.get("id") or "") for row in rows if row.get("id")})[:20],
    }


def _microsoft_state(score: float | None, maximum: float | None, percent: float | None) -> str:
    if score is None and percent is None:
        return "no_data"
    if maximum is not None and maximum > 0 and score is not None:
        percent = score / maximum * 100
    if percent is None:
        return "no_data" if score is None else ("not_implemented" if score <= 0 else "partial")
    if percent >= 100:
        return "implemented"
    if percent <= 0:
        return "not_implemented"
    return "partial"


def _agreement(auditex_state: str, microsoft_state: str) -> str:
    if microsoft_state == "no_data":
        return "no_microsoft_data"
    microsoft_gap = microsoft_state != "implemented"
    if auditex_state == "fail":
        return "agrees" if microsoft_gap else "auditex_only"
    return "microsoft_only" if microsoft_gap else "agrees"


def build_secure_score_reconciliation(
    findings: list[dict[str, Any]],
    normalized_snapshot: Mapping[str, Any] | None,
    *,
    mappings: Mapping[str, Mapping[str, list[str]]] | None = None,
) -> dict[str, Any]:
    """Compare Microsoft Secure Score control results with Auditex findings.

    ``agreement`` values: ``agrees`` (both flag a gap, or neither does),
    ``auditex_only`` (Auditex has an open finding but Microsoft scores the
    control as fully implemented), ``microsoft_only`` (Microsoft reports a gap
    and Auditex has no open finding, which can also mean the rule was not
    assessed), ``no_microsoft_data`` (no control score in the snapshot).
    """
    mapping_rows = mappings if mappings is not None else _shipped_control_mappings()
    rules_by_control: dict[str, set[str]] = defaultdict(set)
    for rule_id, mapping in mapping_rows.items():
        for control_id in mapping.get("ms_secure_score") or []:
            rules_by_control[str(control_id)].add(rule_id)
    for finding in findings:
        framework_mappings = finding.get("framework_mappings")
        if isinstance(framework_mappings, Mapping):
            for control_id in framework_mappings.get("ms_secure_score") or []:
                rules_by_control[str(control_id)].add(str(finding.get("rule_id") or finding.get("id") or ""))

    latest = latest_secure_score(normalized_snapshot)
    control_scores: dict[str, dict[str, Any]] = {}
    if latest:
        for row in latest["record"].get("control_scores") or []:
            if isinstance(row, Mapping) and row.get("control_name"):
                control_scores[str(row["control_name"])] = dict(row)
    profiles = {
        str(record.get("id")): record
        for record in _records(normalized_snapshot, "security_score_control_profiles")
        if record.get("id")
    }
    open_by_rule, _ = _open_findings_by_rule(findings)

    rows: list[dict[str, Any]] = []
    for control_id in sorted(rules_by_control):
        rule_ids = sorted(item for item in rules_by_control[control_id] if item)
        open_ids = sorted({finding_id for rule_id in rule_ids for finding_id in open_by_rule.get(rule_id, [])})
        control_score = control_scores.get(control_id, {})
        profile = profiles.get(control_id, {})
        score = _number(control_score.get("score"))
        maximum = _number(profile.get("max_score"))
        percent = _number(control_score.get("score_in_percentage"))
        microsoft_state = _microsoft_state(score, maximum, percent)
        auditex_state = "fail" if open_ids else "no_finding"
        rows.append(
            {
                "control_profile_id": control_id,
                "title": profile.get("title") or framework_control_title("ms_secure_score", control_id),
                "microsoft_score": score,
                "microsoft_max_score": maximum,
                "microsoft_state": microsoft_state,
                "auditex_rule_ids": rule_ids,
                "auditex_state": auditex_state,
                "auditex_open_finding_count": len(open_ids),
                "auditex_finding_ids": open_ids[:20],
                "agreement": _agreement(auditex_state, microsoft_state),
            }
        )
    overall = None
    if latest:
        overall = {key: latest[key] for key in ("id", "created", "current_score", "max_score", "percentage")}
    return {
        "available": latest is not None,
        "threshold_percent": SECURE_SCORE_LOW_THRESHOLD_PERCENT,
        "overall": overall,
        "control_profile_count": len(profiles),
        "controls": rows,
        "agreement_counts": dict(sorted(_count(row["agreement"] for row in rows).items())),
    }


def _count(values: Any) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for value in values:
        counts[str(value)] += 1
    return dict(counts)


def _collectors_with_status(coverage_ledger: list[dict[str, Any]] | None, predicate: Any) -> set[str]:
    names: set[str] = set()
    for row in coverage_ledger or []:
        if isinstance(row, Mapping) and predicate(str(row.get("coverage_status") or "")):
            names.add(str(row.get("collector") or ""))
    return names


def _complete_collectors(coverage_ledger: list[dict[str, Any]] | None) -> set[str]:
    return _collectors_with_status(coverage_ledger, lambda status: status.startswith("complete"))


def _licence_limited_collectors(coverage_ledger: list[dict[str, Any]] | None) -> set[str]:
    """Collectors that are partial only because a licence-gated section was refused with ``license_required``.

    Every diagnostic of the collector must be such a refusal of one of its licence-gated sections; any other
    diagnostic (a failed users read, a truncated list, incomplete evidence) leaves the collector partial.
    """
    limited: set[str] = set()
    for row in coverage_ledger or []:
        if not isinstance(row, Mapping) or str(row.get("coverage_status") or "") != "partial_success":
            continue
        collector = str(row.get("collector") or "")
        gated = _LICENCE_GATED_SECTIONS.get(collector)
        diagnostics = [item for item in row.get("diagnostics") or [] if isinstance(item, Mapping)]
        if gated and diagnostics and all(
            item.get("error_class") == "license_required" and item.get("item") in gated for item in diagnostics
        ):
            limited.add(collector)
    return limited


def _not_applicable_collectors(coverage_ledger: list[dict[str, Any]] | None) -> set[str]:
    return _collectors_with_status(coverage_ledger, lambda status: status == "not_applicable")


def _dns_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    records = _records(snapshot, "dns_posture_objects")
    if not records:
        return "no_domain_records"
    if any(record.get("resolver_error") for record in records):
        return "resolver_error"
    if rule_id == "dns_posture.tls_rpt_missing" and any(record.get("tls_rpt_present") is None for record in records):
        # None means the bundle predates TLS-RPT collection, so absence was never checked.
        return "tls_rpt_not_collected"
    if rule_id in _MTA_STS_POLICY_RULES:
        for record in records:
            policy_fetched = str(record.get("mta_sts_policy_fetch_status") or "") not in {"", "skipped"}
            # A domain without an MTA-STS record has no policy to evaluate.
            if record.get("mta_sts_dns_present") is not False and not policy_fetched:
                return "mta_sts_policy_not_fetched"
    return None


def _detection_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    signal = _DETECTION_RULE_SIGNALS[rule_id]
    for record in _records(snapshot, "detection_signal_objects"):
        if record.get("name") == signal:
            status = str(record.get("status") or "unknown")
            if status in {"on", "off"}:
                return None
            return f"signal_{status}:{record.get('reason') or 'unknown'}"
    return "signal_not_collected"


def _verdict_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    verdicts = {str(record.get("control")): record for record in _records(snapshot, _IDENTITY_CONTROL_SECTION)}
    for control in _RULE_VERDICT_CONTROLS[rule_id]:
        record = verdicts.get(control)
        if record is None:
            return f"verdict_not_collected:{control}"
        if str(record.get("verdict") or "unknown") == "unknown":
            return f"verdict_unknown:{control}"
    return None


def _admin_set_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    """The effective administrator set must be ``complete`` (and, for the licence rule, its licences read)."""
    if snapshot is None:
        return "inputs_not_available"
    summary = next((row for row in _records(snapshot, _ADMIN_SET_SECTION) if row.get("kind") == _ADMIN_SUMMARY_KIND), None)
    if summary is None:
        return "admin_set_not_collected"
    if summary.get("state") != _ADMIN_SET_COMPLETE:
        return f"admin_set_unknown:{','.join(str(item) for item in summary.get('reasons') or ['unspecified'])}"
    if rule_id == _ADMIN_LICENCE_RULE and summary.get("licence_state") != "known":
        return f"licence_data_unavailable:{','.join(str(item) for item in summary.get('licence_reasons') or ['unspecified'])}"
    return None


def _signin_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    """An account can only be called stale when the sign-in activity read covered it.

    ``identity.stale_guest`` judges guests, ``identity.privileged_stale_account`` the administrators (and needs the
    administrator set), ``identity.stale_enabled_account`` every enabled member. Without sign-in data (the read needs
    Microsoft Entra ID P1 or P2) the rules find nothing, which is not a pass.
    """
    if snapshot is None:
        return "inputs_not_available"
    administrators: set[str] | None = None
    if rule_id == "identity.privileged_stale_account":
        gap = _admin_set_inputs_gap(snapshot, rule_id)
        if gap:
            return gap
        administrators = {
            str(row.get("principal_id") or "").lower()
            for row in _records(snapshot, _ADMIN_SET_SECTION)
            if row.get("kind") == "effective_admin" and row.get("counted")
        }
    for user in _records(snapshot, "users"):
        if user.get("enabled") is False or user.get("signin_data_available") is True:
            continue
        is_guest = str(user.get("user_type") or "").strip().lower() == "guest"
        if rule_id == _STALE_GUEST_RULE:
            relevant = is_guest
        elif administrators is not None:
            relevant = str(user.get("id") or "").lower() in administrators
        else:
            # Members: a guest is judged by identity.stale_guest, and a guest administrator by the privileged rule.
            relevant = not is_guest
        if relevant:
            return "signin_activity_unavailable"
    return None


# Rules that read the authentication method registration report -> the people whose registration they judge:
# ``everyone`` every enabled member user and every counted administrator (a report that misses a user says nothing
# about the user rule, and the attack graph may start from any of them), ``privileged`` the counted administrators who
# are not Global Administrators, ``global_admin`` the Global Administrators.
_MFA_REGISTRATION_RULE_SCOPES = {
    "identity.user_mfa_not_registered": "everyone",
    "identity.privileged_mfa_not_registered": "privileged",
    "identity.global_admin_mfa_not_registered": "global_admin",
    "attack_path.no_mfa_to_tier0": "everyone",
}
MFA_REGISTRATION_GAP_PREFIX = "registration_report_incomplete"


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _mfa_registration_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    """``registration_report_incomplete:<n>`` when the registration report does not cover the people this rule judges.

    The rules read the report's rows only, so an enabled user or a counted administrator the report has no row for (or a
    row without a MFA registration answer) is never judged: an empty report would read as a pass. Every such principal
    is counted from the user list and the effective administrator set; a count above zero is a gap, not a pass.
    """
    if snapshot is None:
        return "inputs_not_available"
    scope = _MFA_REGISTRATION_RULE_SCOPES[rule_id]
    answered: set[str] = set()
    for row in _records(snapshot, "auth_method_registration_objects"):
        if isinstance(row.get("is_mfa_registered"), bool):
            answered.update(key for key in (_lower(row.get("id")), _lower(row.get("user_principal_name"))) if key)
    admins = [
        row
        for row in _records(snapshot, _ADMIN_SET_SECTION)
        if row.get("kind") == "effective_admin" and row.get("counted") and row.get("principal_id") and row.get("enabled") is not False
    ]
    uncovered: set[str] = set()

    def consider(principal_id: Any, principal_name: Any) -> None:
        keys = {_lower(principal_id), _lower(principal_name)} - {""}
        if keys and not keys & answered:
            uncovered.add(_lower(principal_id) or _lower(principal_name))

    if scope == "everyone":
        for user in _records(snapshot, "users"):
            if user.get("enabled") is not False and _lower(user.get("user_type")) in {"", "member"}:
                consider(user.get("id"), user.get("principal_name"))
    for row in admins:
        if scope == "privileged" and row.get("global_administrator"):
            continue
        if scope == "global_admin" and not row.get("global_administrator"):
            continue
        consider(row.get("principal_id"), row.get("principal_name"))
    return f"{MFA_REGISTRATION_GAP_PREFIX}:{len(uncovered)}" if uncovered else None


def _risky_signin_inputs_gap(snapshot: Mapping[str, Any] | None) -> str | None:
    """Sign-ins whose risk level is ``hidden`` (no Microsoft Entra ID P2) carry no risk detail to judge.

    The rule skips a sign-in that reports no risk, so a sample in which every sign-in hides its risk raises nothing
    and would read as a pass. ``risk_detail_hidden`` when every sampled sign-in is hidden.
    """
    if snapshot is None:
        return "inputs_not_available"
    events = _records(snapshot, "security_signin_events")
    if not events:
        return None
    for event in events:
        levels = {_lower(event.get("risk_level_aggregated")), _lower(event.get("risk_level_during_signin"))} - {""}
        if not levels or "hidden" not in levels:
            return None
    return "risk_detail_hidden"


def _sharepoint_external_inputs_gap(snapshot: Mapping[str, Any] | None) -> str | None:
    """Telling an external principal from an internal one needs the tenant's own domain list."""
    if snapshot is None:
        return "inputs_not_available"
    for record in _records(snapshot, "domain_hybrid_objects"):
        if record.get("is_verified") is False:
            continue
        if any(
            "." in value and "@" not in value
            for value in (_lower(record.get(key)) for key in ("id", "domain", "name"))
        ):
            return None
    return "tenant_domains_unknown"


def _google_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    """A clean Google rule is a pass only when the list it reads was read in full (and, for the organisation 2-step policy, known)."""
    if snapshot is None:
        return "inputs_not_available"
    state = snapshot.get("snapshot") if isinstance(snapshot.get("snapshot"), Mapping) else {}
    if rule_id == "google.org_2sv_policy_not_enforced":
        status = str(state.get("two_step_policy_status") or "unknown")
        return None if status in {"enforcing", "not_enforced", "partial"} else f"two_step_policy_{status}"
    list_name = _GOOGLE_RULE_LISTS.get((_GOOGLE_RULE_COLLECTORS.get(rule_id) or ("",))[0])
    if list_name and list_name in (state.get("truncated_sections") or []):
        return f"{list_name.split('.', 1)[1]}_truncated"
    # A crawl read as a sample by design (the Drive files) and cut at its bound proves nothing about the files past it.
    return bounded_sample_gap(rule_id, snapshot)


# Coverage row the intune_depth collector writes when it expanded only its first policies.
# The read is a section-scoped gap (see ``collection_gaps.section_gap_records``), listed under its section's name.
_INTUNE_ASSIGNMENT_FANOUT_SOURCES = frozenset(
    {"intune_depth.deviceConfigurationAssignments", "intune_depth.deviceConfigurationAssignmentsFanout"}
)


def intune_assignments_are_a_sample(snapshot: Mapping[str, Any] | None) -> bool:
    """Whether the assignment read covers only some of the device configuration profiles.

    The collector reads assignments one policy at a time and stops at its fan-out limit, recording a
    ``deviceConfigurationAssignmentsFanout`` gap. A profile it never expanded may well be assigned, so
    "no assignments" over a sample says nothing about the rest. The per-policy rows are checked too, for
    a bundle that carries them but no gap record.
    """
    if snapshot is None:
        return False
    if any(record.get("source") in _INTUNE_ASSIGNMENT_FANOUT_SOURCES for record in _records(snapshot, "collection_gaps")):
        return True
    expanded = len(_records(snapshot, "intune_policy_assignment_objects"))
    configurations = {str(record.get("source")): record for record in _records(snapshot, "normalization_coverage")}.get(
        "intune_depth.deviceConfigurations"
    )
    total = configurations.get("record_count") if configurations else None
    return bool(expanded) and isinstance(total, int) and not isinstance(total, bool) and expanded < total


def _intune_assignment_inputs_gap(snapshot: Mapping[str, Any] | None) -> str | None:
    """The unassigned-policy rule reads intune_depth's own policy inventory and assignment reads."""
    if snapshot is None:
        return "inputs_not_available"
    reports = {str(record.get("source")): record for record in _records(snapshot, "normalization_coverage")}
    configurations = reports.get("intune_depth.deviceConfigurations")
    if configurations is None:
        return "device_configurations_not_collected"
    if configurations.get("collection_status") != "collected" or configurations.get("complete") is not True:
        return "device_configurations_not_read_in_full"
    if not configurations.get("record_count"):
        return "no_device_configurations"
    assignments = reports.get("intune_depth.deviceConfigurationAssignments")
    if assignments is None or assignments.get("collection_status") != "collected" or assignments.get("complete") is not True:
        return "policy_assignments_not_read_in_full"
    if intune_assignments_are_a_sample(snapshot):
        return "policy_assignments_not_read_for_every_policy"
    return None


_TEAMS_FEDERATION_RULE = "teams.external_federation_open"
_SHAREPOINT_EXTERNAL_RULE = "sharepoint.external_principal"
_RISKY_SIGNIN_RULE = "security.risky_signin"
_BREAK_GLASS_RULE = "ca.break_glass_exclusion_missing"

# Device rules -> the device_posture count of devices the check says nothing about. A rule is evaluated
# only when the device list was read in full, there is at least one device and no device is unknown for
# the check; a clean result over a partly unknown fleet is not a pass.
_DEVICE_UNKNOWN_FIELDS = {
    # Compliance never evaluated (unknown, missing, Configuration Manager) or still within the grace period.
    "intune.device_noncompliant": "compliance_unknown",
    "intune.device_encryption_off": "encryption_unknown",
    "intune.device_jailbroken": "jailbreak_unknown",
    "intune.device_stale_sync": "last_sync_unknown",
    "intune.device_os_end_of_life": "os_lifecycle_unknown",
}
_DEFENDER_RULE_FIELDS = {
    "intune.defender_av_off": "av_state",
    "intune.defender_realtime_protection_off": "realtime_state",
    "intune.defender_signatures_stale": "signature_state",
}
_COMPLIANCE_PLATFORM_RULE = "intune.compliance_policy_missing_platform"
_UPDATE_RING_RULES = frozenset({"intune_depth.update_ring_not_assigned", "intune_depth.update_ring_deferral_excessive"})


def _summary(snapshot: Mapping[str, Any], section: str, kind: str) -> Mapping[str, Any] | None:
    return next((row for row in _records(snapshot, section) if row.get("kind") == kind), None)


def _device_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    summary = _summary(snapshot, endpoint_posture.DEVICE_SECTION, endpoint_posture.DEVICE_SUMMARY_KIND)
    if summary is None:
        return "device_posture_not_collected"
    if summary.get("read_state") != "collected":
        return f"device_list_{summary.get('read_state')}"
    if not summary.get("device_count"):
        return "no_managed_devices"
    field = _DEVICE_UNKNOWN_FIELDS[rule_id]
    unknown = summary.get(field)
    if isinstance(unknown, int) and unknown > 0:
        return f"{field}_for_{unknown}_devices"
    if rule_id == "intune.device_os_end_of_life" and summary.get("os_lifecycle_edition_dependent"):
        # The Home/Pro date has passed and the Enterprise/Education date has not; osVersion does not show the edition.
        return f"os_edition_dependent_for_{summary['os_lifecycle_edition_dependent']}_devices"
    return None


def _defender_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    summary = _summary(snapshot, endpoint_posture.DEFENDER_SECTION, endpoint_posture.DEFENDER_SUMMARY_KIND)
    if summary is None:
        return "defender_state_not_collected"
    if summary.get("devices_read_state") != "collected":
        return f"device_list_{summary.get('devices_read_state')}"
    if summary.get("read_state") != "collected":
        return f"defender_state_{summary.get('read_state')}"
    if not summary.get("windows_device_count"):
        return "no_windows_devices"
    unavailable = int(summary.get("state_not_reported") or 0) + int(summary.get("state_read_failed") or 0)
    if unavailable:
        return f"defender_state_unavailable_for_{unavailable}_devices"
    field = _DEFENDER_RULE_FIELDS[rule_id]
    unknown = sum(
        1
        for row in _records(snapshot, endpoint_posture.DEFENDER_SECTION)
        if row.get("kind") == endpoint_posture.DEFENDER_STATE_KIND and row.get(field) == endpoint_posture.STATE_UNKNOWN
    )
    return f"defender_{field}_unknown_for_{unknown}_devices" if unknown else None


def _compliance_inputs_gap(snapshot: Mapping[str, Any] | None) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    summary = _summary(snapshot, endpoint_posture.COMPLIANCE_SECTION, endpoint_posture.COMPLIANCE_SUMMARY_KIND)
    if summary is None:
        return "compliance_policies_not_collected"
    if summary.get("policies_read_state") != "collected":
        return f"compliance_policies_{summary.get('policies_read_state')}"
    if summary.get("devices_read_state") != "collected":
        return f"device_list_{summary.get('devices_read_state')}"
    platforms = [
        row
        for row in _records(snapshot, endpoint_posture.COMPLIANCE_SECTION)
        if row.get("kind") == endpoint_posture.COMPLIANCE_PLATFORM_KIND and row.get("device_count")
    ]
    if not platforms:
        return "no_managed_devices"
    for row in platforms:
        if row.get("policy_count") and not row.get("assigned_policy_count"):
            if row.get("assignments_unknown_count") or summary.get("assignments_read_state") != "collected":
                return "policy_assignments_not_read_for_every_policy"
    return None


def _update_ring_inputs_gap(snapshot: Mapping[str, Any] | None, rule_id: str) -> str | None:
    if snapshot is None:
        return "inputs_not_available"
    summary = _summary(snapshot, endpoint_posture.UPDATE_SECTION, endpoint_posture.UPDATE_SUMMARY_KIND)
    if summary is None:
        return "update_management_not_collected"
    if summary.get("rings_read_state") != "collected":
        return f"update_rings_{summary.get('rings_read_state')}"
    if summary.get("ring_count") and summary.get("ring_assignments_read_state") != "collected":
        return f"ring_assignments_{summary.get('ring_assignments_read_state')}"
    if summary.get("rings_with_unknown_assignments"):
        return "ring_assignments_not_read_for_every_ring"
    if rule_id == "intune_depth.update_ring_not_assigned":
        if not summary.get("rings_assigned") and summary.get("update_profiles_gap"):
            # The beta update profile lists were refused or cut, so "no profile is assigned" was not established.
            return str(summary["update_profiles_gap"])
        if summary.get("devices_read_state") != "collected":
            return f"device_list_{summary.get('devices_read_state')}"
        if not summary.get("windows_device_count"):
            return "no_windows_devices"
        if not summary.get("rings_assigned") and (summary.get("profiles_assigned") or summary.get("windows_comanaged_device_count")):
            # Updates may be managed through an update profile or Configuration Manager: no ring is not no management.
            return "update_managed_by_other_means"
        return None
    if not summary.get("rings_assigned"):
        return "no_assigned_update_ring"
    assigned = [
        row
        for row in _records(snapshot, endpoint_posture.UPDATE_SECTION)
        if row.get("kind") == endpoint_posture.UPDATE_RING_KIND and row.get("assigned") is True
    ]
    if any(not endpoint_posture.ring_settings_known(row) for row in assigned):
        return "ring_settings_not_returned"
    return None


def _teams_federation_inputs_gap(snapshot: Mapping[str, Any] | None) -> str | None:
    """Open federation means federation allowed with no allow list, so the allow list must have been read."""
    if snapshot is None:
        return "inputs_not_available"
    rows = [row for row in _records(snapshot, "teams_policy_objects") if row.get("source_name") == "tenantFederationConfiguration"]
    if not rows:
        return "federation_configuration_not_collected"
    for row in rows:
        federated = row.get("allow_federated_users")
        # A value that is not a boolean (a string, a number) is not a reading of the setting.
        if not isinstance(federated, bool):
            return "federation_setting_not_read"
        if federated is True and row.get("allowed_domains_state") in (None, FEDERATION_UNKNOWN):
            return "federation_allow_list_not_read"
    return None


def _break_glass_inputs_gap(snapshot: Mapping[str, Any] | None) -> str | None:
    """The emergency-access check needs accounts to look for: the operator's list or an inference."""
    if snapshot is None:
        return "inputs_not_available"
    # No assessment record means no Conditional Access policy was collected; the collector status says so.
    for record in _records(snapshot, break_glass.SECTION):
        if record.get("state") == break_glass.STATE_NO_ACCOUNTS:
            return "break_glass_accounts_not_identified"
        if record.get("state") == break_glass.STATE_UNRESOLVED:
            return "break_glass_accounts_unresolved"
    return None


def _inputs_gap(rule_id: str, snapshot: Mapping[str, Any] | None) -> str | None:
    """Why a rule's inputs were absent, or ``None`` when the evidence it reads is present."""
    namespace = rule_id.split(".", 1)[0]
    if rule_id == "intune_depth.policies_without_assignments":
        return _intune_assignment_inputs_gap(snapshot)
    if rule_id in SETTING_RULES:
        return setting_inputs_gap(rule_id, snapshot)
    if rule_id == _TEAMS_FEDERATION_RULE:
        return _teams_federation_inputs_gap(snapshot)
    if rule_id == _BREAK_GLASS_RULE:
        return _break_glass_inputs_gap(snapshot)
    if rule_id in _DEVICE_UNKNOWN_FIELDS:
        return _device_inputs_gap(snapshot, rule_id)
    if rule_id in _DEFENDER_RULE_FIELDS:
        return _defender_inputs_gap(snapshot, rule_id)
    if rule_id == _COMPLIANCE_PLATFORM_RULE:
        return _compliance_inputs_gap(snapshot)
    if rule_id in _UPDATE_RING_RULES:
        return _update_ring_inputs_gap(snapshot, rule_id)
    if rule_id in exchange_protection.RULES:
        return exchange_protection.inputs_gap(rule_id, snapshot)
    if rule_id in _RULE_VERDICT_CONTROLS:
        return _verdict_inputs_gap(snapshot, rule_id)
    if rule_id in _SIGNIN_ACTIVITY_RULES:
        return _signin_inputs_gap(snapshot, rule_id)
    if rule_id in _MFA_REGISTRATION_RULE_SCOPES:
        gap = _admin_set_inputs_gap(snapshot, rule_id) if rule_id in _ADMIN_SET_RULES else None
        return gap or _mfa_registration_inputs_gap(snapshot, rule_id)
    if rule_id in _ADMIN_SET_RULES:
        return _admin_set_inputs_gap(snapshot, rule_id)
    if rule_id == _SHAREPOINT_EXTERNAL_RULE:
        return _sharepoint_external_inputs_gap(snapshot)
    if rule_id == _RISKY_SIGNIN_RULE:
        return _risky_signin_inputs_gap(snapshot) or bounded_sample_gap(rule_id, snapshot)
    if rule_id in _GOOGLE_RULE_COLLECTORS:
        return _google_inputs_gap(snapshot, rule_id)
    if rule_id in _DETECTION_RULE_SIGNALS:
        return _detection_inputs_gap(snapshot, rule_id)
    if namespace == "dns_posture":
        return _dns_inputs_gap(snapshot, rule_id)
    if rule_id.startswith("exposure."):
        if snapshot is None:
            return "inputs_not_available"
        return None if _records(snapshot, "public_footprint_objects") else "public_footprint_not_collected"
    # Event-log rules (security.*) judge the newest events only; a log cut at its sample bound is not_assessed.
    return bounded_sample_gap(rule_id, snapshot)


def rule_inputs_gap(rule_id: str, snapshot: Mapping[str, Any] | None) -> str | None:
    """Why ``rule_id`` cannot be judged from ``snapshot`` (a run's normalized sections), or ``None``.

    This is the input check baseline alignment applies before it lets a rule read ``pass``: a verdict
    that is ``unknown``, an administrator set that is not ``complete``, sign-in data that was not
    collected. Run comparison and the gates use it so that a finding that vanished because its inputs
    went missing is never called resolved.
    """
    return _inputs_gap(rule_id, snapshot)


def _rule_evaluation(
    rule_id: str,
    open_by_rule: Mapping[str, list[str]],
    accepted_by_rule: Mapping[str, list[str]],
    complete_collectors: set[str],
    snapshot: Mapping[str, Any] | None = None,
    not_applicable_collectors: set[str] | None = None,
    licence_limited_collectors: Collection[str] = (),
    unevaluated: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Status of one rule. ``pass`` needs the rule to have been evaluated, not just no finding.

    ``licence_limited_collectors`` are collectors that are partial only because a licence refused a gated section
    (see ``_licence_limited_collectors``): ``identity`` then counts as complete, and ``identity_governance`` as not
    applicable. The sign-in rules, which read the refused section, are then judged on their inputs: they read
    ``not_assessed`` with ``signin_activity_unavailable`` for an account that has no sign-in data. ``unevaluated`` maps a
    rule to a reason it could not be judged that the findings themselves give (a Google check whose evidence
    Google did not return).
    """
    if open_by_rule.get(rule_id):
        return {"rule_id": rule_id, "status": "fail", "evaluated": True}
    if accepted_by_rule.get(rule_id):
        return {"rule_id": rule_id, "status": "accepted_risk", "evaluated": True}
    collectors = rule_evidence_collectors(rule_id)
    complete_for_rule = set(complete_collectors)
    not_applicable_for_rule = set(not_applicable_collectors or ())
    if "identity" in licence_limited_collectors:
        complete_for_rule.add("identity")
    if "identity_governance" in licence_limited_collectors:
        not_applicable_for_rule.add("identity_governance")
    if rule_id in INPUT_JUDGED_RULES:
        reason = _inputs_gap(rule_id, snapshot)
    elif not collectors:
        reason = "no_collector_mapping"
    else:
        incomplete = unmet_rule_collectors(rule_id, complete=complete_for_rule, not_applicable=not_applicable_for_rule)
        reason = f"collector_not_complete:{','.join(incomplete)}" if incomplete else _inputs_gap(rule_id, snapshot)
    if reason is None and "identity" in licence_limited_collectors and rule_id in _SIGNIN_ACTIVITY_RULES:
        # The sign-in read itself was refused (no Microsoft Entra ID P1): even a tenant with no account to judge
        # has no sign-in data, so a stale-account rule is never a pass here.
        reason = "signin_activity_unavailable"
    if reason is None and unevaluated:
        reason = unevaluated.get(rule_id)
    if reason is not None:
        return {"rule_id": rule_id, "status": _NOT_ASSESSED, "evaluated": False, "reason": reason}
    return {"rule_id": rule_id, "status": "pass", "evaluated": True}


def _control_status(rule_statuses: list[str]) -> str:
    if "fail" in rule_statuses:
        return "fail"
    if "accepted_risk" in rule_statuses:
        return "accepted_risk"
    if rule_statuses and all(status == "pass" for status in rule_statuses):
        return "pass"
    return _NOT_ASSESSED


def _bundle_platform(
    snapshot: Mapping[str, Any] | None,
    findings: list[dict[str, Any]] | None = None,
    coverage_ledger: list[dict[str, Any]] | None = None,
) -> str:
    """``google_workspace`` for a Google Workspace bundle, else ``""`` (Microsoft 365).

    The snapshot says which platform it is; failing that, a Google collector in the coverage ledger or a Google
    finding does.
    """
    state = snapshot.get("snapshot") if isinstance(snapshot, Mapping) else None
    if isinstance(state, Mapping) and state.get("platform"):
        return str(state["platform"])
    if any(str(row.get("collector") or "").startswith("google_") for row in coverage_ledger or [] if isinstance(row, Mapping)):
        return GOOGLE_PLATFORM
    if any(str(row.get("rule_id") or "").startswith("google.") for row in findings or [] if isinstance(row, Mapping)):
        return GOOGLE_PLATFORM
    return ""


def _platform_rules(
    rules_by_requirement: Mapping[str, Collection[str]], platform: str, shipped: bool
) -> dict[str, set[str]]:
    """The rules a Cyber Essentials section may list for this bundle's platform.

    A Google Workspace bundle lists only Google rules and a Microsoft 365 bundle only Microsoft ones: a Microsoft rule
    on a Google tenant reads ``not_assessed`` for a collector the run never had, and counts as a mapped rule that
    could never be evaluated. Google rules carry no mapping of their own in ``configs/control-mappings.json`` (they
    are mapped in ``auditex.google_workspace.findings``); their requirements come from
    ``_cyber_essentials_confidence``, so a Google rule that ran clean still appears, as evaluated.
    """
    google = platform == GOOGLE_PLATFORM
    rows: dict[str, set[str]] = {
        requirement: {rule for rule in rules if rule.startswith("google.") == google}
        for requirement, rules in rules_by_requirement.items()
    }
    if google and shipped:
        for rule_id, requirements in _shipped_cyber_essentials_confidence().items():
            if rule_id in _GOOGLE_RULE_COLLECTORS:
                for requirement in requirements:
                    rows.setdefault(requirement, set()).add(rule_id)
    return {requirement: rules for requirement, rules in rows.items() if rules}


def _findings_unevaluated_rules(findings: list[dict[str, Any]]) -> dict[str, str]:
    """Rules an open ``google.evidence_unknown`` finding says Google returned no usable evidence for."""
    reasons: dict[str, str] = {}
    for finding in findings:
        if finding.get("rule_id") != "google.evidence_unknown" or _finding_state(finding) != "open":
            continue
        returned = finding.get("returned_value")
        returned = returned if isinstance(returned, Mapping) else {}
        for rule_id in returned.get("rules_not_evaluated") or []:
            reasons.setdefault(str(rule_id), f"evidence_not_returned:{returned.get('check') or returned.get('field') or 'unknown'}")
    return reasons


def build_baseline_alignment(
    findings: list[dict[str, Any]],
    *,
    normalized_snapshot: Mapping[str, Any] | None = None,
    coverage_ledger: list[dict[str, Any]] | None = None,
    mappings: Mapping[str, Mapping[str, list[str]]] | None = None,
) -> dict[str, Any]:
    """Per-framework control status plus Secure Score reconciliation.

    A control is ``fail`` when any mapped rule has an open finding,
    ``accepted_risk`` when the only findings are waived, ``pass`` when every
    mapped rule was evaluated (its collectors completed and its inputs were
    present) without a finding, and ``not_assessed`` otherwise. Each rule status
    says whether the rule was ``evaluated`` and, if not, the ``reason``. Findings
    with no ``rule_id`` cannot reach a control and are counted in
    ``unmapped_findings``.
    """
    mapping_rows = mappings if mappings is not None else _shipped_control_mappings()
    all_open_by_rule, all_accepted_by_rule = _open_findings_by_rule(findings)
    exemptions = _threshold_exemptions(findings)
    complete = _complete_collectors(coverage_ledger)
    not_applicable = _not_applicable_collectors(coverage_ledger)
    licence_limited = _licence_limited_collectors(coverage_ledger)
    platform = _bundle_platform(normalized_snapshot, findings, coverage_ledger)
    unevaluated = _findings_unevaluated_rules(findings)
    basis_requirements = _shipped_verdict_basis_requirements() if mappings is None else {}

    frameworks: dict[str, Any] = {}
    for framework in BASELINE_FRAMEWORK_KEYS:
        # A finding that did not breach this framework's own bound is not an open finding for it.
        open_by_rule, accepted_by_rule = (
            _open_findings_by_rule(findings, exempt_ids=exemptions[framework])
            if exemptions.get(framework)
            else (all_open_by_rule, all_accepted_by_rule)
        )
        rules_by_control: dict[str, set[str]] = defaultdict(set)
        for rule_id, mapping in mapping_rows.items():
            for control_id in mapping.get(framework) or []:
                rules_by_control[str(control_id)].add(rule_id)
        for finding in findings:
            framework_mappings = finding.get("framework_mappings")
            rule_id = str(finding.get("rule_id") or "")
            if rule_id and isinstance(framework_mappings, Mapping):
                for control_id in framework_mappings.get(framework) or []:
                    rules_by_control[str(control_id)].add(rule_id)
        if framework == CE_FRAMEWORK_KEY:
            rules_by_control = _platform_rules(rules_by_control, platform, mappings is None)
            # Requirement rows come from the catalog, so requirements no rule maps to still appear.
            frameworks[framework] = build_cyber_essentials_section(
                framework_entry(framework),
                rules_by_control,
                evaluate=lambda rule_id: _rule_evaluation(
                    rule_id,
                    open_by_rule,
                    accepted_by_rule,
                    complete,
                    normalized_snapshot,
                    not_applicable,
                    licence_limited,
                    unevaluated,
                ),
                open_by_rule=open_by_rule,
                control_status=_control_status,
                status_order=_STATUS_ORDER,
                confidence=_shipped_cyber_essentials_confidence() if mappings is None else None,
            )
            continue
        controls = []
        for control_id in sorted(rules_by_control):
            rule_ids = sorted(rules_by_control[control_id])
            evaluations = [
                _rule_evaluation(
                    rule_id,
                    open_by_rule,
                    accepted_by_rule,
                    complete,
                    normalized_snapshot,
                    not_applicable,
                    licence_limited,
                    unevaluated,
                )
                for rule_id in rule_ids
            ]
            for index, evaluation in enumerate(evaluations):
                gap = (
                    _basis_requirement_gap(evaluation["rule_id"], framework, control_id, normalized_snapshot, basis_requirements)
                    if evaluation["status"] == "pass"
                    else None
                )
                if gap:
                    evaluations[index] = {"rule_id": evaluation["rule_id"], "status": _NOT_ASSESSED, "evaluated": False, "reason": gap}
            statuses = [evaluation["status"] for evaluation in evaluations]
            finding_ids = sorted({fid for rule_id in rule_ids for fid in open_by_rule.get(rule_id, [])})
            controls.append(
                {
                    "control_id": control_id,
                    "title": framework_control_title(framework, control_id),
                    "status": _control_status(statuses),
                    "rule_ids": rule_ids,
                    # A list, not a mapping: rule ids such as
                    # ``app_credentials.*`` would trip the bundle's
                    # sensitive-key scan if used as object keys.
                    "rule_statuses": evaluations,
                    "open_finding_count": len(finding_ids),
                    "finding_ids": finding_ids[:20],
                }
            )
        entry = framework_entry(framework)
        status_counts = _count(control["status"] for control in controls)
        frameworks[framework] = {
            "title": entry.get("title"),
            "version": entry.get("version"),
            "published": entry.get("published"),
            "status_counts": {status: status_counts.get(status, 0) for status in _STATUS_ORDER},
            "controls": controls,
        }
    return {
        "schema_version": BASELINE_ALIGNMENT_SCHEMA_VERSION,
        "catalog_verified_on": load_framework_catalog().get("verified_on"),
        "assessed_collectors": sorted(item for item in complete if item),
        "frameworks": frameworks,
        "unmapped_findings": unmapped_findings(findings),
        "secure_score": build_secure_score_reconciliation(findings, normalized_snapshot, mappings=mapping_rows),
    }
