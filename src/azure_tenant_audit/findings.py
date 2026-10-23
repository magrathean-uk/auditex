from __future__ import annotations

import json
import math
import os
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import endpoint_posture, exchange_protection, external_sharing, os_lifecycle
from .attack_graph import analyze_attack_graph
from .autopilot import build_board_report_sections
from .baselines import (
    SECURE_SCORE_LOW_THRESHOLD_PERCENT,
    build_baseline_alignment,
    intune_assignments_are_a_sample,
    latest_secure_score,
)
from .effective_admins import (
    ROUTE_DIRECT as _ADMIN_ROUTE_DIRECT,
    ROUTE_ELIGIBLE as _ADMIN_ROUTE_ELIGIBLE,
    ROUTE_GROUP as _ADMIN_ROUTE_GROUP,
    ROW_KIND as _ADMIN_ROW_KIND,
    SECTION as _ADMIN_SET_SECTION,
    STATE_COMPLETE as _ADMIN_SET_COMPLETE,
    SUMMARY_KIND as _ADMIN_SUMMARY_KIND,
)
from .break_glass import SECTION as _BREAK_GLASS_SECTION
from .identity_controls import SECTION as _IDENTITY_CONTROL_SECTION
from .resources import resolve_resource_path
from .waivers import apply_waivers, load_waivers


_PERMISSION_CLASSES = {"insufficient_permissions", "unauthenticated"}
_SERVICE_CLASSES = {
    "service_unavailable",
    "service_not_available",
    "not_found",
    "resource_not_found",
    "not_enabled",
    "license_required",
}

def _load_rule_registry(path: Path) -> dict[str, dict[str, Any]]:
    path = resolve_resource_path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(payload, dict):
        return {}
    registry: dict[str, dict[str, Any]] = {}
    for rule_id, value in payload.items():
        if isinstance(rule_id, str) and isinstance(value, dict):
            registry[rule_id] = value
    return registry


_FINDING_TEMPLATE_REGISTRY = _load_rule_registry(Path("configs/finding-templates.json"))
_CONTROL_MAPPING_REGISTRY = _load_rule_registry(Path("configs/control-mappings.json"))

_FALLBACK_FINDING_TEMPLATES = {
    "collector.issue.permission": {
        "risk_rating": "high",
        "description": "Auditex could not read the requested Microsoft 365 surface with the supplied identity.",
        "impact": "The report has a confirmed evidence gap for this area, so the related control cannot be asserted from this run.",
        "remediation": "Rerun with the minimum read permission required for the blocked surface, or exclude that surface from the agreed scope.",
        "references": ["Microsoft Graph permission review", "Auditex collector permission matrix"],
        "control_ids": ["AUDITEX-COLLECTOR-PERMISSION"],
        "expected_value": "The collector can read the requested surface.",
    },
    "collector.issue.service": {
        "risk_rating": "medium",
        "description": "The collector reached a tenant surface that is absent, disabled, not provisioned, or temporarily unavailable.",
        "impact": "Evidence for the affected service remains partial until the tenant state or service availability changes.",
        "remediation": "Confirm licensing and service availability, then rerun only the affected collector where appropriate.",
        "references": ["Microsoft service health", "Auditex collector diagnostics"],
        "control_ids": ["AUDITEX-COLLECTOR-SERVICE"],
        "expected_value": "The target service surface responds successfully.",
    },
    "collector.issue.collector": {
        "risk_rating": "medium",
        "description": "A collector finished with an operational error unrelated to normal permission or service-state handling.",
        "impact": "The affected evidence set may be missing, incomplete, or unsuitable for comparison.",
        "remediation": "Inspect the collector diagnostic row, fix the runtime or input condition, and rerun the collector.",
        "references": ["Auditex collector diagnostics"],
        "control_ids": ["AUDITEX-COLLECTOR-FAILURE"],
        "expected_value": "The collector completes without runtime errors.",
    },
    "coverage.gap": {
        "risk_rating": "high",
        "description": "One or more audit surfaces are blocked or partial, limiting assurance for that provider area.",
        "impact": "Important risks can remain unknown when required collectors cannot read the surface or only return partial evidence.",
        "remediation": "Resolve the affected collector permissions, scopes, service availability, or configuration, then rerun the audit.",
        "references": ["Auditex coverage diagnostics", "Auditex collector permission matrix"],
        "control_ids": ["AUDITEX-COVERAGE-GAP"],
        "expected_value": "All in-scope audit surfaces complete successfully or have an accepted scope decision.",
    },
    "sharepoint.broad_link": {
        "risk_rating": "high",
        "description": "SharePoint or OneDrive evidence indicates a sharing link with broad audience reach.",
        "impact": "Content may be reachable by users outside the intended collaboration boundary.",
        "remediation": "Reduce the sharing scope, remove stale broad links, and retest affected sites.",
        "references": ["SharePoint sharing policy review"],
        "control_ids": ["AUDITEX-SPO-BROAD-LINK"],
        "expected_value": "External and organization-wide links are absent or explicitly approved.",
    },
    "sharepoint.external_principal": {
        "risk_rating": "high",
        "description": "SharePoint or OneDrive evidence indicates direct access for a principal outside the tenant domains.",
        "impact": "Content may be exposed to external users or groups outside the approved collaboration boundary.",
        "remediation": "Remove unapproved external principals from the item or site permission set and retest affected sites.",
        "references": ["SharePoint permissions review"],
        "control_ids": ["AUDITEX-SPO-EXTERNAL-PRINCIPAL"],
        "expected_value": "Direct SharePoint and OneDrive permissions are limited to approved tenant principals.",
    },
    "exchange.transport_external_redirect": {
        "risk_rating": "critical",
        "description": "An Exchange transport rule redirects or copies mail to a recipient outside accepted tenant domains.",
        "impact": "Transport-level forwarding can exfiltrate many users' mail before mailbox rules or user visibility expose it.",
        "remediation": "Remove the external recipient from the transport rule or disable the rule until the exception is approved.",
        "references": ["Exchange transport rule review"],
        "control_ids": ["AUDITEX-EXO-TRANSPORT-EXTERNAL-REDIRECT"],
        "expected_value": "Transport rules do not redirect or copy mail to external recipients.",
    },
    "exchange.remote_domain_auto_forward_enabled": {
        "risk_rating": "high",
        "description": "An Exchange remote-domain policy permits automatic forwarding outside the tenant.",
        "impact": "Tenant-level auto-forwarding allows mailbox rules and user settings to exfiltrate mail without a transport exception.",
        "remediation": "Disable automatic forwarding on the default remote-domain policy and approve only specific business exceptions.",
        "references": ["Exchange Online remote domain review", "MITRE ATT&CK T1114.003"],
        "control_ids": ["AUDITEX-EXO-REMOTE-DOMAIN-AUTO-FWD"],
        "expected_value": "Remote-domain policies do not allow automatic forwarding to external domains by default.",
    },
    "identity.user_mfa_not_registered": {
        "risk_rating": "medium",
        "description": "A non-admin member user has not registered an MFA method in the authentication method registration report. This reports registration only, not whether MFA is required at sign-in.",
        "impact": "A user with no MFA method cannot satisfy an MFA requirement, so a password alone may be enough to sign in wherever MFA is not enforced.",
        "remediation": "Have the user register an MFA method, and confirm separately that MFA is enforced through Conditional Access or security defaults.",
        "references": ["Microsoft Entra authentication method registration report"],
        "control_ids": ["AUDITEX-USER-MFA-NOT-REGISTERED"],
        "expected_value": "Active member users are registered for MFA.",
    },
    "security.risky_signin": {
        "risk_rating": "high",
        "description": "Microsoft Entra sign-in logs show a risky sign-in event.",
        "impact": "Risky sign-ins can indicate credential theft, impossible travel, anomalous token use, or other account-compromise signals.",
        "remediation": "Investigate the sign-in, revoke sessions where needed, reset credentials, and confirm conditional access controls responded.",
        "references": ["Microsoft Entra risky sign-ins", "Microsoft Graph signIn risk evidence"],
        "control_ids": ["AUDITEX-SIGNIN-RISKY"],
        "expected_value": "Observed sign-ins have no active risk state or elevated risk level.",
    },
    "security.privilege_change_event": {
        "risk_rating": "high",
        "description": "Microsoft Entra directory audit logs show an administrative role or privilege change.",
        "impact": "Unexpected privileged-role changes can indicate persistence setup, emergency access drift, or active tenant compromise.",
        "remediation": "Review the initiator, target role, approval trail, and recent sign-ins; revoke unauthorized role assignments.",
        "references": ["Microsoft Entra directory audit logs", "Privileged role assignment review"],
        "control_ids": ["AUDITEX-PRIVILEGE-CHANGE-EVENT"],
        "expected_value": "Privileged role changes are approved, expected, and traceable.",
    },
    "intune.device_stale_sync": {
        "risk_rating": "medium",
        "description": "A managed Intune device has not synced recently.",
        "impact": "Stale device sync can hide missing security baselines, device loss, deprovisioning gaps, or stale access assumptions.",
        "remediation": "Investigate stale managed devices, retire devices no longer in use, and confirm conditional access blocks unknown device posture.",
        "references": ["Microsoft Intune managed device inventory"],
        "control_ids": ["AUDITEX-INTUNE-DEVICE-STALE-SYNC"],
        "expected_value": "Managed devices sync within the approved recency window.",
    },
    "app_consent.high_privilege": {
        "risk_rating": "high",
        "description": "Application consent evidence shows sensitive scopes or weak ownership governance.",
        "impact": "Over-privileged or unowned application consent can become a durable path to tenant data exposure.",
        "remediation": "Review the consent grant, remove unused scopes, and assign accountable owners before accepting the application.",
        "references": ["Application consent governance review"],
        "control_ids": ["AUDITEX-APP-CONSENT-HIGH-PRIVILEGE"],
        "expected_value": "Sensitive app grants are approved, current, and owned.",
    },
}

_CATEGORY_DEFAULTS = {
    "permission": {
        "description": "Audit evidence for this surface is incomplete because the active identity could not read one or more required endpoints.",
        "impact": "Conclusions for the affected control area are limited to observed data and cannot be treated as complete assurance.",
        "remediation": "Grant the minimum required read permission or rerun with a profile that is approved for this surface.",
        "expected_value": "Collector reads the target surface successfully.",
    },
    "service": {
        "description": "The collector hit a tenant service surface that was unavailable, not provisioned, or not enabled during this run.",
        "impact": "The affected service area remains partially evidenced and may require a scoped rerun after tenant or service changes.",
        "remediation": "Confirm service availability, licensing, and endpoint readiness, then rerun the affected collector.",
        "expected_value": "Target service endpoint returns usable data.",
    },
    "collector": {
        "description": "The collector completed with an operational issue that reduced evidence quality for this surface.",
        "impact": "Collected data for the affected surface may be partial, stale, or missing.",
        "remediation": "Review the collector error and rerun the affected surface after fixing the runtime condition.",
        "expected_value": "Collector completes without runtime errors.",
    },
    "identity": {
        "description": "Identity control evidence indicates a configuration that should be reviewed.",
        "impact": "Identity control strength may be lower than intended for the affected objects.",
        "remediation": "Review the affected identity control and apply the documented secure baseline.",
        "expected_value": "Identity control aligns with the intended baseline.",
    },
}

def _category_for(error_class: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "permission"
    if error_class in _SERVICE_CLASSES:
        return "service"
    return "collector"


def _severity_for(error_class: str | None, status: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "high"
    if error_class == "license_required":
        # A licence the tenant does not hold limits the evidence; it is not a gap in the audit identity's access.
        return "medium"
    if status == "failed":
        return "high"
    return "medium"


def _template_for(rule_id: str) -> dict[str, Any]:
    template = deepcopy(_FALLBACK_FINDING_TEMPLATES.get(rule_id, {}))
    registry_template = _FINDING_TEMPLATE_REGISTRY.get(rule_id)
    if registry_template:
        template.update(deepcopy(registry_template))
    return template


def _framework_mappings_for(rule_id: str) -> dict[str, list[str]]:
    mappings = _CONTROL_MAPPING_REGISTRY.get(rule_id)
    if not mappings:
        return {}
    return deepcopy(mappings)


def _metadata_for(rule_id: str) -> dict[str, Any]:
    metadata = _template_for(rule_id)
    framework_mappings = _framework_mappings_for(rule_id)
    if framework_mappings:
        metadata["framework_mappings"] = framework_mappings
    return metadata


def _canonical_severity(value: Any, *, fallback: str = "medium") -> str:
    text = str(value or fallback).strip().lower()
    return text if text in {"low", "medium", "high", "critical"} else fallback


_RISK_WEIGHTS = {"critical": 6, "high": 4, "medium": 2, "low": 1, "info": 0, "informational": 0}


# Each grade owns a score band; the worst open severity sets the floor and volume moves the score
# within the band without ever saturating, so fixing findings always shows up in the score.
_RISK_BAND_FLOORS = {"critical": 70, "high": 40, "medium": 15, "low": 1}
_RISK_BAND_WIDTH = 29
_RISK_VOLUME_SCALE = 80.0


def _risk_grade(score: int) -> str:
    if score >= _RISK_BAND_FLOORS["critical"]:
        return "critical"
    if score >= _RISK_BAND_FLOORS["high"]:
        return "high"
    if score >= _RISK_BAND_FLOORS["medium"]:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def _risk_score(counts: Counter, open_weight: int) -> int:
    worst = next((severity for severity in ("critical", "high", "medium", "low") if counts.get(severity)), None)
    if worst is None:
        return 0
    volume = round(_RISK_BAND_WIDTH * (1 - math.exp(-open_weight / _RISK_VOLUME_SCALE)))
    return min(100, _RISK_BAND_FLOORS[worst] + volume)


def build_risk_rollup(findings: list[dict[str, Any]]) -> dict[str, Any]:
    open_findings = [item for item in findings if str(item.get("status") or "open") == "open"]
    counts = Counter(_canonical_severity(item.get("severity"), fallback="info") for item in open_findings)
    open_weight = sum(_RISK_WEIGHTS.get(_canonical_severity(item.get("severity"), fallback="info"), 0) for item in open_findings)
    score = _risk_score(counts, open_weight)

    def sort_key(item: dict[str, Any]) -> tuple[int, str]:
        severity = _canonical_severity(item.get("severity"), fallback="info")
        return (-_RISK_WEIGHTS.get(severity, 0), str(item.get("id") or ""))

    return {
        "score": score,
        "grade": _risk_grade(score),
        "open_weight": open_weight,
        "counts_by_open_severity": {key: counts[key] for key in ("critical", "high", "medium", "low", "info") if counts.get(key)},
        "top_open_findings": [
            {
                "id": item.get("id"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "category": item.get("category"),
            }
            for item in sorted(open_findings, key=sort_key)[:5]
        ],
    }


def _coverage_gap_actions(coverage_gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for gap in coverage_gaps:
        surface = str(gap.get("surface") or "unknown")
        severity = _canonical_severity(gap.get("severity"), fallback="medium")
        status = str(gap.get("status") or "partial")
        actions.append(
            {
                "id": f"coverage_gap:{surface}",
                "rule_id": "coverage.gap",
                "title": f"Resolve {surface} coverage gap",
                "severity": severity,
                "category": "coverage",
                "impact": f"{surface} conclusions are {status} and cannot be treated as complete assurance.",
                "remediation": "Resolve the blocked or partial collectors, then rerun the audit for this surface.",
                "status": "open",
                "surface": surface,
                "coverage_status": status,
                "collectors": gap.get("collectors") or [],
                "error_classes": gap.get("error_classes") or [],
                "message": gap.get("message"),
            }
        )
    return actions


def _active_coverage_gaps(coverage_gaps: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    accepted_collectors = {
        str(item.get("collector"))
        for item in findings
        if str(item.get("rule_id") or "").startswith("collector.issue.")
        and str(item.get("status") or "open") != "open"
        and item.get("collector")
    }
    active: list[dict[str, Any]] = []
    for gap in coverage_gaps:
        collectors = [str(item) for item in gap.get("collectors") or [] if str(item)]
        if collectors and all(collector in accepted_collectors for collector in collectors):
            continue
        active.append(gap)
    return active


def _action_sort_key(item: dict[str, Any]) -> tuple[int, str]:
    severity = _canonical_severity(item.get("severity"), fallback="info")
    return (-_RISK_WEIGHTS.get(severity, 0), str(item.get("id") or ""))


def _risk_with_coverage_gaps(findings: list[dict[str, Any]], coverage_gaps: list[dict[str, Any]]) -> dict[str, Any]:
    risk = build_risk_rollup(findings)
    active_gaps = _active_coverage_gaps(coverage_gaps, findings)
    if not active_gaps:
        return risk
    coverage_gap_weight = sum(
        _RISK_WEIGHTS.get(_canonical_severity(gap.get("severity"), fallback="medium"), 0)
        for gap in active_gaps
    )
    # A surface we could not verify counts like an open finding of the gap's severity.
    counts = Counter(_canonical_severity(item.get("severity"), fallback="info") for item in findings if str(item.get("status") or "open") == "open")
    counts.update(_canonical_severity(gap.get("severity"), fallback="medium") for gap in active_gaps)
    score = _risk_score(counts, int(risk.get("open_weight") or 0) + coverage_gap_weight)
    risk.update(
        {
            "score": score,
            "grade": _risk_grade(score),
            "coverage_gap_count": len(active_gaps),
            "coverage_gap_weight": coverage_gap_weight,
        }
    )
    return risk


def _evidence_ref(
    *,
    artifact_path: str,
    artifact_kind: str,
    collector: str,
    record_key: str,
    source_name: str | None = None,
    json_pointer: str | None = None,
    jsonl_line: int | None = None,
    endpoint: str | None = None,
    response_status: str | None = None,
    query_params: dict[str, Any] | None = None,
    collected_at: str | None = None,
    content_hash: str | None = None,
) -> dict[str, Any]:
    ref = {
        "artifact_path": artifact_path,
        "artifact_kind": artifact_kind,
        "collector": collector,
        "record_key": record_key,
    }
    if source_name:
        ref["source_name"] = source_name
    if json_pointer:
        ref["json_pointer"] = json_pointer
    if jsonl_line is not None:
        ref["jsonl_line"] = jsonl_line
    if endpoint:
        ref["endpoint"] = endpoint
    if response_status:
        ref["response_status"] = response_status
    if query_params:
        ref["query_params"] = query_params
    if collected_at:
        ref["collected_at"] = collected_at
    if content_hash:
        ref["content_hash"] = content_hash
    return ref


# A finding about a set of objects cites at most this many of their records.
_AGGREGATE_REF_LIMIT = 25


def _normalized_evidence_refs(section: str, record: dict[str, Any], collector: str) -> list[dict[str, Any]]:
    record_key = str(record.get("key") or record.get("id") or f"{section}:record")
    return [
        _evidence_ref(
            artifact_path=f"normalized/{section}.json",
            artifact_kind="normalized_json",
            collector=collector,
            record_key=record_key,
            source_name=str(record.get("source_name") or section),
        )
    ]


def _finalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(finding)
    if not str(result.get("rule_id") or "").strip():
        # A finding with no rule cannot reach a framework control, a template or a baseline status.
        raise ValueError(f"Finding {result.get('id')!r} has no rule_id; every finding needs a rule and a template.")
    severity = _canonical_severity(result.get("severity"))
    result["severity"] = severity
    result["risk_rating"] = severity
    category = str(result.get("category") or "collector")
    defaults = _CATEGORY_DEFAULTS.get(category, _CATEGORY_DEFAULTS["collector"])
    result["description"] = result.get("description") or defaults["description"]
    result["impact"] = result.get("impact") or defaults["impact"]
    result["remediation"] = result.get("remediation") or defaults["remediation"]
    result["expected_value"] = result.get("expected_value") or defaults["expected_value"]
    if "returned_value" not in result:
        result["returned_value"] = None
    refs = result.get("references")
    result["references"] = list(refs) if isinstance(refs, list) else []
    affected = result.get("affected_objects")
    result["affected_objects"] = [str(item) for item in affected] if isinstance(affected, list) else []
    evidence_refs = result.get("evidence_refs")
    normalized_refs = [dict(item) for item in evidence_refs if isinstance(item, dict)] if isinstance(evidence_refs, list) else []
    if not normalized_refs:
        collector = str(result.get("collector") or "unknown")
        # A builder that cites nothing gets the collector's coverage ledger row, which shows what the
        # collector did; ``evidence_ref_generated`` marks the reference as a stand-in, not a citation.
        normalized_refs = [
            _evidence_ref(
                artifact_path="normalized/coverage_ledger.json",
                artifact_kind="normalized_json",
                collector=collector,
                record_key=f"coverage_ledger:{collector}",
                source_name="coverage_ledger",
            )
        ]
        result["evidence_ref_generated"] = True
    result["evidence_refs"] = normalized_refs
    result.setdefault("control_ids", [])
    return result


def _rule_id_for(error_class: str | None) -> str:
    if error_class in _PERMISSION_CLASSES:
        return "collector.issue.permission"
    if error_class in _SERVICE_CLASSES:
        return "collector.issue.service"
    return "collector.issue.collector"


_APP_CREDENTIAL_EXPIRY_WARNING_DAYS = 30
_MULTI_TENANT_AUDIENCES = {
    "AzureADMultipleOrgs",
    "AzureADandPersonalMicrosoftAccount",
    "PersonalMicrosoftAccount",
}


def _parse_iso_datetime(value: Any) -> "datetime | None":
    from datetime import datetime

    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _credential_expiry_state(
    end_date_time: Any, *, warning_days: int = _APP_CREDENTIAL_EXPIRY_WARNING_DAYS
) -> tuple[str | None, int | None]:
    from datetime import datetime, timezone

    parsed = _parse_iso_datetime(end_date_time)
    if parsed is None:
        return None, None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    delta = parsed - datetime.now(tz=timezone.utc)
    days = int(delta.total_seconds() // 86400)
    if delta.total_seconds() < 0:
        return "expired", days
    if days <= warning_days:
        return "expiring", days
    return "ok", days


def _earliest_state(
    credentials: list[Any],
    target_state: str,
    *,
    warning_days: int = _APP_CREDENTIAL_EXPIRY_WARNING_DAYS,
) -> dict[str, Any] | None:
    """Find the credential whose expiry-state matches ``target_state`` and has the
    smallest days-remaining (most urgent / most expired)."""
    chosen: dict[str, Any] | None = None
    for credential in credentials:
        if not isinstance(credential, dict):
            continue
        state, days = _credential_expiry_state(
            credential.get("end_date_time"), warning_days=warning_days
        )
        if state != target_state:
            continue
        annotated = {
            **credential,
            "expiry_state": state,
            "expiry_days_remaining": days,
        }
        if chosen is None:
            chosen = annotated
            continue
        chosen_days = chosen.get("expiry_days_remaining")
        if days is not None and chosen_days is not None and days < chosen_days:
            chosen = annotated
    return chosen


def _first_long_validity_secret(credentials: list[Any]) -> dict[str, Any] | None:
    """Detect a password credential whose total validity exceeds 2 years OR
    is open-ended (missing ``end_date_time``)."""
    for credential in credentials:
        if not isinstance(credential, dict):
            continue
        end = _parse_iso_datetime(credential.get("end_date_time"))
        start = _parse_iso_datetime(credential.get("start_date_time"))
        if end is None:
            return {**credential, "validity_days": None, "open_ended": True}
        if start is None:
            continue
        validity_days = int((end - start).total_seconds() // 86400)
        if validity_days > _SECRET_LONG_VALIDITY_DAYS:
            return {**credential, "validity_days": validity_days, "open_ended": False}
    return None


def _is_credential_dormant(item: dict[str, Any]) -> bool:
    """Return True iff the application has been silent for > 1 year and the collector
    actually fetched signInActivity (signin_data_available=True). Without that flag,
    we cannot distinguish 'never signed in' from 'we never asked' and stay silent
    rather than flooding findings with false positives.
    """
    from datetime import datetime, timedelta, timezone

    if not item.get("signin_data_available"):
        return False
    last_signin = _parse_iso_datetime(item.get("last_signin_at"))
    created = _parse_iso_datetime(item.get("created_date_time"))
    if created is None:
        return False
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    one_year_ago = datetime.now(tz=timezone.utc) - timedelta(days=365)
    if created > one_year_ago:
        return False
    if last_signin is None:
        # Old app + collector tried + got null → dormant.
        return True
    if last_signin.tzinfo is None:
        last_signin = last_signin.replace(tzinfo=timezone.utc)
    return last_signin < one_year_ago


_CERTIFICATE_EXPIRY_WARNING_DAYS = 30
_SECRET_LONG_VALIDITY_DAYS = 730  # 2 years; Microsoft default cap is 24 months.


def _build_app_credential_findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    findings: list[dict[str, Any]] = []
    object_id = str(item.get("id") or "").strip()
    if not object_id:
        return findings
    affected = [item.get("display_name") or item.get("app_id") or object_id]
    evidence_refs = _normalized_evidence_refs(
        "application_credential_objects", item, "app_credentials"
    )

    earliest_secret_expired = _earliest_state(item.get("password_credentials") or [], "expired")
    earliest_secret_expiring = _earliest_state(
        item.get("password_credentials") or [], "expiring"
    )
    earliest_cert_expired = _earliest_state(item.get("key_credentials") or [], "expired")
    earliest_cert_expiring = _earliest_state(
        item.get("key_credentials") or [],
        "expiring",
        warning_days=_CERTIFICATE_EXPIRY_WARNING_DAYS,
    )

    if earliest_secret_expired is not None:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:secret_expired",
                    "rule_id": "app_credentials.secret_expired",
                    "severity": "critical",
                    "category": "application",
                    "title": "Application secret is expired",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": earliest_secret_expired,
                    "evidence_refs": evidence_refs,
                    "returned_value": earliest_secret_expired.get("expiry_days_remaining"),
                    **_metadata_for("app_credentials.secret_expired"),
                }
            )
        )
    elif earliest_secret_expiring is not None:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:secret_expiring",
                    "rule_id": "app_credentials.secret_expiring",
                    "severity": "high",
                    "category": "application",
                    "title": "Application secret is expiring soon",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": earliest_secret_expiring,
                    "evidence_refs": evidence_refs,
                    "returned_value": earliest_secret_expiring.get("expiry_days_remaining"),
                    **_metadata_for("app_credentials.secret_expiring"),
                }
            )
        )

    if earliest_cert_expired is not None:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:certificate_expired",
                    "rule_id": "app_credentials.certificate_expired",
                    "severity": "high",
                    "category": "application",
                    "title": "Application certificate is expired",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": earliest_cert_expired,
                    "evidence_refs": evidence_refs,
                    "returned_value": earliest_cert_expired.get("expiry_days_remaining"),
                    **_metadata_for("app_credentials.certificate_expired"),
                }
            )
        )
    elif earliest_cert_expiring is not None:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:certificate_expiring",
                    "rule_id": "app_credentials.certificate_expiring",
                    "severity": "medium",
                    "category": "application",
                    "title": "Application certificate is expiring within 30 days",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": earliest_cert_expiring,
                    "evidence_refs": evidence_refs,
                    "returned_value": earliest_cert_expiring.get("expiry_days_remaining"),
                    **_metadata_for("app_credentials.certificate_expiring"),
                }
            )
        )

    long_validity_secret = _first_long_validity_secret(item.get("password_credentials") or [])
    if long_validity_secret is not None:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:secret_long_validity",
                    "rule_id": "app_credentials.secret_long_validity",
                    "severity": "high",
                    "category": "application",
                    "title": "Application secret has long or open-ended validity",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": long_validity_secret,
                    "evidence_refs": evidence_refs,
                    "returned_value": long_validity_secret.get("validity_days"),
                    **_metadata_for("app_credentials.secret_long_validity"),
                }
            )
        )

    if _is_credential_dormant(item):
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:credential_dormant",
                    "rule_id": "app_credentials.credential_dormant",
                    "severity": "low",
                    "category": "application",
                    "title": "Application has not signed in for over 365 days",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": {
                        "created_date_time": item.get("created_date_time"),
                        "last_signin_at": item.get("last_signin_at"),
                    },
                    "evidence_refs": evidence_refs,
                    **_metadata_for("app_credentials.credential_dormant"),
                }
            )
        )

    insecure_redirects = [
        uri
        for uri in (item.get("redirect_uris") or [])
        if isinstance(uri, dict)
        and uri.get("scheme") == "http"
        and not uri.get("is_localhost")
    ]
    if insecure_redirects:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:redirect_insecure",
                    "rule_id": "app_credentials.redirect_insecure",
                    "severity": "high",
                    "category": "application",
                    "title": "Application has insecure redirect URI",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": {"redirect_uris": insecure_redirects},
                    "evidence_refs": evidence_refs,
                    "returned_value": [uri.get("uri") for uri in insecure_redirects],
                    **_metadata_for("app_credentials.redirect_insecure"),
                }
            )
        )

    owner_count = item.get("owner_count")
    if owner_count is not None and owner_count == 0:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:no_owner",
                    "rule_id": "app_credentials.no_owner",
                    "severity": "medium",
                    "category": "application",
                    "title": "Application has no owners",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("app_credentials.no_owner"),
                }
            )
        )

    if str(item.get("sign_in_audience") or "") in _MULTI_TENANT_AUDIENCES:
        findings.append(
            _finalize_finding(
                {
                    "id": f"app_credentials:{object_id}:multi_tenant_audience",
                    "rule_id": "app_credentials.multi_tenant_audience",
                    "severity": "medium",
                    "category": "application",
                    "title": "Application accepts multi-tenant or personal-account sign-ins",
                    "status": "open",
                    "collector": "app_credentials",
                    "affected_objects": affected,
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    "returned_value": item.get("sign_in_audience"),
                    **_metadata_for("app_credentials.multi_tenant_audience"),
                }
            )
        )

    return findings


def _build_cross_tenant_default_findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    findings: list[dict[str, Any]] = []
    evidence_refs = _normalized_evidence_refs("cross_tenant_default_objects", item, "cross_tenant_access")

    if str(item.get("b2b_direct_connect_inbound_access") or "").lower() == "allowed":
        findings.append(
            _finalize_finding(
                {
                    "id": "cross_tenant_access:default:b2b_direct_connect_inbound_open",
                    "rule_id": "cross_tenant_access.default_b2b_direct_connect_inbound_open",
                    "severity": "high",
                    "category": "external_access",
                    "title": "Default B2B Direct Connect inbound access is allowed",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": ["default"],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.default_b2b_direct_connect_inbound_open"),
                }
            )
        )

    if str(item.get("b2b_collaboration_outbound_access") or "").lower() == "allowed":
        findings.append(
            _finalize_finding(
                {
                    "id": "cross_tenant_access:default:b2b_collaboration_outbound_open",
                    "rule_id": "cross_tenant_access.default_b2b_collaboration_outbound_open",
                    "severity": "medium",
                    "category": "external_access",
                    "title": "Default B2B Collaboration outbound access is allowed without partner-specific scoping",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": ["default"],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.default_b2b_collaboration_outbound_open"),
                }
            )
        )

    # Previously-unflagged combinations (A5):

    if str(item.get("b2b_collaboration_inbound_access") or "").lower() == "allowed":
        findings.append(
            _finalize_finding(
                {
                    "id": "cross_tenant_access:default:b2b_collaboration_inbound_open",
                    "rule_id": "cross_tenant_access.default_b2b_collaboration_inbound_open",
                    "severity": "high",
                    "category": "external_access",
                    "title": "Default B2B Collaboration inbound access is allowed for any external tenant",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": ["default"],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.default_b2b_collaboration_inbound_open"),
                }
            )
        )

    if str(item.get("b2b_direct_connect_outbound_access") or "").lower() == "allowed":
        findings.append(
            _finalize_finding(
                {
                    "id": "cross_tenant_access:default:b2b_direct_connect_outbound_open",
                    "rule_id": "cross_tenant_access.default_b2b_direct_connect_outbound_open",
                    "severity": "medium",
                    "category": "external_access",
                    "title": "Default B2B Direct Connect outbound access is allowed without partner scoping",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": ["default"],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.default_b2b_direct_connect_outbound_open"),
                }
            )
        )

    if item.get("automatic_user_consent_inbound_allowed"):
        findings.append(
            _finalize_finding(
                {
                    "id": "cross_tenant_access:default:auto_user_consent_inbound_enabled",
                    "rule_id": "cross_tenant_access.auto_user_consent_inbound_enabled",
                    "severity": "medium",
                    "category": "external_access",
                    "title": "Automatic user consent is enabled for inbound external collaborations",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": ["default"],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.auto_user_consent_inbound_enabled"),
                }
            )
        )

    if item.get("automatic_user_consent_outbound_allowed"):
        findings.append(
            _finalize_finding(
                {
                    "id": "cross_tenant_access:default:auto_user_consent_outbound_enabled",
                    "rule_id": "cross_tenant_access.auto_user_consent_outbound_enabled",
                    "severity": "low",
                    "category": "external_access",
                    "title": "Automatic user consent is enabled for outbound collaborations",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": ["default"],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.auto_user_consent_outbound_enabled"),
                }
            )
        )

    return findings


def _build_cross_tenant_partner_findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    if item.get("is_service_provider"):
        return []
    tenant_id = str(item.get("tenant_id") or item.get("id") or "")
    if not tenant_id:
        return []
    findings: list[dict[str, Any]] = []
    evidence_refs = _normalized_evidence_refs("cross_tenant_partner_objects", item, "cross_tenant_access")
    direct_inbound_allowed = str(item.get("b2b_direct_connect_inbound_access") or "").lower() == "allowed"

    if direct_inbound_allowed and not item.get("inbound_trust_mfa_accepted"):
        findings.append(
            _finalize_finding(
                {
                    "id": f"cross_tenant_access:partner:{tenant_id}:b2b_direct_connect_no_mfa",
                    "rule_id": "cross_tenant_access.partner_inbound_no_mfa",
                    "severity": "high",
                    "category": "external_access",
                    "title": "Partner inbound B2B Direct Connect accepts users without MFA trust",
                    "status": "open",
                    "collector": "cross_tenant_access",
                    "affected_objects": [tenant_id],
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("cross_tenant_access.partner_inbound_no_mfa"),
                }
            )
        )

    return findings


def _effective_admins(normalized_snapshot: dict[str, Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """The effective administrator set's summary record and its principal rows (see ``effective_admins``)."""
    records = (normalized_snapshot.get(_ADMIN_SET_SECTION) or {}).get("records") or []
    summary = next((item for item in records if item.get("kind") == _ADMIN_SUMMARY_KIND), None)
    return summary, [item for item in records if item.get("kind") == _ADMIN_ROW_KIND]


def _counted_admin_rows(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Administrators that count as admins: users (and principals no inventory resolves), not groups or service principals."""
    return [row for row in _effective_admins(normalized_snapshot)[1] if row.get("counted") and row.get("principal_id")]


_ADMIN_RECORD_COLLECTORS = {
    "role_assignments": "identity",
    "governance_objects": "identity_governance",
    "group_membership_edges": "identity",
}


def _admin_record_refs(roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """References to the records (assignments, schedules, memberships) these roles come from."""
    refs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in roles:
        for record in entry.get("records") or []:
            section, key = str(record.get("section") or ""), str(record.get("key") or "")
            if section and key and (section, key) not in seen:
                seen.add((section, key))
                refs.extend(_normalized_evidence_refs(section, {"key": key}, _ADMIN_RECORD_COLLECTORS.get(section, "identity")))
    return refs


def _admin_row_refs(row: dict[str, Any], roles: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """The administrator row and the records behind its roles (all of them, or just ``roles``)."""
    return [
        *_normalized_evidence_refs(_ADMIN_SET_SECTION, row, "identity"),
        *_admin_record_refs(row.get("roles") or [] if roles is None else roles),
    ]


def _global_admin_bounds(rule_id: str) -> list[dict[str, Any]]:
    """The Global Administrator count bound of each framework control the rule maps to.

    ``configs/control-mappings.json`` (``_rule_thresholds``) holds one bound per framework: CIS
    allows two to four, SCuBA two to eight. A bound is kept only for a framework the rule maps, and
    only with the controls the rule maps for it.
    """
    mapped = _framework_mappings_for(rule_id)
    thresholds = (_CONTROL_MAPPING_REGISTRY.get("_rule_thresholds") or {}).get("global_administrator_count") or []
    bounds: list[dict[str, Any]] = []
    for item in thresholds:
        if not isinstance(item, dict):
            continue
        framework = str(item.get("framework") or "")
        controls = [control for control in item.get("controls") or [] if control in (mapped.get(framework) or [])]
        if framework and controls:
            bounds.append({**item, "controls": controls})
    return bounds


def _framework_thresholds(bounds: list[dict[str, Any]], observed: int, breached: Any) -> list[dict[str, Any]]:
    """One row per framework bound: the bound, what was observed and whether this finding breaches it."""
    return [
        {
            "framework": bound["framework"],
            "control_ids": list(bound["controls"]),
            "metric": "global_administrator_count",
            "observed": observed,
            "minimum": bound.get("minimum"),
            "maximum": bound.get("maximum"),
            "breached": bool(breached(bound)),
        }
        for bound in bounds
    ]


def _bounds_text(bounds: list[dict[str, Any]]) -> str:
    return "; ".join(
        f"{bound.get('minimum')} to {bound.get('maximum')} ({bound.get('label') or bound['framework']})" for bound in bounds
    )


def _build_admin_resilience_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Global Administrator findings over the effective administrator set.

    The set (``normalized/effective_admin_set.json``) holds users only, by every route: direct,
    PIM-eligible and through a role-assignable group. When it is ``unknown`` (a source was blocked,
    truncated or not run) a count of one proves nothing, so the singleton rule stays silent and the
    diagnostic ``identity.admin_set_unverified`` is raised; a breach already visible in what was
    read (a disabled admin, too many admins) is still reported.
    """
    summary, _rows = _effective_admins(normalized_snapshot)
    if summary is None:
        return []
    users = {
        str(item.get("id")).lower(): item
        for item in ((normalized_snapshot.get("users") or {}).get("records") or [])
        if item.get("id")
    }
    users_by_upn = {
        str(item.get("principal_name") or "").lower(): item
        for item in users.values()
        if item.get("principal_name")
    }
    registrations: dict[str, dict[str, Any]] = {}
    for item in ((normalized_snapshot.get("auth_method_registration_objects") or {}).get("records") or []):
        if item.get("id"):
            registrations[str(item.get("id")).lower()] = item
        if item.get("user_principal_name"):
            registrations[str(item.get("user_principal_name")).lower()] = item
    ga_rows = {
        str(row["principal_id"]): row
        for row in _counted_admin_rows(normalized_snapshot)
        if row.get("global_administrator")
    }
    principal_ids = sorted(ga_rows)

    def assignment_refs(for_principals: list[str]) -> list[dict[str, Any]]:
        """References to the Global Administrator rows, and the records behind them, of these principals."""
        refs: list[dict[str, Any]] = []
        for principal in for_principals:
            row = ga_rows[principal]
            refs.extend(_admin_row_refs(row, [role for role in row.get("roles") or [] if role.get("global_administrator")]))
        return refs[:_AGGREGATE_REF_LIMIT]

    findings: list[dict[str, Any]] = []
    for principal_id in principal_ids:
        user = users.get(principal_id.lower())
        if not user or user.get("enabled") is not False:
            continue
        affected = user.get("principal_name") or user.get("display_name") or principal_id
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:global_admin_disabled:{principal_id}",
                    "rule_id": "identity.global_admin_disabled",
                    "severity": "high",
                    "category": "identity",
                    "title": "Disabled account still has Global Administrator",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [affected],
                    "description": "A disabled user is still assigned the Microsoft Entra Global Administrator role.",
                    "impact": "Dormant privileged assignments create confusing recovery paths and can be reactivated with tenant-wide privilege.",
                    "remediation": "Remove Global Administrator from disabled users and keep emergency access accounts explicitly documented.",
                    "expected_value": "Disabled accounts have no Global Administrator assignments.",
                    "returned_value": {
                        "principal_id": principal_id,
                        "enabled": user.get("enabled"),
                        "routes": ga_rows[principal_id].get("routes") or [],
                    },
                    "evidence_refs": [
                        *assignment_refs([principal_id]),
                        *_normalized_evidence_refs("users", user, "identity"),
                    ],
                    **_metadata_for("identity.global_admin_disabled"),
                }
            )
        )
    for principal_id in principal_ids:
        user = users.get(principal_id.lower())
        if not user:
            continue
        last_password_change = _parse_iso_datetime(user.get("last_password_change_at"))
        if last_password_change is None:
            continue
        if last_password_change.tzinfo is None:
            last_password_change = last_password_change.replace(tzinfo=timezone.utc)
        if last_password_change >= datetime.now(tz=timezone.utc) - timedelta(days=365):
            continue
        affected = user.get("principal_name") or user.get("display_name") or principal_id
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:global_admin_stale_password:{principal_id}",
                    "rule_id": "identity.global_admin_stale_password",
                    "severity": "medium",
                    "category": "identity",
                    "title": "Global Administrator password is stale",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [affected],
                    "description": "A Microsoft Entra Global Administrator has not changed password in over 365 days.",
                    "impact": "Long-lived privileged passwords raise credential-theft and recovery risk, especially for accounts without documented emergency controls.",
                    "remediation": "Rotate or validate the privileged credential and move routine administration to phishing-resistant, least-privileged access.",
                    "expected_value": "Privileged administrator credentials are rotated or governed through approved emergency-access procedure.",
                    "returned_value": user.get("last_password_change_at"),
                    "evidence_refs": [
                        *assignment_refs([principal_id]),
                        *_normalized_evidence_refs("users", user, "identity"),
                    ],
                    **_metadata_for("identity.global_admin_stale_password"),
                }
            )
        )
    for principal_id in principal_ids:
        user = users.get(principal_id.lower())
        registration = registrations.get(principal_id.lower())
        if registration is None and user and user.get("principal_name"):
            registration = registrations.get(str(user.get("principal_name")).lower())
        if registration is None and principal_id.lower() in users_by_upn:
            registration = registrations.get(principal_id.lower())
        if not registration or registration.get("is_mfa_registered") is not False:
            continue
        affected = (
            (user or {}).get("principal_name")
            or registration.get("user_principal_name")
            or principal_id
        )
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:global_admin_mfa_not_registered:{principal_id}",
                    "rule_id": "identity.global_admin_mfa_not_registered",
                    "severity": "critical",
                    "category": "identity",
                    "title": "Global Administrator is not registered for MFA",
                    "status": "open",
                    "collector": "auth_methods",
                    "affected_objects": [affected],
                    "description": "A Microsoft Entra Global Administrator is not registered for MFA in authentication method reports.",
                    "impact": "A tenant-wide privileged account without MFA registration is exposed to password-only compromise.",
                    "remediation": "Require phishing-resistant MFA for every Global Administrator and confirm registration in authentication method reports.",
                    "expected_value": "Every Global Administrator is registered for MFA.",
                    "returned_value": registration,
                    "evidence_refs": [
                        *assignment_refs([principal_id]),
                        *_normalized_evidence_refs("auth_method_registration_objects", registration, "auth_methods"),
                    ],
                    **_metadata_for("identity.global_admin_mfa_not_registered"),
                }
            )
        )

    count = len(principal_ids)
    complete = summary.get("state") == _ADMIN_SET_COMPLETE
    count_evidence = {
        "global_admin_count": count,
        "principal_ids": principal_ids,
        "admin_set_state": summary.get("state"),
        "routes": sorted({route for row in ga_rows.values() for route in row.get("routes") or []}),
    }
    singleton_bounds = _global_admin_bounds("identity.global_admin_singleton")
    if complete and singleton_bounds and 0 < count < min(int(bound.get("minimum") or 0) for bound in singleton_bounds):
        findings.append(
            _finalize_finding(
                {
                    "id": "identity:global_admin_singleton",
                    "rule_id": "identity.global_admin_singleton",
                    "severity": "high",
                    "category": "identity",
                    "title": "Only one Global Administrator observed",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": principal_ids,
                    "returned_value": count_evidence,
                    "framework_thresholds": _framework_thresholds(
                        singleton_bounds, count, lambda bound: count < int(bound.get("minimum") or 0)
                    ),
                    "evidence_refs": assignment_refs(principal_ids),
                    **{
                        **_metadata_for("identity.global_admin_singleton"),
                        "expected_value": f"Global Administrator users: {_bounds_text(singleton_bounds)}.",
                    },
                }
            )
        )
    sprawl_bounds = _global_admin_bounds("identity.global_admin_sprawl")
    breached = [bound for bound in sprawl_bounds if bound.get("maximum") is not None and count > int(bound["maximum"])]
    if breached:
        findings.append(
            _finalize_finding(
                {
                    "id": "identity:global_admin_sprawl",
                    "rule_id": "identity.global_admin_sprawl",
                    # Above every framework bound it is medium; above the strictest only, low.
                    "severity": "medium" if len(breached) == len(sprawl_bounds) else "low",
                    "category": "identity",
                    "title": "Too many Global Administrators observed",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": principal_ids,
                    "returned_value": {**count_evidence, **({} if complete else {"lower_bound": True})},
                    "framework_thresholds": _framework_thresholds(
                        sprawl_bounds, count, lambda bound: bound.get("maximum") is not None and count > int(bound["maximum"])
                    ),
                    "evidence_refs": assignment_refs(principal_ids),
                    **{
                        **_metadata_for("identity.global_admin_sprawl"),
                        "description": (
                            f"{count if complete else f'At least {count}'} Global Administrator users were observed, more than "
                            + " and more than ".join(f"{bound['maximum']} ({bound.get('label') or bound['framework']})" for bound in breached)
                            + ". Groups and service principals are not counted."
                        ),
                        "expected_value": f"Global Administrator users: {_bounds_text(sprawl_bounds)}.",
                    },
                }
            )
        )
    if not complete:
        findings.append(
            _finalize_finding(
                {
                    "id": "identity:admin_set:unverified",
                    "rule_id": "identity.admin_set_unverified",
                    "severity": "medium",
                    "category": "identity",
                    "title": "The administrator set could not be verified",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": ["Tenant administrator set"],
                    "evidence": {
                        "state": summary.get("state"),
                        "reasons": summary.get("reasons") or [],
                        "sources": summary.get("sources") or [],
                        "observed_admin_count": summary.get("admin_count"),
                        "observed_global_admin_count": summary.get("global_admin_count"),
                    },
                    "returned_value": {"state": summary.get("state"), "reasons": summary.get("reasons") or []},
                    "evidence_refs": _normalized_evidence_refs(_ADMIN_SET_SECTION, summary, "identity"),
                    **_metadata_for("identity.admin_set_unverified"),
                }
            )
        )
    return findings


# Directory roles a workload identity should never hold: each one lets the holder take over the tenant (Global
# Administrator) or give itself or anything else any role (Privileged Role Administrator). By role template id.
_SERVICE_PRINCIPAL_TENANT_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}


def _build_service_principal_role_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per service principal that holds Global Administrator or Privileged Role Administrator.

    The effective administrator set lists a service principal that holds a role (directly, as a PIM-eligible
    assignment, or through a role-assignable group) with ``counted: false``: it is not a person, so no user count
    includes it. Baseline alignment reads the rule ``not_assessed`` when the set is ``unknown``.
    """
    _summary, rows = _effective_admins(normalized_snapshot)
    service_principals = {
        str(item.get("id")).lower(): item
        for item in ((normalized_snapshot.get("service_principals") or {}).get("records") or [])
        if item.get("id")
    }
    findings: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: str(item.get("principal_id") or "")):
        if row.get("principal_type") != "service_principal" or not row.get("principal_id"):
            continue
        held = [
            role for role in row.get("roles") or [] if str(role.get("role_definition_id") or "").lower() in _SERVICE_PRINCIPAL_TENANT_ROLES
        ]
        if not held:
            continue
        principal_id = str(row["principal_id"])
        record = service_principals.get(principal_id.lower()) or {}
        roles = [
            {
                "role": _SERVICE_PRINCIPAL_TENANT_ROLES[str(role["role_definition_id"]).lower()],
                **{key: role[key] for key in ("route", "group_id", "scope") if role.get(key)},
            }
            for role in held
        ]
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:service_principal_privileged_role:{principal_id}",
                    "rule_id": "identity.service_principal_privileged_role",
                    "severity": "high",
                    "category": "identity",
                    "title": "Service principal holds a tenant-wide administrator role",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [row.get("display_name") or principal_id],
                    "evidence": {
                        "principal_id": principal_id,
                        "app_id": record.get("app_id"),
                        "service_principal_type": record.get("service_principal_type"),
                        "enabled": row.get("enabled"),
                        "roles": roles,
                        "routes": row.get("routes") or [],
                    },
                    "returned_value": {"principal_id": principal_id, "roles": roles},
                    "evidence_refs": [
                        *_admin_row_refs(row, held),
                        *(_normalized_evidence_refs("service_principals", record, "identity") if record else []),
                    ],
                    **_metadata_for("identity.service_principal_privileged_role"),
                }
            )
        )
    return findings


_ADMIN_ASSIGNMENT_LABELS = {_ADMIN_ROUTE_DIRECT: "active", _ADMIN_ROUTE_ELIGIBLE: "eligible", _ADMIN_ROUTE_GROUP: "group"}


def _privileged_roles_for_mfa(normalized_snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Administrator roles per principal id (lower-case) from the effective administrator set.

    Direct active assignments, PIM-eligible schedules and roles inherited through a role-assignable
    group are all here (``assignment`` is ``active``, ``eligible`` or ``group``). Each entry keeps
    the references to the records that make the account privileged.
    """
    by_principal: dict[str, list[dict[str, Any]]] = {}
    for row in _counted_admin_rows(normalized_snapshot):
        entries = []
        for role in row.get("roles") or []:
            entry: dict[str, Any] = {
                "role": role.get("role"),
                "assignment": _ADMIN_ASSIGNMENT_LABELS.get(str(role.get("route")), str(role.get("route"))),
                "refs": _admin_record_refs([role]),
            }
            if role.get("group_id"):
                entry["group_id"] = role.get("group_id")
            entries.append(entry)
        by_principal[str(row["principal_id"]).lower()] = entries
    return by_principal


def _build_user_mfa_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """MFA registration findings.

    These report registration only: whether MFA is required at sign-in is the effective-MFA
    verdict (``ca.mfa_not_enforced``). Global Administrators have their own critical rule; any
    other account holding an administrator role, or flagged ``isAdmin`` by the registration
    report, gets the privileged rule instead of the generic user rule.
    """
    users_by_id = {
        str(item.get("id")).lower(): item
        for item in ((normalized_snapshot.get("users") or {}).get("records") or [])
        if item.get("id")
    }
    users_by_upn = {
        str(item.get("principal_name") or "").lower(): item
        for item in users_by_id.values()
        if item.get("principal_name")
    }
    admin_principal_ids = {
        str(row["principal_id"]).lower()
        for row in _counted_admin_rows(normalized_snapshot)
        if row.get("global_administrator")
    }
    privileged_roles = _privileged_roles_for_mfa(normalized_snapshot)
    admin_rows = {str(row["principal_id"]).lower(): row for row in _counted_admin_rows(normalized_snapshot)}
    findings: list[dict[str, Any]] = []
    for registration in ((normalized_snapshot.get("auth_method_registration_objects") or {}).get("records") or []):
        if registration.get("is_mfa_registered") is not False:
            continue
        reg_id = str(registration.get("id") or "").lower()
        upn = str(registration.get("user_principal_name") or "").lower()
        user = users_by_id.get(reg_id) or users_by_upn.get(upn)
        if reg_id in admin_principal_ids or (user and str(user.get("id") or "").lower() in admin_principal_ids):
            continue
        if user and user.get("enabled") is False:
            continue
        affected = (user or {}).get("principal_name") or registration.get("user_principal_name") or registration.get("id")
        roles = privileged_roles.get(str((user or {}).get("id") or reg_id).lower()) or privileged_roles.get(reg_id) or []
        admin_row = admin_rows.get(str((user or {}).get("id") or reg_id).lower()) or admin_rows.get(reg_id)
        registration_refs = _normalized_evidence_refs("auth_method_registration_objects", registration, "auth_methods")
        # Privileged accounts are reported whatever their user type. A guest administrator's MFA may be
        # satisfied in the home tenant, but that is for the reviewer to confirm, not for the rule to assume.
        if roles or registration.get("is_admin") is True:
            identified_by = [name for name, present in (
                ("directory_role", bool(roles)),
                ("registration_report_is_admin", registration.get("is_admin") is True),
            ) if present]
            role_rows = [
                {key: entry[key] for key in ("role", "assignment", "group_id") if entry.get(key)} for entry in roles
            ]
            findings.append(
                _finalize_finding(
                    {
                        "id": f"identity:privileged_mfa_not_registered:{registration.get('id') or affected}",
                        "rule_id": "identity.privileged_mfa_not_registered",
                        "severity": "high",
                        "category": "identity",
                        "title": "Privileged account is not registered for MFA",
                        "status": "open",
                        "collector": "auth_methods",
                        "affected_objects": [affected],
                        "evidence": {**registration, "privileged_roles": role_rows, "identified_by": identified_by},
                        "returned_value": {"is_mfa_registered": False, "privileged_roles": role_rows},
                        "evidence_refs": [
                            *registration_refs,
                            *(_normalized_evidence_refs(_ADMIN_SET_SECTION, admin_row, "identity") if admin_row else []),
                            *(ref for entry in roles for ref in entry["refs"]),
                        ],
                        **_metadata_for("identity.privileged_mfa_not_registered"),
                    }
                )
            )
            continue
        user_type = str((user or {}).get("user_type") or registration.get("user_type") or "").lower()
        if user_type and user_type != "member":
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:user_mfa_not_registered:{registration.get('id') or affected}",
                    "rule_id": "identity.user_mfa_not_registered",
                    "severity": "medium",
                    "category": "identity",
                    "title": "User is not registered for MFA",
                    "status": "open",
                    "collector": "auth_methods",
                    "affected_objects": [affected],
                    "evidence": registration,
                    "returned_value": registration,
                    "evidence_refs": registration_refs,
                    **_metadata_for("identity.user_mfa_not_registered"),
                }
            )
        )
    return findings


_MFA_NOT_ENFORCED_POLICY_LIMIT = 10


def _verdict_records(normalized_snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("control")): item
        for item in ((normalized_snapshot.get(_IDENTITY_CONTROL_SECTION) or {}).get("records") or [])
        if item.get("control")
    }


def _policy_refs(verdict: dict[str, Any], *lists: str) -> list[dict[str, Any]]:
    """References to the Conditional Access policy records a verdict cites, capped to stay readable."""
    refs: list[dict[str, Any]] = []
    for name in lists:
        for policy in verdict.get(name) or []:
            if len(refs) >= _MFA_NOT_ENFORCED_POLICY_LIMIT:
                return refs
            if policy.get("key"):
                refs.extend(_normalized_evidence_refs("conditional_access_graph", policy, "conditional_access"))
    return refs


# Verdict "unknown" is never a pass and never a failure of the main rule; it is its own finding.
_UNVERIFIED_CONTROL_RULES: dict[str, dict[str, str]] = {
    "effective_mfa": {
        "rule_id": "ca.enforcement_unverified",
        "id": "conditional_access:effective_mfa:unverified",
        "collector": "conditional_access",
        "title": "MFA enforcement could not be verified",
        "affected": "Tenant MFA enforcement",
    },
    "administrator_mfa": {
        "rule_id": "ca.enforcement_unverified",
        "id": "conditional_access:administrator_mfa:unverified",
        "collector": "conditional_access",
        "title": "Administrator MFA enforcement could not be verified",
        "affected": "Administrator MFA enforcement",
    },
    "legacy_authentication_block": {
        "rule_id": "ca.enforcement_unverified",
        "id": "conditional_access:legacy_authentication_block:unverified",
        "collector": "conditional_access",
        "title": "Legacy authentication blocking could not be verified",
        "affected": "Tenant legacy authentication",
    },
    "user_consent": {
        "rule_id": "consent_policy.user_consent_unverified",
        "id": "consent_policy:user_consent:unverified",
        "collector": "consent_policy",
        "title": "User consent settings could not be verified",
        "affected": "Tenant user consent",
    },
}


def _exclusion_rows(verdict: dict[str, Any], key: str = "unsanctioned_exclusions", *, limit: int = 10) -> list[dict[str, Any]]:
    """The excluded principals a verdict lists as a gap, trimmed to what a reader needs."""
    return [
        {name: row[name] for name in ("type", "id", "display_name") if row.get(name)}
        for row in (verdict.get(key) or [])[:limit]
    ]


def _exclusion_text(rows: list[dict[str, Any]], total: int) -> str:
    names = [str(row.get("display_name") or f"{row['type']} {row['id']}") for row in rows[:5]]
    return ", ".join(names) + (f" and {total - len(names)} more" if total > len(names) else "")


def _role_gap_text(uncovered: list[dict[str, Any]]) -> str:
    names = [
        f"{row.get('name') or row.get('id')} ({'excluded' if row.get('reason') == 'excluded' else 'not included'})"
        for row in uncovered[:6]
    ]
    return ", ".join(names) + (f" and {len(uncovered) - len(names)} more" if len(uncovered) > len(names) else "")


def _unresolved_note(verdict: dict[str, Any]) -> str:
    """A sentence naming the emergency-access entries the operator listed that matched no collected account."""
    entries = [str(item) for item in verdict.get("unresolved_operator_accounts") or []]
    if not entries:
        return ""
    count = len(entries)
    return (
        f" {count} emergency access {'entry' if count == 1 else 'entries'} listed with --break-glass-accounts could not be "
        f"resolved against the collected users and groups and {'is' if count == 1 else 'are'} not treated as excluded: "
        f"{', '.join(entries[:10])}{' and more' if count > 10 else ''}."
    )


def _append_note(metadata: dict[str, Any], note: str) -> None:
    if note:
        metadata["description"] = f"{metadata.get('description') or ''}{note}".strip()


def _unresolved_returned(verdict: dict[str, Any]) -> dict[str, Any]:
    entries = verdict.get("unresolved_operator_accounts") or []
    return {"unresolved_operator_accounts": list(entries)} if entries else {}


def _build_identity_control_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Findings from the tenant-level identity control verdicts.

    A negative verdict (``not_enforced``, ``not_blocked``, ``unrestricted``) raises its rule, and so does one that
    holds only with exclusions (``enforced_with_exclusions``, ``blocked_with_exclusions``) or only in part
    (``limited`` user consent): the rule's control must not pass on a policy that leaves principals out. An
    ``unknown`` verdict never raises that rule and never passes: it raises the matching
    ``*_unverified`` rule so the gap is visible instead of silent.
    """
    verdicts = _verdict_records(normalized_snapshot)
    findings: list[dict[str, Any]] = []

    def _verdict_ref(control: str, collector: str) -> list[dict[str, Any]]:
        return _normalized_evidence_refs(_IDENTITY_CONTROL_SECTION, verdicts[control], collector)

    mfa = verdicts.get("effective_mfa")
    if mfa and mfa.get("verdict") in {"not_enforced", "enforced_with_exclusions"}:
        with_exclusions = mfa["verdict"] == "enforced_with_exclusions"
        gap = _exclusion_rows(mfa)
        metadata = _metadata_for("ca.mfa_not_enforced")
        if with_exclusions:
            metadata["description"] = (
                "An enabled Conditional Access policy requires MFA of all users on all cloud apps, but every qualifying "
                f"policy excludes {_exclusion_text(gap, int(mfa.get('unsanctioned_exclusion_count') or len(gap)))}, "
                "which is not an emergency access account listed with --break-glass-accounts. Excluded roles, guest "
                "types and groups are not required to use MFA, so the control is not met for them."
            )
        _append_note(metadata, _unresolved_note(mfa))
        findings.append(
            _finalize_finding(
                {
                    "id": "conditional_access:mfa_not_enforced",
                    "rule_id": "ca.mfa_not_enforced",
                    "severity": "medium" if with_exclusions else "high",
                    "category": "identity",
                    "title": (
                        "Conditional Access requires MFA of all users but excludes principals other than emergency access accounts"
                        if with_exclusions
                        else "Neither security defaults nor Conditional Access enforce MFA for all users"
                    ),
                    "status": "open",
                    "collector": "conditional_access",
                    "affected_objects": ["Tenant MFA enforcement"],
                    "evidence": mfa,
                    "returned_value": {
                        "verdict": mfa["verdict"],
                        "basis": mfa.get("basis") or [],
                        "basis_summary": mfa.get("basis_summary"),
                        "non_qualifying_policy_count": len(mfa.get("non_qualifying_mfa_policies") or []),
                        "report_only_policy_count": len(mfa.get("report_only_mfa_policies") or []),
                        **({"unsanctioned_exclusions": gap} if with_exclusions else {}),
                        **_unresolved_returned(mfa),
                    },
                    "evidence_refs": [
                        *_verdict_ref("effective_mfa", "conditional_access"),
                        *_policy_refs(
                            mfa,
                            *(("qualifying_policies",) if with_exclusions else ()),
                            "non_qualifying_mfa_policies",
                            "report_only_mfa_policies",
                        ),
                    ],
                    **metadata,
                }
            )
        )

    admin_mfa = verdicts.get("administrator_mfa")
    if admin_mfa and admin_mfa.get("verdict") in {"not_enforced", "enforced_with_exclusions"}:
        with_exclusions = admin_mfa["verdict"] == "enforced_with_exclusions"
        gap = _exclusion_rows(admin_mfa, "administrator_exclusions")
        metadata = _metadata_for("ca.admin_mfa_not_enforced")
        if with_exclusions:
            metadata["description"] = (
                "An enabled Conditional Access policy requires MFA of administrators, but every qualifying policy excludes "
                f"{_exclusion_text(gap, len(admin_mfa.get('administrator_exclusions') or gap))}, which may include "
                "administrators and is not an emergency access account listed with --break-glass-accounts."
            )
        elif gap:
            metadata["description"] = (
                "Every Conditional Access policy that requires MFA of administrators excludes an administrator role or "
                f"administrator ({_exclusion_text(gap, len(admin_mfa.get('administrator_exclusions') or gap))}), so those "
                "administrators are not required to use MFA, and security defaults are off."
            )
        _append_note(metadata, _unresolved_note(admin_mfa))
        findings.append(
            _finalize_finding(
                {
                    "id": "conditional_access:administrator_mfa_not_enforced",
                    "rule_id": "ca.admin_mfa_not_enforced",
                    "severity": "medium" if with_exclusions else "high",
                    "category": "identity",
                    "title": (
                        "Administrator MFA is enforced with exclusions"
                        if with_exclusions
                        else "MFA is not required of every administrator"
                    ),
                    "status": "open",
                    "collector": "conditional_access",
                    "affected_objects": ["Administrator MFA enforcement"],
                    "evidence": admin_mfa,
                    "returned_value": {
                        "verdict": admin_mfa["verdict"],
                        "basis": admin_mfa.get("basis") or [],
                        "basis_summary": admin_mfa.get("basis_summary"),
                        "administrator_set": admin_mfa.get("administrator_set"),
                        "non_qualifying_policy_count": len(admin_mfa.get("non_qualifying_mfa_policies") or []),
                        "report_only_policy_count": len(admin_mfa.get("report_only_mfa_policies") or []),
                        **({"administrator_exclusions": gap} if gap else {}),
                        **_unresolved_returned(admin_mfa),
                    },
                    "evidence_refs": [
                        *_verdict_ref("administrator_mfa", "conditional_access"),
                        *_policy_refs(
                            admin_mfa,
                            "qualifying_policies",
                            "supplementary_policies",
                            "non_qualifying_mfa_policies",
                            "report_only_mfa_policies",
                        ),
                    ],
                    **metadata,
                }
            )
        )
    admin_enforced = bool(admin_mfa) and admin_mfa.get("verdict") in {"enforced", "enforced_with_exclusions"}
    if admin_enforced and admin_mfa.get("role_catalog_verdict") == "not_enforced":
        uncovered = admin_mfa.get("role_catalog_uncovered_roles") or []
        metadata = _metadata_for("ca.admin_mfa_role_set_incomplete")
        metadata["description"] = (
            "MFA is required of the administrators the tenant has today, but the policies together do not include every "
            f"administrator role the CIS 5.2.2.1 list names, or exclude one ({_role_gap_text(uncovered)}). Whoever is "
            "given one of those roles next is not required to use MFA by Conditional Access."
        )
        findings.append(
            _finalize_finding(
                {
                    "id": "conditional_access:administrator_mfa_role_set_incomplete",
                    "rule_id": "ca.admin_mfa_role_set_incomplete",
                    "severity": "medium",
                    "category": "identity",
                    "title": "Administrator MFA does not cover every administrator role",
                    "status": "open",
                    "collector": "conditional_access",
                    "affected_objects": ["Administrator MFA enforcement"],
                    "evidence": admin_mfa,
                    "returned_value": {
                        "verdict": admin_mfa["verdict"],
                        "role_catalog_verdict": admin_mfa["role_catalog_verdict"],
                        "uncovered_roles": uncovered,
                        "basis": admin_mfa.get("basis") or [],
                    },
                    "evidence_refs": [
                        *_verdict_ref("administrator_mfa", "conditional_access"),
                        *_policy_refs(admin_mfa, "qualifying_policies", "supplementary_policies", "non_qualifying_mfa_policies"),
                    ],
                    **metadata,
                }
            )
        )
    resistant_gap = admin_mfa.get("phishing_resistant_verdict") in {"not_enforced", "enforced_with_exclusions"} if admin_mfa else False
    resistant_roles_gap = bool(admin_mfa) and admin_mfa.get("phishing_resistant_role_catalog_verdict") == "not_enforced"
    if admin_enforced and (resistant_gap or resistant_roles_gap):
        metadata = _metadata_for("ca.admin_phishing_resistant_mfa_not_enforced")
        uncovered = admin_mfa.get("phishing_resistant_role_catalog_uncovered_roles") or []
        if not resistant_gap:
            metadata["description"] = (
                "A policy that requires a phishing-resistant authentication strength reaches the administrators the tenant has "
                "today, but together the phishing-resistant policies do not include every one of ScubaGear's privileged "
                f"roles (MS.AAD.3.6v1), or exclude one ({_role_gap_text(uncovered)}). Whoever is given one of those roles "
                "next is not required to use a phishing-resistant method."
            )
        findings.append(
            _finalize_finding(
                {
                    "id": "conditional_access:administrator_phishing_resistant_mfa_not_enforced",
                    "rule_id": "ca.admin_phishing_resistant_mfa_not_enforced",
                    "severity": "low",
                    "category": "identity",
                    "title": "Administrators are not required to use phishing-resistant MFA",
                    "status": "open",
                    "collector": "conditional_access",
                    "affected_objects": ["Administrator MFA enforcement"],
                    "evidence": admin_mfa,
                    "returned_value": {
                        "verdict": admin_mfa["verdict"],
                        "phishing_resistant_verdict": admin_mfa["phishing_resistant_verdict"],
                        "phishing_resistant_role_catalog_verdict": admin_mfa.get("phishing_resistant_role_catalog_verdict"),
                        "uncovered_roles": uncovered,
                        "basis": admin_mfa.get("basis") or [],
                        "phishing_resistant_policy_ids": admin_mfa.get("phishing_resistant_policy_ids") or [],
                    },
                    "evidence_refs": [
                        *_verdict_ref("administrator_mfa", "conditional_access"),
                        *_policy_refs(admin_mfa, "qualifying_policies", "supplementary_policies"),
                    ],
                    **metadata,
                }
            )
        )

    legacy = verdicts.get("legacy_authentication_block")
    if legacy and legacy.get("verdict") in {"not_blocked", "blocked_with_exclusions"}:
        with_exclusions = legacy["verdict"] == "blocked_with_exclusions"
        gap = _exclusion_rows(legacy)
        metadata = _metadata_for("ca.legacy_auth_not_blocked")
        if with_exclusions:
            metadata["description"] = (
                "An enabled Conditional Access policy blocks legacy authentication clients for all users on all cloud apps, "
                f"but every qualifying policy excludes {_exclusion_text(gap, int(legacy.get('unsanctioned_exclusion_count') or len(gap)))}, "
                "which is not an emergency access account listed with --break-glass-accounts. Legacy protocols cannot "
                "perform MFA, so the excluded principals can still sign in with a password alone."
            )
        _append_note(metadata, _unresolved_note(legacy))
        findings.append(
            _finalize_finding(
                {
                    "id": "conditional_access:legacy_auth_not_blocked",
                    "rule_id": "ca.legacy_auth_not_blocked",
                    "severity": "medium" if with_exclusions else "high",
                    "category": "identity",
                    "title": (
                        "Legacy authentication is blocked, but the block policy excludes principals other than emergency access accounts"
                        if with_exclusions
                        else "Legacy authentication is not blocked"
                    ),
                    "status": "open",
                    "collector": "conditional_access",
                    "affected_objects": ["Tenant legacy authentication"],
                    "evidence": legacy,
                    "returned_value": {
                        "verdict": legacy["verdict"],
                        "basis_summary": legacy.get("basis_summary"),
                        "non_qualifying_policy_count": len(legacy.get("non_qualifying_block_policies") or []),
                        "report_only_policy_count": len(legacy.get("report_only_block_policies") or []),
                        **({"unsanctioned_exclusions": gap} if with_exclusions else {}),
                        **_unresolved_returned(legacy),
                    },
                    "evidence_refs": [
                        *_verdict_ref("legacy_authentication_block", "conditional_access"),
                        *_policy_refs(
                            legacy,
                            *(("blocking_policies",) if with_exclusions else ()),
                            "non_qualifying_block_policies",
                            "report_only_block_policies",
                        ),
                    ],
                    **metadata,
                }
            )
        )

    consent = verdicts.get("user_consent")
    if consent and consent.get("verdict") == "limited":
        policy_objects = [
            item
            for item in ((normalized_snapshot.get("consent_policy_objects") or {}).get("records") or [])
            if item.get("source_name") == "authorizationPolicy"
        ]
        findings.append(
            _finalize_finding(
                {
                    "id": "consent_policy:user_consent_limited",
                    "rule_id": "consent_policy.user_consent_limited",
                    "severity": "medium",
                    "category": "application",
                    "title": "Users can consent to applications under a limited consent policy",
                    "status": "open",
                    "collector": "consent_policy",
                    "affected_objects": ["Tenant user consent"],
                    "evidence": consent,
                    "returned_value": {
                        "verdict": "limited",
                        "consent_mode": consent.get("consent_mode"),
                        "limited_policies": consent.get("limited_policies") or [],
                    },
                    "evidence_refs": [
                        *_verdict_ref("user_consent", "consent_policy"),
                        *(ref for item in policy_objects[:1] for ref in _normalized_evidence_refs("consent_policy_objects", item, "consent_policy")),
                    ],
                    **_metadata_for("consent_policy.user_consent_limited"),
                }
            )
        )
    if consent and consent.get("verdict") == "unrestricted":
        policy_objects = [
            item
            for item in ((normalized_snapshot.get("consent_policy_objects") or {}).get("records") or [])
            if item.get("source_name") == "authorizationPolicy"
        ]
        findings.append(
            _finalize_finding(
                {
                    "id": "consent_policy:user_consent_unrestricted",
                    "rule_id": "consent_policy.user_consent_unrestricted",
                    "severity": "high",
                    "category": "application",
                    "title": "Users can consent to any application",
                    "status": "open",
                    "collector": "consent_policy",
                    "affected_objects": ["Tenant user consent"],
                    "evidence": consent,
                    "returned_value": {
                        "verdict": "unrestricted",
                        "unrestricted_policies": consent.get("unrestricted_policies") or [],
                    },
                    "evidence_refs": [
                        *_verdict_ref("user_consent", "consent_policy"),
                        *(ref for item in policy_objects[:1] for ref in _normalized_evidence_refs("consent_policy_objects", item, "consent_policy")),
                    ],
                    **_metadata_for("consent_policy.user_consent_unrestricted"),
                }
            )
        )

    for control, spec in _UNVERIFIED_CONTROL_RULES.items():
        verdict = verdicts.get(control)
        if not verdict or verdict.get("verdict") != "unknown":
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": spec["id"],
                    "rule_id": spec["rule_id"],
                    "severity": "medium",
                    "category": "identity",
                    "title": spec["title"],
                    "status": "open",
                    "collector": spec["collector"],
                    "affected_objects": [spec["affected"]],
                    "evidence": verdict,
                    "returned_value": {"verdict": "unknown", "reasons": verdict.get("reasons") or []},
                    "evidence_refs": _verdict_ref(control, spec["collector"]),
                    **_metadata_for(spec["rule_id"]),
                }
            )
        )
    return findings


_STALE_ACCOUNT_DAYS = 90


def _privileged_role_names_by_principal(normalized_snapshot: dict[str, Any]) -> dict[str, list[str]]:
    """Map principal id (lower-case) to the administrator roles it holds by any route (see ``effective_admins``)."""
    return {
        str(row["principal_id"]).lower(): list(row.get("role_names") or [])
        for row in _counted_admin_rows(normalized_snapshot)
    }


def _is_stale_enabled_user(user: dict[str, Any], *, days: int = _STALE_ACCOUNT_DAYS) -> bool:
    """Enabled account, created more than ``days`` ago, with no successful sign-in in ``days``.

    Requires signin_data_available=True so a missing licence or scope never reads as
    "never signed in".
    """
    if user.get("signin_data_available") is not True:
        return False
    if user.get("enabled") is not True:
        return False
    if not _is_stale_timestamp(user.get("created_at"), days=days):
        return False
    last_success = user.get("last_successful_signin_at")
    if last_success in (None, ""):
        return True
    return _is_stale_timestamp(last_success, days=days)


def _build_stale_account_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    users = (normalized_snapshot.get("users") or {}).get("records") or []
    privileged = _privileged_role_names_by_principal(normalized_snapshot)
    admin_rows = {str(row["principal_id"]).lower(): row for row in _counted_admin_rows(normalized_snapshot)}
    findings: list[dict[str, Any]] = []
    for user in users:
        if not isinstance(user, dict) or not _is_stale_enabled_user(user):
            continue
        user_id = str(user.get("id") or "")
        if _is_guest(user) and user_id.lower() not in privileged:
            # A stale guest is reported once, by identity.stale_guest, against its own threshold.
            continue
        affected = user.get("principal_name") or user_id
        evidence = {
            "enabled": user.get("enabled"),
            "created_at": user.get("created_at"),
            "last_successful_signin_at": user.get("last_successful_signin_at"),
            "last_signin_at": user.get("last_signin_at"),
            "user_type": user.get("user_type"),
            "threshold_days": _STALE_ACCOUNT_DAYS,
        }
        evidence_refs = _normalized_evidence_refs("users", user, "identity")
        roles = privileged.get(user_id.lower())
        if roles:
            evidence_refs = [*evidence_refs, *_admin_row_refs(admin_rows[user_id.lower()])]
            findings.append(
                _finalize_finding(
                    {
                        "id": f"identity:privileged_stale_account:{user_id}",
                        "rule_id": "identity.privileged_stale_account",
                        "severity": "high",
                        "category": "identity",
                        "title": "Privileged account has not signed in successfully for over 90 days",
                        "status": "open",
                        "collector": "identity",
                        "affected_objects": [affected],
                        "evidence": {**evidence, "privileged_roles": sorted(roles)},
                        "returned_value": user.get("last_successful_signin_at"),
                        "evidence_refs": evidence_refs,
                        **_metadata_for("identity.privileged_stale_account"),
                    }
                )
            )
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:stale_enabled_account:{user_id}",
                    "rule_id": "identity.stale_enabled_account",
                    "severity": "medium",
                    "category": "identity",
                    "title": "Enabled account has not signed in successfully for over 90 days",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [affected],
                    "evidence": evidence,
                    "returned_value": user.get("last_successful_signin_at"),
                    "evidence_refs": evidence_refs,
                    **_metadata_for("identity.stale_enabled_account"),
                }
            )
        )
    return findings


_STALE_GUEST_DAYS_ENV = "AUDITEX_STALE_GUEST_DAYS"
_STALE_GUEST_DAYS_MAX = 3650


def stale_guest_days(days: int | None = None) -> int:
    """Days without a successful sign-in after which a guest is stale.

    The argument wins, then ``AUDITEX_STALE_GUEST_DAYS``, then the 90 days the stale-account rules
    use. A value that is not a whole number from 1 to 3650 is ignored, never half-applied.
    """
    for candidate in (days, os.environ.get(_STALE_GUEST_DAYS_ENV)):
        if candidate is None or isinstance(candidate, bool):
            continue
        try:
            value = int(str(candidate).strip())
        except ValueError:
            continue
        if 1 <= value <= _STALE_GUEST_DAYS_MAX:
            return value
    return _STALE_ACCOUNT_DAYS


def _is_guest(user: dict[str, Any]) -> bool:
    return str(user.get("user_type") or "").strip().lower() == "guest"


def _build_guest_findings(normalized_snapshot: dict[str, Any], *, stale_days: int) -> list[dict[str, Any]]:
    """Stale guests, and guests that hold an administrator role by any route.

    A guest is stale on the same evidence as any other account (``signin_data_available`` and no
    successful sign-in for ``stale_days``); without sign-in data nothing is raised and baseline
    alignment reports the rule ``not_assessed``. A guest administrator is reported even when the
    administrator set is incomplete, because what was read is already a breach.
    """
    findings: list[dict[str, Any]] = []
    admin_rows = {str(row["principal_id"]).lower(): row for row in _counted_admin_rows(normalized_snapshot)}
    for user in ((normalized_snapshot.get("users") or {}).get("records") or []):
        if not isinstance(user, dict) or not _is_guest(user) or str(user.get("id") or "").lower() in admin_rows:
            # A guest that is also privileged is reported by identity.privileged_stale_account.
            continue
        if not _is_stale_enabled_user(user, days=stale_days):
            continue
        user_id = str(user.get("id") or "")
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:stale_guest:{user_id}",
                    "rule_id": "identity.stale_guest",
                    "severity": "medium",
                    "category": "identity",
                    "title": f"Guest account has not signed in successfully for over {stale_days} days",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [user.get("principal_name") or user.get("display_name") or user_id],
                    "evidence": {
                        "enabled": user.get("enabled"),
                        "created_at": user.get("created_at"),
                        "last_successful_signin_at": user.get("last_successful_signin_at"),
                        "last_signin_at": user.get("last_signin_at"),
                        "user_type": user.get("user_type"),
                        "threshold_days": stale_days,
                    },
                    "returned_value": user.get("last_successful_signin_at"),
                    "evidence_refs": _normalized_evidence_refs("users", user, "identity"),
                    **{
                        **_metadata_for("identity.stale_guest"),
                        "expected_value": f"Guest accounts have signed in within {stale_days} days or are removed.",
                    },
                }
            )
        )
    users = {
        str(item.get("id")).lower(): item
        for item in ((normalized_snapshot.get("users") or {}).get("records") or [])
        if item.get("id")
    }
    for principal, row in sorted(admin_rows.items()):
        if row.get("is_guest") is not True:
            continue
        user = users.get(principal) or {}
        roles = [
            {key: role[key] for key in ("role", "route", "group_id") if role.get(key)} for role in row.get("roles") or []
        ]
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:guest_with_privileged_role:{row['principal_id']}",
                    "rule_id": "identity.guest_with_privileged_role",
                    "severity": "high",
                    "category": "identity",
                    "title": "Guest account holds an administrator role",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [row.get("principal_name") or row.get("display_name") or row["principal_id"]],
                    "evidence": {
                        "user_type": row.get("user_type"),
                        "enabled": row.get("enabled"),
                        "roles": roles,
                        "routes": row.get("routes") or [],
                        "global_administrator": bool(row.get("global_administrator")),
                    },
                    "returned_value": {"principal_id": row["principal_id"], "roles": roles},
                    "evidence_refs": [*_admin_row_refs(row), *(_normalized_evidence_refs("users", user, "identity") if user else [])],
                    **_metadata_for("identity.guest_with_privileged_role"),
                }
            )
        )
    return findings


def _build_admin_licence_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Administrators whose account also holds an Exchange Online mailbox or a productivity licence.

    Cyber Essentials expects separate accounts for administrative work, and an admin account that
    can read mail and edit documents is the account a phishing message reaches. Only a principal
    whose licences were read in full is judged (``licence_state: known``), so an unlicensed
    reading never passes by default.
    """
    findings: list[dict[str, Any]] = []
    for row in _counted_admin_rows(normalized_snapshot):
        if row.get("licence_state") != "known" or not (row.get("mailbox_licence") or row.get("productivity_licence")):
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"identity:admin_holds_productivity_licence:{row['principal_id']}",
                    "rule_id": "identity.admin_holds_productivity_licence",
                    "severity": "medium",
                    "category": "identity",
                    "title": "Administrator account holds a mailbox or productivity licence",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [row.get("principal_name") or row.get("display_name") or row["principal_id"]],
                    "evidence": {
                        "mailbox_licence": bool(row.get("mailbox_licence")),
                        "productivity_licence": bool(row.get("productivity_licence")),
                        "licence_sku_part_numbers": row.get("licence_sku_part_numbers") or [],
                        "role_names": row.get("role_names") or [],
                        "routes": row.get("routes") or [],
                    },
                    "returned_value": {
                        "mailbox_licence": bool(row.get("mailbox_licence")),
                        "productivity_licence": bool(row.get("productivity_licence")),
                    },
                    "evidence_refs": _admin_row_refs(row),
                    **_metadata_for("identity.admin_holds_productivity_licence"),
                }
            )
        )
    return findings


def _build_reports_concealed_names_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    records = (normalized_snapshot.get("usage_report_setting_objects") or {}).get("records") or []
    findings: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict) or item.get("concealed_names") is not True:
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": "reports_usage:concealed_names",
                    "rule_id": "reports_usage.concealed_names",
                    "severity": "low",
                    "category": "coverage",
                    "title": "Usage reports conceal user, group, and site names",
                    "status": "open",
                    "collector": "reports_usage",
                    "affected_objects": ["Microsoft 365 admin center report settings"],
                    "evidence": {"display_concealed_names": True},
                    "returned_value": True,
                    "evidence_refs": _normalized_evidence_refs("usage_report_setting_objects", item, "reports_usage"),
                    **_metadata_for("reports_usage.concealed_names"),
                }
            )
        )
    return findings


def _build_risky_signin_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    risky_states = {"atrisk", "confirmedcompromised"}
    ignored_states = {"", "none", "dismissed", "remediated", "confirmedsafe"}
    findings: list[dict[str, Any]] = []
    for item in ((normalized_snapshot.get("security_signin_events") or {}).get("records") or []):
        risk_level = str(item.get("risk_level_aggregated") or item.get("risk_level_during_signin") or "").strip().lower()
        risk_state = str(item.get("risk_state") or "").strip().lower()
        if risk_level not in {"high", "medium", "low"} and (risk_state in ignored_states or risk_state not in risky_states):
            continue
        severity = "high" if risk_level == "high" or risk_state in risky_states else "medium"
        findings.append(
            _finalize_finding(
                {
                    "id": f"security_signin:{item.get('id')}:risky",
                    "rule_id": "security.risky_signin",
                    "severity": severity,
                    "category": "identity",
                    "title": "Risky Microsoft Entra sign-in observed",
                    "status": "open",
                    "collector": "security",
                    "affected_objects": [item.get("user_principal_name") or item.get("id")],
                    "evidence": item,
                    "returned_value": {
                        "risk_level": item.get("risk_level_aggregated") or item.get("risk_level_during_signin"),
                        "risk_state": item.get("risk_state"),
                        "risk_detail": item.get("risk_detail"),
                    },
                    "evidence_refs": _normalized_evidence_refs("security_signin_events", item, "security"),
                    **_metadata_for("security.risky_signin"),
                }
            )
        )
    return findings


def _actor_from_directory_audit(item: dict[str, Any]) -> str:
    initiated_by = item.get("initiated_by") if isinstance(item.get("initiated_by"), dict) else {}
    user = initiated_by.get("user") if isinstance(initiated_by.get("user"), dict) else {}
    app = initiated_by.get("app") if isinstance(initiated_by.get("app"), dict) else {}
    return str(
        user.get("userPrincipalName")
        or user.get("displayName")
        or app.get("displayName")
        or app.get("appId")
        or item.get("id")
    )


def _build_privilege_event_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in ((normalized_snapshot.get("security_directory_audit_events") or {}).get("records") or []):
        activity = str(item.get("activity_display_name") or "").strip().lower()
        category = str(item.get("category") or "").strip().lower()
        result = str(item.get("result") or "").strip().lower()
        if result and result not in {"success", "succeeded"}:
            continue
        if category != "rolemanagement" and "role" not in activity:
            continue
        if not (("add" in activity or "assign" in activity or "activate" in activity) and "role" in activity):
            continue
        actor = _actor_from_directory_audit(item)
        findings.append(
            _finalize_finding(
                {
                    "id": f"security_directory_audit:{item.get('id')}:privilege_change",
                    "rule_id": "security.privilege_change_event",
                    "severity": "high",
                    "category": "identity",
                    "title": "Privileged role change observed",
                    "status": "open",
                    "collector": "security",
                    "affected_objects": [actor],
                    "evidence": item,
                    "returned_value": {
                        "activity": item.get("activity_display_name"),
                        "target_resources": item.get("target_resources") or [],
                    },
                    "evidence_refs": _normalized_evidence_refs("security_directory_audit_events", item, "security"),
                    **_metadata_for("security.privilege_change_event"),
                }
            )
        )
    return findings


def _is_stale_timestamp(value: Any, *, days: int = 90) -> bool:
    parsed = _parse_iso_datetime(value)
    if parsed is None:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed < datetime.now(tz=timezone.utc) - timedelta(days=days)


def _build_inbox_rule_findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(item, dict):
        return []
    if not item.get("is_enabled"):
        return []
    user_id = str(item.get("user_id") or "")
    rule_id = str(item.get("rule_id") or "")
    if not user_id or not rule_id:
        return []
    affected = [item.get("user_principal_name") or item.get("user_mail") or user_id]
    evidence_refs = _normalized_evidence_refs("inbox_rule_objects", item, "mailbox_forwarding")
    findings: list[dict[str, Any]] = []

    if item.get("forwards_externally"):
        findings.append(
            _finalize_finding(
                {
                    "id": f"mailbox_forwarding:{user_id}:{rule_id}:external_forward",
                    "rule_id": "mailbox_forwarding.external_inbox_rule",
                    "severity": "critical",
                    "category": "mail_flow",
                    "title": "Inbox rule forwards mail to external recipient",
                    "status": "open",
                    "collector": "mailbox_forwarding",
                    "affected_objects": affected,
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    "returned_value": item.get("external_recipients"),
                    **_metadata_for("mailbox_forwarding.external_inbox_rule"),
                }
            )
        )

    if item.get("hide_from_user"):
        findings.append(
            _finalize_finding(
                {
                    "id": f"mailbox_forwarding:{user_id}:{rule_id}:hide_from_user",
                    "rule_id": "mailbox_forwarding.hide_from_user",
                    "severity": "high",
                    "category": "mail_flow",
                    "title": "Inbox rule hides messages from the user",
                    "status": "open",
                    "collector": "mailbox_forwarding",
                    "affected_objects": affected,
                    "evidence": item,
                    "evidence_refs": evidence_refs,
                    **_metadata_for("mailbox_forwarding.hide_from_user"),
                }
            )
        )

    return findings


def _tenant_domains(normalized_snapshot: dict[str, Any]) -> set[str]:
    domains: set[str] = set()
    for item in ((normalized_snapshot.get("domain_hybrid_objects") or {}).get("records") or []):
        if item.get("is_verified") is False:
            continue
        for key in ("id", "domain", "name"):
            value = str(item.get(key) or "").strip().lower()
            if "." in value and "@" not in value:
                domains.add(value)
    tenant_name = str((normalized_snapshot.get("snapshot") or {}).get("tenant_name") or "").strip().lower()
    if "." in tenant_name and "@" not in tenant_name:
        domains.add(tenant_name)
    return domains


def _email_domain(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if "@" not in text:
        return None
    domain = text.rsplit("@", 1)[-1].strip()
    return domain or None


def _is_write_like_sharepoint_permission(roles: Any) -> bool:
    if not isinstance(roles, list):
        return False
    normalized = {str(role or "").strip().lower() for role in roles}
    return any(role not in {"", "read", "view"} for role in normalized)


def _accepted_exchange_domains(normalized_snapshot: dict[str, Any]) -> set[str]:
    domains: set[str] = set()
    for item in ((normalized_snapshot.get("exchange_policy_objects") or {}).get("records") or []):
        if item.get("source_name") != "acceptedDomains":
            continue
        for key in ("domain_name", "display_name", "id"):
            value = str(item.get(key) or "").strip().lower()
            if "." in value and "@" not in value:
                domains.add(value)
    return domains


def _list_values(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _flag_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "enabled", "1"}
    return False


def _external_recipients(values: Any, accepted_domains: set[str]) -> list[str]:
    if not accepted_domains:
        return []
    recipients: list[str] = []
    for value in _list_values(values):
        text = str(value or "").strip()
        domain = _email_domain(text)
        if domain and domain not in accepted_domains:
            recipients.append(text)
    return list(dict.fromkeys(recipients))


def _attack_path_rule_id(path: dict[str, Any]) -> str:
    edges = {str(hop.get("edge")) for hop in path.get("hops") or [] if isinstance(hop, dict)}
    if "owns" in edges:
        return "attack_path.app_owner_to_tier0"
    if path.get("foothold") == "no_mfa":
        return "attack_path.no_mfa_to_tier0"
    return "attack_path.privilege_escalation"


def _build_attack_path_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per high or critical privilege-escalation graph path.

    A no-MFA path records the state of the effective administrator set: a route found is real
    evidence whatever that state, but baseline alignment reads the rule ``not_assessed`` rather than
    ``pass`` when no path was found and the set is ``unknown``.
    """
    findings: list[dict[str, Any]] = []
    admin_set_summary, _admin_rows = _effective_admins(normalized_snapshot)
    for path in analyze_attack_graph(normalized_snapshot).get("paths") or []:
        if not path.get("finding_id"):
            continue
        rule_id = _attack_path_rule_id(path)
        if rule_id == "attack_path.app_owner_to_tier0":
            metadata = {"rule_id": "attack_path.app_owner_to_tier0", **_metadata_for("attack_path.app_owner_to_tier0")}
        elif rule_id == "attack_path.no_mfa_to_tier0":
            metadata = {"rule_id": "attack_path.no_mfa_to_tier0", **_metadata_for("attack_path.no_mfa_to_tier0")}
        else:
            metadata = {"rule_id": "attack_path.privilege_escalation", **_metadata_for("attack_path.privilege_escalation")}
        evidence_refs: list[dict[str, Any]] = []
        seen_refs: set[tuple[str, str]] = set()
        for hop in path.get("hops") or []:
            ref = hop.get("evidence_ref") if isinstance(hop, dict) else None
            if not isinstance(ref, dict):
                continue
            ref_key = (str(ref.get("artifact_path")), str(ref.get("record_key")))
            if ref_key not in seen_refs:
                seen_refs.add(ref_key)
                evidence_refs.append(dict(ref))
        findings.append(
            _finalize_finding(
                {
                    **metadata,
                    "id": path["id"],
                    "severity": path.get("severity"),
                    "category": "identity",
                    "title": f"Potential privilege escalation route: {path.get('source')} → {path.get('target')}",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": [path.get("source"), path.get("target")],
                    "returned_value": path.get("summary"),
                    "evidence": {
                        "attack_path_id": path["id"],
                        "hops": path.get("hops"),
                        "techniques": path.get("techniques"),
                        "breakpoints": path.get("breakpoints"),
                        "risk_score": path.get("risk_score"),
                        "foothold_count": path.get("foothold_count"),
                        "classification": path.get("classification", "conditional_hypothesis"),
                        "execution_verified": False,
                        "unmet_preconditions": path.get("unmet_preconditions", []),
                        **(
                            {"effective_admin_set_state": admin_set_summary.get("state")}
                            if admin_set_summary and rule_id == "attack_path.no_mfa_to_tier0"
                            else {}
                        ),
                    },
                    "evidence_refs": evidence_refs,
                }
            )
        )
    return findings


def _build_secure_score_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    latest = latest_secure_score(normalized_snapshot)
    if latest is None or latest["percentage"] >= SECURE_SCORE_LOW_THRESHOLD_PERCENT:
        return []
    record = latest["record"]
    return [
        _finalize_finding(
            {
                "id": f"secure_score:{record.get('id')}:low_overall",
                "rule_id": "secure_score.low_overall",
                "severity": "medium",
                "category": "posture",
                "title": "Microsoft Secure Score is below half of the achievable score",
                "status": "open",
                "collector": "defender",
                "affected_objects": [str(record.get("id"))],
                "evidence": {
                    key: record.get(key) for key in ("id", "created", "current_score", "max_score") if key in record
                },
                "returned_value": f"{latest['current_score']:g}/{latest['max_score']:g} ({latest['percentage']:g}%)",
                "evidence_refs": _normalized_evidence_refs("security_scores", record, "defender"),
                **_metadata_for("secure_score.low_overall"),
            }
        )
    ]


def _tenant_settings_refs(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """References to the tenant sharing settings records that were read."""
    return [
        ref
        for record in ((normalized_snapshot.get(external_sharing.SECTION) or {}).get("records") or [])
        if record.get("read_state") == "collected"
        for ref in _normalized_evidence_refs(external_sharing.SECTION, record, str(record.get("collector") or "sharepoint_access"))
    ]


def _build_onedrive_sharing_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """One graded tenant-level finding for OneDrive external sharing, with the affected sites as evidence.

    Sharing is a tenant setting. The collector copies it onto every site it lists, so a finding per site
    repeated one fact N times at the tenant's severity. The grade follows the capability (anyone links
    high, new and existing guests low, existing guests only none) and, when sites carry a value of their
    own, the share of sites at the anyone level. A site cannot be more permissive than the tenant: one that
    reports a value above it is listed as an inconsistency and counts at its own level.
    """
    settings = external_sharing.tenant_settings(normalized_snapshot)
    capability, capability_basis = external_sharing.onedrive_capability(settings)
    if capability is None:
        return []
    tenant_rank = external_sharing.capability_rank(capability) or 0
    personal_sites = [
        item
        for item in ((normalized_snapshot.get("onedrive_posture_objects") or {}).get("records") or [])
        if str(item.get("site_kind") or "").lower() == "personal"
    ]
    rows: list[dict[str, Any]] = []
    exceeding: list[dict[str, Any]] = []
    anyone = guests = 0
    worst = capability
    for site in personal_sites:
        own = external_sharing.canonical_sharing_capability(site.get("sharing_capability")) if site.get("sharing_capability_source") == "site" else None
        effective = own or capability
        rank = external_sharing.capability_rank(effective) or 0
        row = {
            "id": site.get("id"),
            "name": site.get("site_name"),
            "web_url": site.get("web_url"),
            "effective_sharing_capability": effective,
            "value_source": "site" if own else "tenant",
        }
        if own and rank > tenant_rank:
            exceeding.append(row)
            worst = effective if rank > (external_sharing.capability_rank(worst) or 0) else worst
        if rank == 3:
            anyone += 1
        elif rank == 2:
            guests += 1
        if rank >= 2:
            rows.append(row)
    severity = external_sharing.grade_onedrive_sharing(worst, anyone_sites=anyone, known_sites=len(personal_sites))
    if severity is None:
        return []
    limit = external_sharing.SITE_EVIDENCE_LIMIT
    site_refs = [
        ref
        for site in personal_sites[:_AGGREGATE_REF_LIMIT]
        for ref in _normalized_evidence_refs("onedrive_posture_objects", site, "onedrive_posture")
    ]
    evidence = {
        "sharing_capability": capability,
        "capability_basis": capability_basis,
        "most_permissive_capability": worst,
        "personal_site_count": len(personal_sites),
        "sites_with_anyone_links": anyone,
        "sites_with_guest_sharing": guests,
        "share_of_sites_with_anyone_links": round(anyone / len(personal_sites), 3) if personal_sites else None,
        "site_values": "site_specific" if any(site.get("sharing_capability_source") == "site" for site in personal_sites) else "tenant_default",
        "sites": rows[:limit],
        "sites_listed_truncated": len(rows) > limit,
        "sites_exceeding_tenant_setting": exceeding[:limit],
    }
    if settings.get("unrecognised"):
        evidence["unrecognised_settings"] = settings["unrecognised"]
    return [
        _finalize_finding(
            {
                "id": "onedrive_posture:tenant:external_sharing_enabled",
                "rule_id": "onedrive.external_sharing_enabled",
                "severity": severity,
                "category": "exposure",
                "title": "OneDrive external sharing is enabled",
                "status": "open",
                "collector": "onedrive_posture",
                "affected_objects": [f"OneDrive sharing setting: {worst}"],
                "evidence": evidence,
                "returned_value": {
                    "sharing_capability": worst,
                    "personal_sites": len(personal_sites),
                    "sites_with_anyone_links": anyone,
                    "sites_with_guest_sharing": guests,
                },
                "evidence_refs": [*_tenant_settings_refs(normalized_snapshot), *site_refs],
                **_metadata_for("onedrive.external_sharing_enabled"),
            }
        )
    ]


def _build_sharepoint_tenant_sharing_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Tenant sharing settings that widen who can reach SharePoint and OneDrive content.

    Each rule reads the settings it names and stays silent when a setting was not read: Microsoft Graph
    returns the sharing capability and the domain restriction, while the default link type and the
    anonymous-link settings arrive only when the settings payload carries them (an export from the
    SharePoint Online Management Shell). Baseline alignment reads an unread setting as not assessed.
    """
    settings = external_sharing.tenant_settings(normalized_snapshot)
    if not settings["read"]:
        return []
    collector = str((settings.get("collectors") or ["sharepoint_access"])[0])
    refs = _tenant_settings_refs(normalized_snapshot)
    capability = settings.get("sharing_capability")
    findings: list[dict[str, Any]] = []

    def _tenant_finding(body: dict[str, Any]) -> None:
        findings.append(
            _finalize_finding(
                {
                    "status": "open",
                    "category": "exposure",
                    "collector": collector,
                    "evidence_refs": refs,
                    **body,
                    **_metadata_for(body["rule_id"]),
                }
            )
        )

    def _thresholds(rule_id: str, metric: str, observed: Any, grade: dict[str, Any], requirements: dict[str, str]) -> list[dict[str, Any]]:
        """Per framework: what it requires and whether this finding breaches it (a benchmark that allows
        what the setting is, as CIS does for new and existing guests, is not failed by a low finding)."""
        mapped = _framework_mappings_for(rule_id)
        return [
            {
                "framework": framework,
                "control_ids": list(mapped.get(framework) or []),
                "metric": metric,
                "observed": observed,
                "requirement": requirements[framework],
                "breached": bool(breached),
            }
            for framework, breached in grade["breaches"].items()
            if mapped.get(framework)
        ]

    grade = external_sharing.grade_external_sharing(settings)
    if grade:
        anyone = grade["scope"] == "anyone_links"
        _tenant_finding(
            {
                "id": "sharepoint_tenant:external_sharing_broad",
                "rule_id": "sharepoint.external_sharing_broad",
                "severity": grade["severity"],
                "title": (
                    "SharePoint and OneDrive allow anyone links"
                    if anyone
                    else "SharePoint and OneDrive allow sharing with new guests"
                ),
                "affected_objects": ["Tenant sharing capability"],
                "evidence": {
                    "sharing_capability": capability,
                    "anonymous_link_expiry_days": settings.get("anonymous_link_expiry_days"),
                    "file_anonymous_link_type": settings.get("file_anonymous_link_type"),
                    "folder_anonymous_link_type": settings.get("folder_anonymous_link_type"),
                    "mitigations_observed": grade["mitigations"],
                    "settings_not_read": grade["not_read"],
                },
                "returned_value": {"sharing_capability": capability, "mitigations_observed": grade["mitigations"]},
                "framework_thresholds": _thresholds(
                    "sharepoint.external_sharing_broad",
                    "sharing_capability",
                    capability,
                    grade,
                    {
                        "cis_m365_v7": "New and existing guests, or less permissive",
                        "cisa_scuba": "Existing guests, or only people in the organisation",
                        "cyber_essentials": "No anyone (anonymous) links; authenticated guests are not anonymous access",
                    },
                ),
            }
        )
    grade = external_sharing.grade_domain_restriction(settings)
    if grade:
        _tenant_finding(
            {
                "id": "sharepoint_tenant:sharing_domains_unrestricted",
                "rule_id": "sharepoint.sharing_domains_unrestricted",
                "severity": grade["severity"],
                "title": "External sharing is not limited to approved domains",
                "affected_objects": ["Tenant sharing domain restriction"],
                "evidence": {
                    "sharing_capability": capability,
                    "sharing_domain_restriction_mode": settings.get("sharing_domain_restriction_mode"),
                    "allowed_domain_count": settings.get("allowed_domain_count"),
                    "blocked_domain_count": settings.get("blocked_domain_count"),
                },
                "returned_value": {
                    "sharing_capability": capability,
                    "sharing_domain_restriction_mode": settings.get("sharing_domain_restriction_mode"),
                },
                "framework_thresholds": _thresholds(
                    "sharepoint.sharing_domains_unrestricted",
                    "sharing_domain_restriction_mode",
                    settings.get("sharing_domain_restriction_mode"),
                    grade,
                    {
                        "cis_m365_v7": "An allow list or a block list of domains",
                        "cisa_scuba": "An allow list of approved domains",
                    },
                ),
            }
        )
    grade = external_sharing.grade_default_link_type(settings)
    if grade:
        _tenant_finding(
            {
                "id": "sharepoint_tenant:default_link_type_broad",
                "rule_id": "sharepoint.default_link_type_broad",
                "severity": grade["severity"],
                "title": "The default sharing link is not for specific people",
                "affected_objects": ["Tenant default sharing link type"],
                "evidence": {
                    "default_sharing_link_type": settings.get("default_sharing_link_type"),
                    "sharing_capability": capability,
                },
                "returned_value": {"default_sharing_link_type": settings.get("default_sharing_link_type")},
                "framework_thresholds": _thresholds(
                    "sharepoint.default_link_type_broad",
                    "default_sharing_link_type",
                    settings.get("default_sharing_link_type"),
                    grade,
                    {"cis_m365_v7": "Specific people (Direct)", "cisa_scuba": "Specific people (Direct)"},
                ),
            }
        )
    return findings


def _build_teams_federation_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Teams federation that is allowed with no allow list, so every external domain can reach staff.

    Federation to an allow list of partner domains is the intended configuration and is not reported. A
    configuration whose allow list was not collected, or has a shape this tool does not recognise, is not
    reported either: baseline alignment reads it as not assessed instead of guessing. Consumer and
    public-account access (``AllowTeamsConsumer``, ``AllowPublicUsers``) are evidence on the finding.
    """
    findings: list[dict[str, Any]] = []
    for item in ((normalized_snapshot.get("teams_policy_objects") or {}).get("records") or []):
        if item.get("source_name") != "tenantFederationConfiguration":
            continue
        if item.get("allow_federated_users") is not True:
            continue
        if item.get("allowed_domains_state") != external_sharing.FEDERATION_OPEN:
            continue
        returned = {
            "allow_federated_users": True,
            "allowed_domains": "all known domains (no allow list)",
            "blocked_domain_count": item.get("blocked_domain_count"),
            "allow_teams_consumer": item.get("allow_teams_consumer"),
            "allow_public_users": item.get("allow_public_users"),
        }
        findings.append(
            _finalize_finding(
                {
                    "id": f"teams_policy:{item.get('id')}:external_federation_open",
                    "rule_id": "teams.external_federation_open",
                    "severity": "medium",
                    "category": "collaboration",
                    "title": "Teams external federation is open to every domain",
                    "status": "open",
                    "collector": "teams_policy",
                    "affected_objects": [item.get("policy_name") or item.get("id")],
                    "evidence": item,
                    "returned_value": {key: value for key, value in returned.items() if value is not None},
                    "evidence_refs": _normalized_evidence_refs("teams_policy_objects", item, "teams_policy"),
                    **_metadata_for("teams.external_federation_open"),
                }
            )
        )
    return findings


# Conditional Access finding types produced by normalization, and the rule each one reports under.
_CA_FINDING_RULES = {
    "ca_reporting_only": {"rule_id": "ca.policy_report_only"},
    "ca_break_glass_exclusion": {"rule_id": "ca.break_glass_exclusion_missing"},
}

# SharePoint site ownership states that raise a finding, with the rule and severity of each.
_SITE_OWNERSHIP_RULES = {
    "orphaned": {"rule_id": "sharepoint.site_orphaned", "severity": "high", "suffix": "orphaned_site"},
    "weak": {"rule_id": "sharepoint.site_weak_ownership", "severity": "medium", "suffix": "weak_ownership"},
}


def _normalization_report(normalized_snapshot: dict[str, Any], source: str) -> dict[str, Any]:
    for row in (normalized_snapshot.get("normalization_coverage") or {}).get("records") or []:
        if isinstance(row, dict) and row.get("source") == source:
            return row
    return {}


def _read_in_full(report: dict[str, Any]) -> bool:
    """Whether an endpoint was read without error, cut or unreadable rows, so an empty result means none."""
    return bool(report) and report.get("collection_status") == "collected" and report.get("complete") is True


def _section_records(normalized_snapshot: dict[str, Any], section: str) -> list[dict[str, Any]]:
    return [row for row in ((normalized_snapshot.get(section) or {}).get("records") or []) if isinstance(row, dict)]


def _summary_record(normalized_snapshot: dict[str, Any], section: str, kind: str) -> dict[str, Any] | None:
    return next((row for row in _section_records(normalized_snapshot, section) if row.get("kind") == kind), None)


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _device_base(device: dict[str, Any]) -> dict[str, Any]:
    """The fields every managed-device finding shares; the caller adds ``id``, ``rule_id`` and the rest."""
    return {
        "status": "open",
        "category": "device_management",
        "collector": "intune",
        "affected_objects": [device.get("display_name") or device.get("id")],
        "evidence_refs": _normalized_evidence_refs("devices", device, "intune"),
    }


def _eol_severity(lifecycle: os_lifecycle.Lifecycle, today: Any) -> str:
    """High for a vendor-published end date, medium where the date is derived or a paid extension may still apply."""
    extended = lifecycle.extended_support_until
    extension_open = bool(extended) and str(extended) >= today.isoformat()
    return "high" if lifecycle.confidence == "vendor_published" and not extension_open else "medium"


def _build_device_posture_findings(
    normalized_snapshot: dict[str, Any], *, sync_days: int, now: datetime
) -> list[dict[str, Any]]:
    """Encryption, jailbreak, stale sync and end-of-life findings from the managed device records.

    A device whose field is absent, ``Unknown`` or unparseable is skipped here and counted as unknown in
    ``device_posture`` (which baseline alignment reads); an unknown is never a finding.
    """
    findings: list[dict[str, Any]] = []
    today = now.date()
    for device in _section_records(normalized_snapshot, "devices"):
        family = device.get("os_family") or os_lifecycle.os_family(device.get("platform"))
        device_id = device.get("id")
        if endpoint_posture.encryption_state(device) == endpoint_posture.STATE_OFF:
            findings.append(
                _finalize_finding(
                    {
                        **_device_base(device),
                        "id": f"intune:{device_id}:device_encryption_off",
                        "rule_id": "intune.device_encryption_off",
                        "severity": "high" if family in {os_lifecycle.FAMILY_WINDOWS, os_lifecycle.FAMILY_MACOS} else "medium",
                        "title": "Managed device storage is not encrypted",
                        "evidence": device,
                        "returned_value": device.get("is_encrypted"),
                        **_metadata_for("intune.device_encryption_off"),
                    }
                )
            )
        if endpoint_posture.jailbreak_state(device) == endpoint_posture.STATE_JAILBROKEN:
            findings.append(
                _finalize_finding(
                    {
                        **_device_base(device),
                        "id": f"intune:{device_id}:device_jailbroken",
                        "rule_id": "intune.device_jailbroken",
                        "severity": "high",
                        "title": "Managed device is jailbroken or rooted",
                        "evidence": device,
                        "returned_value": device.get("jail_broken"),
                        **_metadata_for("intune.device_jailbroken"),
                    }
                )
            )
        if endpoint_posture.sync_state(device, sync_days, now) == endpoint_posture.STATE_STALE:
            findings.append(
                _finalize_finding(
                    {
                        **_device_base(device),
                        "id": f"intune:{device_id}:device_stale_sync",
                        "rule_id": "intune.device_stale_sync",
                        "severity": "medium",
                        "title": "Managed device has stale sync",
                        "evidence": {**device, "stale_after_days": sync_days},
                        "returned_value": device.get("last_sync_at"),
                        **{
                            **_metadata_for("intune.device_stale_sync"),
                            "description": f"A managed Intune device has not synced for more than {sync_days} days.",
                            "expected_value": f"Managed devices sync within {sync_days} days.",
                        },
                    }
                )
            )
        lifecycle = endpoint_posture.lifecycle(device, today)
        if lifecycle.state == os_lifecycle.STATE_PAST_END_OF_LIFE:
            findings.append(
                _finalize_finding(
                    {
                        **_device_base(device),
                        "id": f"intune:{device_id}:device_os_end_of_life",
                        "rule_id": "intune.device_os_end_of_life",
                        "severity": _eol_severity(lifecycle, today),
                        "title": "Managed device runs an operating system past its end of support",
                        "evidence": {
                            **device,
                            "os_lifecycle": lifecycle.evidence(),
                            "os_lifecycle_table_verified_on": os_lifecycle.table_verified_on(),
                        },
                        "returned_value": device.get("os_version"),
                        **{
                            **_metadata_for("intune.device_os_end_of_life"),
                            "description": (
                                f"{lifecycle.release_name} reached the end of its security updates on {lifecycle.end_of_support}."
                                + (
                                    f" A paid extended support programme runs to {lifecycle.extended_support_until}; Auditex cannot see enrolment."
                                    if lifecycle.extended_support_until
                                    else ""
                                )
                            ),
                        },
                    }
                )
            )
    return findings


def _build_compliance_policy_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """One finding per platform that has enrolled devices and no compliance policy that applies to anybody."""
    summary = _summary_record(normalized_snapshot, endpoint_posture.COMPLIANCE_SECTION, endpoint_posture.COMPLIANCE_SUMMARY_KIND)
    if summary is None or summary.get("policies_read_state") != "collected":
        return []
    findings: list[dict[str, Any]] = []
    for row in _section_records(normalized_snapshot, endpoint_posture.COMPLIANCE_SECTION):
        if row.get("kind") != endpoint_posture.COMPLIANCE_PLATFORM_KIND or not row.get("device_count"):
            continue
        if not row.get("policy_count"):
            reason = "no_policy"
        elif (
            summary.get("assignments_read_state") == "collected"
            and not row.get("assignments_unknown_count")
            and not row.get("assigned_policy_count")
        ):
            reason = "no_assigned_policy"
        else:
            continue
        platform = str(row.get("platform"))
        findings.append(
            _finalize_finding(
                {
                    "id": f"intune:compliance_policy:{platform}:missing",
                    "rule_id": "intune.compliance_policy_missing_platform",
                    "severity": "medium",
                    "category": "device_management",
                    "title": f"No compliance policy applies to {platform} devices",
                    "status": "open",
                    "collector": "intune",
                    "affected_objects": [f"{platform} devices"],
                    "evidence": {**row, "reason": reason},
                    "returned_value": {"devices": row.get("device_count"), "policies": row.get("policy_count"), "assigned_policies": row.get("assigned_policy_count")},
                    "evidence_refs": _normalized_evidence_refs(endpoint_posture.COMPLIANCE_SECTION, row, "intune"),
                    **{
                        **_metadata_for("intune.compliance_policy_missing_platform"),
                        "description": (
                            f"{row.get('device_count')} {platform} devices are enrolled in Intune, and "
                            + (
                                f"no {platform} device compliance policy exists."
                                if reason == "no_policy"
                                else f"none of the {row.get('policy_count')} {platform} device compliance policies is assigned to a group, all devices or all users."
                            )
                        ),
                    },
                }
            )
        )
    return findings


def _build_update_management_findings(normalized_snapshot: dict[str, Any], *, now: datetime) -> list[dict[str, Any]]:
    """Update rings: none assigned, or an assigned ring that delays quality updates beyond 14 days."""
    summary = _summary_record(normalized_snapshot, endpoint_posture.UPDATE_SECTION, endpoint_posture.UPDATE_SUMMARY_KIND)
    if summary is None:
        return []
    findings: list[dict[str, Any]] = []
    rings = [row for row in _section_records(normalized_snapshot, endpoint_posture.UPDATE_SECTION) if row.get("kind") == endpoint_posture.UPDATE_RING_KIND]
    ring_inputs_complete = (
        summary.get("rings_read_state") == "collected"
        and (not summary.get("ring_count") or summary.get("ring_assignments_read_state") == "collected")
        and not summary.get("rings_with_unknown_assignments")
    )
    if (
        ring_inputs_complete
        and not summary.get("rings_assigned")
        and summary.get("windows_device_count")
        # An assigned update profile or a co-managed device means updates are managed some other way: not a gap.
        and not summary.get("profiles_assigned")
        and not summary.get("windows_comanaged_device_count")
        # A refused or cut profile list (a beta read) is "not read", never "no profile".
        and not summary.get("update_profiles_gap")
    ):
        findings.append(
            _finalize_finding(
                {
                    "id": "intune_depth:update_rings:none_assigned",
                    "rule_id": "intune_depth.update_ring_not_assigned",
                    "severity": "medium",
                    "category": "device_management",
                    "title": "No Windows Update for Business update ring is assigned",
                    "status": "open",
                    "collector": "intune_depth",
                    "affected_objects": ["Windows Update for Business update rings"],
                    "evidence": {key: summary.get(key) for key in ("ring_count", "rings_assigned", "profile_count", "windows_device_count", "update_ring_source")},
                    "returned_value": {"update_rings": summary.get("ring_count"), "assigned": summary.get("rings_assigned")},
                    "evidence_refs": _normalized_evidence_refs(endpoint_posture.UPDATE_SECTION, summary, "intune_depth"),
                    **_metadata_for("intune_depth.update_ring_not_assigned"),
                }
            )
        )
    for ring in rings:
        if ring.get("assignments_known") is not True or ring.get("assigned") is not True:
            continue
        reasons = endpoint_posture.ring_delay_reasons(ring, now)
        if not reasons:
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"intune_depth:{ring.get('id')}:update_ring_deferral",
                    "rule_id": "intune_depth.update_ring_deferral_excessive",
                    "severity": "medium",
                    "category": "device_management",
                    "title": "An assigned update ring delays quality updates beyond 14 days",
                    "status": "open",
                    "collector": "intune_depth",
                    "affected_objects": [ring.get("display_name") or ring.get("id")],
                    "evidence": {
                        **ring,
                        "reasons": reasons,
                        "deferral_limit_days": endpoint_posture.UPDATE_DEFERRAL_LIMIT_DAYS,
                        "install_delay_days": endpoint_posture.ring_install_delay_days(ring),
                    },
                    "returned_value": {"quality_deferral_days": ring.get("quality_deferral_days"), "quality_paused": ring.get("quality_paused")},
                    "evidence_refs": _normalized_evidence_refs(endpoint_posture.UPDATE_SECTION, ring, "intune_depth"),
                    **_metadata_for("intune_depth.update_ring_deferral_excessive"),
                }
            )
        )
    return findings


def _build_defender_av_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Antivirus off, real-time protection off and stale signatures, from devices whose protection state was read."""
    findings: list[dict[str, Any]] = []
    for row in _section_records(normalized_snapshot, endpoint_posture.DEFENDER_SECTION):
        if row.get("kind") != endpoint_posture.DEFENDER_STATE_KIND or row.get("read_status") != endpoint_posture.READ_OK:
            continue
        base = {
            "status": "open",
            "category": "device_management",
            "collector": "intune",
            "affected_objects": [row.get("device_name") or row.get("id")],
            "evidence": row,
            "evidence_refs": _normalized_evidence_refs(endpoint_posture.DEFENDER_SECTION, row, "intune"),
        }
        if row.get("av_state") == endpoint_posture.STATE_OFF:
            findings.append(
                _finalize_finding(
                    {
                        **base,
                        "id": f"intune:{row.get('id')}:defender_av_off",
                        "rule_id": "intune.defender_av_off",
                        "severity": "high",
                        "title": "Defender antivirus is not protecting a Windows device",
                        "returned_value": row.get("product_status") or row.get("malware_protection_enabled"),
                        **_metadata_for("intune.defender_av_off"),
                    }
                )
            )
        if row.get("realtime_state") == endpoint_posture.STATE_OFF:
            findings.append(
                _finalize_finding(
                    {
                        **base,
                        "id": f"intune:{row.get('id')}:defender_realtime_off",
                        "rule_id": "intune.defender_realtime_protection_off",
                        "severity": "medium",
                        "title": "Defender real-time protection is off on a Windows device",
                        "returned_value": row.get("real_time_protection_enabled"),
                        **_metadata_for("intune.defender_realtime_protection_off"),
                    }
                )
            )
        if row.get("signature_state") == endpoint_posture.STATE_STALE:
            findings.append(
                _finalize_finding(
                    {
                        **base,
                        "id": f"intune:{row.get('id')}:defender_signatures_stale",
                        "rule_id": "intune.defender_signatures_stale",
                        "severity": "medium",
                        "title": "Defender antivirus signatures are out of date on a Windows device",
                        "returned_value": row.get("product_status") or row.get("signature_update_overdue"),
                        **_metadata_for("intune.defender_signatures_stale"),
                    }
                )
            )
    return findings


def _build_exchange_protection_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Weakened default malware policy, tenant-wide SMTP AUTH, and DKIM signing switched off for a custom domain."""
    findings: list[dict[str, Any]] = []

    def refs(record: dict[str, Any]) -> list[dict[str, Any]]:
        return _normalized_evidence_refs("exchange_policy_objects", record, "exchange_policy")

    policy = exchange_protection.default_malware_policy(exchange_protection.source_records(normalized_snapshot, exchange_protection.SOURCE_MALWARE))
    weaknesses = exchange_protection.malware_filter_weaknesses(policy) if policy else []
    if policy and weaknesses:
        findings.append(
            _finalize_finding(
                {
                    "id": "exchange_policy:malware_filter:default_weakened",
                    "rule_id": "exchange.malware_filter_weakened",
                    "severity": "high" if len(weaknesses) > 1 else "medium",
                    "category": "mail_flow",
                    "title": "The default anti-malware policy has protections switched off",
                    "status": "open",
                    "collector": "exchange_policy",
                    "affected_objects": [policy.get("display_name") or "Default malware filter policy"],
                    "evidence": {**policy, "weaknesses": weaknesses},
                    "returned_value": {"enable_file_filter": policy.get("enable_file_filter"), "zap_enabled": policy.get("zap_enabled")},
                    "evidence_refs": refs(policy),
                    **_metadata_for("exchange.malware_filter_weakened"),
                }
            )
        )
    for record in exchange_protection.source_records(normalized_snapshot, exchange_protection.SOURCE_TRANSPORT):
        if record.get("smtp_client_auth_disabled") is False:
            findings.append(
                _finalize_finding(
                    {
                        "id": "exchange_policy:transport_config:smtp_auth_enabled",
                        "rule_id": "exchange.smtp_auth_enabled_tenant_wide",
                        "severity": "medium",
                        "category": "mail_flow",
                        "title": "Authenticated SMTP submission is enabled for the whole tenant",
                        "status": "open",
                        "collector": "exchange_policy",
                        "affected_objects": ["Exchange Online transport configuration"],
                        "evidence": record,
                        "returned_value": record.get("smtp_client_auth_disabled"),
                        "evidence_refs": refs(record),
                        **_metadata_for("exchange.smtp_auth_enabled_tenant_wide"),
                    }
                )
            )
            break
    dkim = exchange_protection.dkim_by_domain(normalized_snapshot)
    covered = exchange_protection.dns_dkim_domains(normalized_snapshot)
    for domain in exchange_protection.dkim_disabled_domains(normalized_snapshot):
        if domain in covered:
            # The DNS rule already reports this domain (no DKIM selector published); one gap, one finding.
            continue
        record = dkim[domain]
        findings.append(
            _finalize_finding(
                {
                    "id": f"exchange_policy:{domain}:dkim_signing_disabled",
                    "rule_id": "exchange.dkim_signing_disabled",
                    "severity": "medium",
                    "category": "mail_flow",
                    "title": "DKIM signing is disabled for a verified domain",
                    "status": "open",
                    "collector": "exchange_policy",
                    "affected_objects": [domain],
                    "evidence": record,
                    "returned_value": {"enabled": record.get("dkim_enabled"), "status": record.get("dkim_status")},
                    "evidence_refs": refs(record),
                    **_metadata_for("exchange.dkim_signing_disabled"),
                }
            )
        )
    return findings


def _normalized_findings(
    normalized_snapshot: dict[str, Any],
    *,
    stale_days: int | None = None,
    stale_sync_days: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    now = now or _utc_now()
    findings.extend(
        _build_device_posture_findings(normalized_snapshot, sync_days=endpoint_posture.stale_sync_days(stale_sync_days), now=now)
    )
    findings.extend(_build_compliance_policy_findings(normalized_snapshot))
    findings.extend(_build_update_management_findings(normalized_snapshot, now=now))
    findings.extend(_build_defender_av_findings(normalized_snapshot))
    findings.extend(_build_exchange_protection_findings(normalized_snapshot))
    findings.extend(_build_admin_resilience_findings(normalized_snapshot))
    findings.extend(_build_service_principal_role_findings(normalized_snapshot))
    findings.extend(_build_secure_score_findings(normalized_snapshot))
    findings.extend(_build_user_mfa_findings(normalized_snapshot))
    findings.extend(_build_identity_control_findings(normalized_snapshot))
    findings.extend(_build_stale_account_findings(normalized_snapshot))
    findings.extend(_build_guest_findings(normalized_snapshot, stale_days=stale_guest_days(stale_days)))
    findings.extend(_build_admin_licence_findings(normalized_snapshot))
    findings.extend(_build_reports_concealed_names_findings(normalized_snapshot))
    findings.extend(_build_risky_signin_findings(normalized_snapshot))
    findings.extend(_build_privilege_event_findings(normalized_snapshot))
    tenant_domains = _tenant_domains(normalized_snapshot)
    accepted_exchange_domains = _accepted_exchange_domains(normalized_snapshot)

    for item in ((normalized_snapshot.get("sharepoint_sharing_findings") or {}).get("records") or []):
        findings.append(
            _finalize_finding(
                {
                "id": f"sharepoint:{item.get('id')}",
                "rule_id": "sharepoint.broad_link",
                "severity": item.get("severity", "medium"),
                "category": "exposure",
                "title": "Broad SharePoint or OneDrive sharing link",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("site_id")],
                "evidence": item,
                "returned_value": item.get("link_scope"),
                "evidence_refs": _normalized_evidence_refs("sharepoint_sharing_findings", item, "sharepoint_access"),
                **_metadata_for("sharepoint.broad_link"),
            }
            )
        )

    for item in ((normalized_snapshot.get("sharepoint_permission_edges") or {}).get("records") or []):
        target_type = str(item.get("target_type") or "").lower()
        if target_type not in {"user", "group", "siteuser"}:
            continue
        target_domain = _email_domain(item.get("target_name")) or _email_domain(item.get("target_id"))
        if not target_domain or not tenant_domains or target_domain in tenant_domains:
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"sharepoint_permission:{item.get('id')}:external_principal",
                    "rule_id": "sharepoint.external_principal",
                    "severity": "high" if _is_write_like_sharepoint_permission(item.get("roles")) else "medium",
                    "category": "exposure",
                    "title": "SharePoint or OneDrive grants direct external access",
                    "status": "open",
                    "collector": "sharepoint_access",
                    "affected_objects": [item.get("site_name") or item.get("site_id") or item.get("id")],
                    "evidence": item,
                    "returned_value": item.get("target_name") or item.get("target_id"),
                    "evidence_refs": _normalized_evidence_refs("sharepoint_permission_edges", item, "sharepoint_access"),
                    **_metadata_for("sharepoint.external_principal"),
                }
            )
        )

    for item in ((normalized_snapshot.get("sharepoint_site_posture_objects") or {}).get("records") or []):
        site_rule = _SITE_OWNERSHIP_RULES.get(str(item.get("ownership_state") or "").lower())
        if site_rule is None:
            continue
        site_rule_id = site_rule["rule_id"]
        findings.append(
            _finalize_finding(
                {
                "id": f"sharepoint_site_posture:{item.get('id')}:{site_rule['suffix']}",
                "rule_id": site_rule_id,
                "severity": site_rule["severity"],
                "category": "exposure",
                "title": "SharePoint site ownership is weak",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("sharepoint_site_posture_objects", item, "sharepoint_access"),
                **_metadata_for(site_rule_id),
            }
            )
        )

    findings.extend(_build_onedrive_sharing_findings(normalized_snapshot))
    findings.extend(_build_sharepoint_tenant_sharing_findings(normalized_snapshot))

    risky_scopes = {
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "Mail.Read",
        "Mail.ReadWrite",
        "Mail.Send",
        "Sites.Read.All",
        "Sites.ReadWrite.All",
        "Sites.FullControl.All",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "UserAuthenticationMethod.ReadWrite.All",
        "Files.ReadWrite.All",
        "full_access_as_app",
        "AuditLog.Read.All",
        "eDiscovery.Read.All",
        "Exchange.ManageAsApp",
    }
    for item in ((normalized_snapshot.get("application_consents") or {}).get("records") or []):
        if item.get("source_name") not in (None, "oauth2PermissionGrants"):
            continue
        scope_tokens = {str(token) for token in str(item.get("scope") or "").split() if token}
        high_risk = sorted(scope_tokens & risky_scopes)
        if not high_risk and int(item.get("owner_count") or 0) > 0:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"app_consent:{item.get('id')}:high_privilege",
                "severity": "high" if high_risk else "medium",
                "category": "application",
                "title": "High privilege or weakly owned enterprise application consent",
                "status": "open",
                "collector": "app_consent",
                "affected_objects": [item.get("service_principal_name") or item.get("service_principal_id")],
                "evidence": item,
                "rule_id": "app_consent.high_privilege",
                "returned_value": sorted(high_risk) if high_risk else item.get("owner_count"),
                "recommendations": {
                    "high_risk_scopes": high_risk,
                    "owner_count": item.get("owner_count"),
                },
                "evidence_refs": _normalized_evidence_refs("application_consents", item, "app_consent"),
                **_metadata_for("app_consent.high_privilege"),
            }
            )
        )

    exchange_records = ((normalized_snapshot.get("exchange_policy_objects") or {}).get("records") or [])
    for item in exchange_records:
        # Forwarding to an external SMTP address and forwarding to a mail contact (ForwardingAddress) are both forwarding.
        if item.get("source_name") != "mailboxForwarding" or not (
            item.get("forwarding_smtp_address") or item.get("forwarding_address")
        ):
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"exchange:{item.get('id')}:mailbox_forwarding",
                "rule_id": "exchange.mailbox_forwarding_configured",
                "severity": "high",
                "category": "mail_flow",
                "title": "Mailbox forwarding configured",
                "status": "open",
                "collector": "exchange_policy",
                "affected_objects": [item.get("display_name") or item.get("primary_smtp_address")],
                "evidence": item,
                "returned_value": {
                    key: item.get(key) for key in ("forwarding_smtp_address", "forwarding_address") if item.get(key)
                },
                "evidence_refs": _normalized_evidence_refs("exchange_policy_objects", item, "exchange_policy"),
                **_metadata_for("exchange.mailbox_forwarding_configured"),
            }
            )
        )
    for item in exchange_records:
        if item.get("source_name") != "remoteDomains" or not _flag_enabled(item.get("auto_forward_enabled")):
            continue
        domain_name = str(item.get("domain_name") or "").strip()
        display_name = item.get("display_name") or item.get("id")
        is_default_policy = domain_name in {"", "*"} or str(display_name or "").strip().lower() == "default"
        findings.append(
            _finalize_finding(
                {
                    "id": f"exchange_remote_domain:{item.get('id')}:auto_forward_enabled",
                    "rule_id": "exchange.remote_domain_auto_forward_enabled",
                    "severity": "high" if is_default_policy else "medium",
                    "category": "mail_flow",
                    "title": "Exchange remote domain permits automatic forwarding",
                    "status": "open",
                    "collector": "exchange_policy",
                    "affected_objects": [display_name],
                    "evidence": item,
                    "returned_value": item.get("auto_forward_enabled"),
                    "evidence_refs": _normalized_evidence_refs("exchange_policy_objects", item, "exchange_policy"),
                    **_metadata_for("exchange.remote_domain_auto_forward_enabled"),
                }
            )
        )
    for item in exchange_records:
        if item.get("source_name") != "transportRules":
            continue
        state = str(item.get("state") or "").strip().lower()
        mode = str(item.get("mode") or "").strip().lower()
        if state and state != "enabled":
            continue
        if mode and mode not in {"enforce", "enforced"}:
            continue
        external_targets = [
            *_external_recipients(item.get("redirect_message_to"), accepted_exchange_domains),
            *_external_recipients(item.get("blind_copy_to"), accepted_exchange_domains),
            *_external_recipients(item.get("copy_to"), accepted_exchange_domains),
        ]
        external_targets = list(dict.fromkeys(external_targets))
        if not external_targets:
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"exchange_transport:{item.get('id')}:external_redirect",
                    "rule_id": "exchange.transport_external_redirect",
                    "severity": "critical",
                    "category": "mail_flow",
                    "title": "Exchange transport rule sends mail outside accepted domains",
                    "status": "open",
                    "collector": "exchange_policy",
                    "affected_objects": [item.get("display_name") or item.get("id")],
                    "evidence": item,
                    "returned_value": external_targets,
                    "evidence_refs": _normalized_evidence_refs("exchange_policy_objects", item, "exchange_policy"),
                    **_metadata_for("exchange.transport_external_redirect"),
                }
            )
        )

    findings.extend(_build_teams_federation_findings(normalized_snapshot))

    service_health_records = ((normalized_snapshot.get("service_health_objects") or {}).get("records") or [])
    active_service_health_statuses = {"serviceDegradation", "serviceInterruption", "investigating", "restoringService"}
    for item in service_health_records:
        if item.get("source_name") != "serviceIssues":
            continue
        if item.get("status") not in active_service_health_statuses:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"service_health:{item.get('id')}:active_service_issue",
                "rule_id": "service_health.active_service_issue",
                "severity": "medium",
                "category": "service",
                "title": "Active Microsoft 365 service issue",
                "status": "open",
                "collector": "service_health",
                "affected_objects": [item.get("service") or item.get("title") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("service_health_objects", item, "service_health"),
                **_metadata_for("service_health.active_service_issue"),
            }
            )
        )

    external_identity_records = ((normalized_snapshot.get("external_identity_objects") or {}).get("records") or [])
    broad_guest_invite_settings = {"everyone", "everyoneAndGuestInviters"}
    for item in external_identity_records:
        if item.get("source_name") != "authorizationPolicy":
            continue
        if item.get("allow_invites_from") not in broad_guest_invite_settings:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"external_identity:{item.get('id')}:broad_guest_invite_policy",
                "rule_id": "external_identity.broad_guest_invite_policy",
                "severity": "medium",
                "category": "external_access",
                "title": "Broad guest invitation policy is enabled",
                "status": "open",
                "collector": "external_identity",
                "affected_objects": [item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("external_identity_objects", item, "external_identity"),
                **_metadata_for("external_identity.broad_guest_invite_policy"),
            }
            )
        )

    app_credential_records = (
        (normalized_snapshot.get("application_credential_objects") or {}).get("records") or []
    )
    for item in app_credential_records:
        findings.extend(_build_app_credential_findings(item))

    inbox_rule_records = (
        (normalized_snapshot.get("inbox_rule_objects") or {}).get("records") or []
    )
    for item in inbox_rule_records:
        findings.extend(_build_inbox_rule_findings(item))

    cross_tenant_default_records = (
        (normalized_snapshot.get("cross_tenant_default_objects") or {}).get("records") or []
    )
    for item in cross_tenant_default_records:
        findings.extend(_build_cross_tenant_default_findings(item))

    cross_tenant_partner_records = (
        (normalized_snapshot.get("cross_tenant_partner_objects") or {}).get("records") or []
    )
    for item in cross_tenant_partner_records:
        findings.extend(_build_cross_tenant_partner_findings(item))

    dns_posture_records = ((normalized_snapshot.get("dns_posture_objects") or {}).get("records") or [])
    weak_spf_qualifiers = {"+", "?"}
    for item in dns_posture_records:
        if item.get("managed_by_microsoft"):
            continue
        domain = str(item.get("domain") or item.get("id") or "")
        if not domain:
            continue
        if item.get("resolver_error"):
            # The resolver did not answer for this domain (SERVFAIL, REFUSED, timeout), so nothing it published is known:
            # no record is called missing. Baseline alignment reads the rules not_assessed with reason resolver_error.
            continue
        evidence_refs = _normalized_evidence_refs("dns_posture_objects", item, "dns_posture")
        if not item.get("spf_present"):
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:spf_missing",
                        "rule_id": "dns_posture.spf_missing",
                        "severity": "high",
                        "category": "mail_flow",
                        "title": "SPF record is missing",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        **_metadata_for("dns_posture.spf_missing"),
                    }
                )
            )
        elif item.get("spf_all_qualifier") in weak_spf_qualifiers:
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:spf_passthrough",
                        "rule_id": "dns_posture.spf_passthrough",
                        "severity": "high",
                        "category": "mail_flow",
                        "title": "SPF record allows pass-through",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        "returned_value": item.get("spf_all_qualifier"),
                        **_metadata_for("dns_posture.spf_passthrough"),
                    }
                )
            )
        if not item.get("dmarc_present"):
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:dmarc_missing",
                        "rule_id": "dns_posture.dmarc_missing",
                        "severity": "high",
                        "category": "mail_flow",
                        "title": "DMARC record is missing",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        **_metadata_for("dns_posture.dmarc_missing"),
                    }
                )
            )
        elif str(item.get("dmarc_policy") or "").lower() == "none":
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:dmarc_monitor_only",
                        "rule_id": "dns_posture.dmarc_monitor_only",
                        "severity": "medium",
                        "category": "mail_flow",
                        "title": "DMARC policy is monitor-only",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        "returned_value": item.get("dmarc_policy"),
                        **_metadata_for("dns_posture.dmarc_monitor_only"),
                    }
                )
            )
        if not item.get("dkim_selectors_present"):
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:dkim_missing",
                        "rule_id": "dns_posture.dkim_missing",
                        "severity": "medium",
                        "category": "mail_flow",
                        "title": "No DKIM selectors discovered",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        "returned_value": item.get("dkim_selectors_missing"),
                        **_metadata_for("dns_posture.dkim_missing"),
                    }
                )
            )
        if item.get("spf_multiple_records"):
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:spf_multiple_records",
                        "rule_id": "dns_posture.spf_multiple_records",
                        "severity": "high",
                        "category": "mail_flow",
                        "title": "Multiple SPF records published",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        **_metadata_for("dns_posture.spf_multiple_records"),
                    }
                )
            )
        if item.get("dmarc_present") and item.get("dmarc_pct_partial"):
            policy = str(item.get("dmarc_policy") or "").lower()
            # ``p=none`` already captured by dmarc_monitor_only — only flag partial
            # enforcement when the policy is meant to enforce.
            if policy in {"quarantine", "reject"}:
                findings.append(
                    _finalize_finding(
                        {
                            "id": f"dns_posture:{domain}:dmarc_pct_partial",
                            "rule_id": "dns_posture.dmarc_pct_partial",
                            "severity": "medium",
                            "category": "mail_flow",
                            "title": "DMARC enforcement is partial (pct < 100)",
                            "status": "open",
                            "collector": "dns_posture",
                            "affected_objects": [domain],
                            "evidence": item,
                            "evidence_refs": evidence_refs,
                            "returned_value": item.get("dmarc_pct"),
                            **_metadata_for("dns_posture.dmarc_pct_partial"),
                        }
                    )
                )
        if item.get("dmarc_aggregate_invalid"):
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:dmarc_rua_invalid",
                        "rule_id": "dns_posture.dmarc_rua_invalid",
                        "severity": "low",
                        "category": "mail_flow",
                        "title": "DMARC rua= URI list contains invalid entries",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        "returned_value": item.get("dmarc_aggregate_invalid"),
                        **_metadata_for("dns_posture.dmarc_rua_invalid"),
                    }
                )
            )
        if item.get("bimi_present") and item.get("bimi_logo_https") is False:
            findings.append(
                _finalize_finding(
                    {
                        "id": f"dns_posture:{domain}:bimi_logo_insecure",
                        "rule_id": "dns_posture.bimi_logo_insecure",
                        "severity": "low",
                        "category": "mail_flow",
                        "title": "BIMI logo URL is not served over HTTPS",
                        "status": "open",
                        "collector": "dns_posture",
                        "affected_objects": [domain],
                        "evidence": item,
                        "evidence_refs": evidence_refs,
                        **_metadata_for("dns_posture.bimi_logo_insecure"),
                    }
                )
            )
        findings.extend(_build_transport_security_findings(item, domain, evidence_refs))

    for item in ((normalized_snapshot.get("public_footprint_objects") or {}).get("records") or []):
        if str(item.get("authentication_type") or "").lower() != "federated":
            continue
        domain = str(item.get("domain") or item.get("id") or "")
        if not domain:
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"exposure:{domain}:federated_domain_metadata_public",
                    "rule_id": "exposure.federated_domain_metadata_public",
                    "severity": "low",
                    "category": "identity",
                    "title": "Federated domain sign-in metadata is publicly discoverable",
                    "status": "open",
                    "collector": "dns_posture",
                    "affected_objects": [domain],
                    "evidence": item,
                    "returned_value": {
                        "authentication_type": item.get("authentication_type"),
                        "tenant_id_public": bool(item.get("tenant_id")),
                    },
                    "evidence_refs": _normalized_evidence_refs("public_footprint_objects", item, "dns_posture"),
                    **_metadata_for("exposure.federated_domain_metadata_public"),
                }
            )
        )

    consent_policy_records = ((normalized_snapshot.get("consent_policy_objects") or {}).get("records") or [])
    for item in consent_policy_records:
        if item.get("source_name") != "adminConsentRequestPolicy":
            continue
        if item.get("is_enabled") is not False:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"consent_policy:{item.get('id')}:admin_consent_workflow_disabled",
                "rule_id": "consent_policy.admin_consent_workflow_disabled",
                "severity": "medium",
                "category": "application",
                "title": "Admin consent request workflow is disabled",
                "status": "open",
                "collector": "consent_policy",
                "affected_objects": [item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("consent_policy_objects", item, "consent_policy"),
                **_metadata_for("consent_policy.admin_consent_workflow_disabled"),
            }
            )
        )

    for device in ((normalized_snapshot.get("devices") or {}).get("records") or []):
        compliance_state = str(device.get("compliance_state") or "").strip().lower()
        if compliance_state not in {"noncompliant", "error", "conflict"}:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"intune:{device.get('id')}:device_noncompliant",
                "rule_id": "intune.device_noncompliant",
                "severity": "medium",
                "category": "device_management",
                "title": "Managed device is noncompliant",
                "status": "open",
                "collector": "intune",
                "affected_objects": [device.get("display_name") or device.get("id")],
                "evidence": device,
                "returned_value": device.get("compliance_state"),
                "evidence_refs": _normalized_evidence_refs("devices", device, "intune"),
                **_metadata_for("intune.device_noncompliant"),
            }
            )
        )

    governance_records = ((normalized_snapshot.get("governance_objects") or {}).get("records") or [])
    assignment_count = sum(1 for item in governance_records if item.get("kind") == "role_assignment_schedule")
    eligibility_count = sum(1 for item in governance_records if item.get("kind") == "role_eligibility_schedule")
    # Standing privilege is only a finding when the eligibility read itself succeeded and was empty;
    # a failed or gated eligibility read says nothing about what is eligible.
    eligibility_read = _read_in_full(_normalization_report(normalized_snapshot, "identity_governance.roleEligibilitySchedules"))
    assignment_read = _read_in_full(_normalization_report(normalized_snapshot, "identity_governance.roleAssignmentSchedules"))
    if assignment_count and not eligibility_count and eligibility_read and assignment_read:
        findings.append(
            _finalize_finding(
                {
                "id": "identity_governance:standing_privilege_only",
                "rule_id": "identity_governance.standing_privilege_only",
                "severity": "medium",
                "category": "governance",
                "title": "Privileged standing assignments observed without eligibility schedules",
                "status": "open",
                "collector": "identity_governance",
                "affected_objects": ["role_assignment_schedules"],
                "recommendations": {
                    "role_assignment_schedule_count": assignment_count,
                    "role_eligibility_schedule_count": eligibility_count,
                },
                # The standing assignments themselves, and the read that found no eligibility schedule.
                "evidence_refs": [
                    *(
                        ref
                        for item in [
                            record for record in governance_records if record.get("kind") == "role_assignment_schedule"
                        ][:_AGGREGATE_REF_LIMIT]
                        for ref in _normalized_evidence_refs("governance_objects", item, "identity_governance")
                    ),
                    *_normalized_evidence_refs(
                        "normalization_coverage",
                        _normalization_report(normalized_snapshot, "identity_governance.roleEligibilitySchedules"),
                        "identity_governance",
                    ),
                ],
                **_metadata_for("identity_governance.standing_privilege_only"),
            }
            )
        )

    intune_assignments = ((normalized_snapshot.get("intune_assignment_objects") or {}).get("records") or [])
    intune_policy_rows = ((normalized_snapshot.get("intune_policy_assignment_objects") or {}).get("records") or [])
    # Policies and assignments both come from intune_depth: policies counted from other collectors say
    # nothing about this one, and an unread assignment list is not an empty one.
    configuration_report = _normalization_report(normalized_snapshot, "intune_depth.deviceConfigurations")
    policy_count = int(configuration_report.get("record_count") or 0)
    assignments_read = _read_in_full(_normalization_report(normalized_snapshot, "intune_depth.deviceConfigurationAssignments"))
    # The assignment read expands one profile at a time up to a limit: with profiles left unexpanded,
    # "no assignments" describes the sample only, so the finding stays silent (baselines read not_assessed).
    if (
        policy_count
        and not intune_assignments
        and _read_in_full(configuration_report)
        and assignments_read
        and not intune_assignments_are_a_sample(normalized_snapshot)
    ):
        findings.append(
            _finalize_finding(
                {
                "id": "intune:intune_policies_without_assignments",
                "rule_id": "intune_depth.policies_without_assignments",
                "severity": "medium",
                "category": "device_management",
                "title": "Intune device configuration profiles have no assignments",
                "status": "open",
                "collector": "intune_depth",
                "affected_objects": ["intune_policies"],
                "returned_value": {"policy_count": policy_count, "assignment_count": 0},
                # Policy rows are counted, not kept, so the policy count is cited from the read that counted
                # them. The empty assignments are cited from the per-policy assignment rows (each with
                # ``assignment_count`` 0). The assignment read's own coverage row counts those rows (it
                # reads two for two policies), so it stands in only when the snapshot has no per-policy rows.
                "evidence_refs": [
                    *_normalized_evidence_refs("normalization_coverage", configuration_report, "intune_depth"),
                    *(
                        ref
                        for row in intune_policy_rows[:_AGGREGATE_REF_LIMIT]
                        for ref in _normalized_evidence_refs("intune_policy_assignment_objects", row, "intune_depth")
                    ),
                    *(
                        _normalized_evidence_refs(
                            "normalization_coverage",
                            _normalization_report(normalized_snapshot, "intune_depth.deviceConfigurationAssignments"),
                            "intune_depth",
                        )
                        if not intune_policy_rows
                        else []
                    ),
                ],
                **_metadata_for("intune_depth.policies_without_assignments"),
            }
            )
        )

    findings.extend(_build_attack_path_findings(normalized_snapshot))

    for item in ((normalized_snapshot.get("ca_findings") or {}).get("records") or []):
        finding_id = item.get("finding_type") or item.get("id")
        policy_key = item.get("policy_id") or item.get("id") or item.get("policy_name") or "policy"
        ca_rule = _CA_FINDING_RULES.get(str(item.get("finding_type")))
        if ca_rule is None:
            # Normalization and this map move together; an unmapped type must not become a rule-less finding.
            raise ValueError(f"Conditional Access finding type {item.get('finding_type')!r} has no rule_id.")
        ca_rule_id = ca_rule["rule_id"]
        affected = [item.get("policy_name") or item.get("policy_id")]
        evidence_refs = _normalized_evidence_refs("ca_findings", item, "conditional_access")
        returned_value = None
        policies = [policy for policy in (item.get("policies") or []) if isinstance(policy, dict)]
        if policies:
            # One finding for the tenant, naming each enabled MFA or block policy that lacks the exclusion.
            affected = [policy.get("policy_name") or policy.get("policy_id") for policy in policies]
            evidence_refs += [
                ref
                for policy in policies[:_MFA_NOT_ENFORCED_POLICY_LIMIT]
                if policy.get("key")
                for ref in _normalized_evidence_refs("conditional_access_graph", policy, "conditional_access")
            ]
            evidence_refs += [
                ref
                for record in ((normalized_snapshot.get(_BREAK_GLASS_SECTION) or {}).get("records") or [])
                for ref in _normalized_evidence_refs(_BREAK_GLASS_SECTION, record, "conditional_access")
            ]
            returned_value = {
                "account_source": item.get("account_source"),
                "policies_without_exclusion": len(policies),
                "policy_names": affected[:_MFA_NOT_ENFORCED_POLICY_LIMIT],
                **({"unresolved_accounts": item["unresolved_accounts"]} if item.get("unresolved_accounts") else {}),
            }
        ca_metadata = _metadata_for(ca_rule_id)
        _append_note(ca_metadata, _unresolved_note({"unresolved_operator_accounts": item.get("unresolved_accounts")}))
        findings.append(
            _finalize_finding(
                {
                "id": f"conditional_access:{finding_id}:{policy_key}",
                "rule_id": ca_rule_id,
                "severity": item.get("severity", "medium"),
                "category": "identity",
                "title": item.get("title") or item.get("finding_type") or "Conditional Access finding",
                "status": "open",
                "collector": "conditional_access",
                "affected_objects": affected,
                "evidence": item,
                **({"returned_value": returned_value} if returned_value is not None else {}),
                "evidence_refs": evidence_refs,
                **ca_metadata,
            }
            )
        )

    return findings


def _build_transport_security_findings(
    item: dict[str, Any], domain: str, evidence_refs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) findings for one custom domain.

    Fires only on evidence that was collected: a resolver error, a bundle without
    TLS-RPT data, or an MTA-STS policy that was never fetched never yields a finding.
    """
    if item.get("resolver_error"):
        return []
    rows: list[dict[str, Any]] = []

    def _add(spec: dict[str, str], returned_value: Any) -> None:
        rule_id = spec["rule_id"]
        rows.append(
            _finalize_finding(
                {
                    "id": f"dns_posture:{domain}:{rule_id.split('.', 1)[1]}",
                    "rule_id": rule_id,
                    "severity": spec["severity"],
                    "category": "mail_flow",
                    "title": spec["title"],
                    "status": "open",
                    "collector": "dns_posture",
                    "affected_objects": [domain],
                    "evidence": item,
                    "returned_value": returned_value,
                    "evidence_refs": evidence_refs,
                    **_metadata_for(rule_id),
                }
            )
        )

    fetch_status = item.get("mta_sts_policy_fetch_status")
    mode = str(item.get("mta_sts_policy_mode") or "").lower()
    if item.get("mta_sts_dns_present") is False:
        _add({"rule_id": "dns_posture.mta_sts_missing", "severity": "low", "title": "MTA-STS is not published"}, None)
    elif fetch_status and fetch_status not in {"ok", "skipped"}:
        _add(
            {
                "rule_id": "dns_posture.mta_sts_policy_invalid",
                "severity": "medium",
                "title": "MTA-STS TXT record exists but the policy file is unreachable or invalid",
            },
            {"fetch_status": fetch_status, "http_status": item.get("mta_sts_policy_http_status")},
        )
    elif fetch_status == "ok" and mode in {"testing", "none"}:
        _add(
            {"rule_id": "dns_posture.mta_sts_testing_mode", "severity": "low", "title": "MTA-STS policy does not enforce TLS"},
            mode,
        )
    if item.get("tls_rpt_present") is False:
        _add(
            {
                "rule_id": "dns_posture.tls_rpt_missing",
                "severity": "low",
                "title": "SMTP TLS reporting (TLS-RPT) is not published",
            },
            None,
        )
    return rows


# Detection signal -> (rule_id, severity, title). Only an "off" signal emits a finding;
# "unknown" signals never do (they surface as coverage gaps instead).
_DETECTION_SIGNAL_RULES: dict[str, dict[str, str]] = {
    "unified_audit_log": {
        "rule_id": "detection.unified_audit_log_disabled",
        "severity": "high",
        "title": "Unified audit log ingestion is turned off",
    },
    "mailbox_audit_default": {
        "rule_id": "detection.mailbox_audit_disabled",
        "severity": "high",
        "title": "Mailbox auditing on by default is turned off for the organization",
    },
    "mailbox_audit_bypass_clear": {
        "rule_id": "detection.mailbox_audit_bypass",
        "severity": "medium",
        "title": "Accounts are configured to bypass mailbox audit logging",
    },
    "alert_policies": {
        "rule_id": "detection.no_alert_policies",
        "severity": "medium",
        "title": "No enabled Purview alert policies were found",
    },
    "risk_based_conditional_access": {
        "rule_id": "detection.no_risk_based_policies",
        "severity": "medium",
        "title": "No enabled Conditional Access policy acts on sign-in or user risk",
    },
    "signin_logs": {
        "rule_id": "detection.signin_logs_unavailable",
        "severity": "medium",
        "title": "Entra sign-in logs are unavailable because the tenant lacks the required license",
    },
}


def _build_detection_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in ((normalized_snapshot.get("detection_signal_objects") or {}).get("records") or []):
        if item.get("status") != "off":
            continue
        rule = _DETECTION_SIGNAL_RULES.get(str(item.get("name") or ""))
        if rule is None:
            continue
        rule_id, severity, title = rule["rule_id"], rule["severity"], rule["title"]
        findings.append(
            _finalize_finding(
                {
                    "id": f"detection_coverage:{item.get('name')}",
                    "rule_id": rule_id,
                    "severity": severity,
                    "category": "security",
                    "title": title,
                    "status": "open",
                    "collector": str(item.get("source_collector") or "exchange_policy"),
                    "affected_objects": [str(item.get("title") or item.get("name"))],
                    "evidence": item,
                    "returned_value": item.get("observed_value", item.get("reason")),
                    "evidence_refs": _normalized_evidence_refs(
                        "detection_signal_objects", item, str(item.get("source_collector") or "exchange_policy")
                    ),
                    **_metadata_for(rule_id),
                }
            )
        )
    return findings


def build_findings(
    diagnostics: list[dict[str, Any]],
    *,
    normalized_snapshot: dict[str, Any] | None = None,
    waiver_file: str | Path | None = None,
    stale_guest_days: int | None = None,
    stale_sync_days: int | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Group diagnostics by their would-be finding ID so collectors that probe
    # N sub-resources (e.g. sharepoint_access enumerating site permissions
    # across N sites) emit ONE aggregated finding instead of N duplicates.
    # Live audit on 2026-05-09 surfaced 5 ``sharepoint_access:sitePermissions``
    # findings collapsing to a single id and tripping the C3 duplicate-id
    # validator.
    diagnostic_groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    diagnostic_order: list[str] = []
    for position, item in enumerate(diagnostics):
        collector = str(item.get("collector") or "unknown")
        target = item.get("item") or item.get("endpoint") or collector
        finding_id = f"{collector}:{target}"
        if finding_id not in diagnostic_groups:
            diagnostic_order.append(finding_id)
            diagnostic_groups[finding_id] = []
        diagnostic_groups[finding_id].append((position, item))

    for finding_id in diagnostic_order:
        group_rows = diagnostic_groups[finding_id]
        group = [entry for _position, entry in group_rows]
        primary = group[0]
        collector = str(primary.get("collector") or "unknown")
        target = primary.get("item") or primary.get("endpoint") or collector
        error_class = (
            str(primary.get("error_class")) if primary.get("error_class") else None
        )
        rule_id = _rule_id_for(error_class)
        # Collect distinct endpoints across the group; surface them as
        # affected_objects so the report shows what was probed.
        endpoints = []
        seen_endpoints: set[str] = set()
        for entry in group:
            endpoint = entry.get("endpoint")
            if isinstance(endpoint, str) and endpoint and endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                endpoints.append(endpoint)
        affected_objects: list[str] = []
        if endpoints:
            affected_objects = endpoints
        elif target:
            affected_objects = [str(target)]

        evidence_refs: list[dict[str, Any]] = []
        for entry in group:
            entry_refs = entry.get("evidence_refs")
            if isinstance(entry_refs, list):
                evidence_refs.extend(dict(ref) for ref in entry_refs if isinstance(ref, dict))
        if not evidence_refs:
            # A diagnostic is a row of blockers/blockers.json, which every run writes from this same
            # list. That row is the record of the failed read (raw payloads hold no row for a
            # derived fan-out, and a crashed collector writes none), so it is what a finding cites.
            evidence_refs = [
                _evidence_ref(
                    artifact_path="blockers/blockers.json",
                    artifact_kind="blockers_json",
                    collector=collector,
                    record_key=f"{collector}:{entry.get('item') or entry.get('endpoint') or collector}",
                    source_name=str(entry.get("item") or entry.get("endpoint") or collector),
                    json_pointer=f"/{position}",
                    endpoint=str(entry.get("endpoint")) if entry.get("endpoint") else None,
                    response_status=str(entry.get("status")) if entry.get("status") else None,
                    query_params={
                        key: entry.get(key)
                        for key in ("top", "page", "result_limit")
                        if entry.get(key) is not None
                    }
                    or None,
                )
                for position, entry in group_rows[:_AGGREGATE_REF_LIMIT]
            ]
        body: dict[str, Any] = {
            "id": finding_id,
            "rule_id": rule_id,
            "severity": _severity_for(error_class, str(primary.get("status") or "")),
            "category": _category_for(error_class),
            "title": f"{collector} collector issue",
            "status": "open",
            "collector": collector,
            "affected_objects": affected_objects,
            "error_class": error_class,
            "error": primary.get("error"),
            "returned_value": primary.get("error"),
            "recommendations": primary.get("recommendations", {}),
            "evidence_refs": evidence_refs,
            **_metadata_for(rule_id),
        }
        if len(group) > 1:
            # Transparency for the report: how many distinct probes failed
            # the same way? Operators would otherwise lose this signal.
            body["aggregated_count"] = len(group)
        findings.append(_finalize_finding(body))
    if normalized_snapshot:
        findings.extend(
            _normalized_findings(normalized_snapshot, stale_days=stale_guest_days, stale_sync_days=stale_sync_days, now=now)
        )
        findings.extend(_build_detection_findings(normalized_snapshot))
    waiver_rows = load_waivers(Path(waiver_file)) if waiver_file else []
    return apply_waivers(findings, waiver_rows) if waiver_rows else findings


def _has_attack_graph(attack_graph: dict[str, Any] | None) -> bool:
    return isinstance(attack_graph, dict) and isinstance(attack_graph.get("summary"), dict)


def _merge_attack_paths(
    attack_graph: dict[str, Any] | None, keyword_paths: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Graph-derived paths first; the keyword stage path only when no graph path exists."""
    graph_paths = [
        deepcopy(item)
        for item in ((attack_graph or {}).get("paths") or [])
        if isinstance(item, dict)
    ]
    return graph_paths if graph_paths else list(keyword_paths)


def build_report_pack(
    *,
    tenant_name: str,
    overall_status: str,
    findings: list[dict[str, Any]],
    evidence_paths: list[str],
    blocker_count: int = 0,
    coverage_gaps: list[dict[str, Any]] | None = None,
    diff_summary: dict[str, Any] | None = None,
    privacy: dict[str, Any] | None = None,
    artifact_map: dict[str, Any] | None = None,
    attack_graph: dict[str, Any] | None = None,
    normalized_snapshot: dict[str, Any] | None = None,
    coverage_ledger: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    coverage_gap_rows = [dict(item) for item in (coverage_gaps or []) if isinstance(item, dict)]
    active_coverage_gap_rows = _active_coverage_gaps(coverage_gap_rows, findings)
    board_sections = build_board_report_sections(
        tenant_name=tenant_name,
        overall_status=overall_status,
        findings=findings,
        evidence_paths=evidence_paths,
        blocker_count=blocker_count,
        coverage_gaps=coverage_gap_rows,
    )
    enriched_findings = board_sections["findings"]
    severity_counts = Counter(str(item.get("severity") or "unknown") for item in findings)
    status_counts = Counter(str(item.get("status") or "unknown") for item in findings)
    finding_actions = [
        {
            "id": item.get("id"),
            "rule_id": item.get("rule_id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "category": item.get("category"),
            "impact": item.get("impact"),
            "remediation": item.get("remediation"),
            "status": item.get("status"),
        }
        for item in enriched_findings
        if str(item.get("status") or "open") == "open"
    ]
    action_plan = sorted([*_coverage_gap_actions(active_coverage_gap_rows), *finding_actions], key=_action_sort_key)
    summary = {
        "tenant_name": tenant_name,
        "overall_status": overall_status,
        "finding_count": len(findings),
        "blocker_count": blocker_count,
        "severity_counts": dict(severity_counts),
        "status_counts": dict(status_counts),
        "open_count": status_counts.get("open", 0),
        "accepted_count": status_counts.get("accepted_risk", 0),
        "risk": _risk_with_coverage_gaps(findings, coverage_gap_rows),
    }
    if coverage_gap_rows:
        summary["coverage_gap_count"] = len(coverage_gap_rows)
        summary["active_coverage_gap_count"] = len(active_coverage_gap_rows)
        summary["coverage_gaps"] = coverage_gap_rows
    if diff_summary:
        summary["diff_summary"] = diff_summary
    return {
        "schema_version": "2026-04-21",
        "summary": summary,
        "privacy": privacy or {},
        "artifact_map": artifact_map or {},
        "findings": enriched_findings,
        "action_plan": action_plan,
        "evidence_paths": list(dict.fromkeys(evidence_paths)),
        "executive_summary": board_sections["executive_summary"],
        "technical_appendix": board_sections["technical_appendix"],
        "reviewer_index": board_sections["reviewer_index"],
        "limitations": board_sections["limitations"],
        "proof_table": board_sections["proof_table"],
        "next_actions": board_sections["next_actions"],
        "license_profile": board_sections["license_profile"],
        "auditor_score": board_sections["auditor_score"],
        "attack_paths": _merge_attack_paths(attack_graph, board_sections["attack_paths"]),
        **({"attack_graph": dict(attack_graph["summary"])} if _has_attack_graph(attack_graph) else {}),
        "control_simulator": board_sections["control_simulator"],
        "report_qa": board_sections["report_qa"],
        "replay_context": board_sections["replay_context"],
        "baseline_alignment": build_baseline_alignment(
            findings,
            normalized_snapshot=normalized_snapshot,
            coverage_ledger=coverage_ledger,
        ),
    }


def apply_coverage_gaps_to_report_pack(report_pack: dict[str, Any], coverage_gaps: list[dict[str, Any]]) -> dict[str, Any]:
    if not coverage_gaps:
        return report_pack
    payload = deepcopy(report_pack)
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    evidence_paths = payload.get("evidence_paths") if isinstance(payload.get("evidence_paths"), list) else []
    refreshed = build_report_pack(
        tenant_name=str(summary.get("tenant_name") or ""),
        overall_status=str(summary.get("overall_status") or ""),
        findings=[item for item in findings if isinstance(item, dict)],
        evidence_paths=[str(item) for item in evidence_paths],
        blocker_count=int(summary.get("blocker_count") or 0),
        coverage_gaps=coverage_gaps,
        privacy=payload.get("privacy") if isinstance(payload.get("privacy"), dict) else {},
        artifact_map=payload.get("artifact_map") if isinstance(payload.get("artifact_map"), dict) else {},
        attack_graph=(
            {
                "summary": payload["attack_graph"],
                "paths": [
                    item
                    for item in payload.get("attack_paths") or []
                    if isinstance(item, dict) and item.get("kind") == "privilege_graph"
                ],
            }
            if isinstance(payload.get("attack_graph"), dict)
            else None
        ),
    )
    refreshed["summary"].update(
        {
            key: value
            for key, value in summary.items()
            if key not in {"risk", "coverage_gap_count", "coverage_gaps"}
        }
    )
    refreshed["summary"]["risk"] = _risk_with_coverage_gaps(
        [item for item in findings if isinstance(item, dict)],
        [dict(item) for item in coverage_gaps if isinstance(item, dict)],
    )
    refreshed["summary"]["coverage_gap_count"] = len(coverage_gaps)
    refreshed["summary"]["active_coverage_gap_count"] = len(
        _active_coverage_gaps(
            [dict(item) for item in coverage_gaps if isinstance(item, dict)],
            [item for item in findings if isinstance(item, dict)],
        )
    )
    refreshed["summary"]["coverage_gaps"] = coverage_gaps
    # Keep sections added after build_report_pack (detection_coverage, public_footprint,
    # fixture_provenance, ...) instead of silently dropping them on the refresh.
    for key, value in payload.items():
        refreshed.setdefault(key, value)
    if isinstance(payload.get("baseline_alignment"), dict):
        # The refresh has no snapshot or coverage ledger; keep the alignment
        # computed when the bundle was written.
        refreshed["baseline_alignment"] = payload["baseline_alignment"]
    return refreshed
