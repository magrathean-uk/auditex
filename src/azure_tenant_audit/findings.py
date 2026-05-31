from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .autopilot import build_board_report_sections
from .resources import resolve_resource_path
from .waivers import apply_waivers, load_waivers


_PERMISSION_CLASSES = {"insufficient_permissions", "unauthenticated"}
_SERVICE_CLASSES = {"service_unavailable", "not_found", "not_enabled"}

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
        "description": "A non-admin member user is not registered for MFA in authentication method reports.",
        "impact": "Password-only users are easier to compromise and can become a foothold for mail, data, and lateral access abuse.",
        "remediation": "Require MFA registration for active member users and follow up on users that remain unregistered.",
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


def _risk_grade(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 30:
        return "high"
    if score >= 10:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def build_risk_rollup(findings: list[dict[str, Any]]) -> dict[str, Any]:
    open_findings = [item for item in findings if str(item.get("status") or "open") == "open"]
    counts = Counter(_canonical_severity(item.get("severity"), fallback="info") for item in open_findings)
    open_weight = sum(_RISK_WEIGHTS.get(_canonical_severity(item.get("severity"), fallback="info"), 0) for item in open_findings)
    score = min(100, open_weight * 10)

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
    score = min(100, int(risk.get("score") or 0) + coverage_gap_weight * 5)
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
        normalized_refs = [
            _evidence_ref(
                artifact_path="normalized/snapshot.json",
                artifact_kind="normalized_json",
                collector=collector,
                record_key=str(result.get("id") or collector),
                source_name="snapshot",
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


def _build_admin_resilience_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    users = {
        str(item.get("id")): item
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
    role_definitions = (
        (normalized_snapshot.get("role_definitions") or {}).get("records") or []
    )
    role_assignments = (
        (normalized_snapshot.get("role_assignments") or {}).get("records") or []
    )
    global_admin_role_ids = {
        str(item.get("id"))
        for item in role_definitions
        if str(item.get("display_name") or "").strip().lower() == "global administrator"
    }
    if not global_admin_role_ids:
        return []
    principal_ids = sorted(
        {
            str(item.get("principal_id"))
            for item in role_assignments
            if item.get("role_definition_id") in global_admin_role_ids and item.get("principal_id")
        }
    )
    if not principal_ids:
        return []

    evidence_refs = [
        _evidence_ref(
            artifact_path="normalized/role_assignments.json",
            artifact_kind="normalized_json",
            collector="identity",
            record_key="identity:global_admin_resilience",
            source_name="role_assignments",
        )
    ]
    findings: list[dict[str, Any]] = []
    for principal_id in principal_ids:
        user = users.get(principal_id)
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
                    "returned_value": {"principal_id": principal_id, "enabled": user.get("enabled")},
                    "evidence_refs": evidence_refs,
                    **_metadata_for("identity.global_admin_disabled"),
                }
            )
        )
    for principal_id in principal_ids:
        user = users.get(principal_id)
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
                    "evidence_refs": evidence_refs,
                    **_metadata_for("identity.global_admin_stale_password"),
                }
            )
        )
    for principal_id in principal_ids:
        user = users.get(principal_id)
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
                        *evidence_refs,
                        _evidence_ref(
                            artifact_path="normalized/auth_method_registration_objects.json",
                            artifact_kind="normalized_json",
                            collector="auth_methods",
                            record_key=str(registration.get("key") or registration.get("id") or affected),
                            source_name="auth_method_registration_objects",
                        ),
                    ],
                    **_metadata_for("identity.global_admin_mfa_not_registered"),
                }
            )
        )
    if len(principal_ids) == 1:
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
                    "description": "The tenant has a single observed Global Administrator assignment, creating emergency access fragility.",
                    "impact": "Loss or compromise of that principal can block recovery or concentrate tenant-wide privilege.",
                    "remediation": "Maintain at least two protected emergency-capable admins and use narrower roles for routine work.",
                    "expected_value": "Two to five protected Global Administrator principals are present.",
                    "returned_value": {"global_admin_count": len(principal_ids), "principal_ids": principal_ids},
                    "evidence_refs": evidence_refs,
                    **_metadata_for("identity.global_admin_singleton"),
                }
            )
        )
    elif len(principal_ids) > 5:
        findings.append(
            _finalize_finding(
                {
                    "id": "identity:global_admin_sprawl",
                    "rule_id": "identity.global_admin_sprawl",
                    "severity": "medium",
                    "category": "identity",
                    "title": "Too many Global Administrators observed",
                    "status": "open",
                    "collector": "identity",
                    "affected_objects": principal_ids,
                    "description": "The tenant has a broad Global Administrator set, increasing blast radius if one principal is compromised.",
                    "impact": "Excess tenant-wide privilege makes containment and accountability harder.",
                    "remediation": "Reduce Global Administrator assignments and move routine administration to least-privileged roles or eligible activation.",
                    "expected_value": "Two to five protected Global Administrator principals are present.",
                    "returned_value": {"global_admin_count": len(principal_ids), "principal_ids": principal_ids},
                    "evidence_refs": evidence_refs,
                    **_metadata_for("identity.global_admin_sprawl"),
                }
            )
        )
    return findings


def _global_admin_principal_ids(normalized_snapshot: dict[str, Any]) -> set[str]:
    role_definitions = (normalized_snapshot.get("role_definitions") or {}).get("records") or []
    role_assignments = (normalized_snapshot.get("role_assignments") or {}).get("records") or []
    global_admin_role_ids = {
        str(item.get("id"))
        for item in role_definitions
        if str(item.get("display_name") or "").strip().lower() == "global administrator"
    }
    return {
        str(item.get("principal_id"))
        for item in role_assignments
        if item.get("role_definition_id") in global_admin_role_ids and item.get("principal_id")
    }


def _build_user_mfa_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
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
    admin_principal_ids = {item.lower() for item in _global_admin_principal_ids(normalized_snapshot)}
    findings: list[dict[str, Any]] = []
    for registration in ((normalized_snapshot.get("auth_method_registration_objects") or {}).get("records") or []):
        if registration.get("is_mfa_registered") is not False:
            continue
        reg_id = str(registration.get("id") or "").lower()
        upn = str(registration.get("user_principal_name") or "").lower()
        user = users_by_id.get(reg_id) or users_by_upn.get(upn)
        if reg_id in admin_principal_ids or (user and str(user.get("id") or "").lower() in admin_principal_ids):
            continue
        if registration.get("is_admin") is True:
            continue
        if user and user.get("enabled") is False:
            continue
        user_type = str((user or {}).get("user_type") or registration.get("user_type") or "").lower()
        if user_type and user_type != "member":
            continue
        affected = (user or {}).get("principal_name") or registration.get("user_principal_name") or registration.get("id")
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
                    "evidence_refs": _normalized_evidence_refs(
                        "auth_method_registration_objects",
                        registration,
                        "auth_methods",
                    ),
                    **_metadata_for("identity.user_mfa_not_registered"),
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


def _normalized_findings(normalized_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(_build_admin_resilience_findings(normalized_snapshot))
    findings.extend(_build_user_mfa_findings(normalized_snapshot))
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
        ownership_state = str(item.get("ownership_state") or "").lower()
        if ownership_state not in {"weak", "orphaned"}:
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"sharepoint_site_posture:{item.get('id')}:{'orphaned_site' if ownership_state == 'orphaned' else 'weak_ownership'}",
                "severity": "high" if ownership_state == "orphaned" else "medium",
                "category": "exposure",
                "title": "SharePoint site ownership is weak",
                "status": "open",
                "collector": "sharepoint_access",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("sharepoint_site_posture_objects", item, "sharepoint_access"),
            }
            )
        )

    for item in ((normalized_snapshot.get("onedrive_posture_objects") or {}).get("records") or []):
        site_kind = str(item.get("site_kind") or "").lower()
        sharing_capability = str(item.get("sharing_capability") or "").lower()
        if site_kind != "personal" or not sharing_capability or sharing_capability == "disabled":
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"onedrive_posture:{item.get('id')}:external_sharing_enabled",
                "severity": "high",
                "category": "exposure",
                "title": "OneDrive external sharing is enabled",
                "status": "open",
                "collector": "onedrive_posture",
                "affected_objects": [item.get("site_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("onedrive_posture_objects", item, "onedrive_posture"),
            }
            )
        )

    risky_scopes = {
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "Mail.Read",
        "Sites.Read.All",
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
        if item.get("source_name") != "mailboxForwarding" or not item.get("forwarding_smtp_address"):
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"exchange:{item.get('id')}:mailbox_forwarding",
                "severity": "high",
                "category": "mail_flow",
                "title": "Mailbox forwarding configured",
                "status": "open",
                "collector": "exchange_policy",
                "affected_objects": [item.get("display_name") or item.get("primary_smtp_address")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("exchange_policy_objects", item, "exchange_policy"),
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

    teams_records = ((normalized_snapshot.get("teams_policy_objects") or {}).get("records") or [])
    for item in teams_records:
        if item.get("source_name") != "tenantFederationConfiguration":
            continue
        if not (item.get("allow_public_users") or item.get("allow_federated_users")):
            continue
        findings.append(
            _finalize_finding(
                {
                "id": f"teams_policy:{item.get('id')}:external_federation_open",
                "severity": "medium",
                "category": "collaboration",
                "title": "Teams external federation is enabled",
                "status": "open",
                "collector": "teams_policy",
                "affected_objects": [item.get("policy_name") or item.get("id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("teams_policy_objects", item, "teams_policy"),
            }
            )
        )

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
    for device in ((normalized_snapshot.get("devices") or {}).get("records") or []):
        if not _is_stale_timestamp(device.get("last_sync_at")):
            continue
        findings.append(
            _finalize_finding(
                {
                    "id": f"intune:{device.get('id')}:device_stale_sync",
                    "rule_id": "intune.device_stale_sync",
                    "severity": "medium",
                    "category": "device_management",
                    "title": "Managed device has stale sync",
                    "status": "open",
                    "collector": "intune",
                    "affected_objects": [device.get("display_name") or device.get("id")],
                    "evidence": device,
                    "returned_value": device.get("last_sync_at"),
                    "evidence_refs": _normalized_evidence_refs("devices", device, "intune"),
                    **_metadata_for("intune.device_stale_sync"),
                }
            )
        )

    governance_records = ((normalized_snapshot.get("governance_objects") or {}).get("records") or [])
    assignment_count = sum(1 for item in governance_records if item.get("kind") == "role_assignment_schedule")
    eligibility_count = sum(1 for item in governance_records if item.get("kind") == "role_eligibility_schedule")
    if assignment_count and not eligibility_count:
        findings.append(
            _finalize_finding(
                {
                "id": "identity_governance:standing_privilege_only",
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
                "evidence_refs": [
                    _evidence_ref(
                        artifact_path="normalized/governance_objects.json",
                        artifact_kind="normalized_json",
                        collector="identity_governance",
                        record_key="identity_governance:standing_privilege_only",
                        source_name="role_assignment_schedule",
                    )
                ],
            }
            )
        )

    intune_assignments = ((normalized_snapshot.get("intune_assignment_objects") or {}).get("records") or [])
    policy_count = ((normalized_snapshot.get("snapshot") or {}).get("object_counts") or {}).get("policies", 0)
    if policy_count and not intune_assignments:
        findings.append(
            _finalize_finding(
                {
                "id": "intune:intune_policies_without_assignments",
                "severity": "medium",
                "category": "device_management",
                "title": "Policies observed without sampled Intune assignments",
                "status": "open",
                "collector": "intune_depth",
                "affected_objects": ["intune_policies"],
                "returned_value": {"policy_count": policy_count, "assignment_count": 0},
                "evidence_refs": [
                    _evidence_ref(
                        artifact_path="normalized/snapshot.json",
                        artifact_kind="normalized_json",
                        collector="intune_depth",
                        record_key="intune:intune_policies_without_assignments",
                        source_name="snapshot",
                    )
                ],
            }
            )
        )

    for item in ((normalized_snapshot.get("ca_findings") or {}).get("records") or []):
        finding_id = item.get("finding_type") or item.get("id")
        policy_key = item.get("policy_id") or item.get("id") or item.get("policy_name") or "policy"
        findings.append(
            _finalize_finding(
                {
                "id": f"conditional_access:{finding_id}:{policy_key}",
                "severity": item.get("severity", "medium"),
                "category": "identity",
                "title": item.get("title") or item.get("finding_type") or "Conditional Access finding",
                "status": "open",
                "collector": "conditional_access",
                "affected_objects": [item.get("policy_name") or item.get("policy_id")],
                "evidence": item,
                "evidence_refs": _normalized_evidence_refs("ca_findings", item, "conditional_access"),
            }
            )
        )

    return findings


def build_findings(
    diagnostics: list[dict[str, Any]],
    *,
    normalized_snapshot: dict[str, Any] | None = None,
    waiver_file: str | Path | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    # Group diagnostics by their would-be finding ID so collectors that probe
    # N sub-resources (e.g. sharepoint_access enumerating site permissions
    # across N sites) emit ONE aggregated finding instead of N duplicates.
    # Live audit on 2026-05-09 surfaced 5 ``sharepoint_access:sitePermissions``
    # findings collapsing to a single id and tripping the C3 duplicate-id
    # validator.
    diagnostic_groups: dict[str, list[dict[str, Any]]] = {}
    diagnostic_order: list[str] = []
    for item in diagnostics:
        collector = str(item.get("collector") or "unknown")
        target = item.get("item") or item.get("endpoint") or collector
        finding_id = f"{collector}:{target}"
        if finding_id not in diagnostic_groups:
            diagnostic_order.append(finding_id)
            diagnostic_groups[finding_id] = []
        diagnostic_groups[finding_id].append(item)

    for finding_id in diagnostic_order:
        group = diagnostic_groups[finding_id]
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
            evidence_refs = [
                _evidence_ref(
                    artifact_path=f"raw/{collector}.json",
                    artifact_kind="raw_json",
                    collector=collector,
                    record_key=f"{collector}:{target}",
                    source_name=str(primary.get("item") or target),
                    json_pointer=f"/{primary.get('item') or ''}" if primary.get("item") else None,
                    endpoint=str(primary.get("endpoint")) if primary.get("endpoint") else None,
                    response_status=str(primary.get("status")) if primary.get("status") else None,
                    query_params={
                        key: primary.get(key)
                        for key in ("top", "page", "result_limit")
                        if primary.get(key) is not None
                    }
                    or None,
                )
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
        findings.extend(_normalized_findings(normalized_snapshot))
    waiver_rows = load_waivers(Path(waiver_file)) if waiver_file else []
    return apply_waivers(findings, waiver_rows) if waiver_rows else findings


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
        "attack_paths": board_sections["attack_paths"],
        "control_simulator": board_sections["control_simulator"],
        "report_qa": board_sections["report_qa"],
        "replay_context": board_sections["replay_context"],
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
    return refreshed
