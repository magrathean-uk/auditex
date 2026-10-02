"""Blue-team detection coverage: could this tenant see an attack?

Builds a fixed list of detection signals from evidence other collectors already
gathered. Each signal is ``on``, ``off``, or ``unknown``:

* ``on`` / ``off`` only when the evidence was actually collected and answers the
  question (a ``license_required`` blocker is a definite ``off`` because the
  capability is absent for the tenant).
* ``unknown`` whenever the source was not collected, was blocked by permissions
  or tooling, or was sampled too thinly to prove absence. Unknown is never
  reported as off.

Nothing here performs I/O; it reads collector payloads and diagnostics only.
"""
from __future__ import annotations

from typing import Any

_LICENSE_CLASSES = {"license_required"}
SECTION = "detection_signal_objects"

# Fixed signal catalogue: name -> (title, why it matters, evidence source label)
SIGNAL_CATALOG: dict[str, dict[str, str]] = {
    "unified_audit_log": {
        "title": "Unified audit log ingestion",
        "why_it_matters": "Without the unified audit log there is no searchable record of user and admin activity, so most Microsoft 365 attacks leave no trace for investigators or a SIEM.",
        "source": "exchange_policy.adminAuditLogConfig (Get-AdminAuditLogConfig)",
    },
    "mailbox_audit_default": {
        "title": "Mailbox auditing on by default",
        "why_it_matters": "Mailbox audit records (MailItemsAccessed, Send, inbox-rule changes) are the primary evidence for business email compromise.",
        "source": "exchange_policy.organizationAuditConfig (Get-OrganizationConfig)",
    },
    "mailbox_audit_bypass_clear": {
        "title": "No mailbox audit bypass",
        "why_it_matters": "Accounts with an audit bypass association can read or change any mailbox they can access without leaving mailbox audit records.",
        "source": "exchange_policy.mailboxAuditBypass (Get-MailboxAuditBypassAssociation, count only)",
    },
    "alert_policies": {
        "title": "Purview alert policies enabled",
        "why_it_matters": "Alert policies turn audit events (forwarding rules, elevation, malware campaigns) into notifications that a responder will see.",
        "source": "exchange_policy.protectionAlerts (Get-ProtectionAlert)",
    },
    "risk_based_conditional_access": {
        "title": "Risk-based Conditional Access",
        "why_it_matters": "Policies keyed on sign-in or user risk act on Identity Protection detections automatically instead of waiting for a human.",
        "source": "conditional_access.conditionalAccessPolicies",
    },
    "identity_protection_risk_detection": {
        "title": "Identity Protection risk detection",
        "why_it_matters": "Identity Protection scores leaked credentials, token replay, and impossible travel; without it those detections never fire.",
        "source": "identity_protection.riskyUserSummary (/identityProtection/riskyUsers)",
    },
    "signin_logs": {
        "title": "Entra sign-in logs readable",
        "why_it_matters": "Sign-in logs are needed to investigate password spray, token theft, and suspicious locations.",
        "source": "security.signIns (/auditLogs/signIns)",
    },
    "directory_audit_logs": {
        "title": "Entra directory audit logs readable",
        "why_it_matters": "Directory audit logs record role grants, app consents, and credential additions used for persistence.",
        "source": "security.directoryAudits (/auditLogs/directoryAudits)",
    },
    "defender_alert_api": {
        "title": "Defender alert API reachable",
        "why_it_matters": "A reachable alerts_v2 API means Defender XDR detections exist in a place a SOC or SIEM connector can consume.",
        "source": "defender.securityAlerts or sentinel_xdr.xdrAlerts (/security/alerts_v2)",
    },
    "siem_log_export": {
        "title": "Entra log export to SIEM",
        "why_it_matters": "Exporting Entra logs to Log Analytics, Sentinel, or another SIEM keeps evidence beyond the built-in retention window.",
        "source": "Azure Resource Manager microsoft.aadiam/diagnosticSettings (not collected by Auditex)",
    },
}


def _diagnostic_class(diagnostics: list[dict[str, Any]], collector: str, item: str | None) -> str | None:
    for row in diagnostics:
        if str(row.get("collector") or "") != collector:
            continue
        if item is not None and row.get("item") not in (None, item):
            continue
        return str(row.get("error_class") or "unknown")
    return None


def section_state(
    collector_payloads: dict[str, Any],
    diagnostics: list[dict[str, Any]],
    collector: str,
    key: str,
) -> tuple[str, Any]:
    """Return ``(state, section)``; state is collected | license | blocked | not_collected."""
    payload = collector_payloads.get(collector)
    section = payload.get(key) if isinstance(payload, dict) else None
    if isinstance(section, dict) and section.get("error"):
        error_class = str(section.get("error_class") or _diagnostic_class(diagnostics, collector, key) or "")
        return ("license" if error_class in _LICENSE_CLASSES else "blocked"), section
    if isinstance(section, dict):
        return "collected", section
    error_class = _diagnostic_class(diagnostics, collector, key)
    if error_class is not None:
        return ("license" if error_class in _LICENSE_CLASSES else "blocked"), None
    return "not_collected", None


def _rows(section: Any) -> list[dict[str, Any]]:
    values = section.get("value") if isinstance(section, dict) else None
    return [item for item in values if isinstance(item, dict)] if isinstance(values, list) else []


def _truthy(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def _unknown(state: str) -> tuple[str, str]:
    return "unknown", {"blocked": "source_blocked", "license": "license_required", "not_collected": "not_collected"}.get(
        state, state
    )


def _unified_audit_log(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    state, section = section_state(payloads, diagnostics, "exchange_policy", "adminAuditLogConfig")
    if state != "collected":
        return (*_unknown(state), None)
    values = [_truthy(row.get("UnifiedAuditLogIngestionEnabled")) for row in _rows(section)]
    values = [value for value in values if value is not None]
    if not values:
        return "unknown", "property_missing", None
    return ("on", "ingestion_enabled", True) if all(values) else ("off", "ingestion_disabled", False)


def _mailbox_audit_default(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    state, section = section_state(payloads, diagnostics, "exchange_policy", "organizationAuditConfig")
    if state != "collected":
        return (*_unknown(state), None)
    values = [_truthy(row.get("AuditDisabled")) for row in _rows(section)]
    values = [value for value in values if value is not None]
    if not values:
        return "unknown", "property_missing", None
    return ("off", "audit_disabled", True) if any(values) else ("on", "audit_on_by_default", False)


def _mailbox_audit_bypass(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    state, section = section_state(payloads, diagnostics, "exchange_policy", "mailboxAuditBypass")
    if state != "collected":
        return (*_unknown(state), None)
    rows = _rows(section)
    if not rows:
        # Measure-Object always yields a Count row, so an empty payload is not proof of zero.
        return "unknown", "empty_output", None
    try:
        count = int(rows[0].get("Count") or 0)
    except (TypeError, ValueError):
        return "unknown", "property_missing", None
    return ("off", "bypass_associations_present", count) if count > 0 else ("on", "no_bypass_associations", 0)


def _alert_policies(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    state, section = section_state(payloads, diagnostics, "exchange_policy", "protectionAlerts")
    if state != "collected":
        return (*_unknown(state), None)
    rows = _rows(section)
    enabled = [row for row in rows if _truthy(row.get("Disabled")) is not True]
    value = {"policy_count": len(rows), "enabled_count": len(enabled)}
    return ("on", "enabled_alert_policies", value) if enabled else ("off", "no_enabled_alert_policies", value)


def _risk_based_ca(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    state, section = section_state(payloads, diagnostics, "conditional_access", "conditionalAccessPolicies")
    if state != "collected":
        return (*_unknown(state), None)
    matches = []
    for policy in _rows(section):
        if str(policy.get("state") or "") != "enabled":
            continue
        conditions = policy.get("conditions") if isinstance(policy.get("conditions"), dict) else {}
        # https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0
        sign_in = [lvl for lvl in conditions.get("signInRiskLevels") or [] if lvl not in {"none", "hidden"}]
        user = [lvl for lvl in conditions.get("userRiskLevels") or [] if lvl not in {"none", "hidden"}]
        if sign_in or user:
            matches.append(str(policy.get("displayName") or policy.get("id") or "policy"))
    if matches:
        return "on", "enabled_risk_policies", {"policy_count": len(matches), "policies": sorted(matches)[:10]}
    if section.get("sample_truncated"):
        return "unknown", "policy_sample_truncated", None
    return "off", "no_enabled_risk_policies", {"policy_count": 0}


def _identity_protection(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    state, section = section_state(payloads, diagnostics, "identity_protection", "riskyUserSummary")
    if state == "license":
        return "off", "license_required", None
    if state != "collected":
        return (*_unknown(state), None)
    rows = _rows(section)
    summary = rows[0] if rows else {}
    return "on", "risk_detection_available", {
        "sampled_count": summary.get("sampled_count"),
        "at_risk_count": summary.get("at_risk_count"),
    }


def _graph_log(collector: str, key: str, reason_on: str):
    def _signal(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
        state, _section = section_state(payloads, diagnostics, collector, key)
        if state == "license":
            return "off", "license_required", None
        if state != "collected":
            return (*_unknown(state), None)
        return "on", reason_on, None

    return _signal


def _defender_alerts(payloads: dict[str, Any], diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    states = [
        section_state(payloads, diagnostics, "defender", "securityAlerts")[0],
        section_state(payloads, diagnostics, "sentinel_xdr", "xdrAlerts")[0],
    ]
    if "collected" in states:
        return "on", "alerts_api_reachable", None
    if "license" in states:
        return "off", "license_required", None
    return (*_unknown("blocked" if "blocked" in states else "not_collected"), None)


def _siem_export(_payloads: dict[str, Any], _diagnostics: list[dict[str, Any]]) -> tuple[str, str, Any]:
    # Diagnostic settings live in Azure Resource Manager and need an ARM token plus
    # tenant-level Microsoft.aadiam read access; Auditex does not collect them.
    return "unknown", "not_collected_arm_diagnostic_settings", None


_SIGNAL_BUILDERS = {
    "unified_audit_log": ("exchange_policy", "adminAuditLogConfig", _unified_audit_log),
    "mailbox_audit_default": ("exchange_policy", "organizationAuditConfig", _mailbox_audit_default),
    "mailbox_audit_bypass_clear": ("exchange_policy", "mailboxAuditBypass", _mailbox_audit_bypass),
    "alert_policies": ("exchange_policy", "protectionAlerts", _alert_policies),
    "risk_based_conditional_access": ("conditional_access", "conditionalAccessPolicies", _risk_based_ca),
    "identity_protection_risk_detection": ("identity_protection", "riskyUserSummary", _identity_protection),
    "signin_logs": ("security", "signIns", _graph_log("security", "signIns", "signin_logs_readable")),
    "directory_audit_logs": (
        "security",
        "directoryAudits",
        _graph_log("security", "directoryAudits", "directory_audits_readable"),
    ),
    "defender_alert_api": ("defender", "securityAlerts", _defender_alerts),
    "siem_log_export": ("", "", _siem_export),
}


def build_detection_signals(
    collector_payloads: dict[str, Any],
    diagnostics: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return one row per catalogued signal with status on|off|unknown."""
    diagnostics = [row for row in diagnostics or [] if isinstance(row, dict)]
    rows: list[dict[str, Any]] = []
    for name, (collector, key, builder) in _SIGNAL_BUILDERS.items():
        status, reason, value = builder(collector_payloads, diagnostics)
        catalog = SIGNAL_CATALOG[name]
        rows.append(
            {
                "name": name,
                "title": catalog["title"],
                "status": status,
                "reason": reason,
                "observed_value": value,
                "why_it_matters": catalog["why_it_matters"],
                "evidence_source": catalog["source"],
                "source_collector": collector or None,
                "source_name": key or None,
            }
        )
    return rows


def summarize_detection_coverage(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build ``report_pack["detection_coverage"]`` from normalized signal records."""
    signals = []
    for record in sorted(records, key=lambda item: list(SIGNAL_CATALOG).index(item["name"]) if item.get("name") in SIGNAL_CATALOG else 99):
        name = str(record.get("name") or record.get("id") or "")
        signals.append(
            {
                "name": name,
                "title": record.get("title"),
                "status": record.get("status") if record.get("status") in {"on", "off"} else "unknown",
                "reason": record.get("reason"),
                "why_it_matters": record.get("why_it_matters"),
                "evidence_ref": {
                    "artifact_path": f"normalized/{SECTION}.json",
                    "artifact_kind": "normalized_json",
                    "collector": record.get("source_collector") or "detection_coverage",
                    "record_key": record.get("key") or f"detection_signal:{name}",
                    "source_name": record.get("evidence_source"),
                },
            }
        )
    on = sum(1 for item in signals if item["status"] == "on")
    off = sum(1 for item in signals if item["status"] == "off")
    unknown = sum(1 for item in signals if item["status"] == "unknown")
    known = on + off
    return {
        "signals": signals,
        # Score covers only signals with evidence; unknown never counts as off.
        "score": round(100 * on / known) if known else None,
        "counts": {"on": on, "off": off, "unknown": unknown},
        "assessed_ratio": round(known / len(signals), 2) if signals else 0.0,
        "limitations": [
            "Entra diagnostic-settings export (ARM microsoft.aadiam/diagnosticSettings) is not collected; siem_log_export is always unknown.",
            "Signals marked unknown were not collected or were blocked; they are not evidence that the control is off.",
        ],
    }
