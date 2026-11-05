"""IPPS rows for deterministic rules; synthetic field shapes remain unverified live."""
from __future__ import annotations

from auditex.scuba_adapters_defender import _listing_adapter
from auditex.scuba_projection import Bundle, Unavailable, _require
from azure_tenant_audit.collectors.exchange_ipps_commands import (
    ALERT_FIELDS, DLP_EXCEPTION_FIELDS, DLP_POLICY_FIELDS, DLP_RULE_FIELDS,
)


def _alerts(bundle: Bundle):
    payload, _ = bundle._collector_payload("exchange_policy")
    # Old/off runs retain their existing missing_artifact projection reason.
    envelope = payload.get("protectionAlerts") if payload else None
    if not isinstance(envelope, dict) or envelope.get("ipps_enabled") is not True:
        raise Unavailable("missing_artifact")
    return _listing_adapter("protectionAlerts", ALERT_FIELDS)(bundle)


def _dlp_license(bundle: Bundle):
    # This existing flag means the DLP reads succeeded, not full Teams/Endpoint entitlement.
    # Never infer a licence from a generic failure or an empty policy list alone.
    for name in ("dlpCompliancePolicies", "dlpComplianceRules"):
        bundle.operation("exchange_policy", name)
    return True


def _policies(bundle: Bundle):
    rows = _listing_adapter("dlpCompliancePolicies", DLP_POLICY_FIELDS)(bundle)
    for row in rows:
        for key in DLP_EXCEPTION_FIELDS:
            # The existing rule cannot represent exclusions from a nominal All scope.
            _require(key in row and row[key] in (None, []), key, "unexpected_field")
    return rows


ADAPTERS = {
    "protection_alerts": _alerts,
    "dlp_compliance_policies": _policies,
    "dlp_compliance_rules": _listing_adapter("dlpComplianceRules", DLP_RULE_FIELDS),
    "defender_dlp_license": _dlp_license,
}
