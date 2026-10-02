"""Detection coverage signals, identity_protection collector, and report-pack wiring.

No network: every Graph, PowerShell, and HTTPS dependency is stubbed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.collectors.identity_protection import IdentityProtectionCollector
from azure_tenant_audit.detection_coverage import (
    SIGNAL_CATALOG,
    build_detection_signals,
    summarize_detection_coverage,
)
from azure_tenant_audit.findings import apply_coverage_gaps_to_report_pack, build_findings, build_report_pack
from azure_tenant_audit.graph import GraphError
from azure_tenant_audit.normalize import build_normalized_snapshot


def _signals(payloads: dict[str, Any], diagnostics: list[dict[str, Any]] | None = None) -> dict[str, dict[str, Any]]:
    return {row["name"]: row for row in build_detection_signals(payloads, diagnostics)}


def _exchange(**sections: Any) -> dict[str, Any]:
    return {"exchange_policy": {name: value for name, value in sections.items()}}


# ----- signal derivation -----


def test_every_catalog_signal_is_emitted_and_unknown_without_evidence() -> None:
    signals = _signals({})
    assert set(signals) == set(SIGNAL_CATALOG)
    assert {row["status"] for row in signals.values()} == {"unknown"}
    assert signals["siem_log_export"]["reason"] == "not_collected_arm_diagnostic_settings"


def test_unified_audit_log_on_off_and_unknown() -> None:
    on = _signals(_exchange(adminAuditLogConfig={"value": [{"UnifiedAuditLogIngestionEnabled": True}]}))
    off = _signals(_exchange(adminAuditLogConfig={"value": [{"UnifiedAuditLogIngestionEnabled": "False"}]}))
    blocked = _signals(
        _exchange(adminAuditLogConfig={"error": "command_failed:1", "error_class": "command_not_authenticated"})
    )
    missing_property = _signals(_exchange(adminAuditLogConfig={"value": [{}]}))
    assert on["unified_audit_log"]["status"] == "on"
    assert off["unified_audit_log"]["status"] == "off"
    assert blocked["unified_audit_log"]["status"] == "unknown"
    assert blocked["unified_audit_log"]["reason"] == "source_blocked"
    assert missing_property["unified_audit_log"]["status"] == "unknown"


def test_mailbox_audit_default_and_bypass() -> None:
    signals = _signals(
        _exchange(
            organizationAuditConfig={"value": [{"AuditDisabled": True}]},
            mailboxAuditBypass={"value": [{"Count": 3}]},
        )
    )
    assert signals["mailbox_audit_default"]["status"] == "off"
    assert signals["mailbox_audit_bypass_clear"]["status"] == "off"
    assert signals["mailbox_audit_bypass_clear"]["observed_value"] == 3

    clean = _signals(
        _exchange(
            organizationAuditConfig={"value": [{"AuditDisabled": False}]},
            mailboxAuditBypass={"value": [{"Count": 0}]},
        )
    )
    assert clean["mailbox_audit_default"]["status"] == "on"
    assert clean["mailbox_audit_bypass_clear"]["status"] == "on"

    # Measure-Object always yields a Count row, so empty output is not proof of zero.
    empty = _signals(_exchange(mailboxAuditBypass={"command": "Get-MailboxAuditBypassAssociation"}))
    assert empty["mailbox_audit_bypass_clear"]["status"] == "unknown"


def test_alert_policies_enabled_disabled_and_missing_session() -> None:
    enabled = _signals(_exchange(protectionAlerts={"value": [{"Name": "a", "Disabled": False}]}))
    all_disabled = _signals(_exchange(protectionAlerts={"value": [{"Name": "a", "Disabled": True}]}))
    no_scc_session = _signals(
        _exchange(protectionAlerts={"error": "command_failed:1", "error_class": "command_not_found"})
    )
    assert enabled["alert_policies"]["status"] == "on"
    assert all_disabled["alert_policies"]["status"] == "off"
    assert no_scc_session["alert_policies"]["status"] == "unknown"


def _ca(policies: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {"conditional_access": {"conditionalAccessPolicies": {"value": policies, **extra}}}


def test_risk_based_conditional_access_requires_enabled_risk_condition() -> None:
    risk_policy = {
        "displayName": "Block high sign-in risk",
        "state": "enabled",
        "conditions": {"signInRiskLevels": ["high"], "userRiskLevels": []},
    }
    report_only = dict(risk_policy, state="enabledForReportingButNotEnforced")
    mfa_only = {"displayName": "MFA", "state": "enabled", "conditions": {"signInRiskLevels": [], "userRiskLevels": []}}

    assert _signals(_ca([risk_policy]))["risk_based_conditional_access"]["status"] == "on"
    assert _signals(_ca([report_only, mfa_only]))["risk_based_conditional_access"]["status"] == "off"
    truncated = _signals(_ca([mfa_only], sample_truncated=True))
    assert truncated["risk_based_conditional_access"]["status"] == "unknown"


def test_signin_logs_license_blocker_is_off_but_permission_blocker_is_unknown() -> None:
    license_diag = [{"collector": "security", "item": "signIns", "error_class": "license_required"}]
    permission_diag = [{"collector": "security", "item": "signIns", "error_class": "insufficient_permissions"}]
    assert _signals({}, license_diag)["signin_logs"]["status"] == "off"
    assert _signals({}, permission_diag)["signin_logs"]["status"] == "unknown"
    collected = _signals({"security": {"signIns": {"value": []}, "directoryAudits": {"value": []}}})
    assert collected["signin_logs"]["status"] == "on"
    assert collected["directory_audit_logs"]["status"] == "on"


def test_identity_protection_and_defender_signals() -> None:
    available = _signals(
        {
            "identity_protection": {"riskyUserSummary": {"value": [{"id": "summary", "sampled_count": 2}]}},
            "defender": {"securityAlerts": {"value": []}},
        }
    )
    assert available["identity_protection_risk_detection"]["status"] == "on"
    assert available["defender_alert_api"]["status"] == "on"
    unlicensed = _signals(
        {"identity_protection": {"riskyUserSummary": {"error": "not licensed", "error_class": "license_required"}}}
    )
    assert unlicensed["identity_protection_risk_detection"]["status"] == "off"


def test_summary_score_ignores_unknown_signals() -> None:
    records = [
        {"name": "unified_audit_log", "status": "on", "key": "detection_signal:unified_audit_log"},
        {"name": "mailbox_audit_default", "status": "off"},
        {"name": "alert_policies", "status": "unknown"},
        {"name": "siem_log_export", "status": "something-else"},
    ]
    summary = summarize_detection_coverage(records)
    assert summary["score"] == 50
    assert summary["counts"] == {"on": 1, "off": 1, "unknown": 2}
    statuses = {item["name"]: item["status"] for item in summary["signals"]}
    assert statuses["siem_log_export"] == "unknown"
    assert summary["signals"][0]["evidence_ref"]["artifact_path"] == "normalized/detection_signal_objects.json"
    assert summarize_detection_coverage([{"name": "alert_policies", "status": "unknown"}])["score"] is None


# ----- findings -----


def _findings_for(payloads: dict[str, Any], diagnostics: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    snapshot = build_normalized_snapshot(
        tenant_name="acme", run_id="run-1", collector_payloads=payloads, diagnostics=diagnostics
    )
    return build_findings(diagnostics or [], normalized_snapshot=snapshot)


def test_off_signals_emit_detection_findings_with_mitre_mapping() -> None:
    payloads = {
        **_exchange(
            adminAuditLogConfig={"value": [{"UnifiedAuditLogIngestionEnabled": False}]},
            organizationAuditConfig={"value": [{"AuditDisabled": True}]},
            mailboxAuditBypass={"value": [{"Count": 2}]},
            protectionAlerts={"value": []},
        ),
        **_ca([{"displayName": "MFA", "state": "enabled", "conditions": {}}]),
    }
    diagnostics = [{"collector": "security", "item": "signIns", "error_class": "license_required", "status": "failed"}]
    findings = _findings_for(payloads, diagnostics)
    by_rule = {item["rule_id"]: item for item in findings if str(item.get("rule_id")).startswith("detection.")}
    assert set(by_rule) == {
        "detection.unified_audit_log_disabled",
        "detection.mailbox_audit_disabled",
        "detection.mailbox_audit_bypass",
        "detection.no_alert_policies",
        "detection.no_risk_based_policies",
        "detection.signin_logs_unavailable",
    }
    ual = by_rule["detection.unified_audit_log_disabled"]
    assert ual["severity"] == "high"
    assert "T1562.008" in ual["framework_mappings"]["mitre_attack"]
    assert ual["evidence_refs"][0]["artifact_path"] == "normalized/detection_signal_objects.json"


def test_unknown_signals_never_emit_detection_findings() -> None:
    payloads = _exchange(
        adminAuditLogConfig={"error": "command_failed:1", "error_class": "command_not_authenticated"},
        protectionAlerts={"error": "command_failed:1", "error_class": "command_not_found"},
    )
    findings = _findings_for(payloads)
    assert not [item for item in findings if str(item.get("rule_id")).startswith("detection.")]


# ----- identity_protection collector -----


class _RiskyUsersClient:
    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, path: str, params: dict[str, Any] | None = None, full_url: bool = False) -> dict[str, Any]:
        self.calls.append((path, dict(params or {})))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_identity_protection_collector_keeps_counts_only() -> None:
    client = _RiskyUsersClient(
        {
            "value": [
                {"id": "1", "riskLevel": "high", "riskState": "atRisk", "userPrincipalName": "a@contoso.com"},
                {"id": "2", "riskLevel": "low", "riskState": "remediated", "userPrincipalName": "b@contoso.com"},
            ]
        }
    )
    result = IdentityProtectionCollector().run({"client": client})
    assert result.status == "ok"
    assert client.calls == [("/identityProtection/riskyUsers", {"$select": "id,riskLevel,riskState", "$top": "500"})]
    summary = result.payload["riskyUserSummary"]["value"][0]
    assert summary["at_risk_count"] == 1
    assert summary["risk_level_counts"] == {"high": 1, "low": 1}
    assert "contoso.com" not in json.dumps(result.payload)


def test_identity_protection_collector_classifies_license_error() -> None:
    client = _RiskyUsersClient(
        GraphError("Your tenant is not licensed for this feature.", status=403, request="/identityProtection/riskyUsers")
    )
    result = IdentityProtectionCollector().run({"client": client})
    assert result.status == "partial"
    assert result.coverage[0]["error_class"] == "license_required"
    signals = _signals({"identity_protection": result.payload})
    assert signals["identity_protection_risk_detection"]["status"] == "off"


# ----- report pack wiring -----


def test_coverage_gap_refresh_keeps_detection_sections() -> None:
    pack = build_report_pack(tenant_name="acme", overall_status="ok", findings=[], evidence_paths=[])
    pack["detection_coverage"] = {"signals": [], "score": None}
    pack["public_footprint"] = {"domains": []}
    refreshed = apply_coverage_gaps_to_report_pack(
        pack, [{"surface": "mail", "status": "partial", "severity": "medium", "collectors": ["exchange_policy"]}]
    )
    assert refreshed["detection_coverage"] == {"signals": [], "score": None}
    assert refreshed["public_footprint"] == {"domains": []}
    assert refreshed["summary"]["coverage_gap_count"] == 1


def test_offline_run_reports_detection_coverage_from_fixture(tmp_path: Path) -> None:
    sample = {
        "exchange_policy": {
            "adminAuditLogConfig": {"value": [{"UnifiedAuditLogIngestionEnabled": False}]},
            "organizationAuditConfig": {"value": [{"AuditDisabled": False}]},
        },
        "dns_posture": {
            "domains": {"value": []},
            "domainPosture": {
                "value": [
                    {
                        "domain": "contoso.com",
                        "managed_by_microsoft": False,
                        "spf": {"present": True, "all_qualifier": "-"},
                        "dmarc": {"present": True, "policy": "reject"},
                        "dkim": {"selectors_present": ["selector1"], "selectors_missing": []},
                        "mta_sts": {"dns_present": True, "policy": {"fetch_status": "ok", "mode": "testing"}},
                        "tls_rpt": {"present": False},
                        "bimi": {"present": False},
                    }
                ]
            },
            "publicFootprint": {
                "value": [
                    {
                        "domain": "contoso.com",
                        "authentication_type": "Federated",
                        "discovery_status": "ok",
                        "tenant_id": "11111111-2222-3333-4444-555555555555",
                        "tenant_region_scope": "EU",
                    }
                ]
            },
        },
    }
    sample_path = tmp_path / "detection_sample.json"
    sample_path.write_text(json.dumps(sample), encoding="utf-8")

    rc = run_offline(sample_path, tmp_path, "contoso", "detection", auditor_profile="global-reader")
    assert rc == 0
    run_dir = tmp_path / "contoso-detection"
    validation = json.loads((run_dir / "validation.json").read_text(encoding="utf-8"))
    report_pack = json.loads((run_dir / "reports" / "report-pack.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings" / "findings.json").read_text(encoding="utf-8"))

    assert validation["valid"] is True, validation["issues"]
    statuses = {item["name"]: item["status"] for item in report_pack["detection_coverage"]["signals"]}
    assert statuses["unified_audit_log"] == "off"
    assert statuses["mailbox_audit_default"] == "on"
    assert statuses["alert_policies"] == "unknown"
    assert report_pack["detection_coverage"]["score"] == 50
    footprint = report_pack["public_footprint"]
    assert footprint["federated_domain_count"] == 1
    assert footprint["tenant_ids_observed"] == ["11111111-2222-3333-4444-555555555555"]

    rule_ids = {item.get("rule_id") for item in findings}
    assert "detection.unified_audit_log_disabled" in rule_ids
    assert "detection.mailbox_audit_disabled" not in rule_ids
    assert {"dns_posture.mta_sts_testing_mode", "dns_posture.tls_rpt_missing"} <= rule_ids
    assert "exposure.federated_domain_metadata_public" in rule_ids
    exposure = next(item for item in findings if item.get("rule_id") == "exposure.federated_domain_metadata_public")
    assert exposure["severity"] == "low"
