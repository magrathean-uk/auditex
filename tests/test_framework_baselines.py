"""Baseline framework keys, verified mappings, alignment, Secure Score, and rule packs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditex import cli as auditex_cli
from auditex.reporting import _render_csv
from auditex.rules import build_rule_packs, list_rule_inventory, list_rule_packs
from azure_tenant_audit.baselines import (
    BASELINE_FRAMEWORK_KEYS,
    build_baseline_alignment,
    build_secure_score_reconciliation,
)
from azure_tenant_audit.contracts import _KNOWN_FRAMEWORK_KEYS, _validate_finding_framework_mappings
from azure_tenant_audit.findings import build_findings, build_report_pack
from azure_tenant_audit.normalize import build_normalized_snapshot

_REPO = Path(__file__).resolve().parent.parent
_CATALOG = json.loads((_REPO / "configs" / "framework-catalog.json").read_text(encoding="utf-8"))
_MAPPINGS = {
    key: value
    for key, value in json.loads((_REPO / "configs" / "control-mappings.json").read_text(encoding="utf-8")).items()
    if not key.startswith("_")
}
_TEMPLATES = json.loads((_REPO / "configs" / "finding-templates.json").read_text(encoding="utf-8"))
_DIAGNOSTIC_RULES = {
    "collector.issue.permission",
    "reports_usage.concealed_names",
    "collector.issue.service",
    "collector.issue.collector",
    "coverage.gap",
    "service_health.active_service_issue",
}

# Rules with a verified control in each benchmark. Adding a rule here (or
# removing one) is a deliberate mapping change: update
# docs/reference/framework-mappings.md and configs/framework-catalog.json too.
_EXPECTED_CIS_V7 = {
    "app_consent.high_privilege",
    "attack_path.no_mfa_to_tier0",
    "app_credentials.secret_long_validity",
    "consent_policy.admin_consent_workflow_disabled",
    "dns_posture.dkim_missing",
    "dns_posture.dmarc_missing",
    "dns_posture.dmarc_monitor_only",
    "dns_posture.dmarc_pct_partial",
    "dns_posture.dmarc_rua_invalid",
    "dns_posture.spf_missing",
    "dns_posture.spf_multiple_records",
    "dns_posture.spf_passthrough",
    "exchange.remote_domain_auto_forward_enabled",
    "exchange.transport_external_redirect",
    "external_identity.broad_guest_invite_policy",
    "identity.global_admin_mfa_not_registered",
    "identity.global_admin_singleton",
    "identity.global_admin_sprawl",
    "identity.user_mfa_not_registered",
    "mailbox_forwarding.external_inbox_rule",
    "sharepoint.broad_link",
    "sharepoint.external_principal",
}
_EXPECTED_SECURE_SCORE = {
    "app_consent.high_privilege",
    "attack_path.no_mfa_to_tier0",
    "consent_policy.admin_consent_workflow_disabled",
    "dns_posture.spf_missing",
    "dns_posture.spf_multiple_records",
    "dns_posture.spf_passthrough",
    "exchange.remote_domain_auto_forward_enabled",
    "exchange.transport_external_redirect",
    "identity.global_admin_mfa_not_registered",
    "identity.global_admin_singleton",
    "identity.global_admin_sprawl",
    "identity.user_mfa_not_registered",
    "mailbox_forwarding.external_inbox_rule",
    "sharepoint.broad_link",
    "sharepoint.external_principal",
}


def _rules_with(key: str) -> set[str]:
    return {rule_id for rule_id, mapping in _MAPPINGS.items() if mapping.get(key)}


def test_catalog_lists_exactly_the_known_framework_keys() -> None:
    assert set(_CATALOG["frameworks"]) == set(_KNOWN_FRAMEWORK_KEYS)
    for key in BASELINE_FRAMEWORK_KEYS:
        entry = _CATALOG["frameworks"][key]
        assert entry["version"] and entry["published"] and entry["sources"], key
        assert all(url.startswith("https://") for url in entry["sources"]), key
    assert _CATALOG["frameworks"]["cis_m365_v3"]["status"] == "deprecated"
    assert _CATALOG["frameworks"]["cis_m365_v3"]["replaced_by"] == "cis_m365_v7"


@pytest.mark.parametrize("framework", BASELINE_FRAMEWORK_KEYS)
def test_baseline_mappings_only_use_verified_catalog_ids(framework: str) -> None:
    verified = set(_CATALOG["frameworks"][framework]["controls"])
    for rule_id, mapping in _MAPPINGS.items():
        unknown = sorted(set(mapping.get(framework) or []) - verified)
        assert not unknown, f"{rule_id}: {framework} ids {unknown} are not in configs/framework-catalog.json"


def test_shipped_mappings_do_not_emit_deprecated_cis_v3() -> None:
    assert not _rules_with("cis_m365_v3")


def test_diagnostic_rules_claim_no_benchmark_controls() -> None:
    for rule_id in _DIAGNOSTIC_RULES:
        mapping = _MAPPINGS[rule_id]
        claimed = [key for key in (*BASELINE_FRAMEWORK_KEYS, "cis_m365_v3") if mapping.get(key)]
        assert not claimed, f"{rule_id} claims {claimed}"


def test_mapping_completeness_for_verified_benchmarks() -> None:
    assert _rules_with("cis_m365_v7") == _EXPECTED_CIS_V7
    assert _rules_with("ms_secure_score") == _EXPECTED_SECURE_SCORE
    # Every non-diagnostic rule either has a verified CIS v7 control or a
    # Microsoft framework anchor (Zero Trust pillar or MCSB control), except
    # BIMI which has no Microsoft or CIS counterpart.
    for rule_id in set(_MAPPINGS) - _DIAGNOSTIC_RULES - {"dns_posture.bimi_logo_insecure"}:
        mapping = _MAPPINGS[rule_id]
        assert mapping.get("cis_m365_v7") or mapping.get("ms_zero_trust") or mapping.get("mcsb"), rule_id
    assert set(_MAPPINGS) == {key for key in _TEMPLATES if not key.startswith("_")}


def test_corrected_cis_numbers_for_email_authentication() -> None:
    assert _MAPPINGS["dns_posture.spf_missing"]["cis_m365_v7"] == ["2.1.8"]
    assert _MAPPINGS["dns_posture.dkim_missing"]["cis_m365_v7"] == ["2.1.9"]
    assert _MAPPINGS["dns_posture.dmarc_missing"]["cis_m365_v7"] == ["2.1.10"]
    assert _MAPPINGS["dns_posture.dmarc_missing"]["cisa_scuba"] == ["MS.EXO.4.1v1"]


def _finding(mappings: dict) -> dict:
    return {"id": "f-1", "rule_id": "x.y", "framework_mappings": mappings}


def test_contract_accepts_new_framework_keys() -> None:
    issues: list[dict] = []
    _validate_finding_framework_mappings(
        [
            _finding(
                {
                    "cis_m365_v7": ["5.2.2.1"],
                    "cisa_scuba": ["MS.AAD.3.6v1"],
                    "ms_secure_score": ["AdminMFAV2"],
                    "ms_zero_trust": ["identities"],
                    "mcsb": ["IM-6"],
                    "cis_m365_v3": ["1.1.1"],
                }
            )
        ],
        issues,
    )
    assert issues == []


def test_contract_rejects_unknown_framework_key() -> None:
    issues: list[dict] = []
    _validate_finding_framework_mappings([_finding({"cis_m365_v9": ["1.1"]})], issues)
    assert [issue["code"] for issue in issues] == ["unknown_framework_mapping_key"]


def _secure_score_snapshot(current: float = 30.0, maximum: float = 100.0) -> dict:
    payloads = {
        "defender": {
            "secureScores": {
                "value": [
                    {
                        "id": "score-old",
                        "currentScore": 90.0,
                        "maxScore": 100.0,
                        "createdDateTime": "2026-09-01T00:00:00Z",
                        "controlScores": [],
                    },
                    {
                        "id": "score-new",
                        "currentScore": current,
                        "maxScore": maximum,
                        "createdDateTime": "2026-10-01T00:00:00Z",
                        "controlScores": [
                            {"controlName": "AdminMFAV2", "controlCategory": "Identity", "score": 0.0},
                            {"controlName": "MFARegistrationV2", "controlCategory": "Identity", "score": 9.0},
                            {"controlName": "OneAdmin", "controlCategory": "Identity", "score": 2.0},
                            {"controlName": "aad_admin_consent_workflow", "controlCategory": "Apps", "score": 0.0},
                        ],
                    },
                ]
            },
            "secureScoreControlProfiles": {
                "value": [
                    {"id": "AdminMFAV2", "title": "Admin MFA", "maxScore": 10.0, "service": "AzureAD"},
                    {"id": "MFARegistrationV2", "title": "User MFA", "maxScore": 9.0, "service": "AzureAD"},
                    {"id": "OneAdmin", "title": "More than one GA", "maxScore": 2.0, "service": "AzureAD"},
                    {"id": "aad_admin_consent_workflow", "title": "Consent workflow", "maxScore": 1.0},
                ]
            },
        }
    }
    return build_normalized_snapshot(tenant_name="acme", run_id="run-1", collector_payloads=payloads)


def test_secure_score_low_overall_finding_uses_latest_snapshot() -> None:
    snapshot = _secure_score_snapshot()
    assert snapshot["security_score_control_profiles"]["records"]
    findings = build_findings([], normalized_snapshot=snapshot)
    finding = next(item for item in findings if item["rule_id"] == "secure_score.low_overall")
    assert finding["id"] == "secure_score:score-new:low_overall"
    assert finding["returned_value"] == "30/100 (30%)"
    assert finding["evidence_refs"][0]["artifact_path"] == "normalized/security_scores.json"
    assert finding["framework_mappings"]["mcsb"] == ["PV-2"]


def test_secure_score_at_or_above_half_emits_no_finding() -> None:
    findings = build_findings([], normalized_snapshot=_secure_score_snapshot(current=50.0))
    assert not [item for item in findings if item["rule_id"] == "secure_score.low_overall"]


def test_secure_score_reconciliation_from_synthetic_snapshot() -> None:
    snapshot = _secure_score_snapshot()
    findings = [
        {"id": "identity:ga_mfa:1", "rule_id": "identity.global_admin_mfa_not_registered", "status": "open"},
        {"id": "identity:user_mfa:1", "rule_id": "identity.user_mfa_not_registered", "status": "open"},
    ]
    result = build_secure_score_reconciliation(findings, snapshot)
    assert result["available"] is True
    assert result["overall"]["id"] == "score-new"
    assert result["overall"]["percentage"] == 30.0
    rows = {row["control_profile_id"]: row for row in result["controls"]}
    assert rows["AdminMFAV2"]["microsoft_score"] == 0.0
    assert rows["AdminMFAV2"]["microsoft_max_score"] == 10.0
    assert rows["AdminMFAV2"]["microsoft_state"] == "not_implemented"
    assert rows["AdminMFAV2"]["agreement"] == "agrees"
    # Microsoft scores user MFA as complete but Auditex still sees a gap.
    assert rows["MFARegistrationV2"]["microsoft_state"] == "implemented"
    assert rows["MFARegistrationV2"]["agreement"] == "auditex_only"
    assert rows["OneAdmin"]["agreement"] == "agrees"
    assert rows["aad_admin_consent_workflow"]["agreement"] == "microsoft_only"
    assert rows["mdo_blockmailforward"]["agreement"] == "no_microsoft_data"
    assert set(rows) >= {
        "AdminMFAV2",
        "MFARegistrationV2",
        "OneAdmin",
        "RoleOverlap",
        "IntegratedApps",
        "exo_SPF_records_for_all_domains",
    }


def test_baseline_alignment_shape_in_report_pack() -> None:
    snapshot = _secure_score_snapshot()
    findings = build_findings([], normalized_snapshot=snapshot)
    findings.append(
        {
            "id": "dns_posture:contoso.com:dmarc_missing",
            "rule_id": "dns_posture.dmarc_missing",
            "status": "open",
            "severity": "high",
            "framework_mappings": _MAPPINGS["dns_posture.dmarc_missing"],
        }
    )
    findings.append(
        {"id": "dns_posture:contoso.com:dkim_missing", "rule_id": "dns_posture.dkim_missing", "status": "accepted_risk"}
    )
    coverage_ledger = [
        {"collector": "dns_posture", "coverage_status": "complete_exact_scope"},
        {"collector": "identity", "coverage_status": "blocked_permission"},
    ]
    report = build_report_pack(
        tenant_name="acme",
        overall_status="ok",
        findings=findings,
        evidence_paths=[],
        normalized_snapshot=snapshot,
        coverage_ledger=coverage_ledger,
    )
    alignment = report["baseline_alignment"]
    assert alignment["schema_version"]
    assert alignment["assessed_collectors"] == ["dns_posture"]
    assert set(alignment["frameworks"]) == set(BASELINE_FRAMEWORK_KEYS)
    cis = alignment["frameworks"]["cis_m365_v7"]
    assert cis["version"] == "7.0.0"
    assert set(cis["status_counts"]) == {"fail", "accepted_risk", "pass", "not_assessed"}
    controls = {row["control_id"]: row for row in cis["controls"]}
    assert controls["2.1.10"]["status"] == "fail"
    assert controls["2.1.10"]["finding_ids"] == ["dns_posture:contoso.com:dmarc_missing"]
    assert controls["2.1.9"]["status"] == "accepted_risk"
    assert controls["2.1.8"]["status"] == "pass"
    assert controls["1.1.3"]["status"] == "not_assessed"
    for row in cis["controls"]:
        assert set(row) == {"control_id", "title", "status", "rule_ids", "rule_statuses", "open_finding_count", "finding_ids"}
    assert alignment["secure_score"]["available"] is True
    assert alignment["secure_score"]["controls"]


def test_baseline_alignment_without_coverage_marks_controls_not_assessed() -> None:
    alignment = build_baseline_alignment([])
    statuses = {row["status"] for fw in alignment["frameworks"].values() for row in fw["controls"]}
    assert statuses == {"not_assessed"}
    assert alignment["secure_score"]["available"] is False


def test_every_rule_belongs_to_at_least_one_pack() -> None:
    packs = list_rule_packs()
    members = {rule for pack in packs for rule in pack["rules"]}
    rule_ids = {row["name"] for row in list_rule_inventory()} - {"response.blocked"}
    assert set(_TEMPLATES) <= members
    assert rule_ids <= members, sorted(rule_ids - members)
    names = {pack["name"] for pack in packs}
    assert {f"framework.{key}" for key in BASELINE_FRAMEWORK_KEYS} <= names
    assert "m365.identity" in names


def test_committed_rule_packs_match_generator() -> None:
    assert list_rule_packs() == sorted(build_rule_packs(), key=lambda row: row["name"]), (
        "configs/rule-packs.json is stale; run python3 scripts/generate-rule-packs.py"
    )


def test_rules_packs_cli_filters_by_kind(capsys) -> None:
    assert auditex_cli.main(["rules", "packs", "--kind", "framework"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == len(payload["packs"]) > 0
    assert {pack["kind"] for pack in payload["packs"]} == {"framework"}


def test_csv_export_carries_framework_mappings() -> None:
    output = _render_csv(
        {"findings": [{"id": "a", "severity": "high", "framework_mappings": {"cis_m365_v7": ["2.1.10"]}}]}
    )
    assert "cis_m365_v7" in output.splitlines()[1]
