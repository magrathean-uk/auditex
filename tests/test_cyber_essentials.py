"""Cyber Essentials framework key: catalog validity, mappings, and the baseline requirement section."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from auditex import reporting
from auditex.explorer import _baselines as explorer_baselines
from auditex.google_workspace import findings as google_findings
from auditex.rules import list_rule_packs
from azure_tenant_audit import baselines
from azure_tenant_audit.baselines import BASELINE_FRAMEWORK_KEYS, build_baseline_alignment
from azure_tenant_audit.contracts import _KNOWN_FRAMEWORK_KEYS, _validate_finding_framework_mappings, _walk_sensitive_ai_safe
from azure_tenant_audit.cyber_essentials import (
    CE_FRAMEWORK_KEY,
    REQUIREMENT_STATUSES,
    VERDICT_REQUIREMENT_STATUSES,
    build_cyber_essentials_section,
)
from azure_tenant_audit.findings import build_report_pack

_REPO = Path(__file__).resolve().parent.parent
_CATALOG_PATH = _REPO / "configs" / "framework-catalog.json"
_MAPPINGS_PATH = _REPO / "configs" / "control-mappings.json"
_VERDICT_STATUSES = {"pass", "fail", "accepted_risk", "not_assessed"}
_NO_VERDICT = set(REQUIREMENT_STATUSES) - VERDICT_REQUIREMENT_STATUSES
_THEME_PREFIX = {
    "firewalls": "fw",
    "secure_configuration": "sc",
    "security_update_management": "sum",
    "user_access_control": "uac",
    "malware_protection": "mp",
}
# Headings that exist in the NCSC document (v3.3) and in the CE+ test specification (v3.2).
_CE_PLUS_TEST_HEADINGS = {
    "Test case 1: Remote vulnerability assessment",
    "Test case 2: Check patching, by authenticated vulnerability scan of devices",
    "Test case 3: Check malware protection",
    "Test case 4: Check multi-factor authentication configuration",
    "Test case 5: Check account separation",
}
_DOCUMENT_HEADING_ROOTS = ("E. Requirements by technical control theme > ", "D. Scope > ")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    assert not duplicates, f"duplicate JSON keys: {duplicates}"
    return dict(pairs)


_CATALOG = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
_ENTRY = _CATALOG["frameworks"][CE_FRAMEWORK_KEY]
_REQUIREMENTS: dict[str, dict[str, Any]] = _ENTRY["controls"]
_RAW_MAPPINGS = json.loads(_MAPPINGS_PATH.read_text(encoding="utf-8"))
_MAPPINGS = {key: value for key, value in _RAW_MAPPINGS.items() if not key.startswith("_")}
_CONFIDENCE: dict[str, dict[str, str]] = _RAW_MAPPINGS["_cyber_essentials_confidence"]
_TEMPLATES = json.loads((_REPO / "configs" / "finding-templates.json").read_text(encoding="utf-8"))
_GOOGLE_MAPPINGS = google_findings._GOOGLE_FRAMEWORK_MAPPINGS


# A tenant with a complete administrator set, licences read in full and no guests: the identity rules that
# read normalized evidence have what they need, so an absent finding means they ran clean.
_CLEAN_IDENTITY_SNAPSHOT: dict[str, Any] = {
    "effective_admin_set": {
        "records": [
            {"kind": "effective_admin_set_summary", "key": "effective_admin_set_summary:summary", "state": "complete", "licence_state": "known"}
        ]
    }
}


def _ce_mappings() -> dict[str, list[str]]:
    """Every rule that maps to a Cyber Essentials requirement, Microsoft 365 and Google Workspace."""
    shipped = {rule: list(mapping["cyber_essentials"]) for rule, mapping in _MAPPINGS.items() if mapping.get("cyber_essentials")}
    google = {rule: list(mapping["cyber_essentials"]) for rule, mapping in _GOOGLE_MAPPINGS.items() if mapping.get("cyber_essentials")}
    assert not set(shipped) & set(google)
    return {**shipped, **google}


# ---- catalog validity ----------------------------------------------------------------------------------


def test_the_key_is_registered_everywhere_a_framework_key_is_listed() -> None:
    assert CE_FRAMEWORK_KEY == "cyber_essentials"
    assert CE_FRAMEWORK_KEY in _KNOWN_FRAMEWORK_KEYS
    assert CE_FRAMEWORK_KEY in BASELINE_FRAMEWORK_KEYS
    assert CE_FRAMEWORK_KEY in _CATALOG["frameworks"]
    schema = json.loads((_REPO / "schemas" / "finding.schema.json").read_text(encoding="utf-8"))
    assert CE_FRAMEWORK_KEY in schema["properties"]["framework_mappings"]["properties"]


def test_the_catalog_entry_records_the_document_version_date_and_source() -> None:
    assert _ENTRY["document_title"] == "Cyber Essentials: Requirements for IT Infrastructure v3.3"
    assert _ENTRY["version"] == "v3.3"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _ENTRY["published"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _ENTRY["effective_date"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", _ENTRY["verified_on"])
    assert _ENTRY["document_url"].startswith("https://www.ncsc.gov.uk/") and _ENTRY["document_url"] in _ENTRY["sources"]
    assert all(url.startswith("https://") for url in _ENTRY["sources"])
    assert any("iasme.co.uk" in url for url in _ENTRY["sources"])
    assert _ENTRY["status"] == "current"
    assert "evidence for a Cyber Essentials assessor" in _ENTRY["disclaimer"]
    # CE+ is still assessed against the v3.2 test specification, so the catalog must not imply v3.3.
    (test_spec,) = _ENTRY["related_documents"]
    assert test_spec["version"] == "v3.2" and test_spec["url"].startswith("https://")


def test_the_five_technical_control_themes_are_all_covered() -> None:
    assert set(_ENTRY["themes"]) == set(_THEME_PREFIX)
    assert {spec["theme"] for spec in _REQUIREMENTS.values()} == set(_THEME_PREFIX)


def test_requirement_ids_are_unique_stable_and_follow_their_theme() -> None:
    # Duplicate keys are rejected when the catalog is loaded (object_pairs_hook above).
    assert len(_REQUIREMENTS) == len(set(_REQUIREMENTS)) >= 20
    for requirement_id, spec in _REQUIREMENTS.items():
        assert re.fullmatch(r"ce\.[a-z]+\.[a-z0-9_]+", requirement_id), requirement_id
        assert requirement_id.split(".")[1] == _THEME_PREFIX[spec["theme"]], requirement_id


def test_every_requirement_has_a_status_a_citation_and_a_title() -> None:
    for requirement_id, spec in _REQUIREMENTS.items():
        assert spec["status"] in REQUIREMENT_STATUSES, requirement_id
        assert spec["title"].strip() and spec["evidence_limits"].strip(), requirement_id
        assert spec["citation"].startswith(_DOCUMENT_HEADING_ROOTS), requirement_id
        if spec.get("ce_plus_test"):
            assert spec["ce_plus_test"] in _CE_PLUS_TEST_HEADINGS, requirement_id
        if spec["status"] == "ce_plus_assessor_test":
            assert spec.get("ce_plus_test"), f"{requirement_id} is an assessor test with no CE+ test case named"
        if spec["status"] == "provider_responsibility":
            assert "Table 1" in spec["citation"], requirement_id
    assert set(_ENTRY["requirement_statuses"]) == set(REQUIREMENT_STATUSES)


def test_the_catalog_is_honest_about_what_a_tenant_audit_can_decide() -> None:
    by_status = {status: [rid for rid, spec in _REQUIREMENTS.items() if spec["status"] == status] for status in REQUIREMENT_STATUSES}
    # Most Cyber Essentials requirements are device, network or process side.
    assert len(by_status["manual"]) + len(by_status["ce_plus_assessor_test"]) + len(by_status["provider_responsibility"]) > len(
        by_status["partial"]
    )
    # Firewalls, update management and malware protection have no tenant-decidable requirement.
    for requirement_id in by_status["partial"] + by_status["automated"]:
        assert _REQUIREMENTS[requirement_id]["theme"] in {"secure_configuration", "user_access_control"}, requirement_id
    assert not by_status["automated"], "no CE requirement is decided by tenant evidence alone in v3.3"
    assert by_status["partial"], "the tenant-backed requirements are missing"


# ---- mappings --------------------------------------------------------------------------------------------


def test_every_mapped_rule_exists_and_every_mapped_id_is_catalogued() -> None:
    for rule_id, requirement_ids in _ce_mappings().items():
        assert rule_id in _TEMPLATES or rule_id in _GOOGLE_MAPPINGS, f"{rule_id} is not a shipped rule"
        assert requirement_ids == sorted(set(requirement_ids)), rule_id
        unknown = set(requirement_ids) - set(_REQUIREMENTS)
        assert not unknown, f"{rule_id}: {sorted(unknown)} are not in the Cyber Essentials catalog"


def test_diagnostic_and_coverage_rules_claim_no_cyber_essentials_requirement() -> None:
    for rule_id in _ce_mappings():
        assert not rule_id.startswith(("collector.issue.", "service_health.", "coverage.")), rule_id
        assert rule_id not in {"ca.enforcement_unverified", "consent_policy.user_consent_unverified", "reports_usage.concealed_names"}


def test_every_mapping_declares_its_confidence_and_no_orphan_confidence_exists() -> None:
    mapped = {(rule, requirement) for rule, requirements in _ce_mappings().items() for requirement in requirements}
    declared = {(rule, requirement) for rule, requirements in _CONFIDENCE.items() for requirement in requirements}
    assert mapped == declared
    assert {value for requirements in _CONFIDENCE.values() for value in requirements.values()} <= {"full", "partial"}


def test_a_requirement_the_tenant_can_judge_has_a_rule_behind_it() -> None:
    mapped_requirements = {requirement for requirements in _ce_mappings().values() for requirement in requirements}
    for requirement_id, spec in _REQUIREMENTS.items():
        if spec["status"] in VERDICT_REQUIREMENT_STATUSES:
            assert requirement_id in mapped_requirements, f"{requirement_id} can report a verdict but no rule maps to it"


def test_the_requested_rule_families_are_mapped() -> None:
    mapped = _ce_mappings()
    mfa = "ce.uac.mfa_cloud_services"
    assert mfa in mapped["ca.mfa_not_enforced"]
    assert mfa in mapped["identity.privileged_mfa_not_registered"]
    assert mfa in mapped["ca.legacy_auth_not_blocked"]
    assert "ce.uac.remove_unused_accounts" in mapped["identity.stale_enabled_account"]
    assert "ce.uac.special_access_privileges" in mapped["identity.global_admin_sprawl"]
    assert "ce.sc.saas_configuration" in mapped["consent_policy.user_consent_unrestricted"]
    assert "ce.sum.vulnerability_fixes_14_days" in mapped["intune.device_noncompliant"]
    assert mfa in mapped["google.admin_2sv_not_enforced"] and mfa in mapped["google.user_2sv_not_enrolled"]
    # The enforcement verdict tests the named condition; a registration rule only shows capability.
    assert _CONFIDENCE["ca.mfa_not_enforced"][mfa] == "full"
    assert _CONFIDENCE["identity.user_mfa_not_registered"][mfa] == "partial"


def test_shipped_findings_carry_the_key_through_the_contract_and_the_rule_packs() -> None:
    issues: list[dict[str, Any]] = []
    finding = {"id": "f-1", "rule_id": "ca.mfa_not_enforced", "framework_mappings": {CE_FRAMEWORK_KEY: ["ce.uac.mfa_cloud_services"]}}
    _validate_finding_framework_mappings([finding], issues)
    assert issues == []
    names = {pack["name"]: pack for pack in list_rule_packs()}
    pack = names[f"framework.{CE_FRAMEWORK_KEY}"]
    assert {"ca.mfa_not_enforced", "identity.stale_enabled_account", "google.admin_2sv_not_enforced"} <= set(pack["rules"])


def test_the_confidence_table_never_leaks_into_a_finding() -> None:
    from azure_tenant_audit.findings import _framework_mappings_for

    for rule_id in ("ca.mfa_not_enforced", "identity.stale_enabled_account"):
        assert set(_framework_mappings_for(rule_id)) <= _KNOWN_FRAMEWORK_KEYS


# ---- the baseline section ------------------------------------------------------------------------------


def _ledger(*collectors: str) -> list[dict[str, str]]:
    return [{"collector": name, "coverage_status": "complete_exact_scope"} for name in collectors]


def _section(alignment: dict[str, Any]) -> dict[str, Any]:
    return alignment["frameworks"][CE_FRAMEWORK_KEY]


def _row(alignment: dict[str, Any], requirement_id: str) -> dict[str, Any]:
    (row,) = [row for row in _section(alignment)["controls"] if row["control_id"] == requirement_id]
    return row


def test_the_section_lists_every_catalogued_requirement_even_with_no_findings_and_no_coverage() -> None:
    section = _section(build_baseline_alignment([]))

    assert [row["control_id"] for row in section["controls"]] == list(_REQUIREMENTS)
    assert section["version"] == "v3.3" and section["effective_date"] == _ENTRY["effective_date"]
    assert section["document_url"] == _ENTRY["document_url"] and section["disclaimer"] == _ENTRY["disclaimer"]
    assert section["uncatalogued_requirement_ids"] == []
    assert section["status_counts"] == {"fail": 0, "accepted_risk": 0, "pass": 0, "not_assessed": len(_REQUIREMENTS)}
    assert section["requirement_status_counts"] == {
        status: sum(1 for spec in _REQUIREMENTS.values() if spec["status"] == status) for status in REQUIREMENT_STATUSES
    }


def test_a_requirement_row_has_the_documented_shape() -> None:
    row = _row(build_baseline_alignment([]), "ce.uac.mfa_cloud_services")

    assert set(row) == {
        "control_id", "title", "theme", "requirement_status", "status", "citation", "evidence_limits",
        "rule_ids", "rule_statuses", "evidence", "open_finding_count", "finding_ids", "ce_plus_test",
    }
    assert row["requirement_status"] == "partial" and row["status"] == "not_assessed"
    assert row["citation"] == _REQUIREMENTS["ce.uac.mfa_cloud_services"]["citation"]
    assert {"ca.mfa_not_enforced", "identity.user_mfa_not_registered", "identity.privileged_mfa_not_registered"} <= set(row["rule_ids"])
    assert set(row["evidence"]) == {
        "rules_mapped", "rules_evaluated", "rules_passed", "rules_failed", "rules_accepted_risk", "rules_not_assessed", "open_findings",
    }
    assert row["evidence"]["rules_mapped"] == len(row["rule_ids"]) == len(row["rule_statuses"])
    assert {status["confidence"] for status in row["rule_statuses"]} == {"full", "partial"}


def test_no_manual_assessor_or_provider_requirement_ever_reads_pass() -> None:
    every_collector = set(baselines._NAMESPACE_COLLECTORS.values()) | {c for cs in baselines._RULE_COLLECTORS.values() for c in cs}
    alignment = build_baseline_alignment([], coverage_ledger=_ledger(*sorted(every_collector)))
    rows = _section(alignment)["controls"]

    assert {row["status"] for row in rows} <= _VERDICT_STATUSES
    for row in rows:
        if row["requirement_status"] in _NO_VERDICT:
            assert row["status"] == "not_assessed", row["control_id"]
            assert row["reason"] == f"requirement_status:{row['requirement_status']}"
    # A supporting rule can pass without lending the assessor-tested requirement a verdict.
    patching = _row(alignment, "ce.sum.vulnerability_fixes_14_days")
    assert patching["requirement_status"] == "ce_plus_assessor_test" and patching["status"] == "not_assessed"
    assert patching["evidence"]["rules_passed"] == 1


def test_a_partial_requirement_never_reads_pass_on_a_clean_fully_evaluated_run() -> None:
    every_collector = set(baselines._NAMESPACE_COLLECTORS.values()) | {c for cs in baselines._RULE_COLLECTORS.values() for c in cs}
    alignment = build_baseline_alignment(
        [], normalized_snapshot=_CLEAN_IDENTITY_SNAPSHOT, coverage_ledger=_ledger(*sorted(every_collector))
    )
    section = _section(alignment)

    # No shipped Cyber Essentials requirement is automated, so nothing in the section can read pass.
    assert all(spec["status"] != "automated" for spec in _REQUIREMENTS.values())
    assert {row["status"] for row in section["controls"]} <= {"not_assessed"}
    assert section["status_counts"] == {"fail": 0, "accepted_risk": 0, "pass": 0, "not_assessed": len(_REQUIREMENTS)}
    # Identity rules were all evaluated and clean, and the row says so instead of passing.
    for requirement_id in ("ce.uac.remove_unused_accounts", "ce.sc.unnecessary_accounts", "ce.uac.special_access_privileges"):
        row = _row(alignment, requirement_id)
        assert row["requirement_status"] == "partial" and row["status"] == "not_assessed", requirement_id
        assert row["reason"] == "partial_requirement_no_gap_found", requirement_id
        assert row["evidence"]["rules_evaluated"] == row["evidence"]["rules_passed"] == row["evidence"]["rules_mapped"] > 0
        assert row["open_finding_count"] == 0
        assert {status["status"] for status in row["rule_statuses"]} == {"pass"}


def test_a_requirement_with_unevaluated_rules_stays_not_assessed() -> None:
    row = _row(build_baseline_alignment([], coverage_ledger=_ledger("identity")), "ce.uac.mfa_cloud_services")

    # ca.* needs conditional_access and a known verdict; identity alone is not enough.
    assert row["status"] == "not_assessed"
    reasons = {status["rule_id"]: status.get("reason") for status in row["rule_statuses"]}
    assert reasons["ca.mfa_not_enforced"].startswith("collector_not_complete:")


def test_an_open_finding_fails_the_requirement_and_an_accepted_one_is_accepted_risk() -> None:
    ledger = _ledger("identity")
    open_finding = {"id": "stale-1", "rule_id": "identity.stale_enabled_account", "status": "open"}
    waived = {"id": "stale-1", "rule_id": "identity.stale_enabled_account", "status": "accepted_risk"}

    failed = _row(build_baseline_alignment([open_finding], coverage_ledger=ledger), "ce.uac.remove_unused_accounts")
    accepted = _row(build_baseline_alignment([waived], coverage_ledger=ledger), "ce.uac.remove_unused_accounts")

    assert failed["status"] == "fail" and failed["finding_ids"] == ["stale-1"] and failed["open_finding_count"] == 1
    assert failed["evidence"]["rules_failed"] == 1 and failed["evidence"]["open_findings"] == 1
    assert "reason" not in failed
    assert accepted["status"] == "accepted_risk" and "reason" not in accepted


def test_a_failing_supporting_rule_is_shown_but_gives_an_assessor_requirement_no_verdict() -> None:
    finding = {"id": "intune:dev-1", "rule_id": "intune.device_noncompliant", "status": "open"}
    row = _row(build_baseline_alignment([finding], coverage_ledger=_ledger("intune")), "ce.sum.vulnerability_fixes_14_days")

    assert row["status"] == "not_assessed" and row["requirement_status"] == "ce_plus_assessor_test"
    assert row["open_finding_count"] == 1 and row["finding_ids"] == ["intune:dev-1"]
    assert row["evidence"]["rules_failed"] == 1
    assert row["ce_plus_test"] == "Test case 2: Check patching, by authenticated vulnerability scan of devices"


def test_google_findings_reach_the_requirement_through_their_own_mappings() -> None:
    mfa = _GOOGLE_MAPPINGS["google.admin_2sv_not_enforced"]
    finding = {"id": "g-1", "rule_id": "google.admin_2sv_not_enforced", "status": "open", "framework_mappings": mfa}

    alignment = build_baseline_alignment([finding])

    for requirement_id in ("ce.uac.mfa_cloud_services", "ce.uac.mfa_admin_accounts"):
        row = _row(alignment, requirement_id)
        assert row["status"] == "fail" and "g-1" in row["finding_ids"]
        (rule,) = [status for status in row["rule_statuses"] if status["rule_id"] == "google.admin_2sv_not_enforced"]
        assert rule["confidence"] == "full"
    # With no Google finding the rule is not in the shipped Microsoft mappings, so it is simply absent.
    assert "google.admin_2sv_not_enforced" not in _row(build_baseline_alignment([]), "ce.uac.mfa_cloud_services")["rule_ids"]


def test_requirement_ids_missing_from_the_catalog_are_reported_not_dropped() -> None:
    finding = {"id": "x-1", "rule_id": "x.y", "status": "open", "framework_mappings": {CE_FRAMEWORK_KEY: ["ce.zz.invented"]}}

    section = _section(build_baseline_alignment([finding]))

    assert section["uncatalogued_requirement_ids"] == ["ce.zz.invented"]
    assert "ce.zz.invented" not in {row["control_id"] for row in section["controls"]}


# ---- the builder, with a synthetic catalog -------------------------------------------------------------


def _synthetic_entry() -> dict[str, Any]:
    controls = {f"ce.test.{status}": {"title": status, "theme": "x", "status": status, "citation": "c"} for status in REQUIREMENT_STATUSES}
    controls["ce.test.bogus"] = {"title": "bogus", "theme": "x", "status": "bogus", "citation": "c"}
    controls["ce.test.missing"] = {"title": "missing", "theme": "x", "citation": "c"}
    return {"title": "T", "version": "v0", "controls": controls}


def _build(statuses_by_rule: dict[str, str]) -> dict[str, Any]:
    controls = {f"ce.test.{status}" for status in (*REQUIREMENT_STATUSES, "bogus", "missing")}
    rules = {control: {"rule.a"} for control in controls}
    return build_cyber_essentials_section(
        _synthetic_entry(),
        rules,
        evaluate=lambda rule_id: {"rule_id": rule_id, "status": statuses_by_rule[rule_id], "evaluated": statuses_by_rule[rule_id] == "pass"},
        open_by_rule={},
        control_status=baselines._control_status,
        status_order=baselines._STATUS_ORDER,
    )


def test_a_passing_rule_gives_a_pass_only_to_an_automated_requirement() -> None:
    rows = {row["control_id"]: row for row in _build({"rule.a": "pass"})["controls"]}

    assert rows["ce.test.automated"]["status"] == "pass" and "reason" not in rows["ce.test.automated"]
    # A partial requirement records the clean result as not assessed, keeping the evidence counts.
    partial = rows["ce.test.partial"]
    assert partial["status"] == "not_assessed" and partial["reason"] == "partial_requirement_no_gap_found"
    assert partial["evidence"]["rules_passed"] == partial["evidence"]["rules_evaluated"] == 1
    for status in ("manual", "ce_plus_assessor_test", "provider_responsibility", "bogus", "missing"):
        row = rows[f"ce.test.{status}"]
        assert row["status"] == "not_assessed", status
        assert row["evidence"]["rules_passed"] == 1
    # An unknown or missing status fails closed, and says so.
    assert rows["ce.test.bogus"]["reason"] == "requirement_status:bogus"
    assert rows["ce.test.missing"]["requirement_status"] == "unknown"


def test_a_failing_rule_fails_only_the_requirements_that_may_report_a_verdict() -> None:
    rows = {row["control_id"]: row for row in _build({"rule.a": "fail"})["controls"]}

    assert rows["ce.test.automated"]["status"] == rows["ce.test.partial"]["status"] == "fail"
    assert "reason" not in rows["ce.test.partial"]
    assert all(rows[f"ce.test.{status}"]["status"] == "not_assessed" for status in ("manual", "ce_plus_assessor_test", "provider_responsibility"))


def test_an_accepted_risk_keeps_its_status_on_a_partial_requirement() -> None:
    rows = {row["control_id"]: row for row in _build({"rule.a": "accepted_risk"})["controls"]}

    assert rows["ce.test.automated"]["status"] == rows["ce.test.partial"]["status"] == "accepted_risk"


def test_a_partial_requirement_with_a_rule_not_evaluated_is_plain_not_assessed() -> None:
    rows = {row["control_id"]: row for row in _build({"rule.a": "not_assessed"})["controls"]}

    assert rows["ce.test.partial"]["status"] == "not_assessed" and "reason" not in rows["ce.test.partial"]


def test_an_automated_requirement_with_no_rule_is_not_assessed_with_a_reason() -> None:
    section = build_cyber_essentials_section(
        _synthetic_entry(),
        {},
        evaluate=lambda rule_id: {},
        open_by_rule={},
        control_status=baselines._control_status,
        status_order=baselines._STATUS_ORDER,
    )
    row = {row["control_id"]: row for row in section["controls"]}["ce.test.automated"]

    assert row["status"] == "not_assessed" and row["reason"] == "no_mapped_rules"


# ---- report surfaces -----------------------------------------------------------------------------------


def test_the_report_pack_carries_the_section_without_sensitive_looking_keys() -> None:
    pack = build_report_pack(tenant_name="acme", overall_status="ok", findings=[], evidence_paths=[])
    section = pack["baseline_alignment"]["frameworks"][CE_FRAMEWORK_KEY]

    assert len(section["controls"]) == len(_REQUIREMENTS)
    hits: list[dict[str, Any]] = []
    _walk_sensitive_ai_safe(pack["baseline_alignment"], "", hits)
    assert hits == []


def test_the_markdown_report_lists_each_requirement_with_its_status_and_the_disclaimer() -> None:
    every_collector = set(baselines._NAMESPACE_COLLECTORS.values()) | {c for cs in baselines._RULE_COLLECTORS.values() for c in cs}
    alignment = build_baseline_alignment(
        [], normalized_snapshot=_CLEAN_IDENTITY_SNAPSHOT, coverage_ledger=_ledger(*sorted(every_collector))
    )
    lines: list[str] = []

    reporting._append_baseline_alignment_markdown(lines, alignment)
    text = "\n".join(lines)

    assert "## Cyber Essentials Requirements" in text
    manual = next(line for line in lines if line.startswith("| ce.fw.device_firewall "))
    assert "| manual | not_assessed | requirement_status:manual |" in manual
    partial = next(line for line in lines if line.startswith("| ce.uac.remove_unused_accounts "))
    assert "| partial | not_assessed | partial_requirement_no_gap_found |" in partial
    assert "| pass |" not in "\n".join(line for line in lines if line.startswith("| ce."))
    assert all(f"| {requirement_id} |" in text for requirement_id in _REQUIREMENTS)
    assert "not a Cyber Essentials assessment" in text
    assert _ENTRY["document_url"] in text
    assert "Source: Cyber Essentials: Requirements for IT Infrastructure v3.3 (effective " in text


def test_the_explorer_says_why_a_manual_requirement_has_no_verdict() -> None:
    card = next(card for card in explorer_baselines(build_baseline_alignment([]))["frameworks"] if card["key"] == CE_FRAMEWORK_KEY)

    manual = next(control for control in card["controls"] if control["id"] == "ce.fw.device_firewall")
    assert card["short"] == "Cyber Essentials" and card["total"] == len(_REQUIREMENTS)
    assert manual["status"] == "not_assessed" and "manual" in manual["note"] and "no verdict" in manual["note"]
    clean = build_baseline_alignment([], normalized_snapshot=_CLEAN_IDENTITY_SNAPSHOT, coverage_ledger=_ledger("identity"))
    clean_card = next(card for card in explorer_baselines(clean)["frameworks"] if card["key"] == CE_FRAMEWORK_KEY)
    partial = next(control for control in clean_card["controls"] if control["id"] == "ce.uac.remove_unused_accounts")
    assert partial["status"] == "not_assessed" and "only part of this requirement" in partial["note"]


@pytest.mark.parametrize("framework", [key for key in BASELINE_FRAMEWORK_KEYS if key != CE_FRAMEWORK_KEY])
def test_the_benchmark_frameworks_keep_their_original_row_shape(framework: str) -> None:
    section = build_baseline_alignment([])["frameworks"][framework]

    assert "requirement_status_counts" not in section
    for row in section["controls"]:
        assert set(row) == {"control_id", "title", "status", "rule_ids", "rule_statuses", "open_finding_count", "finding_ids"}
