"""Integrate wave 1: cross-lane changes and review blockers (I1-I12)."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIGS = ROOT / "configs"


def _load(name: str) -> dict:
    return json.loads((CONFIGS / name).read_text(encoding="utf-8"))


def test_i4_finding_templates_cite_only_current_scuba_policy_ids() -> None:
    """R043: a template's references and text must cite the SCuBA version the mappings use."""
    policies = set(_load("scuba-policy-sections.json")["policies"])
    text = (CONFIGS / "finding-templates.json").read_text(encoding="utf-8")
    cited = set(re.findall(r"MS\.[A-Z]+\.\d+\.\d+v\d+", text))
    assert sorted(cited - policies) == []


def test_i6_rule_inventory_rates_expired_app_credentials_low() -> None:
    """R050: the inventory must advertise the severity the expired-credential findings carry."""
    from auditex.rules import list_rule_inventory

    ratings = {row["name"]: row.get("risk_rating") for row in list_rule_inventory()}
    assert ratings["app_credentials.secret_expired"] == "low"
    assert ratings["app_credentials.certificate_expired"] == "low"


def test_i7_permission_notes_describe_retired_cli_operations_as_named_skips() -> None:
    """R107: purview and ediscovery record each retired CLI operation as skipped, not as an error."""
    collectors = _load("collector-permissions.json")["collector_permissions"]
    for name in ("purview", "ediscovery"):
        notes = collectors[name]["notes"]
        assert "error m365_cli_not_used" not in notes, name
        assert "skipped with the reason m365_cli_not_used" in notes, name


def _break_glass_snapshot(policies: list[dict], groups: list[dict]) -> dict:
    from azure_tenant_audit.normalize import build_normalized_snapshot

    payloads = {
        "identity": {
            "users": {"value": [
                {"id": "u-bg1", "displayName": "Emergency One", "userPrincipalName": "bg1@example.com"},
                {"id": "u-alice", "displayName": "Alice", "userPrincipalName": "alice@example.com"},
            ]},
            "groups": {"value": groups},
            "roleDefinitions": {"value": []},
            "roleAssignments": {"value": []},
        },
        "conditional_access": {"conditionalAccessPolicies": {"value": policies}},
    }
    return build_normalized_snapshot(
        tenant_name="acme", run_id="r", collector_payloads=payloads, break_glass_accounts=["bg1@example.com"]
    )


def _mfa_policy(policy_id: str, users: dict) -> dict:
    return {
        "id": policy_id,
        "displayName": f"Policy {policy_id}",
        "state": "enabled",
        "conditions": {"users": users, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


def test_i2_an_exclusion_through_an_unread_group_is_reported_unverified_not_silent() -> None:
    """R040: the run cannot tell whether a plain group holds the listed account, so it says so."""
    from azure_tenant_audit.findings import build_findings

    groups = [{"id": "g-ca-ex", "displayName": "CA Exclusions", "isAssignableToRole": False}]
    policy = _mfa_policy("mfa-all", {"includeUsers": ["All"], "excludeGroups": ["g-ca-ex"]})

    snapshot = _break_glass_snapshot([policy], groups)

    record = snapshot["conditional_access_graph"]["records"][0]
    assert record["missing_break_glass_exclusion"] is False
    assert record["break_glass_exclusion_unverified"] is True
    assert record["break_glass_unverified_groups"] == ["CA Exclusions"]
    assessment = snapshot["break_glass_assessment"]["records"][0]
    assert assessment["policies_missing_exclusion"] == 0
    assert assessment["policies_exclusion_unverified"] == 1
    rules = {item["rule_id"]: item for item in build_findings([], normalized_snapshot=snapshot)}
    assert "ca.break_glass_exclusion_missing" not in rules
    unverified = rules["ca.break_glass_exclusion_unverified"]
    assert unverified["severity"] == "low"
    assert unverified["affected_objects"] == ["Policy mfa-all"]
    assert "CA Exclusions" in unverified["description"]
    assert unverified["returned_value"]["unverified_exclusion_groups"] == ["CA Exclusions"]


def test_i2_a_verified_exclusion_raises_no_unverified_note() -> None:
    groups = [{"id": "g-ca-ex", "displayName": "CA Exclusions", "isAssignableToRole": False}]
    policy = _mfa_policy("mfa-all", {"includeUsers": ["All"], "excludeUsers": ["u-bg1"]})

    snapshot = _break_glass_snapshot([policy], groups)

    record = snapshot["conditional_access_graph"]["records"][0]
    assert not record.get("break_glass_exclusion_unverified")
    assert snapshot["break_glass_assessment"]["records"][0]["policies_exclusion_unverified"] == 0
    from azure_tenant_audit.findings import build_findings

    assert "ca.break_glass_exclusion_unverified" not in {item["rule_id"] for item in build_findings([], normalized_snapshot=snapshot)}


def test_i3_case_searches_with_different_counts_keep_normalisation_complete() -> None:
    """R108: each case's searches are their own ediscovery source, never one shared "unknown.searches"."""
    from azure_tenant_audit.normalize import build_normalized_snapshot

    payload = {
        "cases": {"value": [{"id": "c1"}, {"id": "c2"}]},
        "case_c1": {"searches": {"value": [{"id": "s1"}]}, "operations": {"value": []}},
        "case_c2": {"searches": {"value": [{"id": "s2"}, {"id": "s3"}]}, "operations": {"value": []}},
    }
    snapshot = build_normalized_snapshot(tenant_name="acme", run_id="r", collector_payloads={"ediscovery": payload})

    assert snapshot["snapshot"]["normalization_complete"] is True
    assert snapshot["snapshot"]["normalization_incomplete_sections"] == []
    sources = {row["source"]: row for row in snapshot["normalization_coverage"]["records"]}
    assert not [name for name in sources if name.startswith("unknown.")]
    assert sources["ediscovery.case_c1.searches"]["collector"] == "ediscovery"
    assert sources["ediscovery.case_c2.searches"]["record_count"] == 2
    searches = {(row["case_id"], row["id"]) for row in snapshot["ediscovery_searches"]["records"]}
    assert searches == {("c1", "s1"), ("c2", "s2"), ("c2", "s3")}


def _dns_findings(dmarc_records: list[str]) -> tuple[dict, dict]:
    from azure_tenant_audit import dns_lookup
    from azure_tenant_audit.findings import build_findings
    from azure_tenant_audit.normalize import build_normalized_snapshot

    posture = {
        "domain": "contoso.example",
        "dmarc": dns_lookup._summarize_dmarc(dmarc_records),
        "spf": {"present": True, "all_qualifier": "-"},
        "dkim": {"selectors_present": ["s"]},
        "mta_sts": {"dns_present": True},
    }
    snapshot = build_normalized_snapshot(
        tenant_name="acme",
        run_id="r",
        collector_payloads={"dns_posture": {"domains": {"value": []}, "domainPosture": {"value": [posture]}}},
    )
    record = snapshot["dns_posture_objects"]["records"][0]
    return record, {item["rule_id"]: item for item in build_findings([], normalized_snapshot=snapshot)}


def test_i9_duplicate_dmarc_records_raise_their_own_finding_not_dmarc_missing() -> None:
    """R109: two DMARC records are not "no record"; remediation is to remove the duplicates."""
    record, rules = _dns_findings(["v=DMARC1; p=reject", "v=DMARC1; p=none"])

    assert record["dmarc_present"] is False
    assert record["dmarc_multiple_records"] is True
    assert record["dmarc_record_count"] == 2
    finding = rules["dns_posture.dmarc_multiple_records"]
    assert finding["severity"] == "high"
    assert finding["id"] == "dns_posture:contoso.example:dmarc_multiple_records"
    assert finding["returned_value"] == 2
    assert "dns_posture.dmarc_missing" not in rules


def test_i9_a_single_or_absent_dmarc_record_raises_no_duplicate_finding() -> None:
    record, rules = _dns_findings(["v=DMARC1; p=reject"])
    assert not record.get("dmarc_multiple_records")
    assert "dns_posture.dmarc_multiple_records" not in rules
    _, rules = _dns_findings([])
    assert "dns_posture.dmarc_missing" in rules and "dns_posture.dmarc_multiple_records" not in rules
