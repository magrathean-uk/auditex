"""Value-rule follow-up fixes (lane rules-followup): R100, R027 role half, R003/R099 activation, R106.

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import pytest
from test_review_value_rules_defender_dns import (
    BI_ALL,
    BI_EXCLUDES,
    BI_UNREADABLE,
    GROUP_ONLY,
    SCOPE_ALL,
    SL_BUILTIN,
    SL_FLAGS,
    _safelinks,
    _sl_rule,
)

from azure_tenant_audit.value_rules import assess
from azure_tenant_audit.value_rules.catalogue import catalogue

# ---- R100: a partial Safe Links rule that may apply first cannot be skipped when its policy is unreadable ----


@pytest.mark.parametrize("policies,cell", [
    ([SL_BUILTIN], "policy_not_in_export"),
    ([SL_BUILTIN, {"Identity": "x", **SL_FLAGS}, {"Identity": "x", **SL_FLAGS}], "policy_duplicated"),
    ([SL_BUILTIN, {"Identity": "x", **SL_FLAGS, "ScanUrls": None}], "policy_flag_unusable"),
])
@pytest.mark.parametrize("policy_id", ["MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1"])
def test_r100_partial_rule_with_unreadable_policy_is_not_assessed(policies, cell, policy_id):
    if policy_id.endswith("7.1v1") and cell == "policy_flag_unusable":
        policies = [SL_BUILTIN, {"Identity": "x", **SL_FLAGS, "EnableSafeLinksForTeams": None}]
    record = assess(policy_id, _safelinks([_sl_rule("x", GROUP_ONLY)], policies, BI_ALL))
    assert (record["verdict"], record["cell"]) == ("not_assessed", cell)


def test_r100_partial_rule_after_the_covering_rule_does_not_decide():
    rules = [_sl_rule("cover", SCOPE_ALL, priority=0), _sl_rule("x", GROUP_ONLY, priority=1)]
    record = assess("MS.SECURITYSUITE.7.2v1", _safelinks(rules, [{"Identity": "cover", **SL_FLAGS}], BI_ALL))
    assert (record["verdict"], record["cell"]) == ("met", "policy_flags_ok")


def test_r100_partial_rule_with_a_compliant_policy_still_passes():
    record = assess("MS.SECURITYSUITE.7.2v1",
                    _safelinks([_sl_rule("x", GROUP_ONLY)], [SL_BUILTIN, {"Identity": "x", **SL_FLAGS}], BI_ALL))
    assert (record["verdict"], record["cell"]) == ("met", "policy_flags_ok")


# ---- R003 / R099: the shipped SS 7.x rows read the Built-In Protection rule ----

SL_POLICIES = ["MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"]


def _answer(policy_id, sections):
    record = assess(policy_id, sections)
    return record["verdict"], record["cell"]


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_shipped_rows_list_the_built_in_rule_and_retire_no_rules_configured(policy_id):
    row = catalogue()["policies"][policy_id]
    assert "built_in_protection_rules" in row["sections"]
    assert "no_rules_configured" not in row["cells"]
    assert {"builtin_rule_unusable", "no_policy_covers_all", "partial_tier_may_cover"} <= set(row["cells"])


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_built_in_exclusion_no_rule_covers_is_not_met(policy_id):
    assert _answer(policy_id, _safelinks([], [SL_BUILTIN], BI_EXCLUDES)) == ("not_met", "no_policy_covers_all")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_built_in_exclusion_a_partial_rule_or_preset_may_cover_is_not_assessed(policy_id):
    partial = _safelinks([_sl_rule("x", GROUP_ONLY)], [SL_BUILTIN, {"Identity": "x", **SL_FLAGS}], BI_EXCLUDES)
    assert _answer(policy_id, partial) == ("not_assessed", "partial_tier_may_cover")
    preset = {"Identity": "Standard Preset Security Policy1700000000000", "State": "Enabled", **GROUP_ONLY}
    sections = _safelinks([], [SL_BUILTIN], BI_EXCLUDES)
    sections["protection_policy_rules"] = sections["atp_policy_rules"] = [preset]
    assert _answer(policy_id, sections) == ("not_assessed", "partial_tier_may_cover")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_unreadable_or_missing_built_in_rule_is_not_assessed(policy_id):
    for built_in in (BI_UNREADABLE, []):
        record = assess(policy_id, _safelinks([], [SL_BUILTIN], built_in))
        assert (record["verdict"], record["cell"], record["cited_sections"]) == (
            "not_assessed", "builtin_rule_unusable", ["built_in_protection_rules"])
    record = assess(policy_id, _safelinks([], [SL_BUILTIN], {"bad": 1}))
    assert (record["cell"], record["cited_sections"]) == ("section_not_a_list", ["built_in_protection_rules"])
    record = assess(policy_id, _safelinks([], [SL_BUILTIN]))
    assert (record["cell"], record["reason_text"]) == (
        "section_not_collected", "Data unavailable: required evidence section(s) not collected: built_in_protection_rules.")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_a_covering_rule_needs_no_built_in_reading(policy_id):
    rules = [_sl_rule("cover", SCOPE_ALL)]
    sections = _safelinks(rules, [{"Identity": "cover", **SL_FLAGS}], BI_UNREADABLE)
    assert _answer(policy_id, sections) == ("met", "policy_flags_ok")
    assert _answer(policy_id, {**sections, "built_in_protection_rules": BI_EXCLUDES}) == ("met", "policy_flags_ok")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r099_empty_rule_lists_follow_the_built_in_policy(policy_id):
    flag = catalogue()["policies"][policy_id]["params"]["flags"][0]
    for rules in ([], [_sl_rule("x", GROUP_ONLY, state="Disabled")]):
        assert _answer(policy_id, _safelinks(rules, [SL_BUILTIN], BI_ALL)) == ("met", "policy_flags_ok")
        assert _answer(policy_id, _safelinks(rules, [{**SL_BUILTIN, flag: False}], BI_ALL)) == ("not_met", "policy_flag_off")
        assert _answer(policy_id, _safelinks(rules, [], BI_ALL)) == ("not_assessed", "policy_not_in_export")


# ---- R106: the projection report says when a withheld section still feeds the value rules ----

NOT_COLLECTED = {"collection_status": "not_collected"}


@pytest.fixture
def run(tmp_path, monkeypatch):
    from test_scuba_adapters_aad import TENANT, write

    from auditex import scuba_projection as projection
    monkeypatch.setattr(projection, "AREA_ADAPTER_MODULES", ("auditex.scuba_adapters_aad",))
    write(tmp_path, "run-manifest.json", {"run_id": "synthetic-run", "platform": "m365", "tenant_id": TENANT,
                                          "rule_parameters": {"break_glass_accounts": []}})
    return tmp_path


def _project(run, rows, **options):
    from test_scuba_adapters_aad import operation

    from auditex import scuba_projection as projection
    operation(run, "conditional_access", "conditionalAccessPolicies", rows)
    return projection.project_run(run, **options)


def test_r106_variant_rule_view_is_named_in_the_report(run):
    from test_scuba_adapters_aad import RESTRICTIONS, with_restriction
    result = _project(run, [with_restriction(RESTRICTIONS[0])])
    detail = result.report["sections"]["conditional_access_policies"]
    assert detail["status"] == "not_collected" and detail["unsupported_conditions"]
    assert result.rule_sections["conditional_access_policies"] != NOT_COLLECTED
    assert detail.get("rule_view") == "variant"


def test_r106_adapter_rule_view_behind_a_model_only_gate_is_named(run):
    from test_scuba_adapters_aad import CA
    result = _project(run, [CA])                     # an object shape the model gate has not seen; the rules still read it
    detail = result.report["sections"]["conditional_access_policies"]
    assert (detail["status"], detail["reason"], detail["detail"]["kind"]) == ("not_collected", "incomplete_shape", "unseen_shape")
    assert result.rule_sections["conditional_access_policies"] != NOT_COLLECTED
    assert detail.get("rule_view") == "adapter"
    assert "unsupported_conditions" not in detail


def test_r106_projected_or_unbuilt_sections_carry_no_rule_view(run):
    from test_scuba_adapters_aad import CA
    result = _project(run, [CA])
    sections = result.report["sections"]
    assert {name for name, detail in sections.items() if detail["status"] == "projected"} >= {"scuba_config", "tenant_id"}
    for name, detail in sections.items():
        rule = result.rule_sections.get(name, NOT_COLLECTED)
        if detail["status"] == "projected" or (isinstance(rule, dict) and rule.get("collection_status") == "not_collected"):
            assert "rule_view" not in detail, name


def test_r106_assessment_validator_accepts_the_rule_view_only_on_withheld_sections(run):
    import json

    from test_scuba_adapters_aad import RESTRICTIONS, operation, with_restriction

    import auditex.rule_assessment as rule_assessment
    from azure_tenant_audit.scuba_assessment import validate_assessment
    operation(run, "conditional_access", "conditionalAccessPolicies", [with_restriction(RESTRICTIONS[0])])
    rule_assessment.assess_run(run, policies=["MS.AAD.1.1v1"])
    payload = json.loads((run / "model_assessment.json").read_text())
    sections = payload["projection"]["sections"]
    assert sections["conditional_access_policies"].get("rule_view") == "variant"
    validate_assessment(payload)
    projected = next(name for name, detail in sections.items() if detail["status"] == "projected")
    for name, value in ((projected, "adapter"), ("conditional_access_policies", "model")):
        bad = json.loads(json.dumps(payload))
        bad["projection"]["sections"][name]["rule_view"] = value
        with pytest.raises(ValueError):
            validate_assessment(bad)
