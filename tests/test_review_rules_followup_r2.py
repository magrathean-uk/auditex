"""Value-rule follow-up, repair round 1 (lane rules-followup): review blockers on R100, R003, R099 and R106.

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import json

import pytest
from test_review_value_rules_defender_dns import (
    BI_ALL,
    GROUP_ONLY,
    SCOPE_ALL,
    SL_BUILTIN,
    SL_FLAGS,
    _safelinks,
    _sl_rule,
)

from azure_tenant_audit.value_rules import assess
from azure_tenant_audit.value_rules.catalogue import row_for

SL_POLICIES = ["MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"]
OTHER_GROUP = {**SCOPE_ALL, "SentToMemberOf": ["other"]}


def _answer(policy_id, sections):
    record = assess(policy_id, sections)
    return record["verdict"], record["cell"]


# ---- R100: a partial rule fully shadowed by an earlier rule never applies; one of unknown order may apply first ----


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_orphan_partial_rule_shadowed_by_an_earlier_compliant_rule_does_not_decide(policy_id):
    rules = [_sl_rule("a", GROUP_ONLY, priority=0), _sl_rule("orphan", GROUP_ONLY, priority=1),
             _sl_rule("cover", SCOPE_ALL, priority=5)]
    policies = [SL_BUILTIN, {"Identity": "a", **SL_FLAGS}, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("met", "policy_flags_ok")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_flag_off_partial_rule_shadowed_by_an_earlier_compliant_rule_does_not_decide(policy_id):
    rules = [_sl_rule("a", GROUP_ONLY, priority=0), _sl_rule("off", GROUP_ONLY, priority=1),
             _sl_rule("cover", SCOPE_ALL, priority=5)]
    off = {"Identity": "off", **{flag: False for flag in SL_FLAGS}}
    policies = [SL_BUILTIN, {"Identity": "a", **SL_FLAGS}, off, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("met", "policy_flags_ok")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_orphan_partial_rule_for_other_recipients_is_not_shadowed(policy_id):
    rules = [_sl_rule("a", GROUP_ONLY, priority=0), _sl_rule("orphan", OTHER_GROUP, priority=1),
             _sl_rule("cover", SCOPE_ALL, priority=5)]
    policies = [SL_BUILTIN, {"Identity": "a", **SL_FLAGS}, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("not_assessed", "policy_not_in_export")


@pytest.mark.parametrize("priority", [None, "1", True])
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_orphan_partial_rule_of_unknown_priority_may_apply_first(policy_id, priority):
    rules = [_sl_rule("cover", SCOPE_ALL, priority=5), _sl_rule("orphan", GROUP_ONLY, priority=priority)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("not_assessed", "policy_not_in_export")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_compliant_partial_rule_of_unknown_priority_still_passes(policy_id):
    rules = [_sl_rule("cover", SCOPE_ALL, priority=5), _sl_rule("x", GROUP_ONLY, priority=None)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}, {"Identity": "x", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("met", "policy_flags_ok")


def test_r100_many_shadowed_orphan_rules_stay_fast():
    import time
    n = 6000
    rules = [_sl_rule("cover", SCOPE_ALL, priority=n + 1)]
    rules += [_sl_rule(f"p{i}", {**SCOPE_ALL, "SentTo": [f"u{j}" for j in range(i % 3, 3)]}, priority=i) for i in range(n)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}, {"Identity": "p0", **SL_FLAGS}]
    start = time.perf_counter()
    answer = _answer("MS.SECURITYSUITE.7.3v1", _safelinks(rules, policies, BI_ALL))
    assert time.perf_counter() - start < 5.0
    assert answer == ("met", "policy_flags_ok")       # p0 names u0..u2 first; every later rule names a subset of them


# ---- R003: the Built-In Protection rule is read only when no covering rule applies ----

BI = "built_in_protection_rules"
BI_MISSING = [pytest.param(None, id="absent"), pytest.param({"collection_status": "not_collected"}, id="marked")]


def _without_built_in(sections, marker):
    sections = {k: v for k, v in sections.items() if k != BI}
    if marker is not None:
        sections[BI] = dict(marker)
    return sections


@pytest.mark.parametrize("marker", BI_MISSING)
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_covering_rule_decides_without_the_built_in_section(policy_id, marker):
    rules = [_sl_rule("cover", SCOPE_ALL)]
    sections = _without_built_in(_safelinks(rules, [{"Identity": "cover", **SL_FLAGS}]), marker)
    assert _answer(policy_id, sections) == ("met", "policy_flags_ok")
    flag = row_for(policy_id)["params"]["flags"][0]
    sections = _without_built_in(_safelinks(rules, [{"Identity": "cover", **SL_FLAGS, flag: False}]), marker)
    assert _answer(policy_id, sections) == ("not_met", "policy_flag_off")


@pytest.mark.parametrize("marker", BI_MISSING)
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_built_in_fallback_without_the_built_in_section_is_not_collected(policy_id, marker):
    for rules in ([], [_sl_rule("x", GROUP_ONLY)]):
        record = assess(policy_id, _without_built_in(_safelinks(rules, [SL_BUILTIN, {"Identity": "x", **SL_FLAGS}]), marker))
        assert (record["verdict"], record["cell"], record["cited_sections"], record["reason_text"]) == (
            "not_assessed", "section_not_collected", [BI],
            "Data unavailable: required evidence section(s) not collected: built_in_protection_rules.")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_built_in_missing_beside_another_section_still_cites_both(policy_id):
    sections = _safelinks([_sl_rule("cover", SCOPE_ALL)], [{"Identity": "cover", **SL_FLAGS}])
    del sections["safe_links_rules"]
    record = assess(policy_id, sections)
    assert (record["cell"], record["cited_sections"]) == ("section_not_collected", ["built_in_protection_rules", "safe_links_rules"])


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_shipped_explainer_template_carries_the_built_in_cells(policy_id):
    import json
    from pathlib import Path

    template = json.loads((Path(__file__).resolve().parents[1] / "configs/explainer-template.json").read_text(encoding="utf-8"))
    cells = {c["cell"] for c in template["cells"] if c["policy_id"] == policy_id}
    assert {"builtin_rule_unusable", "no_policy_covers_all", "partial_tier_may_cover"} <= cells
    assert "no_rules_configured" not in cells
    assert template["policies"][policy_id]["sections"] == row_for(policy_id)["sections"]


# ---- R099: SS 7.x answers written before the rows read the Built-In rule still validate ----

LEGACY_SECTIONS = ["atp_policy_rules", "defender_license", "protection_policy_rules", "safe_links_policies", "safe_links_rules"]
EVERYONE = {k: None for k in ("SentTo", "SentToMemberOf", "RecipientDomainIs", "ExceptIfSentTo", "ExceptIfSentToMemberOf",
                              "ExceptIfRecipientDomainIs")}


def _assessment(tmp_path, rules):
    import json

    import auditex.rule_assessment as rule_assessment
    ops = {"eopProtectionPolicyRules": [], "atpProtectionPolicyRules": [], "atpPolicyForO365": [{"Identity": "Default"}],
           "atpBuiltInProtectionRules": [{"Identity": "ATP Built-In Protection Rule", **EVERYONE}],
           "safeLinksPolicies": [{"Name": "Built-In Protection Policy", **SL_BUILTIN}], "safeLinksRules": rules}
    (tmp_path / "raw").mkdir()
    (tmp_path / "run-manifest.json").write_text(json.dumps({"run_id": "synthetic-r099", "platform": "m365"}) + "\n")
    (tmp_path / "raw/exchange_policy.json").write_text(json.dumps({n: {"value": r, "status": "ok"} for n, r in ops.items()}) + "\n")
    rule_assessment.assess_run(tmp_path, policies=SL_POLICIES)
    payload = json.loads((tmp_path / "model_assessment.json").read_text())
    for detail in payload["projection"]["sections"].values():
        detail.pop("rule_view", None)          # the pre-lane writer had no rule_view (R106)
    payload["schema_version"] = "2026-11-05"   # ... and wrote this version
    return payload


def _legacy_rows(payload):
    rows = [row for row in payload["policies"] if row["policy_id"] in SL_POLICIES]
    assert len(rows) == 3
    return rows


def test_r099_pre_lane_no_rules_configured_answer_still_validates(tmp_path):
    from azure_tenant_audit.scuba_assessment import validate_assessment
    payload = _assessment(tmp_path, [])
    for row in _legacy_rows(payload):
        # Exactly what the pre-lane writer emitted for empty rule lists.
        what = row_for(row["policy_id"])["params"]["what"]
        row["rule_precheck"].update(section=list(LEGACY_SECTIONS), cell="no_rules_configured", reason_code="no_rules_configured",
                                    reason_text="Requirement not met: no preset security policy rule and no Safe Links rule exists, so no "
                                                f"Standard, Strict or custom Safe Links policy applies ({what}).")
        row["claims"][0]["value"] = False
        row["recommendations"] = ["review_policy_against_baseline_text"]
        row["comparison"]["model_status"] = "fail"
        row.pop("explainer", None)
    validate_assessment(payload)
    tampered = json.loads(json.dumps(payload))
    _legacy_rows(tampered)[0]["rule_precheck"]["section"] = row_for(SL_POLICIES[0])["sections"]
    with pytest.raises(ValueError):
        validate_assessment(tampered)                # the retired cell is accepted only as the pre-lane writer cited it


def test_r099_pre_lane_policy_flags_ok_answer_still_validates(tmp_path):
    from azure_tenant_audit.scuba_assessment import validate_assessment
    payload = _assessment(tmp_path, [{"Identity": "x rule", "Name": "x rule", "State": "Disabled", "Priority": 0,
                                      "SafeLinksPolicy": "x", **EVERYONE, "SentToMemberOf": ["g"]}])
    for row in _legacy_rows(payload):
        assert row["rule_precheck"]["cell"] == "policy_flags_ok"
        row["rule_precheck"]["section"] = list(LEGACY_SECTIONS)
        row.pop("explainer", None)
    validate_assessment(payload)
    tampered = json.loads(json.dumps(payload))
    _legacy_rows(tampered)[0]["rule_precheck"]["section"] = LEGACY_SECTIONS[:-1]
    with pytest.raises(ValueError):
        validate_assessment(tampered)


# ---- R106: rule_view belongs to a new assessment schema version; 2026-11-05 keeps the contract its readers know ----


def test_r106_rule_view_is_written_under_a_new_schema_version(tmp_path):
    from azure_tenant_audit.scuba_assessment import (
        ASSESSMENT_SCHEMAS,
        validate_assessment,
    )
    payload = _assessment(tmp_path, [])
    written = json.loads((tmp_path / "model_assessment.json").read_text())
    assert any("rule_view" in d for d in written["projection"]["sections"].values())
    assert written["schema_version"] != "2026-11-05" and written["schema_version"] in ASSESSMENT_SCHEMAS
    validate_assessment(written)
    # A file that advertises 2026-11-05 means what that version's readers know: no rule_view.
    old = json.loads(json.dumps(written))
    old["schema_version"] = "2026-11-05"
    with pytest.raises(ValueError):
        validate_assessment(old)
    old["projection"] = payload["projection"]         # rule_view removed, as the pre-lane writer wrote it
    validate_assessment(old)


def test_r106_frozen_2026_11_05_schema_has_no_rule_view():
    from pathlib import Path

    from azure_tenant_audit.scuba_assessment import ASSESSMENT_SCHEMAS
    root = Path(__file__).resolve().parents[1]
    frozen = json.loads((root / ASSESSMENT_SCHEMAS["2026-11-05"]).read_text(encoding="utf-8"))
    assert frozen["properties"]["schema_version"]["const"] == "2026-11-05"
    assert "rule_view" not in frozen["$defs"]["projection_section"]["properties"]


# ---- Bot review wave 2: Safe Links policy resolution and evidence (group N) ----

BI_ROW = {"Identity": "ATP Built-In Protection Rule", "ExceptIfSentTo": None, "ExceptIfSentToMemberOf": None,
          "ExceptIfRecipientDomainIs": None}
BI_SEVERAL = "Data unusable: built_in_protection_rules holds more than one rule; the policy was not assessed."
BI_UNREADABLE = "Data unusable: built_in_protection_rules holds no rule with readable exclusions; the policy was not assessed."


def _reason(policy_id, sections):
    record = assess(policy_id, sections)
    return record["verdict"], record["cell"], record["reason_text"], record["cited_sections"]


@pytest.mark.parametrize("built_in, text", [
    pytest.param([BI_ROW, {"Identity": "ATP Built-In Protection Rule"}], BI_SEVERAL, id="unrestricted-beside-unreadable"),
    pytest.param([BI_ROW, BI_ROW], BI_SEVERAL, id="two-unrestricted"),
    pytest.param([{**BI_ROW, "ExceptIfSentTo": [None]}], BI_UNREADABLE, id="null-exclusion"),
    pytest.param([{**BI_ROW, "ExceptIfSentToMemberOf": ["g", 7]}], BI_UNREADABLE, id="non-string-exclusion"),
    pytest.param([{**BI_ROW, "ExceptIfSentTo": [""]}], BI_UNREADABLE, id="empty-string-exclusion"),
])
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item66_built_in_fallback_needs_exactly_one_readable_rule(policy_id, built_in, text):
    assert _reason(policy_id, _safelinks([], [SL_BUILTIN], built_in)) == (
        "not_assessed", "builtin_rule_unusable", text, [BI])
    # A covering rule decides without the Built-In rule, however it is shaped.
    rules, policies = [_sl_rule("cover", SCOPE_ALL)], [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, built_in)) == ("met", "policy_flags_ok")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item66_one_unrestricted_built_in_rule_still_passes(policy_id):
    assert _answer(policy_id, _safelinks([], [SL_BUILTIN], [BI_ROW])) == ("met", "policy_flags_ok")


STANDARD = "Standard Preset Security Policy1700000000000"
OFF = {flag: False for flag in SL_FLAGS}


def _to(*names):
    return {**SCOPE_ALL, "SentTo": list(names)}


def _with_preset(sections, eop_scope, atp_scope, state="Enabled"):
    """A Standard preset whose EOP part (protection_policy_rules) and Defender part (atp_policy_rules) have the scopes
    given; None leaves that part out."""
    if eop_scope is not None:
        sections["protection_policy_rules"] = [{"Identity": STANDARD, "State": state, **eop_scope}]
    if atp_scope is not None:
        sections["atp_policy_rules"] = [{"Identity": STANDARD, "State": state, **atp_scope}]
    return sections


# Item 58: presets apply before every custom rule, so a custom rule both enabled parts of one preset tier cover never applies.

@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item58_orphan_rule_inside_an_enabled_preset_scope_never_applies(policy_id):
    rules = [_sl_rule("orphan", GROUP_ONLY, priority=0), _sl_rule("cover", SCOPE_ALL, priority=5)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}]
    sections = _with_preset(_safelinks(rules, policies, BI_ALL), GROUP_ONLY, GROUP_ONLY)
    assert _answer(policy_id, sections) == ("met", "policy_flags_ok")
    # A flag-off rule inside the preset scope is superseded the same way.
    rules = [_sl_rule("off", GROUP_ONLY, priority=0), _sl_rule("cover", SCOPE_ALL, priority=5)]
    sections = _with_preset(_safelinks(rules, [*policies, {"Identity": "off", **OFF}], BI_ALL), GROUP_ONLY, GROUP_ONLY)
    assert _answer(policy_id, sections) == ("met", "policy_flags_ok")


@pytest.mark.parametrize("eop, atp, state", [
    pytest.param(GROUP_ONLY, None, "Enabled", id="eop-part-only"),
    pytest.param(None, GROUP_ONLY, "Enabled", id="atp-part-only"),
    pytest.param(GROUP_ONLY, GROUP_ONLY, "Disabled", id="disabled"),
    pytest.param(GROUP_ONLY, OTHER_GROUP, "Enabled", id="parts-for-other-recipients"),
    pytest.param(_to("alice"), _to("alice"), "Enabled", id="preset-for-other-recipients"),
])
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item58_orphan_rule_outside_a_complete_preset_scope_stays_unjudged(policy_id, eop, atp, state):
    rules = [_sl_rule("orphan", GROUP_ONLY, priority=0), _sl_rule("cover", SCOPE_ALL, priority=5)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}]
    sections = _with_preset(_safelinks(rules, policies, BI_ALL), eop, atp, state)
    assert _answer(policy_id, sections) == ("not_assessed", "policy_not_in_export")


# Item 59: a non-compliant partial rule of unknown Priority may apply before the covering rule.

UNKNOWN_ORDER = ("Data unusable: a partly scoped Safe Links rule whose policy turns off a flag the policy reads has no "
                 "numeric Priority, so it may apply before the covering rule; the policy was not assessed.")


@pytest.mark.parametrize("priority", [None, "1", True])
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item59_flag_off_partial_rule_of_unknown_priority_leaves_the_order_unknown(policy_id, priority):
    rules = [_sl_rule("cover", SCOPE_ALL, priority=5), _sl_rule("off", GROUP_ONLY, priority=priority)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}, {"Identity": "off", **OFF}]
    assert _reason(policy_id, _safelinks(rules, policies, BI_ALL)) == (
        "not_assessed", "rule_unusable", UNKNOWN_ORDER, ["safe_links_rules"])


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item59_known_priority_and_compliant_policies_keep_their_verdicts(policy_id):
    base = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}, {"Identity": "off", **OFF}]
    for priority, answer in ((0, ("not_met", "partial_rule_noncompliant")), (6, ("met", "policy_flags_ok"))):
        rules = [_sl_rule("cover", SCOPE_ALL, priority=5), _sl_rule("off", GROUP_ONLY, priority=priority)]
        assert _answer(policy_id, _safelinks(rules, base, BI_ALL)) == answer
    # The covering policy decides not_met whatever the order.
    rules = [_sl_rule("cover", SCOPE_ALL, priority=5), _sl_rule("off", GROUP_ONLY, priority=None)]
    policies = [SL_BUILTIN, {"Identity": "cover", **OFF}, {"Identity": "off", **OFF}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("not_met", "policy_flag_off")
    # Inside an enabled preset scope the rule never applies (item 58).
    rules = [_sl_rule("cover", SCOPE_ALL, priority=5), _sl_rule("off", GROUP_ONLY, priority=None)]
    sections = _with_preset(_safelinks(rules, base, BI_ALL), GROUP_ONLY, GROUP_ONLY)
    assert _answer(policy_id, sections) == ("met", "policy_flags_ok")


# Item 60: many partial rules with the same two scope conditions, listed latest first, stay linear.

def test_item60_identical_two_condition_scopes_in_descending_order_stay_fast():
    import time
    n = 30000
    scope = {**SCOPE_ALL, "SentTo": ["alice"], "SentToMemberOf": ["team"]}
    rules = [_sl_rule("cover", SCOPE_ALL, priority=n + 1)]
    rules += [_sl_rule(f"p{i}", scope, priority=i) for i in range(n, 0, -1)]
    policies = [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}, {"Identity": "p1", **SL_FLAGS}]
    start = time.perf_counter()
    answer = _answer("MS.SECURITYSUITE.7.2v1", _safelinks(rules, policies, BI_ALL))
    assert time.perf_counter() - start < 3.0          # each lookup walked every later rule: about 9 s before the fix
    assert answer == ("met", "policy_flags_ok")


# Item 61: each Built-In exclusion is judged on its own; one no earlier rule may cover is definitely uncovered.

BI_EXCLUDES_BOB_CAROL = [{**BI_ROW, "ExceptIfSentTo": ["bob", "Carol"]}]


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item61_an_exclusion_no_rule_may_cover_is_not_met(policy_id):
    rules = [_sl_rule("bob", _to("BOB"), priority=0)]
    policies = [SL_BUILTIN, {"Identity": "bob", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_EXCLUDES_BOB_CAROL)) == ("not_met", "no_policy_covers_all")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item61_every_exclusion_possibly_covered_stays_undecided(policy_id):
    rules = [_sl_rule("bob", _to("bob"), priority=0), _sl_rule("carol", _to("carol"), priority=1)]
    policies = [SL_BUILTIN, {"Identity": "bob", **SL_FLAGS}, {"Identity": "carol", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_EXCLUDES_BOB_CAROL)) == ("not_assessed", "partial_tier_may_cover")
    group = [_sl_rule("team", GROUP_ONLY, priority=0)]                    # a group may hold either recipient
    policies = [SL_BUILTIN, {"Identity": "team", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(group, policies, BI_EXCLUDES_BOB_CAROL)) == ("not_assessed", "partial_tier_may_cover")


# Item 50: the undecidable Built-In answer names what may cover the excluded recipients and cites its sections.

MAY_CUSTOM = ("Data unusable: the built-in protection rule has exclusions and a partly scoped Safe Links rule exists that "
              "may cover the excluded recipients; the policy was not assessed.")
MAY_PRESET = ("Data unusable: the built-in protection rule has exclusions and a partly scoped Standard or Strict preset "
              "security policy exists that may cover the excluded recipients; the policy was not assessed.")
MAY_BOTH = ("Data unusable: the built-in protection rule has exclusions and a partly scoped preset security policy and "
            "Safe Links rule exist that may cover the excluded recipients; the policy was not assessed.")
BI_EXCLUDES_GROUP_MEMBER = [{**BI_ROW, "ExceptIfSentTo": ["member"]}]


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_item50_preset_driven_uncertainty_names_and_cites_the_preset(policy_id):
    preset_only = _with_preset(_safelinks([], [SL_BUILTIN], BI_EXCLUDES_GROUP_MEMBER), GROUP_ONLY, GROUP_ONLY)
    assert _reason(policy_id, preset_only) == (
        "not_assessed", "partial_tier_may_cover", MAY_PRESET,
        ["atp_policy_rules", BI, "protection_policy_rules"])
    policies = [SL_BUILTIN, {"Identity": "team", **SL_FLAGS}]
    both = _with_preset(_safelinks([_sl_rule("team", GROUP_ONLY)], policies, BI_EXCLUDES_GROUP_MEMBER), GROUP_ONLY, GROUP_ONLY)
    assert _reason(policy_id, both) == (
        "not_assessed", "partial_tier_may_cover", MAY_BOTH,
        ["atp_policy_rules", BI, "protection_policy_rules", "safe_links_rules"])
    custom_only = _safelinks([_sl_rule("team", GROUP_ONLY)], policies, BI_EXCLUDES_GROUP_MEMBER)
    assert _reason(policy_id, custom_only) == (
        "not_assessed", "partial_tier_may_cover", MAY_CUSTOM, [BI, "safe_links_rules"])
    # A custom rule that provably names none of the excluded recipients does not drive the uncertainty.
    policies = [SL_BUILTIN, {"Identity": "alice", **SL_FLAGS}]
    other = _with_preset(_safelinks([_sl_rule("alice", _to("alice"))], policies, BI_EXCLUDES_GROUP_MEMBER), GROUP_ONLY, GROUP_ONLY)
    assert _reason(policy_id, other)[2:] == (MAY_PRESET, ["atp_policy_rules", BI, "protection_policy_rules"])
