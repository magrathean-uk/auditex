"""Value-rule follow-up, repair round 2 (lane rules-followup): review blockers on R100, R003, R099 and R106.

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

import json

import pytest
from test_review_rules_followup_r2 import (
    LEGACY_SECTIONS,
    SL_POLICIES,
    _assessment,
    _legacy_rows,
)
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

# ---- R099: the pre-lane reading is bound to files that advertise 2026-11-05 ----


def _current(payload):
    return {**json.loads(json.dumps(payload)), "schema_version": "2026-11-22"}


def test_r099_pre_lane_rule_fault_row_still_validates(tmp_path, monkeypatch):
    import azure_tenant_audit.value_rules.defender_resolution as resolution
    from azure_tenant_audit.scuba_assessment import validate_assessment

    def broken(*_args):
        raise ValueError("synthetic rule fault")

    monkeypatch.setattr(resolution, "_safelinks_core", broken)
    payload = _assessment(tmp_path, [])
    for row in _legacy_rows(payload):
        assert (row["rule_precheck"]["cell"], row["rule_precheck"]["reason_code"]) == (None, "rule_evaluation_failed")
        row["rule_precheck"]["section"] = list(LEGACY_SECTIONS)        # the five sections the pre-lane rule read
    validate_assessment(payload)
    tampered = json.loads(json.dumps(payload))
    _legacy_rows(tampered)[0]["rule_precheck"]["section"] = LEGACY_SECTIONS[:-1]
    with pytest.raises(ValueError):
        validate_assessment(tampered)
    with pytest.raises(ValueError):
        validate_assessment(_current(payload))                         # a current file cites what the current rule reads


def test_r099_output_contract_states_the_safe_links_exception_kept_to_2026_11_05():
    # Bot review wave 2 (51): the contract must say which older Safe Links answers only a 2026-11-05 file accepts.
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docs/reference/output-contract.md").read_text(encoding="utf-8")
    paragraph = text[text.index("Its schema is `schemas/model_assessment.schema.json`"):]
    paragraph = " ".join(paragraph[:paragraph.index("\n\n")].split())
    exception = re.search(r"one exception kept to `2026-11-05`: (.+?)A `2026-11-22` file rejects both", paragraph)
    assert exception, "the contract no longer states the Safe Links exception kept to 2026-11-05"
    exception = exception.group(1)
    assert "SS 7.1 to 7.3" in exception and "`no_rules_configured`" in exception
    assert re.findall(r"`([a-z_]+)`", exception[exception.index("("):exception.index(")")]) == sorted(LEGACY_SECTIONS)


def test_r099_retired_answers_are_rejected_in_a_current_file(tmp_path):
    from azure_tenant_audit.scuba_assessment import validate_assessment
    payload = _assessment(tmp_path, [{"Identity": "x rule", "Name": "x rule", "State": "Disabled", "Priority": 0,
                                      "SafeLinksPolicy": "x", "SentToMemberOf": ["g"]}])
    for row in _legacy_rows(payload):
        assert row["rule_precheck"]["cell"] == "policy_flags_ok"
        row["rule_precheck"]["section"] = list(LEGACY_SECTIONS)
        row.pop("explainer", None)
    validate_assessment(payload)
    with pytest.raises(ValueError, match="cites the wrong section"):
        validate_assessment(_current(payload))

    (tmp_path / "empty").mkdir()
    payload = _assessment(tmp_path / "empty", [])
    for row in _legacy_rows(payload):
        what = row_for(row["policy_id"])["params"]["what"]
        row["rule_precheck"].update(section=list(LEGACY_SECTIONS), cell="no_rules_configured", reason_code="no_rules_configured",
                                    reason_text="Requirement not met: no preset security policy rule and no Safe Links rule exists, so no "
                                                f"Standard, Strict or custom Safe Links policy applies ({what}).")
        row["claims"][0]["value"] = False
        row["recommendations"] = ["review_policy_against_baseline_text"]
        row["comparison"]["model_status"] = "fail"
        row.pop("explainer", None)
    validate_assessment(payload)
    with pytest.raises(ValueError, match="Unsupported value-rule cell or reason"):
        validate_assessment(_current(payload))


# ---- R100: a known false flag decides; earlier rules that together name every recipient shadow a later one ----

def _answer(policy_id, sections):
    record = assess(policy_id, sections)
    return record["verdict"], record["cell"]


def _to(*recipients):
    return {**SCOPE_ALL, "SentTo": list(recipients)}


@pytest.mark.parametrize("covering", [True, False], ids=["covering", "built_in"])
@pytest.mark.parametrize("policy_id", SL_POLICIES[:2])
def test_r100_known_false_flag_beside_a_null_flag_is_not_met(policy_id, covering):
    first, second = row_for(policy_id)["params"]["flags"][:2]
    rules = [_sl_rule("group", GROUP_ONLY, priority=0)] + ([_sl_rule("cover", SCOPE_ALL, priority=5)] if covering else [])
    policies = [SL_BUILTIN, {"Identity": "group", **SL_FLAGS, first: False, second: None}, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("not_met", "partial_rule_noncompliant")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_orphan_jointly_shadowed_by_earlier_rules_does_not_decide(policy_id):
    rules = [_sl_rule("a", _to("alice"), priority=0), _sl_rule("b", _to("bob"), priority=1),
             _sl_rule("orphan", _to("alice", "bob"), priority=2), _sl_rule("cover", SCOPE_ALL, priority=5)]
    policies = [SL_BUILTIN, {"Identity": "a", **SL_FLAGS}, {"Identity": "b", **SL_FLAGS}, {"Identity": "cover", **SL_FLAGS}]
    assert _answer(policy_id, _safelinks(rules, policies, BI_ALL)) == ("met", "policy_flags_ok")


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r100_orphan_not_jointly_shadowed_still_unjudged(policy_id):
    policies = [SL_BUILTIN, {"Identity": "a", **SL_FLAGS}, {"Identity": "b", **SL_FLAGS}, {"Identity": "cover", **SL_FLAGS}]
    cover = _sl_rule("cover", SCOPE_ALL, priority=5)
    cases = (
        [_sl_rule("a", _to("alice"), priority=0), _sl_rule("orphan", _to("alice", "carol"), priority=2)],   # carol named by no one
        [_sl_rule("a", _to("alice"), priority=0), _sl_rule("b", _to("bob"), priority=3),                     # bob's rule comes later
         _sl_rule("orphan", _to("alice", "bob"), priority=2)],
        [_sl_rule("a", _to("alice"), priority=0), _sl_rule("b", {**SCOPE_ALL, "SentToMemberOf": ["bob"]}, priority=1),
         _sl_rule("orphan", _to("alice", "bob"), priority=2)],                                                # another condition kind
        [_sl_rule("a", {**_to("alice"), "ExceptIfSentToMemberOf": ["x"]}, priority=0), _sl_rule("b", _to("bob"), priority=1),
         _sl_rule("orphan", _to("alice", "bob"), priority=2)],                                                # alice's rule has exceptions
        [_sl_rule("a", {**_to("alice"), "SentToMemberOf": ["g"]}, priority=0), _sl_rule("b", _to("bob"), priority=1),
         _sl_rule("orphan", _to("alice", "bob"), priority=2)],                                                # alice's rule sets two kinds
    )
    for rules in cases:
        assert _answer(policy_id, _safelinks([*rules, cover], policies, BI_ALL)) == ("not_assessed", "policy_not_in_export")


# ---- R003: a partial rule that provably names none of the excluded recipients; malformed Built-In data ----

BI_EXCLUDES_BOB = [{"Identity": "ATP Built-In Protection Rule", "ExceptIfSentTo": ["bob"], "ExceptIfSentToMemberOf": None,
                    "ExceptIfRecipientDomainIs": None}]


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_partial_rule_for_other_recipients_cannot_cover_the_built_in_exclusion(policy_id):
    policies = [SL_BUILTIN, {"Identity": "alice", **SL_FLAGS}]
    # Conditions are joined by AND (repair round 2 of item 61): naming Alice and a domain still reaches only Alice.
    for scope in (_to("alice", "Carol"), {**_to("alice"), "RecipientDomainIs": ["example.com"]}):
        rules = [_sl_rule("alice", scope, priority=0)]
        assert _answer(policy_id, _safelinks(rules, policies, BI_EXCLUDES_BOB)) == ("not_met", "no_policy_covers_all"), scope


@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_partial_rule_that_may_name_an_excluded_recipient_still_may_cover(policy_id):
    policies = [SL_BUILTIN, {"Identity": "p", **SL_FLAGS}]
    for scope in (_to("alice", "BOB"), {**SCOPE_ALL, "SentToMemberOf": ["team"]}, {**SCOPE_ALL, "RecipientDomainIs": ["example.com"]},
                  {**_to("alice", "bob"), "RecipientDomainIs": ["example.com"]}):
        sections = _safelinks([_sl_rule("p", scope, priority=0)], policies, BI_EXCLUDES_BOB)
        assert _answer(policy_id, sections) == ("not_assessed", "partial_tier_may_cover"), scope
    group_excluded = [{**BI_EXCLUDES_BOB[0], "ExceptIfSentToMemberOf": ["team"]}]
    sections = _safelinks([_sl_rule("p", _to("alice"), priority=0)], policies, group_excluded)
    assert _answer(policy_id, sections) == ("not_assessed", "partial_tier_may_cover")     # a group's members are unknown


@pytest.mark.parametrize("built_in", [{"Identity": "ATP Built-In Protection Rule"}, "unreadable", 7])
@pytest.mark.parametrize("policy_id", SL_POLICIES)
def test_r003_malformed_built_in_section_does_not_block_a_covering_rule(policy_id, built_in):
    rules = [_sl_rule("cover", SCOPE_ALL)]
    assert _answer(policy_id, _safelinks(rules, [SL_BUILTIN, {"Identity": "cover", **SL_FLAGS}], built_in)) == ("met", "policy_flags_ok")
    record = assess(policy_id, _safelinks([], [SL_BUILTIN], built_in))
    assert (record["cell"], record["cited_sections"]) == ("section_not_a_list", ["built_in_protection_rules"])


# ---- R106: the output contract names the version current outputs carry; rule_view is never renamed ----


def test_r106_output_contract_names_the_written_schema_version():
    import re
    from pathlib import Path

    import auditex.rule_assessment as rule_assessment
    root = Path(__file__).resolve().parents[1]
    text = (root / "docs/reference/output-contract.md").read_text(encoding="utf-8")
    named = re.search(r"Its schema is `schemas/model_assessment\.schema\.json` \(version `([^`]+)`\)", text).group(1)
    schema = json.loads((root / "schemas/model_assessment.schema.json").read_text(encoding="utf-8"))
    assert named == rule_assessment.SCHEMA_VERSION == schema["properties"]["schema_version"]["const"]
    paragraph = text[text.index("Its schema is `schemas/model_assessment.schema.json`"):]
    paragraph = paragraph[:paragraph.index("\n\n")]
    assert "`2026-11-05`" in paragraph and "rule_view" in paragraph


def test_r106_rule_view_key_is_kept_when_a_person_is_named_rule_view():
    from test_redaction_person_names import _people

    from azure_tenant_audit.output_redaction import redact_output
    value = {"projection": {"sections": {"safe_links_rules": {"status": "not_collected", "rule_view": "adapter"}}}}
    out = redact_output(value, context=_people("Rule View"))
    assert out["projection"]["sections"]["safe_links_rules"] == {"status": "not_collected", "rule_view": "adapter"}


# ---- Wave 2 bot review (item 57): an unreadable control may still carry the control in the R027 shared-gap test ----

def _ca_unreadable_narrow(**users):
    from test_value_rules_aad_review import ca
    return ca({"BuiltInControls": "unreadable", "Operator": "OR"}, users={"IncludeUsers": [], "IncludeGroups": [], **users})


def test_r027_unreadable_control_including_the_shared_role_keeps_the_union_possible():
    from test_value_rules_aad_review import MFA, ca, ca_sections, cell
    one = ca(MFA, users={"ExcludeRoles": ["synthetic-role"]})
    narrow = _ca_unreadable_narrow(IncludeRoles=["synthetic-role"])
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), narrow)) == ("not_assessed", "union_possible")


def test_r027_shared_role_gap_still_decides_when_every_possible_carrier_excludes_it():
    from test_value_rules_aad_review import MFA, ca, ca_sections, cell
    one = ca(MFA, users={"ExcludeRoles": ["synthetic-role"]})
    twin = json.loads(json.dumps(one))
    excluding = _ca_unreadable_narrow(IncludeRoles=["synthetic-other"], ExcludeRoles=["synthetic-role"])
    assert cell("MS.AAD.3.2v2", ca_sections(one, twin, excluding)) == ("not_met", "no_policy_meets")
    other_control = ca({"BuiltInControls": ["compliantDevice"], "Operator": "OR"}, users={"IncludeUsers": [], "IncludeRoles": ["synthetic-role"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, twin, other_control)) == ("not_met", "no_policy_meets")


def test_r027_unreadable_control_without_the_shared_exclusion_keeps_the_union_possible():
    from test_value_rules_aad_review import MFA, ca, ca_sections, cell
    one = ca(MFA, users={"ExcludeUsers": ["synthetic-principal"]})
    narrow = _ca_unreadable_narrow(IncludeUsers=["synthetic-principal"])
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), narrow)) == ("not_assessed", "union_possible")


def test_r027_unreadable_control_on_a_different_app_keeps_the_shared_app_gap():
    from test_value_rules_aad_review import MFA, ca, ca_sections, cell
    one = ca(MFA, apps={"ExcludeApplications": ["synthetic-app-b"]})
    other_app = ca({"BuiltInControls": "unreadable", "Operator": "OR"}, apps={"IncludeApplications": ["synthetic-app-a"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), other_app)) == ("not_met", "near_miss_exclusions")
    same_app = ca({"BuiltInControls": "unreadable", "Operator": "OR"}, apps={"IncludeApplications": ["synthetic-app-b"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), same_app)) == ("not_assessed", "union_possible")
    office = ca({"BuiltInControls": "unreadable", "Operator": "OR"}, apps={"IncludeApplications": ["Office365"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), office)) == ("not_assessed", "union_possible")


def test_r027_unreadable_control_on_a_different_role_keeps_the_shared_role_gap():
    from test_value_rules_aad_review import MFA, ca, ca_sections, cell
    one = ca(MFA, users={"ExcludeRoles": ["synthetic-role"]})
    other_role = _ca_unreadable_narrow(IncludeRoles=["synthetic-other"])
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), other_role)) == ("not_met", "no_policy_meets")
    with_user = _ca_unreadable_narrow(IncludeRoles=["synthetic-other"], IncludeUsers=["synthetic-principal"])
    assert cell("MS.AAD.3.2v2", ca_sections(one, json.loads(json.dumps(one)), with_user)) == ("not_assessed", "union_possible")
