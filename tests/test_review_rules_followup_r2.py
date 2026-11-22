"""Value-rule follow-up, repair round 1 (lane rules-followup): review blockers on R100, R003, R099 and R106.

Each test names the review finding it pins. Synthetic, offline data only.
"""
from __future__ import annotations

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
