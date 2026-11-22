"""Value-rule follow-up fixes (lane rules-followup): R100, R027 role half, R003/R099 activation, R106.

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
