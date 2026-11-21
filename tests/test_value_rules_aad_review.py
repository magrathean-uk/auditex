"""Deep-review fixes for the AAD value rules (R001, R027, R028, R042), synthetic evidence only."""
from __future__ import annotations

from copy import deepcopy

import pytest

from azure_tenant_audit.value_rules import assess

ENV = {"M365Environment": "commercial"}


def ca(grant, *, users=None, apps=None, actions=None):
    u = {"IncludeUsers": ["All"], "ExcludeUsers": [], "ExcludeGroups": [], "ExcludeRoles": [], "IncludeRoles": [],
         "ExcludeGuestsOrExternalUsers": None}
    u.update(users or {})
    a = {"IncludeApplications": ["All"], "ExcludeApplications": [], "IncludeUserActions": []}
    a.update(apps or {})
    if actions is not None:
        a.update(IncludeApplications=[], IncludeUserActions=actions)
    return {"DisplayName": "synthetic", "State": "enabled",
            "Conditions": {"Users": u, "Applications": a, "ClientAppTypes": ["all"], "AuthenticationFlows": None,
                           "UserRiskLevels": [], "SignInRiskLevels": []},
            "GrantControls": {"AuthenticationStrength": None, **grant}}


def ca_sections(*policies, config=None):
    return {"conditional_access_policies": list(policies), "scuba_config": {**ENV, **(config or {})}}


def cell(policy, sections):
    record = assess(policy, sections)
    return record["verdict"], record["cell"]


# R001: terms of use and custom controls are alternatives to the built-in controls.

PR = {"AllowedCombinations": ["fido2"]}
GRANTS = {
    "MS.AAD.3.1v1": ({"BuiltInControls": [], "AuthenticationStrength": PR}, {}),
    "MS.AAD.3.2v2": ({"BuiltInControls": ["mfa"]}, {}),
    "MS.AAD.3.7v1": ({"BuiltInControls": ["compliantDevice", "domainJoinedDevice"]}, {}),
    "MS.AAD.3.8v1": ({"BuiltInControls": ["compliantDevice"]}, {"actions": ["urn:user:registersecurityinfo"]}),
}


@pytest.mark.parametrize("policy", sorted(GRANTS))
@pytest.mark.parametrize("extra", ["TermsOfUse", "CustomAuthenticationFactors"])
def test_r001_extra_grant_control_under_or_is_not_met(policy, extra):
    grant, where = GRANTS[policy]
    base = ca({**grant, "Operator": "OR"}, **where)
    assert cell(policy, ca_sections(base)) == ("met", "met_policy_clean")
    with_extra = deepcopy(base)
    with_extra["GrantControls"][extra] = ["synthetic-extra"]
    assert cell(policy, ca_sections(with_extra)) == ("not_met", "no_policy_meets")


@pytest.mark.parametrize("policy", sorted(GRANTS))
@pytest.mark.parametrize("extra", ["TermsOfUse", "CustomAuthenticationFactors"])
def test_r001_extra_grant_control_under_and_still_requires_the_control(policy, extra):
    grant, where = GRANTS[policy]
    p = ca({**grant, "Operator": "AND", extra: ["synthetic-extra"]}, **where)
    assert cell(policy, ca_sections(p)) == ("met", "met_policy_clean")


@pytest.mark.parametrize("policy", sorted(GRANTS))
def test_r001_extra_grant_control_without_operator_is_unknown(policy):
    grant, where = GRANTS[policy]
    p = ca({**grant, "Operator": None, "TermsOfUse": ["synthetic-extra"]}, **where)
    assert cell(policy, ca_sections(p)) == ("not_assessed", "policy_field_unusable")


@pytest.mark.parametrize("value", [None, []])
def test_r001_blank_extra_grant_control_changes_nothing(value):
    p = ca({"BuiltInControls": ["mfa"], "Operator": "OR", "TermsOfUse": value, "CustomAuthenticationFactors": value})
    assert cell("MS.AAD.3.2v2", ca_sections(p)) == ("met", "met_policy_clean")


@pytest.mark.parametrize("extra", [{"TermsOfUse": "synthetic"}, {"TermsOfUse": [7]},
                                   {"FutureControl": ["synthetic"]}])
def test_r001_unreadable_or_unknown_grant_control_is_unknown(extra):
    p = ca({"BuiltInControls": ["mfa"], "Operator": "OR", **extra})
    assert cell("MS.AAD.3.2v2", ca_sections(p)) == ("not_assessed", "policy_field_unusable")


def test_r001_block_beside_terms_of_use_stays_decided_by_block():
    p = ca({"BuiltInControls": ["block"], "Operator": "OR", "TermsOfUse": ["synthetic-extra"]},
           users={"IncludeUsers": ["All"]})
    p["Conditions"]["ClientAppTypes"] = ["exchangeActiveSync", "other"]
    assert cell("MS.AAD.1.1v1", ca_sections(p)) == ("met", "met_policy_clean")
