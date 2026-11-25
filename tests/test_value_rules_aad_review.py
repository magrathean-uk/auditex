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


# R027: a gap every control-carrying policy shares cannot be closed by their union.

MFA = {"BuiltInControls": ["mfa"], "Operator": "OR"}


def test_r027_shared_excluded_role_is_not_met_not_union_possible():
    one = ca(MFA, users={"ExcludeRoles": ["synthetic-role"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one)) == ("not_met", "no_policy_meets")
    assert cell("MS.AAD.3.2v2", ca_sections(one, deepcopy(one))) == ("not_met", "no_policy_meets")


@pytest.mark.parametrize("field", ["ExcludeUsers", "ExcludeGroups"])
def test_r027_shared_non_exempt_exclusion_is_not_met_not_union_possible(field):
    one = ca(MFA, users={field: ["synthetic-principal"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one)) == ("not_met", "near_miss_exclusions")
    assert cell("MS.AAD.3.2v2", ca_sections(one, deepcopy(one))) == ("not_met", "near_miss_exclusions")


def test_r027_shared_non_exempt_application_is_not_met():
    one = ca(MFA, apps={"ExcludeApplications": ["synthetic-app"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, deepcopy(one))) == ("not_met", "near_miss_exclusions")


def test_r027_different_gaps_can_still_close_in_union():
    one = ca(MFA, users={"ExcludeRoles": ["synthetic-role-a"]})
    two = ca(MFA, users={"ExcludeRoles": ["synthetic-role-b"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, two)) == ("not_assessed", "union_possible")
    one = ca(MFA, users={"ExcludeUsers": ["synthetic-a"]})
    two = ca(MFA, users={"ExcludeUsers": ["synthetic-b"]})
    assert cell("MS.AAD.3.2v2", ca_sections(one, two)) == ("not_assessed", "union_possible")


def test_r027_exempt_shared_exclusion_does_not_decide():
    one = ca(MFA, users={"ExcludeUsers": ["synthetic-break-glass"], "IncludeUsers": ["synthetic-a"]})
    two = ca(MFA, users={"ExcludeUsers": ["synthetic-break-glass"], "IncludeUsers": ["synthetic-b"]})
    config = {"Aad": {"MS.AAD.3.2v1": {"CapExclusions": {"Users": ["synthetic-break-glass"]}}}}
    assert cell("MS.AAD.3.2v2", ca_sections(one, two, config=config)) == ("not_assessed", "union_possible")


# R028 (settled 25 Nov 2026, not a defect): Microsoft documents that an assigned custom app management policy overrides the
# tenant default only for the restrictions it defines; a restriction it does not define falls back to the tenant default
# ("Anything not defined inherits from default policy", Microsoft Graph application management policy API overview). The
# rules read precedence per restriction type, as the pinned v3.9.1 vectors do, and these tests pin that reading.

ALL_APPS = "0001-01-01T00:00:00Z"


def entry(rtype, state="enabled", maxd=None, **extra):
    e = {"RestrictionType": rtype, "State": state, "RestrictForAppsCreatedAfterDateTime": ALL_APPS,
         "MaxLifetime": None if maxd is None else f"P{maxd}D"}
    e.update(extra)
    return e


def default_policy(**extra):
    pw = [entry("passwordAddition", **extra), entry("passwordLifetime", maxd=90, **extra)]
    keys = [entry("asymmetricKeyLifetime", maxd=180, **extra)]
    scope = {"PasswordCredentials": pw, "KeyCredentials": keys}
    return {"Id": "synthetic-default", "IsEnabled": True,
            "ApplicationRestrictions": deepcopy(scope), "ServicePrincipalRestrictions": deepcopy(scope)}


def custom_policy(password=(), keys=(), targets=({"Id": "synthetic-app"},), enabled=True):
    def tag(items):
        return [{**e, "AppliesTo": [dict(t) for t in targets]} for e in items]
    return {"Id": "synthetic-custom", "IsEnabled": enabled,
            "Restrictions": {"PasswordCredentials": tag(password), "KeyCredentials": tag(keys)}}


def app_sections(custom=(), default=None):
    return {"default_app_management_policy": [default or default_policy()], "app_management_policies": list(custom)}


def test_r028_baseline_is_met():
    assert cell("MS.AAD.5.5v1", app_sections()) == ("met", "restrictions_compliant")
    assert cell("MS.AAD.5.7v1", app_sections()) == ("met", "restrictions_compliant")


@pytest.mark.parametrize("policy,custom", [
    ("MS.AAD.5.5v1", custom_policy(password=[entry("passwordLifetime", maxd=90)])),
    ("MS.AAD.5.5v1", custom_policy(keys=[entry("asymmetricKeyLifetime", maxd=180)])),
    ("MS.AAD.5.7v1", custom_policy(password=[entry("passwordAddition")])),
])
def test_r028_custom_policy_without_the_restriction_falls_back_to_the_default(policy, custom):
    assert cell(policy, app_sections([custom])) == ("met", "restrictions_compliant")


def test_r028_disabled_or_untargeted_custom_policy_changes_nothing():
    off = custom_policy(password=[entry("passwordLifetime", maxd=90)], enabled=False)
    untargeted = custom_policy(password=[entry("passwordLifetime", maxd=90)], targets=())
    assert cell("MS.AAD.5.5v1", app_sections([off])) == ("met", "restrictions_compliant")
    assert cell("MS.AAD.5.5v1", app_sections([untargeted])) == ("met", "restrictions_compliant")


def test_r028_unreadable_targets_on_another_restriction_do_not_matter():
    custom = custom_policy(password=[entry("passwordLifetime", maxd=90)])
    custom["Restrictions"]["PasswordCredentials"][0]["AppliesTo"] = "synthetic"
    assert cell("MS.AAD.5.5v1", app_sections([custom])) == ("met", "restrictions_compliant")


def test_r028_lifetime_is_moot_where_the_custom_policy_blocks_password_addition():
    custom = custom_policy(password=[entry("passwordAddition")])
    assert cell("MS.AAD.5.6v1", app_sections([custom])) == ("not_applicable", "moot_addition_blocked")


def test_r027_shared_exclusion_keeps_the_3_2v2_key_guard():
    """Impact note: an exemption written under MS.AAD.3.2v2 (which ScubaGear ignores) stays ambiguous, never a shared-gap not met."""
    one = ca(MFA, users={"ExcludeUsers": ["synthetic-break-glass"], "ExcludeRoles": ["synthetic-role-a"]})
    two = ca(MFA, users={"ExcludeUsers": ["synthetic-break-glass"], "ExcludeRoles": ["synthetic-role-b"]})
    config = {"Aad": {"MS.AAD.3.2v2": {"CapExclusions": {"Users": ["synthetic-break-glass"]}}}}
    assert cell("MS.AAD.3.2v2", ca_sections(one, two, config=config)) == ("not_assessed", "exemption_key_ambiguous")
