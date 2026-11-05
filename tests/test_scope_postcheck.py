"""Scope post-check: a met verdict the pinned Rego reads blind to Conditional Access scoping is marked, never changed.

Synthetic evidence only; no tenant, network or model calls (the endpoint is stubbed).
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

import jsonschema
import pytest

from auditex.model_serving import ModelClient, ModelConfig, assess_run, canonical, policy_catalogue
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.scuba_scope import (
    LIMITATION_ID, ScopeEntry, post_check, requirement_met, scope_catalogue, scope_entries, scope_summary,
)
from test_model_serving import envelope, fake_projection

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/model_assessment.schema.json").read_text())
CA = "conditional_access_policies"
LOCATION = "7c1e4b52-3a90-4d68-8f21-b5d0a6e93c14"
NAMED = {"IncludeLocations": [LOCATION], "ExcludeLocations": []}

# The v9 dataset card, "What the Rego ignores, measured per policy": the scope groups whose tested values never
# changed a label, per policy, and the policies whose grant operator the Rego ignores.
EVERY_GROUP = {"client_app_types", "client_applications", "devices", "locations", "platforms"}
CARD_IGNORED = {
    "MS.AAD.1.1v1": EVERY_GROUP - {"client_app_types"},
    "MS.AAD.2.1v1": EVERY_GROUP, "MS.AAD.2.3v1": EVERY_GROUP, "MS.AAD.3.1v1": EVERY_GROUP,
    "MS.AAD.3.2v2": EVERY_GROUP, "MS.AAD.3.6v1": EVERY_GROUP, "MS.AAD.3.7v1": EVERY_GROUP,
    "MS.AAD.3.8v1": EVERY_GROUP, "MS.AAD.3.9v1": EVERY_GROUP,
    "MS.AAD.9.1v1": {"devices", "locations", "platforms"},
}
CARD_OPERATOR_IGNORED = {"MS.AAD.1.1v1", "MS.AAD.2.1v1", "MS.AAD.2.3v1", "MS.AAD.3.1v1", "MS.AAD.3.2v2",
                         "MS.AAD.3.6v1", "MS.AAD.3.8v1", "MS.AAD.3.9v1"}
# MS.AAD.9.1v1 is not on the card, but its Rego (AADConfig.rego l1948-1962) never reads the grant operator either.
OPERATOR_IGNORED = CARD_OPERATOR_IGNORED | {"MS.AAD.9.1v1"}
# The Rego's own list (Utils/AAD.rego l190-236), restated here so that a table edit cannot weaken a test with it.
PHISHING_RESISTANT = {"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"}
STRENGTH = {"AllowedCombinations": ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]}
# A policy that could decide each item: what the pinned Rego requires of it, in ProviderExport (projection) spelling.
BASES = {
    "MS.AAD.1.1v1": {"builtin": ["block"], "ClientAppTypes": ["other", "exchangeActiveSync"]},
    "MS.AAD.2.1v1": {"builtin": ["block"], "UserRiskLevels": ["high"]},
    "MS.AAD.2.3v1": {"builtin": ["block"], "SignInRiskLevels": ["high"]},
    "MS.AAD.3.1v1": {"strength": STRENGTH},
    "MS.AAD.3.2v2": {"builtin": ["mfa"]},
    "MS.AAD.3.6v1": {"strength": STRENGTH},
    "MS.AAD.3.7v1": {"builtin": ["compliantDevice", "domainJoinedDevice"], "operator": "OR"},
    "MS.AAD.3.8v1": {"builtin": ["compliantDevice", "domainJoinedDevice"], "operator": "OR",
                     "Applications": {"IncludeUserActions": ["urn:user:registersecurityinfo"]}},
    "MS.AAD.3.9v1": {"builtin": ["block"], "AuthenticationFlows": {"TransferMethods": "deviceCodeFlow"}},
    "MS.AAD.9.1v1": {"builtin": ["block"], "AgentIdRiskLevels": "high",
                     "ClientApplications": {"IncludeAgentIdServicePrincipals": ["All"]}},
}


def policy(name="Require MFA", *, state="enabled", builtin=(), strength=None, operator=None, **conditions):
    """An all-users, all-applications policy with no exclusion (ProviderExport spelling) unless a condition overrides it."""
    users = {"IncludeUsers": ["All"], "ExcludeRoles": [], "ExcludeUsers": [], "ExcludeGroups": [],
             "ExcludeGuestsOrExternalUsers": None}
    return {"DisplayName": name, "State": state,
            "Conditions": {"ClientAppTypes": ["all"], "Users": users, "Applications": {"IncludeApplications": ["All"]},
                           **conditions},
            "GrantControls": {"BuiltInControls": list(builtin), "Operator": operator, "AuthenticationStrength": strength}}


def users(**fields):
    """The Users condition of a policy that differs from the default in the given fields."""
    return {"IncludeUsers": ["All"], "ExcludeRoles": [], "ExcludeUsers": [], "ExcludeGroups": [],
            "ExcludeGuestsOrExternalUsers": None, **fields}


def base(policy_id, name="Compliant", **override):
    spec = {**BASES[policy_id], **override}
    return policy(name, **{key: value for key, value in spec.items()})


def camel(value):
    if isinstance(value, dict):
        return {key[:1].lower() + key[1:]: camel(item) for key, item in value.items()}
    if isinstance(value, list):
        return [camel(item) for item in value]
    return value


def answer_for(verdict, case):
    ids = [item["id"] for item in case["evidence"]]
    criticality = {"id": "policy_criticality", "status": "confirmed", "evidence_ids": ["e0"],
                   "value": case["evidence"][0]["observed"]["criticality"]}
    requirement = {"id": "requirement_met", "status": "confirmed", "value": True, "evidence_ids": ids}
    limitations, recommendations = [], []
    if verdict == "inferred_met":
        requirement["status"] = "inferred"
    elif verdict == "not_met":
        requirement["value"] = False
        recommendations = ["review_policy_against_baseline_text"]
    elif verdict == "not_applicable":
        requirement["status"] = "inferred"
        limitations = ["policy_not_applicable"]
    elif verdict == "unknown":
        requirement.update(status="unknown", value=None, evidence_ids=ids[:2])
        limitations, recommendations = ["required_evidence_section_not_collected"], ["collect_missing_evidence_section"]
    return {"claims": [requirement, criticality], "limitations": limitations, "recommendations": recommendations}


def assess(tmp_path, monkeypatch, policy_id, policies, verdict="met", **kwargs):
    """One model row for ``policy_id`` over a faked projection whose Conditional Access section is ``policies``."""
    (tmp_path / "run-manifest.json").write_text(
        '{"run_id":"run","rule_parameters":{"break_glass_accounts":[]}}')
    # project_run synthesises the policy's scuba_config view from this manifest.
    # Leave that view in place: fake_projection replaces ordinary evidence and
    # clears per-policy views for any section it replaces.
    values = {section: {} for section in policy_catalogue()["policies"][policy_id]["sections"]
              if section != "scuba_config"}
    values[CA] = policies
    monkeypatch.setattr("auditex.model_serving.project_run", lambda root, **options: fake_projection(root, values))
    prompts = []

    def reply(self, method, path, payload):
        prompts.append(canonical(payload))
        return envelope(answer_for(verdict, json.loads(payload["messages"][1]["content"])))

    monkeypatch.setattr(ModelClient, "_request", reply)
    result = assess_run(tmp_path, ModelConfig(model_name="stub"), policies=[policy_id], **kwargs)
    validate_assessment(result)
    jsonschema.validate(result, SCHEMA)
    return result, result["policies"][0], prompts


@pytest.fixture
def marked(tmp_path, monkeypatch):
    result, row, _ = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2", [policy("Office only", builtin=["mfa"], Locations=NAMED)])
    assert "post_check" in row
    return result


# --- verdict-level behaviour -------------------------------------------------------------------------------


@pytest.mark.parametrize("verdict", ["met", "inferred_met"])
def test_met_row_with_location_scoped_enabled_policy_is_marked_and_the_verdict_is_kept(tmp_path, monkeypatch, verdict):
    (tmp_path / "plain").mkdir()
    plain = assess(tmp_path / "plain", monkeypatch, "MS.AAD.3.2v2", [policy(builtin=["mfa"])], verdict)[1]
    result, row, prompts = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2",
                                  [policy("Office only", builtin=["mfa"], Locations=NAMED)], verdict)
    assert row["post_check"] == {"kind": "scope_narrowed", "policies": ["Office only"],
                                 "conditions": ["conditions.locations"], "count": 1}
    assert row["limitations"] == [LIMITATION_ID]
    # The oracle's verdict, comparison and recommendations are exactly those of the unscoped run.
    for key in ("claims", "recommendations", "comparison", "validation_status", "reason", "attempts"):
        assert row[key] == plain[key]
    assert row["claims"][0]["value"] is True and row["claims"][0]["status"] == ("confirmed" if verdict == "met" else "inferred")
    assert result["totals"] == {"answered": 1, "unknown": 0, "invalid": 0, "skipped": 0, "rule_answered": 0,
                                "scope_narrowed": 1}
    assert result["scope_post_check"] == {
        "status": "evaluated", "source": "projection", "reason": None, "count": 1,
        "policies": [{"name": "Office only", "conditions": ["conditions.locations"]}]}
    # Nothing of the post-check reaches the prompt: the case, its limitation vocabulary and the training shape are unchanged.
    assert LIMITATION_ID not in "".join(prompts)
    assert "limitation_ids" in prompts[0] and "scope_narrowed" not in policy_catalogue()["limitation_ids"]


@pytest.mark.parametrize("state", ["disabled", "enabledForReportingButNotEnforced"])
def test_report_only_or_disabled_scoped_policy_does_not_trigger(tmp_path, monkeypatch, state):
    result, row, _ = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2",
                            [policy("Office only", state=state, builtin=["mfa"], Locations=NAMED)])
    assert "post_check" not in row and row["limitations"] == []
    assert result["totals"]["scope_narrowed"] == 0
    assert result["scope_post_check"]["count"] == 0 and result["scope_post_check"]["policies"] == []


def test_unscoped_met_row_is_untouched(tmp_path, monkeypatch):
    policies = [policy(builtin=["mfa"], Locations={"IncludeLocations": ["All"], "ExcludeLocations": []},
                       Platforms={"IncludePlatforms": ["all"], "ExcludePlatforms": []}, Devices=None,
                       ClientApplications=None, Operator=None)]
    result, row, _ = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2", policies)
    assert "post_check" not in row and row["limitations"] == [] and row["claims"][0]["value"] is True
    assert result["totals"]["scope_narrowed"] == 0 and result["scope_post_check"]["policies"] == []


@pytest.mark.parametrize("verdict", ["not_met", "unknown", "not_applicable"])
def test_other_verdicts_are_untouched_even_with_a_scoped_policy(tmp_path, monkeypatch, verdict):
    result, row, _ = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2",
                            [policy("Office only", builtin=["mfa"], Locations=NAMED)], verdict)
    assert "post_check" not in row and LIMITATION_ID not in row["limitations"]
    assert result["totals"]["scope_narrowed"] == 0
    # The envelope list is verdict-independent: the scoped policy is still named.
    assert result["scope_post_check"]["policies"] == [{"name": "Office only", "conditions": ["conditions.locations"]}]


def test_requirement_met_excludes_rule_rows_and_not_applicable_answers():
    row = {"validation_status": "valid", "reason": None, "limitations": [],
           "claims": [{"id": "requirement_met", "status": "confirmed", "value": True}]}
    assert requirement_met(row)
    assert not requirement_met({**row, "reason": "rule_precheck"})
    assert not requirement_met({**row, "limitations": ["policy_not_applicable"]})
    assert not requirement_met({**row, "validation_status": "invalid"})
    assert not requirement_met({**row, "claims": [{"id": "requirement_met", "status": "unknown", "value": None}]})


# --- which conditions narrow -------------------------------------------------------------------------------


def narrowed(policy_id, *policies, **options):
    found = post_check(policy_id, scope_entries(policies), **options)
    return None if found is None else found["conditions"]


@pytest.mark.parametrize("condition,conditions", [
    ("locations", {"Locations": NAMED}),
    ("locations", {"Locations": {"IncludeLocations": ["AllTrusted"], "ExcludeLocations": []}}),
    ("locations", {"Locations": {"IncludeLocations": ["All"], "ExcludeLocations": ["AllTrusted"]}}),
    ("platforms", {"Platforms": {"IncludePlatforms": ["android", "iOS"], "ExcludePlatforms": []}}),
    ("platforms", {"Platforms": {"IncludePlatforms": ["all"], "ExcludePlatforms": ["android", "iOS"]}}),
    ("devices", {"Devices": {"DeviceFilter": {"Mode": "include", "Rule": 'device.isCompliant -eq True'}}}),
    ("devices", {"Devices": {"DeviceFilter": {"Mode": "exclude", "Rule": 'device.extensionAttribute1 -eq "Kiosk"'}}}),
    ("client_applications", {"ClientApplications": {"IncludeServicePrincipals": ["ServicePrincipalsInMyTenant"],
                                                    "ExcludeServicePrincipals": [], "ServicePrincipalFilter": None}}),
    ("client_app_types", {"ClientAppTypes": ["browser", "mobileAppsAndDesktopClients"]}),
])
def test_each_scope_condition_narrows(condition, conditions):
    paths = scope_catalogue()["paths"]
    assert narrowed("MS.AAD.3.2v2", policy(builtin=["mfa"], **conditions)) == [paths[condition]]


@pytest.mark.parametrize("conditions", [
    {}, {"Locations": None, "Platforms": None, "Devices": None, "ClientApplications": None},
    {"Locations": {"IncludeLocations": ["All"]}}, {"Locations": {"IncludeLocations": ["All"], "ExcludeLocations": []}},
    {"Platforms": {"IncludePlatforms": ["all"], "ExcludePlatforms": []}},
    {"Devices": {"DeviceFilter": None}}, {"ClientApplications": {"IncludeServicePrincipals": [], "ServicePrincipalFilter": None}},
    {"ClientAppTypes": ["all"]},
])
def test_unscoped_forms_do_not_narrow(conditions):
    assert narrowed("MS.AAD.3.2v2", policy(builtin=["mfa"], **conditions)) is None


def test_graph_spelling_and_projection_spelling_are_read_alike():
    scoped = policy("Office only", builtin=["mfa"], Locations=NAMED, Platforms={"IncludePlatforms": ["iOS"]})
    assert narrowed("MS.AAD.3.2v2", scoped) == narrowed("MS.AAD.3.2v2", camel(scoped)) == [
        "conditions.locations", "conditions.platforms"]


@pytest.mark.parametrize("policy_id", sorted(BASES))
def test_plain_compliant_policy_is_not_marked_but_each_ignored_scope_is(policy_id):
    assert narrowed(policy_id, base(policy_id)) is None
    assert narrowed(policy_id, base(policy_id, Locations=NAMED)) == ["conditions.locations"]
    assert narrowed(policy_id, base(policy_id, Platforms={"IncludePlatforms": ["iOS"]})) == ["conditions.platforms"]
    assert narrowed(policy_id, base(policy_id, Devices={"DeviceFilter": {"Mode": "include", "Rule": "x"}})) == ["conditions.devices"]
    # A condition the Rego reads is already part of its verdict and is not flagged (the policy still carries what it reads).
    agents = BASES[policy_id].get("ClientApplications", {})
    for group, spec in (("client_applications", {"ClientApplications": {**agents, "IncludeServicePrincipals": ["All"]}}),
                        ("client_app_types", {"ClientAppTypes": ["browser", "other", "exchangeActiveSync", "all"]})):
        expected = None if group not in CARD_IGNORED[policy_id] else [scope_catalogue()["paths"][group]]
        assert narrowed(policy_id, base(policy_id, **spec)) == expected


# --- the grant operator ------------------------------------------------------------------------------------


@pytest.mark.parametrize("policy_id", sorted(BASES))
def test_or_operator_marks_only_the_policies_where_the_rego_ignores_it(policy_id):
    accepted = {"strength": STRENGTH} if "strength" in BASES[policy_id] else {}
    # An OR grant that also offers a control the item does not accept: a user can pass without the required one.
    weakened = base(policy_id, operator="OR", builtin=[*BASES[policy_id].get("builtin", []), "passwordChange"], **accepted)
    expected = ["grantControls.operator"] if policy_id in OPERATOR_IGNORED else None
    assert narrowed(policy_id, weakened) == expected
    # AND demands every control, so it is stricter than the Rego asks, not weaker.
    assert narrowed(policy_id, {**weakened, "GrantControls": {**weakened["GrantControls"], "Operator": "AND"}}) is None


@pytest.mark.parametrize("policy_id", sorted(OPERATOR_IGNORED))
def test_or_without_an_alternative_control_is_not_a_narrowing(policy_id):
    # Graph returns OR for an ordinary single-control policy; the baseline form of MS.AAD.3.8v1 is itself OR of two.
    assert narrowed(policy_id, base(policy_id, operator="OR")) is None


def test_or_with_mfa_and_a_weaker_control_marks_ms_aad_3_2v2_but_mfa_or_strength_does_not():
    assert narrowed("MS.AAD.3.2v2", policy(builtin=["mfa", "compliantApplication"], operator="OR")) == ["grantControls.operator"]
    assert narrowed("MS.AAD.3.2v2", policy(builtin=["mfa"], strength=STRENGTH, operator="OR")) is None


def test_scoped_policy_that_could_not_decide_the_item_is_ignored():
    geo_block = policy("Block outside the UK", builtin=["block"], Locations=NAMED)
    legacy_block = policy("Block legacy", builtin=["block"], ClientAppTypes=["other", "exchangeActiveSync"], Locations=NAMED)
    agent_block = policy("Block risky agents", builtin=["block"], AgentIdRiskLevels="high",
                         ClientApplications={"IncludeAgentIdServicePrincipals": ["All"]})
    mfa_untrusted = policy("MFA outside the office", builtin=["mfa"], Locations=NAMED)
    assert narrowed("MS.AAD.3.2v2", geo_block) is None            # block does not give MFA
    assert narrowed("MS.AAD.2.1v1", geo_block, legacy_block, agent_block) is None   # none carries a high user risk level
    assert narrowed("MS.AAD.3.1v1", mfa_untrusted) is None        # no authentication strength
    assert narrowed("MS.AAD.3.7v1", mfa_untrusted) is None        # no device control
    assert narrowed("MS.AAD.1.1v1", geo_block) is None            # not about legacy client types
    assert narrowed("MS.AAD.1.1v1", legacy_block) == ["conditions.locations"]


def test_post_check_names_are_distinct_sorted_and_bounded():
    entries = scope_entries([policy(name, builtin=["mfa"], Locations=NAMED) for name in ("B", "A", "A", "C")])
    assert post_check("MS.AAD.3.2v2", entries) == {"kind": "scope_narrowed", "policies": ["A", "B", "C"],
                                                   "conditions": ["conditions.locations"], "count": 4}
    assert post_check("MS.AAD.3.2v2", entries, max_items=2)["policies"] == ["A", "B"]
    assert scope_summary(entries, max_items=2) == {"count": 4, "policies": [
        {"name": "A", "conditions": ["conditions.locations"]}, {"name": "B", "conditions": ["conditions.locations"]}]}
    long = scope_entries([policy("x" * 500, builtin=["mfa"], Locations=NAMED), policy(None, builtin=["mfa"], Locations=NAMED)])
    assert sorted(entry.name for entry in long) == ["(unnamed policy)", "x" * 200]


def test_unknown_policy_and_non_candidate_inputs_never_raise():
    assert post_check("MS.AAD.3.3v2", [ScopeEntry("x", frozenset({"locations"}), frozenset())]) is None
    assert scope_entries([None, "text", 3, {}, {"state": "enabled"}, {"state": "enabled", "conditions": "text"}]) == []


# --- the gate: a policy counts only when it carries every check the Rego makes of a deciding policy ---------

USER, APP, ROLE = "5f0c8e2a-7d41-4c36-9b18-2e6a40d1f7b3", "797f4846-ba00-4fd7-ba43-dac1f8f63013", "62e90394-69f5-4237-9190-012177145e10"
REGISTER = "urn:user:registersecurityinfo"
OFFICE_ONLY = {"Locations": NAMED}
WEAKER = {"AllowedCombinations": [*sorted(PHISHING_RESISTANT), "password,sms"]}


def scoped(policy_id, **override):
    """A policy that carries everything the Rego requires of the item, narrowed to one office."""
    return base(policy_id, "Office only", **{**OFFICE_ONLY, **override})


def breakers(policy_id):
    """Overrides that each remove one check the Rego makes of ``policy_id``: the policy could no longer decide it."""
    wrong = {
        "MS.AAD.1.1v1": {"only_other": {"ClientAppTypes": ["other"]}, "only_exchange_activesync": {"ClientAppTypes": ["exchangeActiveSync"]},
                         "no_block": {"builtin": ["mfa"]}},
        "MS.AAD.2.1v1": {"medium_risk": {"UserRiskLevels": ["medium"]}, "no_block": {"builtin": ["mfa"]}},
        "MS.AAD.2.3v1": {"medium_risk": {"SignInRiskLevels": ["medium"]}, "no_block": {"builtin": ["mfa"]}},
        "MS.AAD.3.1v1": {"weaker_strength": {"strength": WEAKER}, "mfa_control_instead": {"strength": None, "builtin": ["mfa"]},
                         "empty_strength": {"strength": {"AllowedCombinations": []}}},
        "MS.AAD.3.2v2": {"no_mfa": {"builtin": []}, "phishing_resistant_only_strength": {"builtin": [], "strength": STRENGTH},
                         "not_an_mfa_strength": {"builtin": [], "strength": {"AllowedCombinations": ["password"]}}},
        "MS.AAD.3.6v1": {"weaker_strength": {"strength": WEAKER}, "mfa_control_instead": {"strength": None, "builtin": ["mfa"]}},
        "MS.AAD.3.7v1": {"only_compliant": {"builtin": ["compliantDevice"]}, "only_domain_joined": {"builtin": ["domainJoinedDevice"]},
                         "third_control": {"builtin": ["compliantDevice", "domainJoinedDevice", "mfa"]},
                         "operator_and": {"operator": "AND"}, "operator_missing": {"operator": None},
                         "user_action_scoped": {"Applications": {"IncludeApplications": ["All"], "IncludeUserActions": [REGISTER]}}},
        "MS.AAD.3.8v1": {"no_user_action": {"Applications": {"IncludeUserActions": []}},
                         "other_user_action": {"Applications": {"IncludeUserActions": ["urn:user:registerdevice"]}},
                         "no_device_control": {"builtin": ["mfa"]}},
        "MS.AAD.3.9v1": {"several_methods": {"AuthenticationFlows": {"TransferMethods": "deviceCodeFlow,authenticationTransfer"}},
                         "other_method": {"AuthenticationFlows": {"TransferMethods": "authenticationTransfer"}},
                         "no_method": {"AuthenticationFlows": {"TransferMethods": None}}, "no_block": {"builtin": ["mfa"]}},
        "MS.AAD.9.1v1": {"not_all_client_types": {"ClientAppTypes": ["browser"]}, "medium_risk": {"AgentIdRiskLevels": "medium"},
                         "some_agents": {"ClientApplications": {"IncludeAgentIdServicePrincipals": ["agent-1"]}},
                         "no_agents": {"ClientApplications": None}, "no_block": {"builtin": ["mfa"]}},
    }[policy_id]
    if policy_id not in {"MS.AAD.3.6v1", "MS.AAD.9.1v1"}:
        wrong["not_all_users"] = {"Users": users(IncludeUsers=[USER])}
    if policy_id != "MS.AAD.3.8v1":
        wrong["not_all_applications"] = {"Applications": {"IncludeApplications": [APP]}}
    if policy_id != "MS.AAD.9.1v1":
        wrong["role_excluded"] = {"Users": users(ExcludeRoles=[ROLE])}
    return wrong


@pytest.mark.parametrize("policy_id", sorted(BASES))
def test_a_policy_missing_one_check_the_rego_makes_is_not_a_candidate(policy_id):
    assert narrowed(policy_id, scoped(policy_id)) == ["conditions.locations"]
    for label, override in breakers(policy_id).items():
        assert narrowed(policy_id, scoped(policy_id, **override)) is None, label


def test_the_reviewed_probes_no_longer_mark_a_row():
    # A role-scoped MFA policy on the browser only does not decide MS.AAD.3.2v2 (it does not include all users).
    role_mfa = policy("Admins on the browser", builtin=["mfa"], ClientAppTypes=["browser"],
                      Users=users(IncludeUsers=[], IncludeRoles=[ROLE]))
    assert narrowed("MS.AAD.3.2v2", role_mfa) is None and scope_summary(scope_entries([role_mfa]))["count"] == 0
    # A guest policy with a weak authentication strength decides neither MS.AAD.3.1v1 nor MS.AAD.3.6v1.
    guests = policy("Guests", strength=WEAKER, Users=users(IncludeUsers=["GuestsOrExternalUsers"]), Locations=NAMED)
    assert narrowed("MS.AAD.3.1v1", guests) is None and narrowed("MS.AAD.3.6v1", guests) is None
    # A policy that blocks only the "other" legacy client type does not decide MS.AAD.1.1v1.
    other_only = policy("Block other clients", builtin=["block"], ClientAppTypes=["other"], Locations=NAMED)
    assert narrowed("MS.AAD.1.1v1", other_only) is None


@pytest.mark.parametrize("policy_id", sorted(BASES))
def test_checks_the_rego_does_not_make_never_drop_the_deciding_policy(policy_id):
    """Whatever the Rego accepts stays a candidate: exclusions (its allow-list is not in the evidence) and the unread fields."""
    apps = {**BASES[policy_id].get("Applications", {"IncludeApplications": ["All"]}), "ExcludeApplications": [APP]}
    excluding = {"Users": users(ExcludeUsers=[USER], ExcludeGroups=[ROLE], ExcludeGuestsOrExternalUsers={"GuestOrExternalUserTypes": "internalGuest"}),
                 "Applications": apps}
    assert narrowed(policy_id, scoped(policy_id, **excluding)) == ["conditions.locations"]


def test_fields_a_policys_rego_skips_do_not_gate_it():
    # MS.AAD.3.6v1 is role based (l612 skips includeUsers); MS.AAD.3.8v1 skips the applications (l773);
    # MS.AAD.9.1v1 reads neither the users nor the excluded roles (l1948-1962) and never reads excluded agents.
    assert narrowed("MS.AAD.3.6v1", scoped("MS.AAD.3.6v1", Users=users(IncludeUsers=[], IncludeRoles=[ROLE]))) == ["conditions.locations"]
    assert narrowed("MS.AAD.3.8v1", scoped("MS.AAD.3.8v1", Applications={"IncludeApplications": [APP], "IncludeUserActions": [REGISTER]})) == [
        "conditions.locations"]
    agents = {"IncludeAgentIdServicePrincipals": ["All"], "ExcludeAgentIdServicePrincipals": ["agent-1"]}
    assert narrowed("MS.AAD.9.1v1", scoped("MS.AAD.9.1v1", Users=users(IncludeUsers=[USER], ExcludeRoles=[ROLE]),
                                           ClientApplications=agents)) == ["conditions.locations"]


@pytest.mark.parametrize("combinations,expected", [
    (["fido2"], "phishingResistant"), (["x509CertificateMultiFactor", "windowsHelloForBusiness", "fido2"], "phishingResistant"),
    (sorted(PHISHING_RESISTANT) + ["password,sms"], "generalMfa"), (["password,microsoftAuthenticatorPush"], "generalMfa"),
    (["password"], "other"), ([], "other"), (None, "other"), (["password,sms", "unlisted"], "other"),
])
def test_authentication_strength_is_classed_as_the_rego_reads_it(combinations, expected):
    strength = {"Id": "s", "DisplayName": "Phishing-resistant MFA", "AllowedCombinations": combinations}
    for spelling in (strength, camel(strength)):
        (entry,) = scope_entries([policy(builtin=["mfa"], strength=spelling)])
        assert {token for token in entry.tokens if token.startswith("grantControls.authenticationStrength=")} == {
            f"grantControls.authenticationStrength={expected}"}


def test_retained_entries_keep_no_identifier_and_only_candidates_are_retained():
    (entry,) = scope_entries([policy("Kept", builtin=["mfa"], Users=users(ExcludeUsers=[USER], ExcludeGroups=[ROLE]),
                                     Applications={"IncludeApplications": [APP, "All"]}),
                              policy("Not a candidate", builtin=["passwordChange"], Locations=NAMED)])
    assert entry.name == "Kept" and entry.groups == frozenset()
    assert not any(USER in token or ROLE in token or APP in token for token in entry.tokens)
    assert {"conditions.users.excludeUsers#1", "conditions.users.excludeGroups#1", "conditions.applications.includeApplications=All"} <= entry.tokens


# --- a compliant unscoped candidate decides the item everywhere: the scoped one is left to the envelope ------


@pytest.mark.parametrize("policy_id", sorted(BASES))
def test_a_compliant_unscoped_candidate_leaves_the_row_unmarked(policy_id):
    unscoped = base(policy_id, "Everywhere")
    assert narrowed(policy_id, scoped(policy_id), unscoped) is None
    assert narrowed(policy_id, unscoped, scoped(policy_id)) is None
    # The scoped policy is still named by the envelope list, whatever the verdicts.
    assert scope_summary(scope_entries([scoped(policy_id), unscoped])) == {
        "count": 1, "policies": [{"name": "Office only", "conditions": ["conditions.locations"]}]}


@pytest.mark.parametrize("policy_id", sorted(BASES))
def test_an_unscoped_candidate_the_rego_could_refuse_does_not_suppress_the_mark(policy_id):
    # An exclusion needs an allow-list entry in the ScubaGear config, which is not in the evidence: err towards flagging.
    for excluded in (users(ExcludeUsers=[USER]), users(ExcludeGroups=[ROLE]),
                     users(ExcludeGuestsOrExternalUsers={"GuestOrExternalUserTypes": "internalGuest"})):
        assert narrowed(policy_id, scoped(policy_id), base(policy_id, "Excluding", Users=excluded)) == ["conditions.locations"]
    apps = {**BASES[policy_id].get("Applications", {"IncludeApplications": ["All"]}), "ExcludeApplications": [APP]}
    assert narrowed(policy_id, scoped(policy_id), base(policy_id, "Excluding", Applications=apps)) == ["conditions.locations"]


def test_an_unscoped_policy_that_could_not_decide_the_item_does_not_suppress_the_mark():
    narrowed_mfa = policy("Office only", builtin=["mfa"], Locations=NAMED)
    # All users, every application, but a phishing-resistant-only strength: the Rego does not count it as general MFA.
    resistant_only = policy("Phishing-resistant for everyone", strength=STRENGTH)
    admins_only = policy("Admins", builtin=["mfa"], Users=users(IncludeUsers=[], IncludeRoles=[ROLE]))
    assert narrowed("MS.AAD.3.2v2", narrowed_mfa, resistant_only, admins_only) == ["conditions.locations"]


def test_a_met_row_with_a_scoped_and_an_unscoped_candidate_is_not_marked_but_the_envelope_names_the_scope(tmp_path, monkeypatch):
    result, row, _ = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2", [
        policy("Office only", builtin=["mfa"], Locations=NAMED), policy("Everywhere", builtin=["mfa"])])
    assert "post_check" not in row and row["limitations"] == [] and row["claims"][0]["value"] is True
    assert result["totals"]["scope_narrowed"] == 0
    assert result["scope_post_check"]["policies"] == [{"name": "Office only", "conditions": ["conditions.locations"]}]


# --- the envelope record lists a condition only for an item that ignores it ----------------------------------


def summary(*policies):
    return scope_summary(scope_entries(policies))


def test_envelope_does_not_list_compliant_policies_on_conditions_the_rego_reads():
    legacy = policy("Block legacy authentication", builtin=["block"], ClientAppTypes=["exchangeActiveSync", "other"])
    agents = policy("Block risky agents", builtin=["block"], AgentIdRiskLevels="high",
                    ClientApplications={"IncludeAgentIdServicePrincipals": ["All"]})
    some_agents = policy("Block named agents", builtin=["block"], AgentIdRiskLevels="high",
                         ClientApplications={"IncludeAgentIdServicePrincipals": ["agent-1"]})
    assert summary(legacy, agents, some_agents) == {"count": 0, "policies": []}
    # A location on those policies is a narrowing the Rego ignores, and is the only condition listed.
    assert summary(scoped_like(legacy), scoped_like(agents)) == {"count": 2, "policies": [
        {"name": "Block legacy authentication", "conditions": ["conditions.locations"]},
        {"name": "Block risky agents", "conditions": ["conditions.locations"]}]}


def scoped_like(source):
    return {**source, "Conditions": {**source["Conditions"], **OFFICE_ONLY}}


def test_envelope_lists_a_client_type_set_when_another_item_the_policy_could_decide_ignores_it():
    risky_legacy = policy("Risky legacy", builtin=["block"], UserRiskLevels=["high"], ClientAppTypes=["other", "exchangeActiveSync"])
    assert summary(risky_legacy) == {"count": 1, "policies": [{"name": "Risky legacy", "conditions": ["conditions.clientAppTypes"]}]}


def test_agents_all_with_nothing_excluded_is_unscoped_and_an_excluded_agent_is_not():
    every_agent = {"IncludeAgentIdServicePrincipals": ["All"]}
    assert summary(policy("Risky users", builtin=["block"], UserRiskLevels=["high"], ClientApplications=every_agent))["count"] == 0
    assert summary(policy("Risky users", builtin=["block"], UserRiskLevels=["high"], ClientApplications={
        **every_agent, "ExcludeAgentIdServicePrincipals": ["agent-1"]}))["policies"] == [
        {"name": "Risky users", "conditions": ["conditions.clientApplications"]}]
    assert summary(policy("Risky users", builtin=["block"], UserRiskLevels=["high"], ClientApplications={
        **every_agent, "IncludeServicePrincipals": ["ServicePrincipalsInMyTenant"]}))["count"] == 1


@pytest.mark.parametrize("condition", [
    {"Locations": {"IncludeLocations": None, "ExcludeLocations": None}}, {"Locations": {"IncludeLocations": [], "ExcludeLocations": []}},
    {"Locations": {}}, {"Platforms": {"IncludePlatforms": None, "ExcludePlatforms": None}},
    {"Platforms": {"IncludePlatforms": [], "ExcludePlatforms": []}}, {"Platforms": {}},
])
def test_an_empty_location_or_platform_condition_is_unscoped(condition):
    (entry,) = scope_entries([policy(builtin=["mfa"], **condition)])
    assert entry.groups == frozenset()


@pytest.mark.parametrize("condition,group", [
    ({"Locations": {"IncludeLocations": [], "ExcludeLocations": ["AllTrusted"]}}, "locations"),
    ({"Locations": {"IncludeLocations": None, "ExcludeLocations": [LOCATION]}}, "locations"),
    ({"Platforms": {"IncludePlatforms": [], "ExcludePlatforms": ["iOS"]}}, "platforms"),
])
def test_an_empty_include_with_an_exclusion_still_narrows(condition, group):
    (entry,) = scope_entries([policy(builtin=["mfa"], **condition)])
    assert entry.groups == frozenset({group})


def test_names_are_masked_before_they_are_cut():
    name = "x" * 190 + " person@example.invalid"
    (entry,) = scope_entries([policy(name, builtin=["mfa"])], mask=lambda text: text.replace("person@", "***@"))
    assert entry.name == ("x" * 190 + " ***@example.invalid")[:200] and "person" not in entry.name
    # Without a mask the name is cut as before.
    assert scope_entries([policy(name, builtin=["mfa"])])[0].name == name[:200]


# --- the envelope list from the raw payload when the projection withholds the section ----------------------


def write_raw(root, policies, *, manifest=None, **metadata):
    (root / "raw").mkdir(parents=True, exist_ok=True)
    (root / "run-manifest.json").write_text(json.dumps(manifest or {"run_id": "run", "platform": "m365"}))
    (root / "raw/conditional_access.json").write_text(json.dumps(
        {"conditionalAccessPolicies": {"value": camel(policies), "status": "ok", **metadata}}))


def assess_raw(root, monkeypatch, **kwargs):
    monkeypatch.setattr(ModelClient, "_request", lambda *args: pytest.fail("No section is projected, so no model call"))
    result = assess_run(root, ModelConfig(model_name="stub"), policies=["MS.AAD.3.2v2"], **kwargs)
    validate_assessment(result)
    jsonschema.validate(result, SCHEMA)
    return result


def test_withheld_section_still_yields_the_envelope_list_from_the_raw_payload(tmp_path, monkeypatch):
    write_raw(tmp_path, [
        policy("Office only", builtin=["mfa"], Locations=NAMED),
        policy("Mobile only", builtin=["mfa"], Platforms={"IncludePlatforms": ["iOS"]}, Devices={"DeviceFilter": {"Mode": "include", "Rule": "x"}}),
        policy("Report only", state="enabledForReportingButNotEnforced", builtin=["mfa"], Locations=NAMED),
        policy("Everywhere", builtin=["mfa"], Locations={"IncludeLocations": ["All"], "ExcludeLocations": []}),
        policy("Disabled", state="disabled", builtin=["mfa"], Locations=NAMED)])
    result = assess_raw(tmp_path, monkeypatch)
    section = result["projection"]["sections"][CA]
    assert section["status"] == "not_collected" and section["reason"] == "incomplete_shape"
    assert section["unsupported_conditions"] == ["conditions.devices", "conditions.locations", "conditions.platforms"]
    assert result["scope_post_check"] == {"status": "evaluated", "source": "raw", "reason": None, "count": 2, "policies": [
        {"name": "Mobile only", "conditions": ["conditions.devices", "conditions.platforms"]},
        {"name": "Office only", "conditions": ["conditions.locations"]}]}
    # The unavailable section keeps every dependent verdict unknown, so no row is marked.
    assert result["totals"]["scope_narrowed"] == 0 and "post_check" not in result["policies"][0]
    assert next(c for c in result["policies"][0]["claims"] if c["id"] == "requirement_met")["status"] == "unknown"


def test_raw_payload_with_nothing_scoped_lists_nothing(tmp_path, monkeypatch):
    write_raw(tmp_path, [policy("Require MFA", builtin=["mfa"])])
    result = assess_raw(tmp_path, monkeypatch)
    assert result["scope_post_check"] == {"status": "evaluated", "source": "raw", "reason": None,
                                          "count": 0, "policies": []}


@pytest.mark.parametrize("case,reason", [
    ("missing", "missing_artifact"), ("error", "incomplete_shape"), ("platform", "not_applicable_to_platform"),
    ("rows", "oversize"), ("entries", "oversize"),
])
def test_raw_evidence_that_cannot_be_read_is_not_evaluated_with_a_reason(tmp_path, monkeypatch, case, reason):
    scoped = [policy("One", builtin=["mfa"], Locations=NAMED), policy("Two", builtin=["mfa"], Locations=NAMED)]
    options = {}
    if case == "missing":
        (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    elif case == "error":
        write_raw(tmp_path, scoped, error="Forbidden")
    elif case == "platform":
        write_raw(tmp_path, scoped, manifest={"run_id": "run", "platform": "google_workspace"})
    else:
        write_raw(tmp_path, scoped)
        if case == "rows":
            options["projection_scan_max_rows"] = 1
        else:
            monkeypatch.setattr("azure_tenant_audit.scuba_scope.MAX_ENTRIES", 1)
    result = assess_raw(tmp_path, monkeypatch, **options)
    assert result["scope_post_check"] == {"status": "not_evaluated", "source": None, "reason": reason,
                                          "count": 0, "policies": []}
    assert result["totals"]["scope_narrowed"] == 0


@pytest.mark.parametrize("no_redaction,expected", [(False, "Office of ***@example.invalid"),
                                                    (True, "Office of person@example.invalid")])
def test_raw_names_mask_email_local_parts_unless_redaction_is_off(tmp_path, monkeypatch, no_redaction, expected):
    write_raw(tmp_path, [policy("Office of person@example.invalid", builtin=["mfa"], Locations=NAMED)])
    result = assess_raw(tmp_path, monkeypatch, no_redaction=no_redaction)
    assert result["scope_post_check"]["policies"][0]["name"] == expected


@pytest.mark.parametrize("no_redaction", [False, True])
def test_raw_names_are_masked_before_they_are_cut_to_the_name_limit(tmp_path, monkeypatch, no_redaction):
    # A cut at 200 characters falls inside the domain: cutting first would leave "person@exam" unmasked.
    name = "x" * 190 + " person@example.invalid"
    write_raw(tmp_path, [policy(name, builtin=["mfa"], Locations=NAMED)])
    listed = assess_raw(tmp_path, monkeypatch, no_redaction=no_redaction)["scope_post_check"]["policies"][0]["name"]
    assert len(listed) == 200
    assert listed == (name[:200] if no_redaction else ("x" * 190 + " ***@example.invalid")[:200])
    assert no_redaction or "person" not in listed


def test_dry_run_reads_no_scope_evidence(tmp_path, monkeypatch):
    write_raw(tmp_path, [policy("Office only", builtin=["mfa"], Locations=NAMED)])
    monkeypatch.setattr("auditex.model_serving.collect_scope_evidence", lambda *a, **k: pytest.fail("dry run reads no scope"))
    assert assess_run(tmp_path, ModelConfig(), dry_run=True, policies=["MS.AAD.3.2v2"])["dry_run"] is True


def test_envelope_and_row_lists_are_bounded_by_the_projection_item_budget(tmp_path, monkeypatch):
    scoped = [policy(f"Office {name}", builtin=["mfa"], Locations=NAMED) for name in "CBA"]
    result, row, _ = assess(tmp_path, monkeypatch, "MS.AAD.3.2v2", scoped, projection_max_items=2)
    assert row["post_check"]["policies"] == ["Office A", "Office B"] and row["post_check"]["count"] == 3
    assert [item["name"] for item in result["scope_post_check"]["policies"]] == ["Office A", "Office B"]
    assert result["scope_post_check"]["count"] == 3


# --- schema and validators ---------------------------------------------------------------------------------


def reassign(row, policy_id, conditions):
    """Move a marked row to another policy, keeping its criticality claim valid for that policy."""
    row["policy_id"] = policy_id
    row["claims"][1]["value"] = policy_catalogue()["policies"][policy_id]["policy_item"]["criticality"]
    row["post_check"]["conditions"] = conditions


MUTATIONS = {
    # name: (mutation of a valid marked result, structural: the JSON schema rejects it too)
    "kind": (lambda r: r["policies"][0]["post_check"].update(kind="other"), True),
    "extra_field": (lambda r: r["policies"][0]["post_check"].update(extra=1), True),
    "empty_conditions": (lambda r: r["policies"][0]["post_check"].update(conditions=[]), True),
    "unknown_condition": (lambda r: r["policies"][0]["post_check"].update(conditions=["conditions.users"]), True),
    "empty_policies": (lambda r: r["policies"][0]["post_check"].update(policies=[]), True),
    "zero_count": (lambda r: r["policies"][0]["post_check"].update(count=0), True),
    "missing_count": (lambda r: r["policies"][0]["post_check"].pop("count"), True),
    "unknown_total": (lambda r: r["totals"].update(other=1), True),
    "unknown_reason": (lambda r: r["scope_post_check"].update(reason="stale"), True),
    "record_extra_field": (lambda r: r["scope_post_check"].update(extra=1), True),
    "record_bad_condition": (lambda r: r["scope_post_check"]["policies"][0].update(conditions=["grantControls.operator"]), True),
    "limitation_vocabulary": (lambda r: r["policies"][0]["limitations"].append("scope_narrowed_somewhere"), True),
    "limitation_removed": (lambda r: r["policies"][0]["limitations"].remove("scope_narrowed"), False),
    "limitation_without_post_check": (lambda r: r["policies"][0].pop("post_check"), False),
    "count_below_listed": (lambda r: r["policies"][0]["post_check"].update(policies=["A", "B"], count=1), False),
    "unsorted_policies": (lambda r: r["policies"][0]["post_check"].update(policies=["B", "A"], count=2), False),
    "name_too_long": (lambda r: r["policies"][0]["post_check"].update(policies=["x" * 201]), False),
    "not_applicable_answer": (lambda r: r["policies"][0]["limitations"].insert(0, "policy_not_applicable"), False),
    "policy_not_in_table": (lambda r: reassign(r["policies"][0], "MS.AAD.3.3v2", ["conditions.locations"]), False),
    "operator_where_rego_reads_it": (lambda r: reassign(r["policies"][0], "MS.AAD.3.7v1", ["grantControls.operator"]), False),
    "client_applications_where_rego_reads_them": (
        lambda r: reassign(r["policies"][0], "MS.AAD.9.1v1", ["conditions.clientApplications"]), False),
    "total_too_low": (lambda r: r["totals"].update(scope_narrowed=0), False),
    "total_too_high": (lambda r: r["totals"].update(scope_narrowed=2), False),
    "total_missing": (lambda r: r["totals"].pop("scope_narrowed"), False),
    "record_missing": (lambda r: r.pop("scope_post_check"), False),
    "record_not_evaluated": (lambda r: r["scope_post_check"].update(
        status="not_evaluated", source=None, reason="missing_artifact", count=0, policies=[]), False),
    "record_source_disagrees_with_projection": (lambda r: r["scope_post_check"].update(source="raw"), False),
    "record_evaluated_without_source": (lambda r: r["scope_post_check"].update(source=None), False),
    "record_count_below_listed": (lambda r: r["scope_post_check"].update(count=0), False),
    "record_unsorted_names": (lambda r: r["scope_post_check"].update(count=2, policies=[
        {"name": "B", "conditions": ["conditions.locations"]}, {"name": "A", "conditions": ["conditions.locations"]}]), False),
    "record_unsorted_conditions": (lambda r: r["scope_post_check"]["policies"][0].update(
        conditions=["conditions.platforms", "conditions.locations"]), False),
}


def test_schema_and_validators_accept_the_marked_result(marked):
    validate_assessment(marked)
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    jsonschema.validate(marked, SCHEMA)
    assert marked["schema_version"] == "2026-11-05" and marked["projection"]["schema_version"] == "2026-10-29"


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_both_validators_reject_malformed_scope_fields(marked, name):
    mutate, structural = MUTATIONS[name]
    broken = deepcopy(marked)
    mutate(broken)
    with pytest.raises(ValueError):
        validate_assessment(broken)
    if structural:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(broken, SCHEMA)


def test_assessments_written_before_the_post_check_still_validate(marked):
    legacy = deepcopy(marked)
    for row in legacy["policies"]:
        row.pop("post_check", None)
        row["limitations"] = [item for item in row["limitations"] if item != LIMITATION_ID]
    del legacy["scope_post_check"], legacy["totals"]["scope_narrowed"]
    validate_assessment(legacy)
    jsonschema.validate(legacy, SCHEMA)


def test_scope_limitation_is_a_row_extension_not_a_shadow_or_catalogue_one():
    row_pattern = SCHEMA["$defs"]["policy"]["properties"]["limitations"]["items"]["pattern"]
    shadow_pattern = SCHEMA["$defs"]["model_shadow"]["properties"]["limitations"]["items"]["pattern"]
    assert re.search(row_pattern, LIMITATION_ID) and not re.search(row_pattern, "scope_narrowed_x")
    assert not re.search(shadow_pattern, LIMITATION_ID)
    assert LIMITATION_ID not in policy_catalogue()["limitation_ids"]


# --- the table ---------------------------------------------------------------------------------------------


def test_scope_table_mirrors_the_v9_dataset_card_and_the_policy_catalogue():
    table = scope_catalogue()
    assert {pid: set(rule["ignored"]) for pid, rule in table["policies"].items()} == CARD_IGNORED
    assert {pid for pid, rule in table["policies"].items() if rule["operator"]} == OPERATOR_IGNORED
    catalogue = policy_catalogue()["policies"]
    assert all(CA in catalogue[pid]["sections"] for pid in table["policies"])
    # MS.AAD.3.3v2 reads Conditional Access only for applicability and has no measured blind spot.
    assert {pid for pid, entry in catalogue.items() if CA in entry["sections"]} - set(table["policies"]) == {"MS.AAD.3.3v2"}
    strength = table["authentication_strength"]
    known = {*table["tracked"], *table["members"], *table["exact"], *table["counted"], strength["path"]}
    for rule in table["policies"].values():
        assert rule["grants"] and all(token.startswith("grantControls.") for token in rule["grants"])
        assert all(re.split("[=#]", token)[0] in known for token in [*rule["grants"], *rule["alongside"]])
        assert all(re.split("[=#]", token)[0] in known for group in rule["requires"] for token in group)
    assert set(table["paths"]) == EVERY_GROUP | {"operator"}
    assert set(table["exclusions"]) <= set(table["counted"]) and set(table["controls"]) >= {strength["path"]}
    assert set(strength["phishing_resistant"]) == PHISHING_RESISTANT < set(strength["mfa_combinations"])
    assert len(strength["mfa_combinations"]) == 17


# What the pinned AADConfig.rego requires of a deciding policy, restated from its BaseCheck functions (line ranges
# cited in the table's source text), so that an edit of the table cannot weaken the gate without failing here.
USERS_ALL, APPS_ALL = ["conditions.users.includeUsers=All"], ["conditions.applications.includeApplications=All"]
NO_ROLE_EXCLUDED = ["conditions.users.excludeRoles#0"]
COMMON = [USERS_ALL, APPS_ALL, NO_ROLE_EXCLUDED]
REGO = {
    "MS.AAD.1.1v1": ("l50-62", COMMON + [["conditions.clientAppTypes=other"], ["conditions.clientAppTypes=exchangeActiveSync"]],
                     ["grantControls.builtInControls=block"]),
    "MS.AAD.2.1v1": ("l133-144", COMMON + [["conditions.userRiskLevels=high"]], ["grantControls.builtInControls=block"]),
    "MS.AAD.2.3v1": ("l231-242", COMMON + [["conditions.signInRiskLevels=high"]], ["grantControls.builtInControls=block"]),
    "MS.AAD.3.1v1": ("l319-329", COMMON, ["grantControls.authenticationStrength=phishingResistant"]),
    "MS.AAD.3.2v2": ("l396-406", COMMON, ["grantControls.authenticationStrength=generalMfa", "grantControls.builtInControls=mfa"]),
    "MS.AAD.3.6v1": ("l610-622", [APPS_ALL, NO_ROLE_EXCLUDED], ["grantControls.authenticationStrength=phishingResistant"]),
    "MS.AAD.3.7v1": ("l689-705", COMMON + [["grantControls.builtInControls=compliantDevice"],
                                           ["grantControls.builtInControls=domainJoinedDevice"],
                                           ["grantControls.builtInControls#2"], ["grantControls.operator=OR"],
                                           ["conditions.applications.includeUserActions#0"]],
                     ["grantControls.builtInControls=compliantDevice", "grantControls.builtInControls=domainJoinedDevice"]),
    "MS.AAD.3.8v1": ("l771-787", [USERS_ALL, NO_ROLE_EXCLUDED, ["conditions.applications.includeUserActions=urn:user:registersecurityinfo"]],
                     ["grantControls.builtInControls=compliantDevice", "grantControls.builtInControls=domainJoinedDevice"]),
    "MS.AAD.3.9v1": ("l852-863", COMMON + [["conditions.authenticationFlows.transferMethods=deviceCodeFlow"]],
                     ["grantControls.builtInControls=block"]),
    "MS.AAD.9.1v1": ("l1948-1962", [APPS_ALL, ["conditions.clientAppTypes=all"], ["conditions.agentIdRiskLevels=high"],
                                    ["conditions.clientApplications.includeAgentIdServicePrincipals=All"]],
                     ["grantControls.builtInControls=block"]),
}


@pytest.mark.parametrize("policy_id", sorted(REGO))
def test_requires_table_restates_every_check_the_rego_makes_and_cites_its_lines(policy_id):
    lines, requires, grants = REGO[policy_id]
    rule = scope_catalogue()["policies"][policy_id]
    assert sorted(map(sorted, rule["requires"])) == sorted(map(sorted, requires))
    assert sorted(rule["grants"]) == sorted(grants)
    assert f"{policy_id} {lines}:" in scope_catalogue()["source"]


def test_scope_table_cites_the_rego_files_and_lists_every_policy():
    table = scope_catalogue()
    assert set(REGO) == set(table["policies"])
    assert "AADConfig.rego" in table["source"] and "Utils/AAD.rego" in table["source"]
    assert all(lines in table["source"] for lines in ("l190-196", "l200-236", "l107-181"))
