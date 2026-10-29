"""v9 generators (enum sweeps, Conditional Access shapes) are deterministic, leave their inputs alone, agree with the pinned Rego and keep new rows out of test."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from collections import Counter
from pathlib import Path

import pytest

from auditex.model_training import distinct_prompt_sha256, validate_case, validate_cases
from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS

ROOT = Path(__file__).resolve().parents[1]
SPO_BASE = {"DefaultLinkPermission": 1, "DefaultSharingLinkType": 1, "EmailAttestationReAuthDays": 30, "EmailAttestationRequired": True,
            "FileAnonymousLinkType": 1, "FolderAnonymousLinkType": 1, "ODBSharingCapability": 0, "RequireAnonymousLinksExpireInDays": 30,
            "SharingCapability": 0, "SharingDomainRestrictionMode": 0}
SHAREPOINT = ["MS.SHAREPOINT.1.1v1", "MS.SHAREPOINT.1.2v1", "MS.SHAREPOINT.1.3v1", "MS.SHAREPOINT.2.1v1", "MS.SHAREPOINT.2.2v1",
              "MS.SHAREPOINT.3.1v1", "MS.SHAREPOINT.3.2v1", "MS.SHAREPOINT.3.3v2"]
AUTHORIZATION = {"AllowInvitesFrom": "adminsAndGuestInviters", "DefaultUserRolePermissions": {"AllowedToCreateApps": False},
                 "GuestUserRoleId": "2af84b1e-32c8-42b7-82bc-daa82404023b", "Id": "authorizationPolicy",  # gitleaks:allow
                 "PermissionGrantPolicyIdsAssignedToDefaultUserRole": []}


@pytest.fixture(scope="module")
def miner():
    path = ROOT / "scripts/build-oracle-cases.py"
    spec = importlib.util.spec_from_file_location("oracle_v9", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _spo_harvest():
    harvested = [{"name": "base", "input": {"SPO_tenant": [dict(SPO_BASE)]}}]
    for index, capability in enumerate((3, 1, 2), 1):
        harvested.append({"name": f"sharing-{capability}", "input": {"SPO_tenant": [{**SPO_BASE, "SharingCapability": capability}]}})
    harvested.append({"name": "polluted", "input": {"SPO_tenant": [{**SPO_BASE, "SharingCapability": 2, "RequireAnonymousLinksExpireInDays": 31}]}})
    harvested.append({"name": "missing-key", "input": {"SPO_tenant": [{k: v for k, v in SPO_BASE.items() if k != "SharingCapability"}]}})
    harvested.append({"name": "other-section", "input": {"SPO_tenant": [dict(SPO_BASE)], "unrelated": [1]}})
    return harvested


def _auth_harvest():
    def tenant(**changes):
        policy = {**AUTHORIZATION, **changes}
        return {"authorization_policies": [policy], "risky_delegated_permission_classifications": []}
    return [{"name": "base", "input": tenant()},
            {"name": "create-apps", "input": tenant(DefaultUserRolePermissions={"AllowedToCreateApps": True})},
            {"name": "no-grants", "input": tenant(PermissionGrantPolicyIdsAssignedToDefaultUserRole=["ManagePermissionGrantsForSelf.x"])},
            {"name": "guest-differs", "input": tenant(GuestUserRoleId="a0b1b346-4d3e-4e8b-98f8-753987be4970")}]  # gitleaks:allow


def test_enum_domains_follow_the_annotator_and_the_brief(miner):
    domains = {(d["section"], d["field"]): d for d in miner.v9_enum_domains()}
    for field in ("DefaultSharingLinkType", "DefaultLinkPermission", "FileAnonymousLinkType", "FolderAnonymousLinkType",
                  "SharingDomainRestrictionMode", "ODBSharingCapability"):
        assert domains["SPO_tenant", field]["values"] == sorted(ENUM_NAME_KEYS[field])
    assert {1, 2, 3} <= set(domains["SPO_tenant", "DefaultSharingLinkType"]["values"])
    assert {1, 2} <= set(domains["SPO_tenant", "DefaultLinkPermission"]["values"])
    assert {0, 1} <= set(domains["SPO_tenant", "SharingDomainRestrictionMode"]["values"])
    assert domains["authorization_policies", "AllowInvitesFrom"]["values"] == [
        "none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "everyone"]
    assert len(domains["authorization_policies", "GuestUserRoleId"]["values"]) == 3
    assert all(d["readers"] for d in domains.values())
    assert "SharingCapability" not in {field for _, field in domains}   # swept by the gate table (v8 gate_sweep)


def test_spo_enum_sweep_covers_each_value_on_each_clean_base_without_mutation(miner):
    harvested = _spo_harvest()
    before = copy.deepcopy(harvested)
    sections = {pid: ["SPO_tenant"] for pid in SHAREPOINT}
    variants = miner.v9_enum_variants("Sharepoint", harvested, sections)
    assert harvested == before
    domains = [d for d in miner.v9_enum_domains() if d["product"] == "Sharepoint"]
    bases = {name for name in ("base", "sharing-3", "sharing-1", "sharing-2")}
    assert len(variants) == len(bases) * sum(len(d["values"]) for d in domains)
    for domain in domains:
        for value in domain["values"]:
            selected = [v for v in variants if v["template_prefix"].startswith(f"v9:enum_sweep:{domain['field']}={value}:b")]
            assert len(selected) == len(bases)   # the polluted, incomplete and extra-section tenants are no clean base
            assert {v["name"].rsplit("base=", 1)[1] for v in selected} == bases
            for variant in selected:
                assert variant["input"]["SPO_tenant"][0][domain["field"]] == value
                assert set(domain["readers"]) <= set(variant["policies"])
            for pid in set(SHAREPOINT) - set(domain["readers"]):
                assert sum(pid in v["policies"] for v in selected) == 1   # exactly one bystander base per policy and value
    assert all(v["split"] == "train" and "base" in v and v["template_prefix"].startswith("v9:enum_sweep:") for v in variants)
    assert variants == miner.v9_enum_variants("Sharepoint", copy.deepcopy(harvested), sections)
    assert miner.v9_enum_variants("EXO", harvested, sections) == []


def test_enum_edit_drops_the_derived_name_and_leaves_other_fields(miner):
    tenant = {"SPO_tenant": [{**SPO_BASE, "DefaultSharingLinkType_name": "direct"}], "keep": [1]}
    edited = miner._v9_set_field(tenant, "SPO_tenant", "DefaultSharingLinkType", 3)
    assert edited["SPO_tenant"] == [{**SPO_BASE, "DefaultSharingLinkType": 3}] and edited["keep"] == [1]
    assert tenant["SPO_tenant"][0]["DefaultSharingLinkType_name"] == "direct"


def test_authorization_sweep_uses_the_two_fields_and_two_bystander_bases(miner):
    sections = {"MS.AAD.5.1v1": ["authorization_policies"], "MS.AAD.5.2v1": ["authorization_policies", "risky_delegated_permission_classifications"],
                "MS.AAD.8.1v1": ["authorization_policies"], "MS.AAD.8.2v1": ["authorization_policies"], "MS.AAD.3.1v1": ["conditional_access_policies"]}
    variants = miner.v9_enum_variants("AAD", _auth_harvest(), sections)
    invites = [v for v in variants if "AllowInvitesFrom=" in v["template_prefix"]]
    roles = [v for v in variants if "GuestUserRoleId=" in v["template_prefix"]]
    assert len(invites) == 3 * 4 and len(roles) == 3 * 3   # the base whose guest role differs is no clean base
    assert all("MS.AAD.8.2v1" in v["policies"] for v in invites) and all("MS.AAD.8.1v1" in v["policies"] for v in roles)
    assert all("MS.AAD.3.1v1" not in v["policies"] for v in variants)   # it does not show the section
    for pid in ("MS.AAD.5.1v1", "MS.AAD.5.2v1", "MS.AAD.8.1v1"):
        assert sum(pid in v["policies"] for v in invites if "=everyone" in v["template_prefix"]) == 2
    assert {v["input"]["authorization_policies"][0]["AllowInvitesFrom"] for v in invites} == set(miner.V9_INVITE_VALUES)


def test_strength_objects_carry_the_graph_keys_and_only_built_ins_borrow_a_built_in_name(miner):
    keys = {"Id", "DisplayName", "PolicyType", "RequirementsSatisfied", "AllowedCombinations"}
    for combination, combinations in miner.V9_STRENGTHS.items():
        flavours = miner.v9_strength_flavours(combination)
        assert len(flavours) == 2 and flavours == miner.v9_strength_flavours(combination)
        for flavour in flavours:
            strength = miner.v9_strength_object(combination, flavour)
            assert set(strength) == keys
            assert strength["AllowedCombinations"] == combinations and strength["PolicyType"] in {"builtIn", "custom"}
            assert strength["RequirementsSatisfied"] in {"mfa", "none"}
            assert (strength["PolicyType"] == "builtIn") == (flavour == "builtin")
    assert {c for c in miner.V9_STRENGTHS if "builtin" in miner.v9_strength_flavours(c)} == set(miner.V9_BUILTIN_STRENGTHS)
    assert miner.v9_strength_object("phishing_resistant", "builtin")["Id"] == "00000000-0000-0000-0000-000000000004"
    lookalike = miner.v9_strength_object("password_only", "lookalike")
    assert lookalike["DisplayName"] == "Phishing-resistant MFA" and lookalike["PolicyType"] == "custom"
    assert miner.v9_strength_object("fido2_only", "custom_none")["RequirementsSatisfied"] == "none"
    assert miner.v9_strength_object("null", "custom_mfa")["AllowedCombinations"] is None
    assert miner.v9_strength_object("fido2_only", "custom_mfa")["Id"] != miner.v9_strength_object("fido2_only", "custom_none")["Id"]
    # a built-in strength's combinations are the documented ones
    assert miner.V9_STRENGTHS["phishing_resistant"] == ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]


def _ca_base():
    return {"conditional_access_policies": [], "scuba_config": {"CapExclusions": {"Applications": [], "Groups": [], "GuestUserTypes": [], "Users": []},
                                                                  "RoleExclusions": {"Groups": [], "Users": []}},
            "service_plans": [{"ServicePlanId": "c7d91867-e1ce-4402-8d4f-22188b44b6c2", "ServicePlanName": "AAD_PREMIUM_P2"}],
            "privileged_roles": [{"RoleTemplateId": "Role1"}, {"RoleTemplateId": "Role2"}],
            "authentication_method": [{"authentication_method_feature_settings": [
                {"Id": "MicrosoftAuthenticator", "State": "enabled", "IsSoftwareOathEnabled": False,
                 "FeatureSettings": {"DisplayLocationInformationRequiredState": {"State": "enabled"}}}]}]}


def test_ca_variants_cover_strengths_conditions_and_the_disabled_counterparts(miner):
    base = _ca_base()
    before = copy.deepcopy(base)
    variants = miner.v9_ca_variants(base)
    assert base == before
    strengths = [v for v in variants if v["template_prefix"].startswith("v9:ca_strength:")]
    assert len(strengths) == 3 * 2 * len(miner.V9_STRENGTHS)
    assert {v["policies"][0] for v in strengths} == {"MS.AAD.3.1v1", "MS.AAD.3.2v2", "MS.AAD.3.6v1"}
    for variant in strengths:
        policy = variant["input"]["conditional_access_policies"][0]
        assert set(policy["GrantControls"]["AuthenticationStrength"]) == {"Id", "DisplayName", "PolicyType", "RequirementsSatisfied", "AllowedCombinations"}
        assert policy["GrantControls"]["BuiltInControls"] == []
    conditions = [v for v in variants if v["template_prefix"].startswith("v9:ca_condition:")]
    items = {v["policies"][0] for v in conditions}
    assert items == set(miner.CA_ITEMS) | {miner.V9_AI_AGENT_ITEM}
    for item in items:
        axes = {v["template_prefix"].split(":")[2].split("=")[0] for v in conditions if v["policies"] == [item]}
        assert {"locations", "platforms", "devices", "locations_on_disabled_policy", "platforms_on_disabled_policy",
                "devices_on_disabled_policy"} <= axes
    located = {v["template_prefix"].split("=")[1] for v in conditions if v["template_prefix"].startswith("v9:ca_condition:locations=")}
    assert located == {"all_include_only", "all_except_trusted", "trusted_only", "named_location", "null"}
    disabled = [v for v in conditions if "_on_disabled_policy=" in v["template_prefix"]]
    assert len(disabled) == len(items) * len(miner.V9_CA_FAILING_AXES)
    assert all(v["input"]["conditional_access_policies"][0]["State"] == "disabled" for v in disabled)
    shapes = {}
    for variant in conditions:
        policy = variant["input"]["conditional_access_policies"][0]
        for axis, key in (("locations", "Locations"), ("platforms", "Platforms"), ("devices", "Devices")):
            if variant["template_prefix"].startswith(f"v9:ca_condition:{axis}="):
                shapes[axis, variant["template_prefix"].split("=")[1]] = policy["Conditions"][key]
    assert shapes["locations", "all_except_trusted"] == {"IncludeLocations": ["All"], "ExcludeLocations": ["AllTrusted"]}
    assert shapes["platforms", "mobile_only"] == {"IncludePlatforms": ["android", "iOS"], "ExcludePlatforms": []}
    assert shapes["devices", "filter_include"]["DeviceFilter"]["Mode"] == "include"
    assert shapes["locations", "null"] is None
    agent = [v for v in conditions if v["policies"] == ["MS.AAD.9.1v1"] and "agent_service_principals=all" in v["template_prefix"]]
    assert agent and agent[0]["input"]["scuba_config"]["M365Environment"] == "commercial"
    assert len({(v["template_prefix"], v["policies"][0]) for v in variants}) == len(variants)
    assert variants == miner.v9_ca_variants(copy.deepcopy(base))
    with pytest.raises(ValueError, match="two privileged roles"):
        miner.v9_ca_variants({**base, "privileged_roles": [{"RoleTemplateId": "Role1"}]})


def test_authenticator_variants_pair_the_3_1_policy_with_each_configuration(miner):
    base = _ca_base()
    variants = miner.v9_authenticator_variants(base)
    assert base == _ca_base()
    assert {v["policies"][0] for v in variants} == {"MS.AAD.3.3v2"}
    setups = Counter(v["template_prefix"].rsplit(":s", 1)[1] for v in variants)
    assert set(setups) == set(miner.V9_AUTHENTICATOR_BASES) and setups["configured"] > setups["software_oath_enabled"] > 0
    feature = {setup: next(v for v in variants if v["template_prefix"].endswith(":s" + setup))["input"]["authentication_method"][0][
        "authentication_method_feature_settings"][0] for setup in setups}
    assert feature["software_oath_enabled"]["IsSoftwareOathEnabled"] is True
    assert feature["location_not_required"]["FeatureSettings"]["DisplayLocationInformationRequiredState"]["State"] == "disabled"
    assert feature["configured"]["IsSoftwareOathEnabled"] is False


def test_v9_variants_dispatch_by_product(miner):
    sections = {pid: ["SPO_tenant"] for pid in SHAREPOINT}
    assert {v["template_prefix"].split(":")[1] for v in miner.v9_variants("Sharepoint", _spo_harvest(), sections)} == {"enum_sweep"}
    assert miner.v9_variants("EXO", _spo_harvest(), sections) == []
    with pytest.raises(ValueError, match="base input"):
        miner.v9_variants("AAD", _auth_harvest(), {})
    kinds = {v["template_prefix"].split(":")[1] for v in miner.v9_variants("AAD", _auth_harvest(), {}, _ca_base())}
    assert kinds == {"ca_strength", "ca_condition", "ca_authenticator"} == set(miner.V9_GENERATORS) - {"enum_sweep"}


def _v9_row(miner, index: int, *, family: str = "scuba-demo-ms-demo-1", group: str = "enum", value: str | None = None, policy: str = "MS.DEMO.1.1v1") -> dict:
    tenant = {"single": {"enabled": True, "n": index}}
    variants = [(dict(name=f"v9:enum_sweep:{group}={value or index}; base=base", input=tenant, sha256="0" * 64, policies=[policy],
                      template_prefix=f"v9:enum_sweep:{group}={value or index}:b{index}", split="train"),
                 [{"PolicyId": policy, "Criticality": "Should", "RequirementMet": True, "ReportDetails": "Requirement met"}])]
    row = miner.build_cases("demo", variants, {policy: ["single"]}, {}, tenant, commit="abcdef123456", opa_version="1.20.2",
                            config_name="DemoConfig.rego", not_collected_every=10**9, masks={}, id_salt=miner.V9_ID_SALT)[0][0]
    row["family"] = family
    return row


def test_generated_rows_record_the_v9_generator_in_template_and_source(miner):
    row = _v9_row(miner, 1)
    validate_case(row)
    assert "/v9:enum_sweep:" in row["provenance"]["template"] and "variant=v9:enum_sweep:" in row["provenance"]["source"]
    assert row["split"] == "train" and row["provenance"]["distinct_prompt_sha256"] == distinct_prompt_sha256(row)
    assert row["id"].startswith("scuba-demo-ms-demo-1-1v1-")


def _many(miner, count=40, **kwargs):
    rows = [_v9_row(miner, index, **kwargs) for index in range(count)]
    for index, row in enumerate(rows):   # distinct prompts, so every row is its own template
        user = json.loads(row["messages"][1]["content"])
        user["evidence"][0]["observed"]["baseline_text"] = f"Fictional policy variant {index}"
        row["messages"][1]["content"] = miner.canonical(user)
        row["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(row)
    return rows


def test_new_v9_rows_never_land_in_test_and_templates_stay_together(miner):
    cases = _many(miner, value="shared")
    before = copy.deepcopy(cases)
    assigned = miner.assign_v9_splits(cases)
    assert cases == before
    assert {r["split"] for r in assigned} <= {"train", "validation"}
    validation = sum(r["split"] == "validation" for r in assigned)
    assert 0 < validation <= round(0.2 * len(assigned))
    assert all(r["family"].endswith("-v9-" + r["split"]) for r in assigned)
    assert all(len({r["split"] for r in assigned if r["provenance"]["template"] == t}) == 1 for t in {r["provenance"]["template"] for r in assigned})
    assert assigned == miner.assign_v9_splits(list(reversed(cases)))[::-1]
    validate_cases(assigned)
    bad = copy.deepcopy(cases)
    bad[0]["split"] = "test"
    with pytest.raises(ValueError, match="never be test"):
        miner.assign_v9_splits(bad)
    bad[0]["split"] = "train"
    bad[0]["provenance"]["template"] = "demo/MS.DEMO.1.1v1/v8:section_drop:x"
    with pytest.raises(ValueError, match="only generated v9"):
        miner.assign_v9_splits(bad)


def test_v9_split_keeps_each_swept_value_in_train(miner):
    # three values on three bases: validation may take bases, never the last train witnesses of a value
    rows = []
    for value in ("a", "b", "c"):
        for base in range(6):
            row = _many(miner, 1, group="field", value=value)[0]
            row["id"] += f"-{value}{base}"
            row["provenance"]["template"] = f"demo/MS.DEMO.1.1v1/v9:enum_sweep:field={value}:b{base}:replace:x"
            user = json.loads(row["messages"][1]["content"])
            user["case_id"] = row["id"]
            user["evidence"][0]["observed"]["baseline_text"] = f"variant {value}{base}"
            row["messages"][1]["content"] = miner.canonical(user)
            row["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(row)
            rows.append(row)
    assigned = miner.assign_v9_splits(rows)
    for value in ("a", "b", "c"):
        splits = Counter(r["split"] for r in assigned if f"field={value}:" in r["provenance"]["template"])
        assert splits["train"] >= 2
    assert any(r["split"] == "validation" for r in assigned)
    # a value seen once overall cannot be validated away, so a family of single-witness values stays in train
    singles = _many(miner, 10)
    assert {r["split"] for r in miner.assign_v9_splits(singles)} == {"train"}


# --- agreement with the pinned Rego (local OPA; skipped unless the pinned tools are exported) --------------------------------

@pytest.fixture(scope="module")
def rego(miner, tmp_path_factory):
    opa_value, scuba_value = os.environ.get("AUDITEX_TEST_OPA"), os.environ.get("AUDITEX_TEST_SCUBAGEAR")
    if not opa_value or not scuba_value:
        pytest.skip("export AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for local oracle evaluation")
    opa, scuba = Path(opa_value), Path(scuba_value)
    folder = tmp_path_factory.mktemp("v9")
    cache: dict[str, list[dict]] = {}

    class Rego:
        def evaluate(self, product: str, tenant: dict) -> list[dict]:
            meta = miner.product_meta(scuba, product)
            content = miner.canonical(tenant)
            key = product + miner.sha(content.encode())
            if key not in cache:
                path = folder / f"{len(cache)}.json"
                path.write_text(content, encoding="utf-8")
                cache[key] = miner.opa_json(opa, ["-d", str(meta["config"]), "-d", str(scuba / "Rego/Utils"), "-i", str(path), f"data.{meta['package']}.tests"])
            return cache[key]

        def verdict(self, product: str, tenant: dict, pid: str) -> tuple[bool, str]:
            target = [r for r in self.evaluate(product, tenant) if r.get("PolicyId") == pid and miner.is_verdict(r)]
            assert len(target) == 1
            return target[0]["RequirementMet"], miner.oracle_outcome(target[0])

        def base(self, product: str) -> dict:
            meta = miner.product_meta(scuba, product)
            return miner.load_base(opa, meta)[0]

    return Rego()


def test_spo_sweep_labels_follow_the_documented_semantics(miner, rego):
    base = rego.base("Sharepoint")
    harvested = [{"name": "base", "input": base}] + [
        {"name": f"sharing-{value}", "input": miner._v9_set_field(base, "SPO_tenant", "SharingCapability", value)} for value in (3, 1, 2)]
    sections = {pid: ["SPO_tenant"] for pid in SHAREPOINT}
    variants = miner.v9_enum_variants("Sharepoint", harvested, sections)
    assert len(variants) == 80
    for variant in variants:
        spo = variant["input"]["SPO_tenant"][0]
        for pid in variant["policies"]:
            met, outcome = rego.verdict("Sharepoint", variant["input"], pid)
            unchanged = rego.verdict("Sharepoint", variant["base"], pid)
            if pid == "MS.SHAREPOINT.2.1v1":
                assert (met, outcome) == (spo["DefaultSharingLinkType"] == 1, "evaluated")
            elif pid == "MS.SHAREPOINT.2.2v1":
                assert (met, outcome) == (spo["DefaultLinkPermission"] == 1, "evaluated")
            elif pid == "MS.SHAREPOINT.1.2v1":
                assert (met, outcome) == (spo["ODBSharingCapability"] in (0, 3), "evaluated")
            elif pid == "MS.SHAREPOINT.1.3v1" and spo["SharingCapability"] != 0:
                assert (met, outcome) == (spo["SharingDomainRestrictionMode"] == 1, "evaluated")
            elif pid == "MS.SHAREPOINT.3.2v1" and spo["SharingCapability"] == 2:
                assert (met, outcome) == (spo["FileAnonymousLinkType"] == 1 and spo["FolderAnonymousLinkType"] == 1, "evaluated")
            elif pid in ("MS.SHAREPOINT.1.3v1", "MS.SHAREPOINT.3.2v1"):
                assert (met, outcome) == (True, "not_applicable")   # sharing closed: the anonymous-link settings do not matter
            else:   # a bystander: the swept field is not one it reads, so its answer does not move
                assert (met, outcome) == unchanged


def test_authorization_sweep_labels_follow_the_documented_semantics(miner, rego):
    base = rego.base("AAD")
    creates_apps = json.loads(miner.canonical(base))
    creates_apps["authorization_policies"][0]["DefaultUserRolePermissions"]["AllowedToCreateApps"] = True
    consents = json.loads(miner.canonical(base))
    consents["authorization_policies"][0]["PermissionGrantPolicyIdsAssignedToDefaultUserRole"] = ["ManagePermissionGrantsForSelf.microsoft-user-default-recommended"]
    harvested = [{"name": "base", "input": base}, {"name": "creates-apps", "input": creates_apps}, {"name": "consents", "input": consents}]
    sections = {"MS.AAD.5.1v1": ["authorization_policies"], "MS.AAD.5.2v1": ["authorization_policies", "risky_delegated_permission_classifications"],
                "MS.AAD.8.1v1": ["authorization_policies"], "MS.AAD.8.2v1": ["authorization_policies"]}
    variants = miner.v9_enum_variants("AAD", harvested, sections)
    assert len(variants) == 3 * (4 + 3)
    for variant in variants:
        policy = variant["input"]["authorization_policies"][0]
        for pid in variant["policies"]:
            met, outcome = rego.verdict("AAD", variant["input"], pid)
            if pid == "MS.AAD.8.2v1":
                assert (met, outcome) == (policy["AllowInvitesFrom"] == "adminsAndGuestInviters", "evaluated")
            elif pid == "MS.AAD.8.1v1":
                assert (met, outcome) == (policy["GuestUserRoleId"] in (miner.V9_GUEST_ROLES["restricted"], miner.V9_GUEST_ROLES["limited"]), "evaluated")
            else:
                assert (met, outcome) == rego.verdict("AAD", variant["base"], pid)


PHISHING_RESISTANT = {"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"}


def _is_phishing_resistant(combinations) -> bool:
    return bool(combinations) and set(combinations) <= PHISHING_RESISTANT


def _is_general_mfa(miner, combinations) -> bool:
    strengths, mfa = set(combinations or ()), set(miner.MFA_STRENGTH)
    return bool(strengths & mfa) and not strengths - mfa and bool(strengths - PHISHING_RESISTANT)


def test_strength_labels_follow_the_combinations_and_never_the_metadata(miner, rego):
    base = rego.base("AAD")
    variants = [v for v in miner.v9_ca_variants(base) if v["template_prefix"].startswith("v9:ca_strength:")]
    seen: dict[tuple, set] = {}
    for variant in variants:
        item = variant["policies"][0]
        combinations = variant["input"]["conditional_access_policies"][0]["GrantControls"]["AuthenticationStrength"]["AllowedCombinations"]
        expected = _is_general_mfa(miner, combinations) if item == "MS.AAD.3.2v2" else _is_phishing_resistant(combinations)
        assert rego.verdict("AAD", variant["input"], item) == (expected, "evaluated"), variant["name"]
        seen.setdefault((item, json.dumps(combinations)), set()).add(rego.verdict("AAD", variant["input"], item))
    assert all(len(labels) == 1 for labels in seen.values())


def test_conditions_the_rego_ignores_do_not_change_the_label_and_those_it_reads_do(miner, rego):
    base = rego.base("AAD")
    agent_met = {("agent_service_principals", "all"): True, ("agent_service_principals", "all_with_service_principals"): True,
                 ("agent_service_principals", "one_agent"): False, ("agent_service_principals", "none_listed"): False,
                 ("agent_service_principals", "null"): False, ("agent_risk", "medium_and_high"): True, ("agent_risk", "medium"): False,
                 ("agent_risk", "low"): False, ("agent_risk", "null"): False}
    checked = Counter()
    for variant in miner.v9_ca_variants(base):
        if not variant["template_prefix"].startswith("v9:ca_condition:"):
            continue
        item, (axis, value) = variant["policies"][0], variant["template_prefix"].split(":")[2].split("=")
        label = rego.verdict("AAD", variant["input"], item)
        plain = rego.verdict("AAD", variant["base"], item)
        assert plain == (True, "evaluated"), item   # the single-purpose policy meets its own item
        if axis.endswith("_on_disabled_policy"):
            assert label == (False, "evaluated"), (item, axis)   # a disabled policy fails the item whatever else it says
            checked["disabled"] += 1
        elif axis in {"locations", "platforms", "devices"} or (axis == "client_applications" and item != "MS.AAD.9.1v1"):
            assert label == plain, (item, axis, value)   # the Rego does not read it
            checked["ignored"] += 1
        elif (axis, value) in agent_met:
            assert item == "MS.AAD.9.1v1" and label == (agent_met[axis, value], "evaluated"), (axis, value)
            checked["honoured"] += 1
    assert checked["disabled"] == 30 and checked["ignored"] > 100 and checked["honoured"] == len(agent_met)


def test_authenticator_branch_is_not_applicable_exactly_when_a_phishing_resistant_policy_counts(miner, rego):
    base = rego.base("AAD")
    variants = miner.v9_authenticator_variants(base)
    assert variants
    counting = {"phishing_resistant.builtin", "fido2_only.custom_mfa", "hello_and_fido2.custom_mfa", "locations_named", "platforms_mobile_only",
                "devices_filter_include"}
    for variant in variants:
        shape = variant["template_prefix"].split(":")[2].split("=")[1]
        met, outcome = rego.verdict("AAD", variant["input"], "MS.AAD.3.3v2")
        if shape in counting:
            assert (met, outcome) == (True, "not_applicable"), variant["name"]
        else:
            assert outcome == "evaluated", variant["name"]
            setup = variant["template_prefix"].rsplit(":s", 1)[1]
            assert met is (setup == "configured"), variant["name"]
