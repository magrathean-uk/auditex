"""v10 generators (met / not-met rebalancing) are deterministic, leave their inputs alone, declare intents that agree with the pinned
Rego, and their split keeps both classes in train and new rows out of test."""
from __future__ import annotations

import copy
import importlib.util
import ipaddress
import json
import os
from collections import Counter
from pathlib import Path

import pytest

from auditex.model_training import distinct_prompt_sha256, validate_case, validate_cases

ROOT = Path(__file__).resolve().parents[1]
TEAMS = ["MS.TEAMS.5.1v2", "MS.TEAMS.5.2v2", "MS.TEAMS.5.3v2"]
POWERBI_NAMES = ["PublishToWeb", "AllowGuestUserToAccessSharedContent", "ExternalSharingV2", "ServicePrincipalAccessPermissionAPIs",
                 "AllowServicePrincipalsCreateAndUseProfiles", "BlockResourceKeyAuthentication", "RScriptVisual", "EimInformationProtectionEdit"]


@pytest.fixture(scope="module")
def miner():
    path = ROOT / "scripts/build-oracle-cases.py"
    spec = importlib.util.spec_from_file_location("oracle_v10", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bases():
    return {
        "EXO": {"transport_rule": [{"FromScope": "NotInOrganization", "Mode": "Enforce", "PrependSubject": "External", "State": "Enabled"}],
                "org_config": [{"AuditDisabled": False}]},
        "Teams": {"app_policies": [{"DefaultCatalogAppsType": "AllowedAppList", "GlobalCatalogAppsType": "AllowedAppList", "Identity": "Global",
                                    "PrivateCatalogAppsType": "AllowedAppList"}], "meeting_policies": []},
        "SecuritySuite": {"conn_filter": [{"EnableSafeList": False, "IPAllowList": [], "Name": "A"}], "scuba_config": {}},
        "PowerBI": {"powerbi_license_found": True,
                    "powerbi_tenant_settings": [{"settingName": name, "enabled": index % 2 == 0, "title": name, "tenantSettingGroup": "Group"}
                                                for index, name in enumerate(POWERBI_NAMES)]},
    }


def test_v10_variants_dispatch_by_product_and_leave_the_base_alone(miner):
    for name, base in _bases().items():
        before = copy.deepcopy(base)
        variants = miner.v10_variants(name, base)
        assert base == before and variants
        assert len({v["template_prefix"] for v in variants}) == len(variants)
        for variant in variants:
            generator = variant["template_prefix"].split(":")[1]
            assert generator in miner.V10_GENERATORS and variant["name"].startswith(f"v10:{generator}:")
            assert variant["split"] == "train" and variant["base"] == base
            assert set(variant["intent"]) == set(variant["policies"]) and set(variant["intent"].values()) <= {"met", "not_met"}
            assert {k for k in variant["input"] if variant["input"][k] != base.get(k)} <= {"transport_rule", "app_policies", "tenant_app_settings",
                                                                                            "conn_filter", "powerbi_tenant_settings"}
        assert miner.v10_variants(name, base) == variants
    assert miner.v10_variants("AAD", {}) == [] and miner.v10_variants("Sharepoint", {}) == []


def test_every_v10_policy_gets_both_classes(miner):
    intents = Counter()
    for name, base in _bases().items():
        for variant in miner.v10_variants(name, base):
            intents.update(variant["intent"].items())
    for pid in ["MS.EXO.7.1v1", *TEAMS, "MS.SECURITYSUITE.8.2v1", "MS.POWERBI.7.1v1"]:
        assert intents[pid, "met"] >= 4 and intents[pid, "not_met"] >= 4, pid


def test_exo_met_shapes_hold_one_working_warning_rule_among_decoys(miner):
    def working(rule):
        return rule["State"] == "Enabled" and rule["Mode"] == "Enforce" and bool(rule["PrependSubject"]) and rule["FromScope"] == "NotInOrganization"

    variants = miner.v10_exo_variants(_bases()["EXO"])
    assert len(variants) == len(miner.V10_EXO_MET) + len(miner.V10_EXO_NOT_MET)
    for variant in variants:
        rules = variant["input"]["transport_rule"]
        assert variant["policies"] == ["MS.EXO.7.1v1"] and all("Name" in rule for rule in rules)
        assert sum(map(working, rules)) == (1 if variant["intent"]["MS.EXO.7.1v1"] == "met" else 0)
    decoyed = [v for v in variants if v["intent"]["MS.EXO.7.1v1"] == "met" and len(v["input"]["transport_rule"]) > 1]
    assert len(decoyed) >= 10
    # the working rule is not always first
    assert any(not working(v["input"]["transport_rule"][0]) for v in decoyed)


@pytest.mark.parametrize(("settings", "policies", "expected"), [
    (None, [("ABA",)], {"MS.TEAMS.5.1v2": "met", "MS.TEAMS.5.2v2": "not_met", "MS.TEAMS.5.3v2": "met"}),
    ("certificate", [("AAB",)], {"MS.TEAMS.5.1v2": "met", "MS.TEAMS.5.2v2": "met", "MS.TEAMS.5.3v2": "not_met"}),
    (("None", "None", "None"), [("BBB",)], {"MS.TEAMS.5.1v2": "met", "MS.TEAMS.5.2v2": "met", "MS.TEAMS.5.3v2": "met"}),
    (("AllowedApps", "None", "AllowedApps"), [("AAA",)], {"MS.TEAMS.5.1v2": "not_met", "MS.TEAMS.5.2v2": "met", "MS.TEAMS.5.3v2": "not_met"}),
    (("-", "None", "-"), [("BAB",)], {"MS.TEAMS.5.1v2": "not_met", "MS.TEAMS.5.2v2": "met", "MS.TEAMS.5.3v2": "not_met"}),
])
def test_teams_intent_follows_the_documented_precedence(miner, settings, policies, expected):
    built = [miner._v10_app_policy(f"Tag:P{index}", *letters[0]) for index, letters in enumerate(policies)]
    assert miner._v10_teams_intent(built, settings) == expected


def test_teams_tenants_label_all_three_items_and_show_cross_catalogue_decoys(miner):
    variants = miner.v10_teams_variants(_bases()["Teams"])
    assert len(variants) == len(miner.V10_TEAMS_TENANTS)
    cross = 0
    for variant in variants:
        assert variant["policies"] == TEAMS
        policies, settings = variant["input"]["app_policies"], variant["input"].get("tenant_app_settings")
        assert all(set(p) == {"Identity", "DefaultCatalogAppsType", "GlobalCatalogAppsType", "PrivateCatalogAppsType"} for p in policies)
        assert settings is None or all(set(s) <= {"SettingName", "SettingValue", "CertificateBasedAuth"} for s in settings)
        for pid, (field, _) in miner.V10_TEAMS_ITEMS.items():
            others = [f for p, (f, _) in miner.V10_TEAMS_ITEMS.items() if p != pid]
            if variant["intent"][pid] == "met" and any(p[f] == "BlockedAppList" for p in policies for f in others):
                cross += 1
    assert cross >= 6


def test_connection_filters_use_documentation_addresses_and_vary_the_allow_list(miner):
    variants = miner.v10_conn_filter_variants(_bases()["SecuritySuite"])
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for variant in variants:
        filters = variant["input"]["conn_filter"]
        assert variant["policies"] == ["MS.SECURITYSUITE.8.2v1"] and len({tuple(sorted(f)) for f in filters}) == 1
        assert set(filters[0]) == {"Name", "EnableSafeList", "IPAllowList"}   # no field the 8.x Rego does not read
        for entry in (e for f in filters for e in f["IPAllowList"]):
            assert any(ipaddress.ip_network(entry).subnet_of(n) for n in documentation), entry
        assert variant["intent"]["MS.SECURITYSUITE.8.2v1"] == ("not_met" if any(f["EnableSafeList"] for f in filters) else "met")
    met = [v for v in variants if v["intent"]["MS.SECURITYSUITE.8.2v1"] == "met"]
    assert any(f["IPAllowList"] for v in met for f in v["input"]["conn_filter"])


def test_powerbi_shapes_take_base_settings_and_place_the_label_setting_once(miner):
    base = _bases()["PowerBI"]
    variants = miner.v10_powerbi_variants(base)
    assert len(variants) == 2 * len(miner.V10_POWERBI_SETS)
    positions = set()
    for variant in variants:
        settings = variant["input"]["powerbi_tenant_settings"]
        eim = [i for i, s in enumerate(settings) if s["settingName"] == "EimInformationProtectionEdit"]
        assert len(eim) == 1 and variant["input"]["powerbi_license_found"] is True
        positions.add(eim[0])
        assert variant["intent"]["MS.POWERBI.7.1v1"] == ("met" if settings[eim[0]]["enabled"] else "not_met")
        others = [s for s in settings if s["settingName"] != "EimInformationProtectionEdit"]
        assert others == [s for name in [s["settingName"] for s in others] for s in base["powerbi_tenant_settings"] if s["settingName"] == name]
    assert len(positions) > 1


def _v10_row(miner, index: int, *, outcome: str = "met", policy: str = "MS.DEMO.1.1v1", family: str = "scuba-demo-ms-demo-1",
             salt: str | None = None, shape: int | None = None, name: str | None = None) -> dict:
    tenant = {"single": {"enabled": True, "n": index if shape is None else shape, "outcome": outcome, **({"Name": name} if name else {})}}
    variants = [(dict(name=f"v10:exo_7_1:{outcome}=s{index}; base=product", input=tenant, sha256="0" * 64, policies=[policy],
                      template_prefix=f"v10:exo_7_1:{outcome}=s{index}", split="train"),
                 [{"PolicyId": policy, "Criticality": "Should", "RequirementMet": outcome == "met", "ReportDetails": "Requirement met"}])]
    row = miner.build_cases("demo", variants, {policy: ["single"]}, {}, tenant, commit="abcdef123456", opa_version="1.20.2",
                            config_name="DemoConfig.rego", not_collected_every=10**9, masks={}, id_salt=salt or miner.V10_ID_SALT)[0][0]
    row["family"] = family
    return row


def test_generated_rows_record_the_v10_generator_and_salt(miner):
    row = _v10_row(miner, 1)
    validate_case(row)
    assert "/v10:exo_7_1:" in row["provenance"]["template"] and "variant=v10:exo_7_1:" in row["provenance"]["source"]
    assert row["provenance"]["oracle_outcome"] == "met" and row["provenance"]["distinct_prompt_sha256"] == distinct_prompt_sha256(row)
    assert row["id"] != _v10_row(miner, 1, salt=miner.V9_ID_SALT)["id"]


def test_v10_split_is_stratified_by_outcome_never_test_and_keeps_templates_whole(miner):
    cases = [_v10_row(miner, i, outcome="met") for i in range(20)] + [_v10_row(miner, 100 + i, outcome="not_met") for i in range(20)]
    before = copy.deepcopy(cases)
    assigned = miner.assign_v10_splits(cases)
    assert cases == before
    assert {r["split"] for r in assigned} == {"train", "validation"}
    for outcome in ("met", "not_met"):
        split = Counter(r["split"] for r in assigned if r["provenance"]["oracle_outcome"] == outcome)
        assert split["validation"] == 3 and split["train"] == 17
    assert all(r["family"] == f"scuba-demo-ms-demo-1-v10-{r['split']}" for r in assigned)
    assert assigned == miner.assign_v10_splits(list(reversed(cases)))[::-1]
    validate_cases(assigned)
    bad = copy.deepcopy(cases)
    bad[0]["split"] = "test"
    with pytest.raises(ValueError, match="never be test"):
        miner.assign_v10_splits(bad)
    bad[0]["split"] = "train"
    bad[0]["provenance"]["template"] = "demo/MS.DEMO.1.1v1/v9:enum_sweep:x"
    with pytest.raises(ValueError, match="only generated v10"):
        miner.assign_v10_splits(bad)


def test_v10_split_gives_validation_one_group_per_outcome_and_keeps_one_in_train(miner):
    cases = [_v10_row(miner, i, outcome="met") for i in range(12)] + [_v10_row(miner, 100 + i, outcome="not_met") for i in range(2)]
    assigned = miner.assign_v10_splits(cases)
    assert Counter(r["split"] for r in assigned if r["provenance"]["oracle_outcome"] == "not_met") == {"train": 1, "validation": 1}
    assert Counter(r["split"] for r in assigned if r["provenance"]["oracle_outcome"] == "met") == {"train": 10, "validation": 2}
    # a single group stays in train
    lone = miner.assign_v10_splits([_v10_row(miner, i, outcome="met") for i in range(6)] + [_v10_row(miner, 100, outcome="not_met")])
    assert [r["split"] for r in lone if r["provenance"]["oracle_outcome"] == "not_met"] == ["train"]


def test_v10_near_key_ignores_names_wording_order_and_repetition_only(miner):
    def case(observed, policy="MS.EXO.7.1v1"):
        user = {"policy_id": policy, "evidence": [{"id": "e0", "section": "policy", "observed": {"x": 1}},
                                                  {"id": "e1", "section": "transport_rule", "observed": observed}]}
        return {"messages": [{"role": "system", "content": ""}, {"role": "user", "content": json.dumps(user)}]}

    def rule(name, prefix, state="Enabled"):
        return {"Name": name, "PrependSubject": prefix, "State": state, "FromScope": "NotInOrganization", "Mode": "Enforce"}

    key = miner.v10_near_key(case([rule("A", "[External]"), rule("B", "[Ext]", "Disabled")]))
    assert key == miner.v10_near_key(case([rule("Disabled tag", "x", "Disabled"), rule("Warn", "CAUTION")]))   # names, wording, order
    assert key == miner.v10_near_key(case([rule("A", "[External]"), rule("C", "[EXT]"), rule("B", "[Ext]", "Disabled")]))   # repetition
    assert key != miner.v10_near_key(case([rule("A", ""), rule("B", "[Ext]", "Disabled")]))   # empty wording counts
    assert key != miner.v10_near_key(case([rule("A", "[External]"), rule("B", "[Ext]")]))   # state counts
    assert key != miner.v10_near_key(case([rule("A", "[External]"), rule("B", "[Ext]", "Disabled")], policy="MS.EXO.7.2v1"))


def _strict_case(policy, observed, outcome="met", section="conn_filter"):
    user = {"policy_id": policy, "evidence": [{"id": "e0", "section": "policy", "observed": {"x": 1}},
                                              {"id": "e1", "section": section, "observed": observed}]}
    return {"messages": [{"role": "system", "content": ""}, {"role": "user", "content": json.dumps(user)}],
            "provenance": {"oracle_outcome": outcome}, "expected": {"claims": [{"id": "requirement_met", "value": outcome == "met"}]}}


def test_v10_read_only_keeps_what_a_path_reaches(miner):
    star = miner.STAR
    value = [{"EnableSafeList": True, "IPAllowList": ["192.0.2.1"], "Extra": {"a": 1, "b": 2}, "Name": "A"}]
    assert miner._v10_read_only(value, [(star, "EnableSafeList")]) == [{"EnableSafeList": True}]
    assert miner._v10_read_only(value, [(star, "Extra", "a"), (star, "Name")]) == [{"Extra": {"a": 1}, "Name": "A"}]
    assert miner._v10_read_only(value, [(star,)]) == value and miner._v10_read_only(value, ()) == value
    assert miner._v10_read_only(value, [("EnableSafeList",)]) == value   # a list met by a field name stays whole
    assert miner._v10_read_only({"Policy": {"On": True, "Off": 1}}, [(star, "On")]) == {"Policy": {"On": True}}


def test_v10_strict_key_drops_unread_fields_before_the_set_normalisation(miner):
    reads = {"MS.SECURITYSUITE.8.2v1": {"conn_filter": [(miner.STAR, "EnableSafeList"), (miner.STAR, "Name")]}}
    pid = "MS.SECURITYSUITE.8.2v1"
    one = _strict_case(pid, [{"Name": "Default", "EnableSafeList": False, "IPAllowList": []}])
    extra = _strict_case(pid, [{"Name": "Default", "EnableSafeList": False, "IPAllowList": ["203.0.113.0/24"], "IPBlockList": ["192.0.2.66"]},
                               {"Name": "Relay", "EnableSafeList": False, "IPAllowList": []}])
    assert miner.v10_near_key(one) != miner.v10_near_key(extra)   # the round-2 key sees the unread fields
    assert miner.v10_strict_key(one, reads) == miner.v10_strict_key(extra, reads)
    assert miner.v10_strict_key(one, reads) != miner.v10_strict_key(_strict_case(pid, [{"Name": "D", "EnableSafeList": True, "IPAllowList": []}]), reads)
    # a policy the reads do not list keeps every field
    other = {**reads, pid: {}}
    assert miner.v10_strict_key(one, other) != miner.v10_strict_key(extra, other)


def test_v10_sound_reads_keeps_a_section_whole_when_reducing_it_mixes_labels(miner):
    pid = "MS.POWERBI.7.1v1"
    cases = [_strict_case(pid, [{"settingName": "Eim", "enabled": True}], "met", "powerbi_tenant_settings"),
             _strict_case(pid, [{"settingName": "Eim", "enabled": False}], "not_met", "powerbi_tenant_settings"),
             _strict_case("MS.EXO.7.1v1", [{"State": "Enabled", "Comments": "a"}], "met", "transport_rule"),
             _strict_case("MS.EXO.7.1v1", [{"State": "Enabled", "Comments": "b"}], "met", "transport_rule")]
    field_reads = {pid: {("powerbi_tenant_settings", (miner.STAR, "settingName"))},   # the AST walk missed `enabled`
                   "MS.EXO.7.1v1": {("transport_rule", (miner.STAR, "State"))}}
    reads, record = miner.v10_sound_reads(cases, field_reads)
    assert reads[pid] == {} and record[pid]["kept_whole_read_missed"] == ["powerbi_tenant_settings"]
    assert reads["MS.EXO.7.1v1"] == {"transport_rule": [(miner.STAR, "State")]} and record["MS.EXO.7.1v1"]["kept_whole_read_missed"] == []
    assert miner.v10_strict_key(cases[2], reads) == miner.v10_strict_key(cases[3], reads)
    assert miner.v10_strict_key(cases[0], reads) != miner.v10_strict_key(cases[1], reads)


def test_v10_split_keeps_cosmetic_twins_together_and_follows_existing_rows(miner):
    # rows 0 to 3 share one shape under different names: one group, one split, wherever the hash falls
    cases = [_v10_row(miner, i, shape=0, name=f"Rule {i}") for i in range(4)] + [_v10_row(miner, 10 + i) for i in range(16)]
    assigned = miner.assign_v10_splits(cases)
    assert len({r["split"] for r in assigned[:4]}) == 1
    assert len({miner.v10_near_key(r) for r in assigned[:4]}) == 1
    # an existing validation row with the twins' key pulls the group into validation; one in train keeps it there
    existing = _v10_row(miner, 99, shape=0, name="Inherited")
    for split in ("validation", "train"):
        pinned = miner.assign_v10_splits(cases, existing=[{**existing, "split": split}])
        assert {r["split"] for r in pinned[:4]} == {split}
    with pytest.raises(ValueError, match="different oracle outcomes"):
        miner.assign_v10_splits([_v10_row(miner, 1, shape=0, name="A"), {**_v10_row(miner, 2, shape=0, name="B"),
                                                                          "provenance": {**_v10_row(miner, 2, shape=0, name="B")["provenance"],
                                                                                         "oracle_outcome": "not_met"}}])


# --- agreement with the pinned Rego (local OPA; skipped unless the pinned tools are exported) --------------------------------

@pytest.fixture(scope="module")
def rego(miner, tmp_path_factory):
    opa_value, scuba_value = os.environ.get("AUDITEX_TEST_OPA"), os.environ.get("AUDITEX_TEST_SCUBAGEAR")
    if not opa_value or not scuba_value:
        pytest.skip("export AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for local oracle evaluation")
    return Path(opa_value), Path(scuba_value), tmp_path_factory.mktemp("v10")


@pytest.mark.parametrize("product", ["EXO", "Teams", "SecuritySuite", "PowerBI"])
def test_declared_intents_agree_with_the_pinned_rego(miner, rego, product):
    opa, scuba, folder = rego
    meta = miner.product_meta(scuba, product)
    base = miner.load_base(opa, meta)[0]
    for index, variant in enumerate(miner.v10_variants(product, base)):
        path = folder / f"{product}-{index}.json"
        path.write_text(miner.canonical(variant["input"]), encoding="utf-8")
        results = miner.opa_json(opa, ["-d", str(meta["config"]), "-d", str(scuba / "Rego/Utils"), "-i", str(path), f"data.{meta['package']}.tests"])
        for pid in variant["policies"]:
            target = [r for r in results if r.get("PolicyId") == pid and miner.is_verdict(r)]
            assert len(target) == 1 and miner.oracle_outcome(target[0]) == "evaluated"
            assert ("met" if target[0]["RequirementMet"] else "not_met") == variant["intent"][pid], (variant["name"], pid)
