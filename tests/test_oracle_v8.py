"""Opt-in v8 generators preserve legacy inputs and keep new templates out of test."""
from __future__ import annotations

import copy
import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

from auditex.model_training import distinct_prompt_sha256, validate_case, validate_cases
from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import gate_value, rule_catalogue


@pytest.fixture(scope="module")
def miner():
    path = Path(__file__).resolve().parents[1] / "scripts/build-oracle-cases.py"
    spec = importlib.util.spec_from_file_location("oracle_v8", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gate_sweep_covers_all_eight_rules_and_every_base_without_mutation(miner):
    rules = rule_catalogue()["rules"]
    sections = {rule["policy_id"]: [rule["section"]] for rule in rules}
    harvested = [{"name": "base", "input": {}}, {"name": "sibling", "input": {"unrelated": [1, 2]}}]
    before = copy.deepcopy(harvested)
    variants = miner.v8_value_variants("gates", harvested, sections)
    assert len(rules) == 8
    assert len(variants) == 2 * sum(len(rule["allowed_values"]) for rule in rules)
    for rule in rules:
        for base in harvested:
            selected = [v for v in variants if v["policies"] == [rule["policy_id"]] and v["name"].endswith("base=" + base["name"])]
            values = {gate_value(rule, v["input"]) for v in selected}
            assert values == set(rule["allowed_values"])
            assert set(rule["closed_values"]) <= values
            assert values - set(rule["closed_values"])
    assert all(v["split"] == "train" and "v8:gate_sweep:" in v["template_prefix"] for v in variants)
    assert harvested == before


def test_gate_edit_handles_singleton_and_selector_and_removes_stale_enum_name(miner):
    sharepoint, authenticator = rule_catalogue()["rules"][0], rule_catalogue()["rules"][-1]
    tenant = {"SPO_tenant": [{"SharingCapability": 2, "SharingCapability_name": "stale", "Other": 7}]}
    edited = miner._v8_gate_edit(tenant, sharepoint, 0)
    assert edited["SPO_tenant"] == [{"SharingCapability": 0, "Other": 7}]
    absent = miner._v8_gate_edit(edited, sharepoint, None, remove=True)
    assert absent["SPO_tenant"] == [{"Other": 7}]
    assert gate_value(authenticator, miner._v8_gate_edit({}, authenticator, "disabled")) == "disabled"
    with pytest.raises(ValueError, match="singleton"):
        miner._v8_gate_edit({"SPO_tenant": [{}, {}]}, sharepoint, 0)


def _base_cases(miner):
    policies = {"MS.DEMO.1.1v1": ["single"], "MS.DEMO.2.1v1": ["first", "second"],
                "MS.SHAREPOINT.3.1v1": ["SPO_tenant", "other"]}
    tenant = {"single": {"enabled": True}, "first": [1], "second": [2],
              "SPO_tenant": [{"SharingCapability": 0, "SharingCapability_name": "stale"}], "other": {"v": 1}}
    variants = [(dict(name="base", input=tenant, sha256="0" * 64),
                 [{"PolicyId": pid, "Criticality": "Should", "RequirementMet": True,
                   "ReportDetails": "only applicable if external sharing is enabled" if "SHAREPOINT" in pid else "Requirement met"}
                  for pid in policies])]
    return miner.build_cases("demo", variants, policies, {}, tenant, commit="abcdef123456", opa_version="1.20.2",
                             config_name="DemoConfig.rego", not_collected_every=10**9, masks={})[0]


def test_section_drops_cover_each_dependency_single_sections_and_missing_gate(miner):
    bases = _base_cases(miner)
    before = copy.deepcopy(bases)
    cases = miner.v8_section_cases("demo", bases)
    assert len(cases) == 6  # 1 + 2 + (2 sections and the missing gate field)
    for row in cases:
        validate_case(row)
        claim = row["expected"]["claims"][0]
        # The prompt contract makes a visibly closed gate decisive even when
        # another dependency is dropped; the old absence-first expectation was wrong.
        closed = ":section_drop:other:" in row["provenance"]["template"]
        assert (claim["status"], claim["value"]) == (("inferred", True) if closed else ("unknown", None))
        assert row["expected"]["limitations"] == (["policy_not_applicable"] if closed else
                                                  ["required_evidence_section_not_collected"])
        assert row["expected"]["recommendations"] == ([] if closed else ["collect_missing_evidence_section"])
        assert row["provenance"]["oracle_outcome"] == ("not_applicable" if closed else
            "not_collected" if ":section_drop:" in row["provenance"]["template"] else "fail_closed_missing_input")
        assert "v8:" in row["provenance"]["template"]
        assert "generator=v8:" in row["provenance"]["source"]
        assert row["provenance"]["distinct_prompt_sha256"] == distinct_prompt_sha256(row)
        assert row["split"] != "test"
        user = json.loads(row["messages"][1]["content"])
        if "section_drop:" in row["provenance"]["template"]:
            assert any(e["observed"] == NOT_COLLECTED for e in user["evidence"])
        else:
            spo = next(e["observed"] for e in user["evidence"] if e["section"] == "SPO_tenant")
            assert "SharingCapability" not in spo[0] and "SharingCapability_name" not in spo[0]
    assert bases == before


def test_targeted_shapes_include_value_dimensions_and_distinct_violations(miner):
    base = [{"name": "base", "input": {}}]
    powerbi = miner.v8_value_variants("PowerBI", base, {})
    assert len(powerbi) == 120
    present = [v["input"] for v in powerbi if v["input"]["powerbi_tenant_settings"] and
               isinstance(v["input"]["powerbi_tenant_settings"][0], dict) and
               v["input"]["powerbi_tenant_settings"][0].get("settingName") == "EimInformationProtectionEdit"]
    assert {p["powerbi_tenant_settings"][0]["enabled"] for p in present} == {True, False}
    assert any("powerbi_license_found" not in p for p in present)
    assert any(p["powerbi_tenant_settings"][0].get("enabledSecurityGroups") ==
               [{"graphId": "10000000-0000-4000-8000-000000000001", "name": "Audit group A"}] for p in present)
    exo = miner.v8_value_variants("EXO", base, {})
    teams = miner.v8_value_variants("Teams", base, {})
    assert len(exo) == 18 and len(teams) == 24
    assert {v["policies"][0] for v in teams} == {"MS.TEAMS.5.2v2", "MS.TEAMS.5.3v2"}
    assert len({v["template_prefix"] for v in exo}) == 18
    assert all(v["split"] == "train" for v in powerbi + exo + teams)


def test_new_rows_never_land_in_test_and_templates_remain_together(miner):
    base = miner.v8_section_cases("demo", _base_cases(miner))[0]
    cases = []
    for index in range(20):
        row = copy.deepcopy(base)
        row["id"] = f"extension-{index}"
        row["provenance"]["template"] = f"demo/MS.DEMO.1.1v1/v8:section_drop:shape-{index}"
        user = json.loads(row["messages"][1]["content"])
        user["case_id"] = row["id"]
        user["evidence"][0]["observed"]["baseline_text"] = f"Fictional policy variant {index}"
        row["messages"][1]["content"] = miner.canonical(user)
        row["provenance"]["distinct_prompt_sha256"] = distinct_prompt_sha256(row)
        cases.append(row)
    before = copy.deepcopy(cases)
    assigned = miner.assign_v8_splits(cases)
    assert Counter(r["split"] for r in assigned) == {"train": 17, "validation": 3}
    assert {r["split"] for r in assigned} <= {"train", "validation"}
    assert assigned == miner.assign_v8_splits(list(reversed(cases)))[::-1]
    validate_cases(assigned)
    assert cases == before
    bad = copy.deepcopy(cases)
    bad[0]["split"] = "test"
    with pytest.raises(ValueError, match="never be test"):
        miner.assign_v8_splits(bad)
    bad[0]["split"] = "train"
    bad[0]["provenance"]["template"] = "legacy"
    with pytest.raises(ValueError, match="only generated v8"):
        miner.assign_v8_splits(bad)


@pytest.mark.parametrize("product", ["PowerBI", "EXO", "Teams"])
def test_targeted_value_shapes_agree_with_pinned_rego(miner, tmp_path, product):
    import os

    opa_value = os.environ.get("AUDITEX_TEST_OPA")
    scuba_value = os.environ.get("AUDITEX_TEST_SCUBAGEAR")
    if not opa_value or not scuba_value:
        pytest.skip("export AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for local oracle evaluation")
    opa, scuba = Path(opa_value), Path(scuba_value)
    meta = miner.product_meta(scuba, product)
    base, _, _ = miner.load_base(opa, meta)
    variants = miner.v8_value_variants(product, [{"name": "base", "input": base}], {})
    seen = set()
    for variant in variants:
        content = miner.canonical(variant["input"])
        if content in seen:
            continue
        seen.add(content)
        path = tmp_path / "tenant.json"
        path.write_text(content, encoding="utf-8")
        results = miner.opa_json(opa, ["-d", str(meta["config"]), "-d", str(scuba / "Rego/Utils"),
                                       "-i", str(path), f"data.{meta['package']}.tests"])
        target = [r for r in results if r.get("PolicyId") == variant["policies"][0] and miner.is_verdict(r)]
        assert len(target) == 1
        if product == "PowerBI":
            tenant = variant["input"]
            settings = [s for s in tenant["powerbi_tenant_settings"] if isinstance(s, dict) and
                        s.get("settingName") == "EimInformationProtectionEdit"]
            if tenant.get("powerbi_license_found") is not True or not settings:
                assert miner.oracle_outcome(target[0]) == "fail_closed_missing_input"
            else:
                assert miner.oracle_outcome(target[0]) == "evaluated"
                assert target[0]["RequirementMet"] is settings[0]["enabled"]
        else:
            assert miner.oracle_outcome(target[0]) == "evaluated"
            assert target[0]["RequirementMet"] is False
