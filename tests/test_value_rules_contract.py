"""A1/A2 shared contract: exact variants, additive assessments and unchanged offline answers."""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from auditex.model_precheck import precheck_case
from auditex.model_serving import ModelConfig, assess_run, canonical, messages_for, policy_catalogue
from azure_tenant_audit.model_assessment import validate_assessment
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response
from azure_tenant_audit.value_rules import catalogue as loader
from azure_tenant_audit.value_rules.record import _rec, checked

ROOT = Path(__file__).resolve().parents[1]
SOURCE = deepcopy(loader.catalogue())
VARIANTS = {(p, c): e["cited_variants"] for p, r in SOURCE["policies"].items()
            for c, e in r["cells"].items() if "cited_variants" in e}
VARIANTS.update({(p, c): e["cited_variants"] for p, cells in SOURCE["cell_contracts"].items()
                 for c, e in cells.items() if "cited_variants" in e})
TWO_CODES = SOURCE["cell_contracts"]["MS.AAD.6.1v1"]["orphan_sub_domain"]["reason_texts_by_code"]


@pytest.fixture
def contracts(monkeypatch):
    """Synthetic rows exercise future-stage contracts without registering product rules."""
    data = deepcopy(SOURCE)
    for (policy, cell), variants in VARIANTS.items():
        row = data["policies"].setdefault(policy, {
            "kind": "contract_probe", "rule_id": policy + ".contract_probe", "params": {},
            "sections": list(policy_catalogue()["policies"][policy]["sections"]), "cells": {}})
        if cell not in row["cells"]:
            for name in sorted({s for v in variants for s in v}):
                if name not in row["sections"]:
                    row["sections"].append(name)
            row["cells"][cell] = {"verdict": "not_assessed", "reason_code": "data_unusable_item_value",
                                   "reason_texts": ["Data unusable: synthetic contract probe; the policy was not assessed."],
                                   "cited": variants[0]}
    policy = "MS.AAD.6.1v1"
    data["policies"][policy] = {
        "kind": "contract_probe", "rule_id": policy + ".contract_probe", "params": {},
        "sections": ["domain_settings"], "cells": {
            "orphan_sub_domain": {"verdict": "not_assessed", "reason_code": sorted(TWO_CODES)[0],
                                  "reason_texts": sorted(TWO_CODES.values()), "cited": ["domain_settings"]}}}
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    try:
        loader.catalogue()  # Exercise the real loader, not just the record checker.
        yield data
    finally:
        loader.catalogue.cache_clear()


@pytest.fixture
def assessment(tmp_path, monkeypatch):
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic-contract"}')
    return assess_run(tmp_path, ModelConfig(model_name="contract-probe"), policies=["MS.POWERBI.1.1v1"])


def assessment_for(template, record, *, legacy=False):
    result = deepcopy(template)
    policy = record["policy_id"]
    item = policy_catalogue()["policies"][policy]
    detail = {"class": "value_rule", "rule_id": loader.row_for(policy)["rule_id"],
              "section": record["cited_sections"], "field": None, "value": None,
              **{k: record[k] for k in ("cell", "reason_code", "reason_text")}}
    result["policies"][0].update(policy_id=policy, rule_precheck=detail)
    result["policies"][0].update(precheck_response(detail, item["policy_item"], item["sections"], legacy=legacy))
    return result


def test_a1_exception_set_is_pinned_and_does_not_register_policies():
    # A2 citation-domains.json supplies 64 source-derived domains (190 variants).
    # The immutable catalogue supplies the three fixed SS7 order exceptions.
    serial = {p + ":" + c: variants for (p, c), variants in VARIANTS.items()}
    assert len(VARIANTS) == 67
    assert sum(len(v) > 1 for v in VARIANTS.values()) == 64
    assert sum(len(v) for v in VARIANTS.values() if len(v) > 1) == 190
    assert sum(map(len, VARIANTS.values())) == 193
    assert sha256(canonical(serial).encode()).hexdigest() == "00fd8197ded5350556d989e70be23d6c53c30ff536833ae426f0a15d85f192b7"
    # stage 5 added 11 policies (held SS 1.1 still unregistered), stage 9 the eight AAD pilot rules (A1 exception
    # contract preserved) and stage 7 sixteen AAD role and Conditional Access registrations.
    assert len(SOURCE["policies"]) == 64 + 11 + 8 + 16
    assert "MS.AAD.6.1v1" in SOURCE["policies"]
    assert set(TWO_CODES) == {"data_unusable_sub_domain_root_case", "data_unusable_sub_domain_without_root"}
    assert TWO_CODES == {
        "data_unusable_sub_domain_root_case": "Data unusable: a managed sub-domain matches a managed verified root domain only when letter case is ignored, so the export does not establish that it is under that root and its password policy is unknown; the policy was not assessed.",
        "data_unusable_sub_domain_without_root": "Data unusable: a managed sub-domain has no managed verified root domain in the export, so its password policy is unknown; the policy was not assessed."}


A2_FIXTURE = ROOT / "tests/fixtures/value-rules/vectors-a2-constructed.jsonl"
A2_VECTORS = [json.loads(line) for line in A2_FIXTURE.read_text().splitlines()]


def test_a2_constructed_fixture_identity_and_held_contracts():
    assert sha256(A2_FIXTURE.read_bytes()).hexdigest() == "0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b"
    assert len(A2_VECTORS) == 3
    held = json.loads((A2_FIXTURE.parent / "held-rows-s4.json").read_text())
    for policy, row in held.items():
        assert policy not in SOURCE["policies"]
        assert row["cells"]["rule_scope_unusable"]["cited_variants"] == VARIANTS[policy, "rule_scope_unusable"]


@pytest.mark.parametrize("vector", A2_VECTORS, ids=lambda v: v["vector_id"])
def test_a2_constructed_exact_record_response_and_wrong_citations(vector, monkeypatch, assessment):
    policy = vector["policy"]
    assert vector["origin"] == "a2-constructed" and vector["source_kind"] == "constructed"
    assert vector["gold_verdict"] is None and vector["gold_source"] is None
    data = deepcopy(SOURCE)
    # Test-only registration lets the held rows pass through the real dispatch checker.
    data["policies"].update(json.loads((A2_FIXTURE.parent / "held-rows-s4.json").read_text()))
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    before = deepcopy(vector)
    try:
        record = assess(policy, vector["sections"])
        assert record == {"policy_id": policy, "detail": {}, **{
            key: vector["rule_" + key] for key in
            ("verdict", "cell", "reason_code", "reason_text", "cited_sections")}}
        assert vector == before
        checked(record)
        row = loader.row_for(policy)
        response = as_pack_response(record, "Shall", row["sections"])
        cited = vector["rule_cited_sections"]
        assert response == {
            "claims": [
                {"id": "requirement_met", "status": "unknown", "value": None,
                 "evidence_ids": ["e0", *[f"e{row['sections'].index(s) + 1}" for s in cited]]},
                {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]}],
            "limitations": ["evidence_unusable"], "recommendations": ["recollect_unusable_evidence"]}
        result = assessment_for(assessment, record)
        assert result["policies"][0]["limitations"] == [
            "evidence_unusable", *[f"evidence_unusable:{s}:unusable" for s in cited]]
        validate_assessment(result)
        with pytest.raises(ValueError, match="wrong section"):
            checked({**record, "cited_sections": ["accepted_domains"]})
    finally:
        loader.catalogue.cache_clear()
    assert all(p not in SOURCE["policies"] for p in ("MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"))


@pytest.mark.parametrize("number", [1, 2, 3])
def test_loader_rejects_reordering_the_fixed_ss7_contract(number, monkeypatch):
    data = deepcopy(SOURCE)
    entry = data["policies"][f"MS.SECURITYSUITE.7.{number}v1"]["cells"]["preset_rule_unusable"]
    entry["cited"] = list(reversed(entry["cited"]))
    entry["cited_variants"] = [entry["cited"]]
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    try:
        with pytest.raises(ValueError, match="citation"):
            loader.catalogue()
    finally:
        loader.catalogue.cache_clear()


def test_loader_rejects_extra_reason_code_map_on_an_unrelated_cell(monkeypatch):
    data = deepcopy(SOURCE)
    entry = data["policies"]["MS.POWERBI.1.1v1"]["cells"]["licence_false"]
    entry["reason_texts_by_code"] = {entry["reason_code"]: entry["reason_texts"][0],
                                    "data_unavailable_extra": entry["reason_texts"][0]}
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    try:
        with pytest.raises(ValueError, match="reason variants"):
            loader.catalogue()
    finally:
        loader.catalogue.cache_clear()


@pytest.mark.parametrize("policy,cell", sorted(VARIANTS))
def test_each_exact_citation_variant_and_wrong_variant(policy, cell, contracts, assessment):
    row = loader.row_for(policy)
    entry = loader.cell_entry(policy, cell, row)
    for cited in VARIANTS[policy, cell]:
        record = _rec(policy, entry["verdict"], entry["reason_code"], entry["reason_texts"][0], cell, cited)
        checked(record)
        validate_assessment(assessment_for(assessment, record))
    # A duplicate is in the policy's read set but is never a permitted variant.
    wrong = VARIANTS[policy, cell][0] * 2
    record = {**record, "cited_sections": wrong}
    with pytest.raises(ValueError, match="wrong section"):
        checked(record)
    with pytest.raises(ValueError):
        validate_assessment(assessment_for(assessment, record))
    # A union of valid alternatives is not itself a permitted alternative.
    union = list(dict.fromkeys(s for v in VARIANTS[policy, cell] for s in v))
    if union not in VARIANTS[policy, cell]:
        with pytest.raises(ValueError, match="wrong section"):
            checked({**record, "cited_sections": union})
        with pytest.raises(ValueError):
            validate_assessment(assessment_for(assessment, {**record, "cited_sections": union}))
    if cell == "preset_rule_unusable":
        with pytest.raises(ValueError, match="wrong section"):
            checked({**record, "cited_sections": list(reversed(VARIANTS[policy, cell][0]))})
        with pytest.raises(ValueError):
            validate_assessment(assessment_for(assessment, {
                **record, "cited_sections": list(reversed(VARIANTS[policy, cell][0]))}))


@pytest.mark.parametrize("code,text", sorted(TWO_CODES.items()))
def test_two_reason_codes_are_paired_with_their_own_text(code, text, contracts, assessment):
    record = _rec("MS.AAD.6.1v1", "not_assessed", code, text, "orphan_sub_domain", ["domain_settings"])
    checked(record)
    validate_assessment(assessment_for(assessment, record))
    for bad in ({**record, "reason_code": "data_unusable_other"},
                {**record, "reason_text": next(t for t in TWO_CODES.values() if t != text)}):
        with pytest.raises(ValueError, match="catalogue"):
            checked(bad)
        with pytest.raises(ValueError, match="cell or reason"):
            validate_assessment(assessment_for(assessment, bad))


@pytest.mark.parametrize("sections,cell,code,text,kind,recommendation", [
    ({"powerbi_license_found": False, "powerbi_access_denied_reason": "", "powerbi_tenant_settings": []},
     "licence_false", "data_unavailable_no_licence",
     "Data unavailable: licence not detected: no Power BI licence was found (a false read can also mean missing permissions or a failed command), so the tenant settings could not be read; the policy was not assessed.",
     "blocked", "check_licence_or_permissions"),
    ({"powerbi_license_found": True, "powerbi_access_denied_reason": "", "powerbi_tenant_settings": []},
     "settings_empty", "data_unavailable_setting_not_found",
     "Data unavailable: tenant setting PublishToWeb is not in the exported settings (the list is empty); the policy was not assessed.",
     "absent", "recollect_unusable_evidence"),
    ({"powerbi_license_found": True, "powerbi_access_denied_reason": "", "powerbi_tenant_settings": None},
     "settings_not_a_list", "data_unusable_settings_not_a_list",
     "Data unusable: powerbi_tenant_settings is not a list of tenant-setting objects; the policy was not assessed.",
     "unusable", "recollect_unusable_evidence"),
])
def test_evidence_unusable_exact_response(sections, cell, code, text, kind, recommendation, assessment):
    policy = "MS.POWERBI.1.1v1"
    # The expected strings are closed specification text, independent of evidence.
    sections["canary"] = "private-person@example.invalid"
    record = assess(policy, sections)
    assert (record["cell"], record["reason_code"], record["reason_text"]) == (cell, code, text)
    detail = precheck_policy(policy, sections, list(sections), value_rules=True)
    item = policy_catalogue()["policies"][policy]
    response = precheck_response(detail, item["policy_item"], item["sections"])
    assert response["limitations"] == ["evidence_unusable", *[
        f"evidence_unusable:{s}:{kind}" for s in record["cited_sections"]]]
    assert response["recommendations"] == [recommendation]
    assert response["claims"][0]["status"] == "unknown" and response["claims"][0]["value"] is None
    assert "private-person" not in canonical([record, response])
    validate_assessment(assessment_for(assessment, record))
    validate_assessment(assessment_for(assessment, record, legacy=True))
    for key, bad in (("recommendations", ["collect_missing_evidence_section"]),
                     ("limitations", ["evidence_unusable"]),
                     ("limitations", ["evidence_unusable", "evidence_unusable:other:unusable"])):
        altered = assessment_for(assessment, record)
        altered["policies"][0][key] = bad
        with pytest.raises(ValueError):
            validate_assessment(altered)
    legacy = as_pack_response(record, "Shall", item["sections"], legacy=True)
    assert legacy["limitations"] == ["required_evidence_section_not_collected"]
    assert legacy["recommendations"] == ["collect_missing_evidence_section"]


def test_undecidable_keeps_baseline_review_and_missing_stays_missing(assessment):
    policy = "MS.POWERPLATFORM.2.3v1"
    record = assess(policy, {"dlp_policies": [], "tenant_id": "synthetic-tenant"})
    assert record["reason_code"] == "data_unavailable_no_baseline_text"
    result = assessment_for(assessment, record)
    assert result["policies"][0]["recommendations"] == ["review_policy_against_baseline_text"]
    assert all(s.startswith("evidence_unusable") for s in result["policies"][0]["limitations"])
    validate_assessment(result)
    record = assess("MS.POWERBI.1.1v1", {})
    result = assessment_for(assessment, record)
    assert result["policies"][0]["recommendations"] == ["collect_missing_evidence_section"]
    assert all(s.startswith("required_evidence_section_not_collected") for s in result["policies"][0]["limitations"])
    validate_assessment(result)


def test_legacy_schema_and_model_non_rule_fixture_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITEX_DISABLE_VALUE_RULES", "1")
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic-contract"}')
    result = assess_run(tmp_path, ModelConfig(model_name="contract-probe"), policies=["MS.POWERBI.1.1v1"])
    for version in ("2026-10-29", "2026-11-05"):
        result["schema_version"] = version
        validate_assessment(result)
    rows = []
    for line in (ROOT / "tests/fixtures/model-serving-cases.jsonl").read_text().splitlines():
        item = json.loads(line)
        case = json.loads(next(m["content"] for m in item["messages"] if m["role"] == "user"))
        rows.append({"precheck": precheck_case(case), "messages": messages_for(case)})
    # Captured at the required clean starting HEAD before this contract change.
    assert sha256(canonical(rows).encode()).hexdigest() == "efd8c647e7982248916068d1c40c0d798c2c47dec5aa958cc990faa0a3ce1882"


def test_all_external_final_vectors_have_valid_contracts(monkeypatch, tmp_path):
    vectors = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS")
    inventory = os.getenv("AUDITEX_TEST_VALUE_RULE_CATALOGUE")
    if not vectors or not inventory:
        pytest.skip("set final value-rule vectors and catalogue paths for all 102 policies")
    ref = json.loads(Path(inventory).read_text())
    data = deepcopy(SOURCE)
    data["policies"] = {}
    for policy, row in ref.items():
        row = deepcopy(row)
        row.update(rule_id=policy + "." + row["kind"], params={})
        row["cells"]["section_not_collected"]["cited"] = row["sections"]
        # Reuse the shipped single source for previously added variants.
        for cell, entry in SOURCE["policies"].get(policy, {}).get("cells", {}).items():
            if "cited_variants" in entry:
                row["cells"][cell]["cited_variants"] = entry["cited_variants"]
        data["policies"][policy] = row
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    counts = Counter()
    dual_codes = Counter()
    try:
        loader.catalogue()
        for line in Path(vectors).open():
            v = json.loads(line)
            record = _rec(v["policy"], v["rule_verdict"], v["rule_reason_code"], v["rule_reason_text"],
                          v["rule_cell"], v["rule_cited_sections"])
            checked(record)
            counts[v["policy"] + ":" + v["rule_cell"]] += 1
            if v["policy"] == "MS.AAD.6.1v1" and v["rule_cell"] == "orphan_sub_domain":
                dual_codes[v["rule_reason_code"]] += 1
            entry = ref[v["policy"]]["cells"][v["rule_cell"]]
            if v["rule_verdict"] == "not_assessed":
                modern = as_pack_response(record, "Shall", data["policies"][v["policy"]]["sections"])
                assert modern["recommendations"] == entry["recommendations"]
                assert modern["limitations"] == [entry["limitations"][0]]
        assert sum(counts.values()) == 26898
        assert len(counts) == 1084
        assert dual_codes == {"data_unusable_sub_domain_without_root": 22, "data_unusable_sub_domain_root_case": 9}
        (tmp_path / "contract-vector-counts.json").write_text(json.dumps(dict(counts), sort_keys=True, indent=2))
    finally:
        loader.catalogue.cache_clear()
