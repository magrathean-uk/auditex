"""A1/A2 shared contract: exact variants, additive assessments and unchanged offline answers."""
import json
import os
from collections import Counter
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from auditex.rule_assessment import (
    assess_run,
    canonical,
    policy_catalogue,
    precheck_case,
)
from azure_tenant_audit.scuba_assessment import validate_assessment
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import as_pack_response, assess
from azure_tenant_audit.value_rules import catalogue as loader
from azure_tenant_audit.value_rules.record import _rec, checked

ROOT = Path(__file__).resolve().parents[1]
SOURCE = deepcopy(loader.catalogue())
VARIANTS = {(p, c): e["cited_variants"] for p, r in SOURCE["policies"].items()
            for c, e in r["cells"].items() if "cited_variants" in e}
VARIANTS.update({(p, c): [e["cited"]] for p, r in SOURCE["policies"].items()
                 for c, e in r["cells"].items() if (p, c) in loader._ORDER_EXCEPTIONS})
TWO_CODES = SOURCE["policies"]["MS.AAD.6.1v1"]["cells"]["orphan_sub_domain"]["reason_texts_by_code"]


@pytest.fixture
def contracts():
    """The shipped catalogue now holds every A1/A2 contract on its own cells; nothing is registered synthetically."""
    loader.catalogue.cache_clear()
    yield loader.catalogue()
    loader.catalogue.cache_clear()


@pytest.fixture
def assessment(tmp_path, monkeypatch):
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic-contract"}')
    return assess_run(tmp_path, policies=["MS.POWERBI.1.1v1"])


def assessment_for(template, record, *, legacy=False):
    result = deepcopy(template)
    # The helper replaces the answer; an explanation of the old answer cannot be carried across.
    result["policies"][0].pop("explainer", None)
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
    # v3.9.1: all 102 policies are registered, including SS 1.1, 6.1 and 6.2 (previously held for the collector).
    assert len(SOURCE["policies"]) == 102
    assert sum(len(r["cells"]) for r in SOURCE["policies"].values()) == 1084
    assert "cell_contracts" not in SOURCE and "rule_failure" not in SOURCE
    assert set(TWO_CODES) == {"data_unusable_sub_domain_root_case", "data_unusable_sub_domain_without_root"}
    assert TWO_CODES == {
        "data_unusable_sub_domain_root_case": "Data unusable: a managed sub-domain matches a managed verified root domain only when letter case is ignored, so the export does not establish that it is under that root and its password policy is unknown; the policy was not assessed.",
        "data_unusable_sub_domain_without_root": "Data unusable: a managed sub-domain has no managed verified root domain in the export, so its password policy is unknown; the policy was not assessed."}


A2_FIXTURE = ROOT / "tests/fixtures/value-rules/vectors-a2-constructed.jsonl"
A2_VECTORS = [json.loads(line) for line in A2_FIXTURE.read_text().splitlines()]


def test_a2_constructed_fixture_identity_and_registered_contracts():
    assert sha256(A2_FIXTURE.read_bytes()).hexdigest() == "0351259550c0a87d27d65cfac8f98b8547334cbd1d94321af244ad06b622ac0b"
    assert len(A2_VECTORS) == 3
    for policy in ("MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"):
        assert ["protection_policy_rules"] in VARIANTS[policy, "rule_scope_unusable"]
        assert len(VARIANTS[policy, "rule_scope_unusable"]) == 4
    assert ["built_in_protection_rules"] in VARIANTS["MS.SECURITYSUITE.1.3v1", "list_element_unusable"]


@pytest.mark.parametrize("vector", A2_VECTORS, ids=lambda v: v["vector_id"])
def test_a2_constructed_exact_record_response_and_wrong_citations(vector, assessment):
    policy = vector["policy"]
    assert vector["origin"] == "a2-constructed" and vector["source_kind"] == "constructed"
    assert vector["gold_verdict"] is None and vector["gold_source"] is None
    before = deepcopy(vector)
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
    # Build a historical precheck fixture explicitly; the removed switch cannot select this route.
    monkeypatch.setattr("auditex.rule_assessment.precheck_case", lambda case, **kw: precheck_case(
        case, **{**kw, "value_rules": False}))
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic-contract"}')
    result = assess_run(tmp_path, policies=["MS.POWERBI.1.1v1"])
    for version in ("2026-10-29", "2026-11-05"):
        result["schema_version"] = version
        validate_assessment(result)
    rows = []
    for line in (ROOT / "tests/fixtures/model-serving-cases.jsonl").read_text().splitlines():
        item = json.loads(line)
        case = json.loads(next(m["content"] for m in item["messages"] if m["role"] == "user"))
        # The fixture records the retired prompt; its first two messages equal what messages_for built.
        rows.append({"precheck": precheck_case(case), "messages": item["messages"][:2]})
    # Captured at the required clean starting HEAD before this contract change.
    assert sha256(canonical(rows).encode()).hexdigest() == "efd8c647e7982248916068d1c40c0d798c2c47dec5aa958cc990faa0a3ce1882"


def test_all_external_final_vectors_have_valid_contracts(tmp_path):
    vectors = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS_V391")
    if not vectors:
        pytest.skip("set AUDITEX_TEST_VALUE_RULE_VECTORS_V391 to the replay kit vectors.jsonl")
    shipped = loader.catalogue()["policies"]
    # The kit's own catalogue is the independent reference; the shipped one stands in only when absent.
    kit_catalogue = Path(vectors).parent / "cell-catalogue.json"
    ref = json.loads(kit_catalogue.read_text()) if kit_catalogue.is_file() else shipped
    assert set(ref) == set(shipped)
    counts = Counter()
    dual_codes = Counter()
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
            modern = as_pack_response(record, "Shall", shipped[v["policy"]]["sections"])
            assert modern["recommendations"] == entry["recommendations"]
            assert modern["limitations"] == [entry["limitations"][0]]
    assert sum(counts.values()) == 26898
    assert len(counts) == 1084
    assert dual_codes == {"data_unusable_sub_domain_without_root": 22, "data_unusable_sub_domain_root_case": 9}
    (tmp_path / "contract-vector-counts.json").write_text(json.dumps(dict(counts), sort_keys=True, indent=2))


A1_FAULT_TEXT = ("Not assessed: Auditex could not evaluate this policy on the collected evidence. "
                 "This is a product fault, not a tenant setting.")
A1_NO_RULE_TEXT = "Not assessed: Auditex has no rule for this policy yet."


def test_shared_reasons_are_catalogued_once_and_are_not_cells():
    shared = loader.catalogue()["shared_reasons"]
    assert shared == {
        "rule_evaluation_failed": {"reason_code": "rule_evaluation_failed", "verdict": "not_assessed",
                                   "reason_text": A1_FAULT_TEXT, "recommendation": "report_product_fault"},
        "rule_not_implemented": {"reason_code": "rule_not_implemented", "verdict": "not_assessed",
                                 "reason_text": A1_NO_RULE_TEXT, "recommendation": None}}
    assert all(not set(shared) & set(row["cells"]) for row in loader.catalogue()["policies"].values())
    assert sum(len(row["cells"]) for row in loader.catalogue()["policies"].values()) == 1084


@pytest.mark.parametrize("policy", sorted(loader.rule_policies()))
def test_rule_failure_is_a_null_cell_citing_the_whole_read_set(policy):
    from azure_tenant_audit.value_rules import rule_failure
    record = rule_failure(policy)
    assert record == {"policy_id": policy, "verdict": "not_assessed", "reason_code": "rule_evaluation_failed",
                      "reason_text": A1_FAULT_TEXT, "cell": None,
                      "cited_sections": list(loader.row_for(policy)["sections"]), "detail": {}}
    assert checked(record) is record
    item = policy_catalogue()["policies"][policy]
    response = as_pack_response(record, item["policy_item"]["criticality"], item["sections"])
    assert response["limitations"] == [] and response["recommendations"] == ["report_product_fault"]
    assert response["claims"][0]["status"] == "unknown" and response["claims"][0]["value"] is None
    detail = {"class": "value_rule", "rule_id": loader.row_for(policy)["rule_id"], "section": record["cited_sections"],
              "field": None, "value": None, "cell": None, "reason_code": record["reason_code"],
              "reason_text": record["reason_text"]}
    assert precheck_response(detail, item["policy_item"], item["sections"]) == response
    assert precheck_response(detail, item["policy_item"], item["sections"], named_limitations=False) == response


def test_rule_failure_validates_end_to_end_and_no_rule_is_not_a_rule_record(assessment, monkeypatch):
    from azure_tenant_audit.value_rules import rule_failure
    policy = "MS.EXO.13.1v1"
    failed = rule_failure(policy)
    result = assessment_for(assessment, failed)
    assert result["policies"][0]["rule_precheck"]["cell"] is None
    assert result["policies"][0]["recommendations"] == ["report_product_fault"] and result["policies"][0]["limitations"] == []
    validate_assessment(result)
    for key, bad in (("reason_text", "Not assessed: other."), ("reason_code", "rule_failed"),
                     ("section", result["policies"][0]["rule_precheck"]["section"][:0] or ["org_config", "org_config"])):
        tampered = deepcopy(result)
        tampered["policies"][0]["rule_precheck"][key] = bad
        with pytest.raises(ValueError):
            validate_assessment(tampered)
    # No rule: product answers a row-level reason (auditex.rule_assessment._uncovered_record), never a rule record. Its
    # constant is the catalogued A1 text, and a rule record that claims it is refused by every checker.
    from auditex.rule_assessment import RULE_NOT_IMPLEMENTED_TEXT
    shared = loader.shared_reason("rule_not_implemented")
    assert RULE_NOT_IMPLEMENTED_TEXT == shared["reason_text"] == A1_NO_RULE_TEXT and shared["recommendation"] is None
    sections = policy_catalogue()["policies"][policy]["sections"]
    claimed = {"policy_id": policy, "verdict": "not_assessed", "reason_code": "rule_not_implemented",
               "reason_text": A1_NO_RULE_TEXT, "cell": None, "cited_sections": list(sections), "detail": {}}
    with pytest.raises(ValueError):
        checked(claimed)
    detail = {"class": "value_rule", "rule_id": policy + ".rule_not_implemented", "section": list(sections),
              "field": None, "value": None, "cell": None, "reason_code": "rule_not_implemented",
              "reason_text": A1_NO_RULE_TEXT}
    with pytest.raises(ValueError):
        precheck_response(detail, policy_catalogue()["policies"][policy]["policy_item"], sections)
    result = deepcopy(assessment)
    result["policies"][0].update(policy_id=policy, rule_precheck=detail)
    with pytest.raises(ValueError):
        validate_assessment(result)


def test_old_rule_failure_sentinel_is_rejected_with_a_clear_error(assessment):
    """Before A1 a failed rule was a cell named after its reason code. Nothing accepts that any more."""
    policy = "MS.EXO.13.1v1"
    item = policy_catalogue()["policies"][policy]
    legacy = {"policy_id": policy, "verdict": "not_assessed", "reason_code": "rule_evaluation_failed",
              "reason_text": A1_FAULT_TEXT, "cell": "rule_evaluation_failed",
              "cited_sections": list(loader.row_for(policy)["sections"]), "detail": {}}
    with pytest.raises(ValueError, match="must be null"):
        checked(legacy)
    detail = {"class": "value_rule", "rule_id": loader.row_for(policy)["rule_id"], "section": legacy["cited_sections"],
              "field": None, "value": None, "cell": "rule_evaluation_failed",
              "reason_code": "rule_evaluation_failed", "reason_text": A1_FAULT_TEXT}
    with pytest.raises(ValueError, match="Legacy rule-failure sentinel"):
        precheck_response(detail, item["policy_item"], item["sections"])
    result = deepcopy(assessment)
    result["policies"][0].update(policy_id=policy, rule_precheck=detail)
    result["policies"][0].update(claims=[
        {"id": "requirement_met", "status": "unknown", "value": None, "evidence_ids": ["e0"]},
        {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]}],
        limitations=[], recommendations=["report_product_fault"])
    with pytest.raises(ValueError, match="Legacy rule-failure sentinel"):
        validate_assessment(result)
    # The catalogue refuses the old top-level entry and a cell that shadows a shared reason.
    for edit in (lambda d: d.update(rule_failure={"cell": "rule_evaluation_failed"}),
                 lambda d: d.update(cell_contracts={}),
                 lambda d: d["policies"]["MS.EXO.13.1v1"]["cells"].update(
                     rule_evaluation_failed=dict(next(iter(d["policies"]["MS.EXO.13.1v1"]["cells"].values()))))):
        data = deepcopy(SOURCE)
        edit(data)
        loader.catalogue.cache_clear()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loader, "open_text_resource", lambda _, data=data: json.dumps(data))
            with pytest.raises(ValueError):
                loader.catalogue()
    loader.catalogue.cache_clear()


def _loader_rejects(edit, match=None):
    data = deepcopy(SOURCE)
    edit(data["policies"])
    loader.catalogue.cache_clear()
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
            with pytest.raises(ValueError, match=match):
                loader.catalogue()
    finally:
        loader.catalogue.cache_clear()


def _cell(policies, policy, cell):
    return policies[policy]["cells"][cell]


def test_loader_checks_the_a1_evidence_fields_against_the_reason_code():
    blocked = ("MS.POWERBI.1.1v1", "licence_false")
    unusable = ("MS.POWERBI.1.1v1", "settings_not_a_list")
    met = next((p, c) for p, r in SOURCE["policies"].items() for c, e in r["cells"].items() if e["verdict"] == "met")
    assert _cell(SOURCE["policies"], *blocked)["recommendations"] == ["check_licence_or_permissions"]
    assert _cell(SOURCE["policies"], "MS.AAD.1.1v1", "section_not_collected")["evidence_kind"] is None
    edits = [
        (lambda d: _cell(d, *blocked).pop("evidence_kind"), "evidence kind"),
        (lambda d: _cell(d, *blocked).update(evidence_kind="unusable"), "evidence kind"),
        (lambda d: _cell(d, *blocked).update(recommendations=["recollect_unusable_evidence"]), "evidence limitations"),
        (lambda d: _cell(d, *unusable).update(limitations=["evidence_unusable"]), "evidence limitations"),
        (lambda d: _cell(d, *met).update(evidence_kind="absent"), "evidence fields"),
        (lambda d: _cell(d, "MS.AAD.1.1v1", "section_not_collected").update(evidence_kind="absent"), "evidence kind"),
        (lambda d: _cell(d, "MS.AAD.1.1v1", "no_policies").update(recommendations=[]), "evidence fields"),
    ]
    for edit, match in edits:
        _loader_rejects(edit, match)


def test_loader_accepts_cited_variants_only_on_not_assessed_cells_and_exactly_as_listed():
    met = next((p, c) for p, r in SOURCE["policies"].items() for c, e in r["cells"].items() if e["verdict"] == "met")
    _loader_rejects(lambda d: _cell(d, *met).update(cited_variants=[_cell(d, *met)["cited"]]), "citation")
    _loader_rejects(lambda d: _cell(d, "MS.AAD.1.1v1", "section_not_collected").update(
        cited_variants=[_cell(d, "MS.AAD.1.1v1", "section_not_collected")["cited"]]), "citation")
    # A2: every one of the four SS 6.1 variants is needed and nothing else is accepted.
    cell = ("MS.SECURITYSUITE.6.1v1", "rule_scope_unusable")
    assert ["protection_policy_rules"] in _cell(SOURCE["policies"], *cell)["cited_variants"]
    _loader_rejects(lambda d: _cell(d, *cell).update(cited_variants=[["no_such_section"]]), "citation")
    _loader_rejects(lambda d: _cell(d, *cell).update(
        cited_variants=[v for v in _cell(d, *cell)["cited_variants"] if v != ["protection_policy_rules"]]), "citation")


def test_catalogue_is_spec_v391_with_the_unchanged_scubagear_pin():
    data = loader.catalogue()
    assert (data["spec_version"], data["scubagear_revision"], data["schema_version"]) == ("v3.9.1", "2446ad72", 1)
    for field, value in (("spec_version", "v3.9"), ("scubagear_revision", "00000000"), ("schema_version", 2)):
        bad = {**SOURCE, field: value}
        loader.catalogue.cache_clear()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(loader, "open_text_resource", lambda _, bad=bad: json.dumps(bad))
            with pytest.raises(ValueError, match="Invalid value-rule catalogue"):
                loader.catalogue()
    loader.catalogue.cache_clear()
