"""Stage-5 rows obey the current shared catalogue and assessment contracts."""
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from azure_tenant_audit.value_rules import catalogue as loader
from azure_tenant_audit.value_rules.record import checked
from test_value_rules_s5 import DIRECTORY, FIXTURE, POLICIES, SS11, direct, read_rows, rule_rows


def assessment_with_comparison(template, record):
    """Replace claims, derive their comparison and refresh the summary totals."""
    from auditex.rule_assessment import _totals
    from test_value_rules_contract import assessment_for

    result = assessment_for(template, record)
    row = result["policies"][0]
    requirement = next((claim for claim in row["claims"] if claim["id"] == "requirement_met"), {})
    model_status = None
    if row["validation_status"] == "valid" and requirement.get("status") == "confirmed":
        model_status = "pass" if requirement.get("value") is True else "fail"
    comparison = row["comparison"]
    comparison["model_status"] = model_status
    comparison["result"] = "not_assessed"
    if model_status is not None and comparison["baseline_status"] in {"pass", "fail"}:
        comparison["result"] = "agree" if comparison["baseline_status"] == model_status else "disagree"
    result["totals"] = _totals(result["policies"])
    return result


def test_ss11_is_enabled_and_every_stage5_vector_passes_the_dispatch_checker():
    assert SS11 in loader.catalogue()["policies"]
    for vector in read_rows(FIXTURE):
        checked(direct(vector["policy"], vector["sections"]))


def test_fixture_origins_and_p9_correction_are_auditable():
    from importlib.util import module_from_spec, spec_from_file_location

    spec = spec_from_file_location("stage5_builder", DIRECTORY.parents[2] / "scripts/build-value-rule-fixture-s5.py")
    builder = module_from_spec(spec)
    spec.loader.exec_module(builder)
    shared = builder.shared_builder()
    rows = read_rows(FIXTURE)
    assert all(row["vector_id"] and builder.include_held(row, shared) for row in rows)
    counts = Counter("pack-train" if r["source_kind"] == "packlic-train" else r["source_kind"] for r in rows)
    counts.update({"pack-test": 0, "pilot": 0})
    manifest = json.loads((DIRECTORY / "manifest-s5.json").read_text())
    assert counts == manifest["origin_audit"]
    assert manifest["replacement_recipes"] == []
    corrected = [r for r in rows if "source_gold_response" in r]
    assert len(corrected) == 1
    vector = corrected[0]
    assert vector["vector_id"] == builder.P9_VECTOR
    assert vector["parity_exempt"].startswith("D90:")
    original = deepcopy(vector["source_gold_response"])
    assert original["claims"][0]["evidence_ids"] == ["e0", "e3", "e4"]
    original["claims"][0]["evidence_ids"].remove("e4")
    assert vector["gold_response"] == original
    assert manifest["gold_corrections"] == {builder.P9_VECTOR: builder.P9_RECIPE}


def test_each_cell_validates_as_a_modern_assessment(tmp_path, monkeypatch):
    from azure_tenant_audit.scuba_assessment import validate_assessment
    from azure_tenant_audit.value_rules.record import as_pack_response
    from auditex.model_serving import ModelConfig, assess_run

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    (tmp_path / "run-manifest.json").write_text('{"run_id":"synthetic-stage5"}')
    template = assess_run(tmp_path, ModelConfig(model_name="contract-probe"), policies=["MS.POWERBI.1.1v1"])
    seen = set()
    for vector in read_rows(FIXTURE):
        key = vector["policy"], vector["rule_cell"]
        if key in seen:
            continue
        seen.add(key)
        record = checked(direct(vector["policy"], vector["sections"]))
        record["cited_sections"] = record["cited_sections"] or rule_rows()[vector["policy"]]["sections"]
        result = assessment_with_comparison(template, record)
        validate_assessment(result)
        response = as_pack_response(record, vector["criticality"], list(vector["sections"]))
        if record["verdict"] == "not_assessed":
            expected = "required_evidence_section_not_collected" if record["cell"] == "section_not_collected" else "evidence_unusable"
            assert response["limitations"] == [expected]
    assert len(seen) == 202


def test_optional_current_reference_and_a1_cells():
    from importlib.util import module_from_spec, spec_from_file_location

    source = os.getenv("AUDITEX_TEST_VALUE_RULE_CATALOGUE")
    if not source:
        pytest.skip("set AUDITEX_TEST_VALUE_RULE_CATALOGUE for v3.9.1+A1 verification")
    reference = json.loads(Path(source).read_text())
    spec = spec_from_file_location("stage5_reference", Path(source).with_name("ref_impl.py"))
    ref = module_from_spec(spec)
    spec.loader.exec_module(ref)
    a1 = json.loads(Path(source).with_name("a1-evidence-unusable-cells.json").read_text())
    expected = {(e["policy"], e["cell"]): e for e in a1 if e["policy"] in POLICIES}
    reached = set()
    from azure_tenant_audit.value_rules.record import as_pack_response
    for vector in read_rows(FIXTURE):
        policy = vector["policy"]
        record = direct(policy, vector["sections"])
        reference_record = ref.assess(policy, deepcopy(vector["sections"]))
        for key in ("verdict", "cell", "reason_code", "reason_text", "cited_sections"):
            assert record[key] == reference_record[key], (vector["vector_id"], key)
        cell = record["cell"]
        entry = reference[policy]["cells"][cell]
        assert record["reason_text"] in entry["reason_texts"]
        assert record["reason_code"] == entry["reason_code"]
        if (policy, cell) in expected:
            reached.add((policy, cell))
            response = as_pack_response(record, vector["criticality"], list(vector["sections"]))
            assert response["limitations"] == ["evidence_unusable"]
            assert response["recommendations"] == [expected[policy, cell]["recommendation"]]
    assert reached == set(expected)
