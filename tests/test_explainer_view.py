"""Part 3 privacy boundary and isolation controls, adapted from S/A tests."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from azure_tenant_audit.explainer import build_view
from azure_tenant_audit.explainer.textkit import FAULT, canonical, resolved_units
from azure_tenant_audit.explainer.view import EMAIL, VIEW_FIELDS, mask_emails, shown_section

FIX = Path(__file__).parent / "fixtures/explainer/renderer"
B = json.loads((Path(__file__).resolve().parents[1] / "configs/explainer-baselines.json").read_text())
C = json.loads((Path(__file__).resolve().parents[1] / "configs/explainer-what-to-collect.json").read_text())
PID = "MS.AAD.1.1v1"


def record():
    return {"policy_id": PID, "cell": "met_policy_clean", "verdict": "met", "reason_code": "policy_meets_requirement",
            "reason_text": "Requirement met: a Conditional Access policy meets every condition.", "cited_sections": ["scuba_config"]}


def build(rec=None, sections=None, order=None):
    return build_view(rec or record(), sections if sections is not None else {"scuba_config": None},
                      order or ["conditional_access_policies", "scuba_config"], baselines=B, collection=C)


def test_exact_fields_cited_evidence_and_stable_positions():
    view = build(sections={"conditional_access_policies": "CANARY", "scuba_config": {"M365Environment": "commercial", "secret_path": "CANARY"}})
    assert set(view) == VIEW_FIELDS
    assert [e["id"] for e in view["evidence"]] == ["e0", "e2"]
    assert [e["section"] for e in view["evidence"]] == ["policy", "scuba_config"]
    assert "CANARY" not in canonical(view)
    assert view["evidence"][0]["observed"] == {"policy_id": PID, "requirement": B["policies"][PID]["requirement"], "criticality": B["policies"][PID]["criticality"]}


@pytest.mark.parametrize("extra", ["detail", "labels", "tenant_id", "tenant_name", "run_id", "paths", "timestamps", "credentials", "other_policy", "internal_view"])
def test_extra_record_fields_are_never_read(extra):
    class Guard(dict):
        def __getitem__(self, key):
            if key == extra:
                raise AssertionError("forbidden record read")
            return super().__getitem__(key)
        def get(self, key, default=None):
            if key == extra:
                raise AssertionError("forbidden record read")
            return super().get(key, default)
    rec = Guard(record())
    rec[extra] = "SECRET_CANARY"
    assert build(rec) == build()


def test_no_input_mutation_or_aliasing():
    rec = record()
    sections = {"scuba_config": {"M365Environment": "commercial"}}
    inputs = deepcopy((rec, sections, B, C))
    view = build(rec, sections)
    assert (rec, sections, B, C) == inputs
    view["evidence"][1]["observed"]["M365Environment"] = "changed"
    assert (rec, sections, B, C) == inputs


@pytest.mark.parametrize("value,want", [(None, None), ([], {"not_shown": "shape"}), (True, {"not_shown": "shape"}),
    ({"M365Environment": ["commercial"], "collection_status": "not_collected", "ExcludedUsers": "SECRET"},
     {"M365Environment": {"not_shown": "shape"}, "collection_status": "not_collected"})])
def test_scuba_config_minimisation(value, want):
    assert shown_section("scuba_config", value) == want


def test_json_cap_counts_canonical_characters_after_guard():
    assert shown_section("sample", "x" * 5998) == "x" * 5998
    assert shown_section("sample", "x" * 5999) == {"not_shown": "size"}
    assert shown_section("sample", "é" * 5998) == "é" * 5998
    assert shown_section("sample", {"a": "x" * 6000}) == {"not_shown": "size"}


def test_email_guard_idempotent_values_only_no_extra_pseudonymisation():
    data = {"key@example.com": ["john@example.com", "***@example.com", {"DisplayName": "Alice", "id": "GUID", "Role": "Global Administrator"}]}
    expected = {"key@example.com": ["***@example.com", "***@example.com", {"DisplayName": "Alice", "id": "GUID", "Role": "Global Administrator"}]}
    assert mask_emails(data) == expected and mask_emails(expected) == expected
    source = (Path(__file__).resolve().parents[1] / "src/auditex/scuba_projection.py").read_text()
    assert EMAIL.pattern in source


def test_missing_and_null_citations():
    assert [e["id"] for e in build(sections={})["evidence"]] == ["e0"]
    rec = record()
    rec["cited_sections"] = None
    view = build(rec, {"conditional_access_policies": [], "scuba_config": None})
    assert [e["id"] for e in view["evidence"]] == ["e0", "e1", "e2"]
    rec["cited_sections"] = []
    assert [e["id"] for e in build(rec)["evidence"]] == ["e0"]


@pytest.mark.parametrize("cites", ["scuba_config", ["unknown"], ["scuba_config", "scuba_config"], [None]])
def test_rejects_invalid_citations(cites):
    rec = dict(record(), cited_sections=cites)
    with pytest.raises(ValueError):
        build(rec)


@pytest.mark.parametrize("order", [["scuba_config", "scuba_config"], ["policy"], ["tenant/path"], [None], "scuba_config"])
def test_rejects_invalid_section_order(order):
    with pytest.raises(ValueError):
        build(order=order)


def test_unknown_policy_and_invalid_record_rejected():
    with pytest.raises(KeyError):
        build(dict(record(), policy_id="unknown"))
    with pytest.raises(ValueError):
        build({"policy_id": PID})
    with pytest.raises(ValueError):
        build(dict(record(), verdict="deferred"))


def test_baseline_addresses_and_commands_preserved_in_public_remediation():
    rec = dict(record(), policy_id="MS.EXO.4.3v1", verdict="not_met", cell="synthetic", cited_sections=[])
    view = build(rec)
    assert "reports@dmarc.cyber.dhs.gov" in " ".join(view["approved_remediation"])
    assert view["approved_remediation"] == [u["text"] for u in resolved_units(B, rec["policy_id"])]
    # The builder does not validate catalogue records: the renderer rejects this synthetic cell.


def test_xref_own_then_target_children_including_pp_without_a_rule():
    for x in B["xrefs"]:
        got = resolved_units(B, x["policy_id"])
        own = B["policies"][x["policy_id"]]["instructions"]
        assert got[:len(own)] == own
        target = B["policies"][x["target"]]["instructions"]
        if x["labels"] is None:
            expected = target
        else:
            expected, enabled = [], False
            for unit in target:
                if unit["level"] == 0:
                    enabled = unit["kind"] == "num" and unit["label"] in x["labels"]
                if enabled:
                    expected.append(unit)
        assert got[len(own):] == expected
    assert len(B["xrefs"]) == 16


def test_unknown_requirement_is_empty_and_criticality_null():
    entry = next(e for e in C["cells"] if e["policy_id"] == "MS.POWERPLATFORM.2.3v1")
    rec = dict(record(), policy_id=entry["policy_id"], cell=entry["cell"], verdict=entry["verdict"], cited_sections=[])
    view = build(rec)
    assert view["evidence"][0]["observed"] == {"policy_id": rec["policy_id"], "requirement": "", "criticality": None}


def test_shared_fault_requires_collected_evidence_and_ignores_diagnostics():
    rec = {"policy_id": PID, **{k: FAULT[k] for k in ("cell", "verdict", "reason_code", "reason_text")}, "cited_sections": None, "detail": "SECRET"}
    sections = {"conditional_access_policies": [], "scuba_config": None}
    view = build(rec, sections)
    assert view["approved_remediation"] == ["Report this fault to the product team at contact+auditex@magrathean.uk."]
    assert "SECRET" not in canonical(view)
    for bad in ({}, {"conditional_access_policies": {"collection_status": "not_collected"}, "scuba_config": None}):
        with pytest.raises(ValueError):
            build(rec, bad)
    for changes in ({"cell": "rule_evaluation_failed"}, {"reason_text": FAULT["reason_text"] + " secret"}, {"cited_sections": []}):
        with pytest.raises(ValueError):
            build(dict(rec, **changes), sections)


def test_direct_builder_fixed_read_sets_for_all_102_policies():
    from azure_tenant_audit.explainer.textkit import expand_template
    template = expand_template(json.loads((Path(__file__).resolve().parents[1] / 'configs/explainer-template.json').read_text()))
    assert len(C['policy_sections']) == len(template['policies']) == 102
    for pid, meta in template['policies'].items():
        required = meta['sections']
        assert required == C['policy_sections'][pid]
        rec = dict(record(), policy_id=pid, cited_sections=None)
        sections = {s: [] for s in required}
        sections['extra_uncited'] = {'value': 'SYNTHETIC_PRIVATE_VALUE'}
        order = ['extra_uncited', *required]
        view = build_view(rec, sections, order, baselines=B, collection=C)
        assert 'SYNTHETIC_PRIVATE_VALUE' not in canonical(view)
        assert [e['section'] for e in view['evidence'][1:]] == required
        assert [e['id'] for e in view['evidence'][1:]] == [f'e{i}' for i in range(2, len(required) + 2)]
        for cites in (['extra_uncited'], [*required, 'extra_uncited']):
            with pytest.raises(ValueError, match='citations'):
                build_view(dict(rec, cited_sections=cites), sections, order, baselines=B, collection=C)
