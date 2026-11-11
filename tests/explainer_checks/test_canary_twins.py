"""Frozen canary evidence plus five deliberately leaky callback controls.

These controls validate the auditor. The integration owner must also call
canary.audit_twins with the real view builder and real output-redaction path.
"""
import json
import re

import pytest

from .canary import audit_twins
from .driver import run_pair
from .fault_fixtures import fault_pair
from .support import local_resources


def boundary_stub(record, sections, order, *, leak=None):
    """Small synthetic callback to test the auditor, never a runtime substitute."""
    view = {key: record.get(key) for key in ("policy_id", "verdict", "cell", "reason_code", "reason_text")}
    if leak == "F":
        view.update(record)
    evidence = []
    cited = record.get("cited_sections") or list(sections)
    for index, section in enumerate(order, 1):
        if section not in sections or (section not in cited and leak != "U"):
            continue
        value = sections[section]
        if section == "scuba_config" and isinstance(value, dict) and leak != "C":
            value = {k: v for k, v in value.items() if k in ("M365Environment", "collection_status")}
        if len(json.dumps(value, sort_keys=True, separators=(",", ":"))) > 6000 and leak != "B":
            value = {"not_shown": "size"}
        if leak != "P":
            value = json.loads(re.sub(r'[A-Za-z0-9_.+-]+@', '***@', json.dumps(value)))
        evidence.append({"id": f"e{index}", "section": section, "observed": value})
    view.update(evidence=evidence, approved_remediation=[])
    return view


@pytest.mark.parametrize("leak", ["F", "U", "B", "P", "C"])
def test_canary_auditor_negative_controls(leak):
    record = fault_pair()["prompt"]["record"]
    sections = {"app_management_policies": [], "default_app_management_policy": {}}
    order = list(sections)
    clean = audit_twins(boundary_stub, record, sections, order)
    assert clean == {"ok": True, "leaks": [], "identical": {"F": True, "U": True}}
    bad = audit_twins(lambda r, s, o: boundary_stub(r, s, o, leak=leak), record, sections, order)
    assert not bad["ok"] and leak in bad["leaks"]
    result = run_pair(fault_pair(), local_resources(), canary=bad)
    assert result["d"]["pass"] is False
    assert "builder_canary_leak" in {f["code"] for f in result["d"]["failures"]}


def runtime_build(record, sections, order):
    from azure_tenant_audit import explainer
    baselines, collection, _ = explainer._resources()
    return explainer.build_view(record, sections, order, baselines=baselines, collection=collection)


def test_runtime_builder_twins_over_a_stable_sample():
    """Real build_view, real citations: every fifteenth generated base pair, five twins each (the full set is the
    explainer_acceptance twins job in test_explainer_integration)."""
    from azure_tenant_audit import explainer

    from . import corpus
    _, _, templates = explainer._resources()
    checked = 0
    for pair in corpus.base_pairs()[::15]:
        record = pair["prompt"]["record"]
        sections = corpus.vector_for(pair)["sections"]
        required = templates["policies"][record["policy_id"]]["sections"]
        order = corpus.section_order(record, sections, templates)
        audit = audit_twins(runtime_build, record, sections, order, fixed_sections=required)
        assert audit["ok"], (pair["id"], audit)
        # A twin that cites a section outside the policy's read set must be rejected; one inside it is accepted.
        wanted = [twin for twin, section in (("P", "privileged_users"), ("C", "scuba_config")) if section not in required]
        assert audit["rejected"] == wanted, (pair["id"], audit)
        checked += 1
    assert checked >= 90


def test_scoped_canary_auditor_requires_forbidden_citation_rejection():
    rec = fault_pair()['prompt']['record']
    sections = {'app_management_policies': [], 'default_app_management_policy': {}}
    order = list(sections)
    def strict(record, evidence, supplied_order):
        if any(s not in order for s in record.get('cited_sections', [])):
            raise ValueError('invalid citations')
        return boundary_stub(record, evidence, supplied_order)
    clean = audit_twins(strict, rec, sections, order, fixed_sections=order)
    assert clean['ok'] and clean['rejected'] == ['P', 'C']
    permissive = audit_twins(boundary_stub, rec, sections, order, fixed_sections=order)
    assert not permissive['ok']
    assert {'P-not-rejected', 'C-not-rejected'} <= set(permissive['leaks'])
