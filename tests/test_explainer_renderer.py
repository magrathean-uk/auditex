"""Catalogue-wide S/B self-test port, with planted rejection controls.

Inputs are audited synthetic/public contract fixtures. No dependency on Parts
1/2/4/5, a live checkout, rule execution, vectors, a model or tenant evidence.
"""
from copy import deepcopy
import gzip
import json
from pathlib import Path
import re

import jsonschema
import pytest

from azure_tenant_audit.explainer import build_view, load_templates, render, render_full
from azure_tenant_audit.explainer import textkit as tk
from azure_tenant_audit.explainer.render import _validate_output

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/explainer/renderer"
T = tk.expand_template(json.loads((ROOT / "configs/explainer-template.json").read_text()))
B = json.loads((Path(__file__).resolve().parents[1] / "configs/explainer-baselines.json").read_text())
C = json.loads((Path(__file__).resolve().parents[1] / "configs/explainer-what-to-collect.json").read_text())
SCHEMA = json.loads((ROOT / "schemas/explainer.schema.json").read_text())


def cases():
    for cell in T["cells"]:
        for pair in cell["reason_pairs"]:
            variants = cell.get("cited_variants", [cell["cited"]])
            if cell["cell"] == "section_not_collected":
                variants = [[s for s in T["policies"][cell["policy_id"]]["sections"] if s in pair["reason_text"]]]
            for cites in variants:
                yield {"policy_id": cell["policy_id"], "cell": cell["cell"], "verdict": cell["verdict"], **pair, "cited_sections": cites}


CASES = list(cases())
_BASE_CASES = {}


def view_for(record, missing=False):
    order = T["policies"][record["policy_id"]]["sections"]
    return build_view(record, {} if missing else {s: [] for s in order}, order, baselines=B, collection=C)


def baseline_case(record):
    key = tk.canonical(record)
    if key not in _BASE_CASES:
        view = view_for(record)
        _BASE_CASES[key] = (view, render(record, view, templates=T))
    return _BASE_CASES[key]


def assert_source_constraints(out, rec, view):
    """Local S self-test controls; the independent eight-check suite is Part 4."""
    _validate_output(out, rec["verdict"], command_units=T["policies"][rec["policy_id"]]["command_units"])
    assert set(out["evidence_refs"]) <= {e["id"] for e in view["evidence"]}
    expl = out["explanation"]
    req = T["policies"][rec["policy_id"]]["requirement"]
    expl_nr = expl.replace(req, "") if req else expl
    pos, neg = tk.polarity(expl_nr)
    if rec["verdict"] == "met":
        assert not neg and not tk.NOCONCL.search(expl) and not tk.NOTAPPLIC.search(expl)
    elif rec["verdict"] == "not_met":
        assert not pos and not tk.NOCONCL.search(expl) and not tk.NOTAPPLIC.search(expl)
    elif rec["verdict"] == "not_assessed":
        assert not pos and not neg and not tk.COMPLIANCE_ANY.search(expl)
        assert "no conclusion" in expl.casefold() and tk.NOCONCL.search(expl)
        assert not tk.NOTAPPLIC.search(expl)
        for s in rec["cited_sections"] or []:
            assert s in expl + " ".join(out["remediation_steps"])
    else:
        assert tk.NOTAPPLIC.search(expl) and not pos and not neg
    # Source's identifier-specific planted controls; fixed template words may be new.
    corpus = tk.canonical(view) + rec["reason_text"] + " ".join(T["policies"][rec["policy_id"]]["sections"])
    for rx in (r"\b\d+\b", r"\b[A-Za-z]+(?:_[A-Za-z0-9]+)+\b", r"\b[A-Z][a-z]+[A-Z][A-Za-z0-9]*\b",
               r"[\w.+*-]+@[\w-]+(?:\.[\w-]+)+", r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b"):
        for token in re.findall(rx, expl + " ".join(out["remediation_steps"])):
            assert token.casefold() in corpus.casefold()
    assert not re.search(r"\b(rego|opa|gguf|llama|checkpoint|jupiter|civo|1password)\b|/Volumes|\.jsonl?\b|\.py\b", expl, re.I)
    if rec["verdict"] == "not_assessed":
        assert out["remediation_steps"] == view["approved_remediation"]
    if rec["verdict"] == "not_met":
        cell = next(c for c in T["cells"] if c["id"] == rec["policy_id"] + "/" + rec["cell"])
        assert out["remediation_steps"] == [s["text"] for s in cell["remediation_steps"]]


@pytest.mark.parametrize("rec", CASES, ids=lambda r: r["policy_id"] + "/" + r["cell"])
def test_every_closed_reason_and_citation_variant(rec):
    view, out = baseline_case(rec)
    assert_source_constraints(out, rec, view)
    assert out == render(deepcopy(rec), deepcopy(view), templates=T)
    if rec["verdict"] in ("met", "not_applicable"):
        assert out["remediation_steps"] == []
    if rec["verdict"] == "not_assessed":
        assert out["remediation_steps"] == view["approved_remediation"]
    if rec["verdict"] == "not_met":
        cell = next(c for c in T["cells"] if c["id"] == rec["policy_id"] + "/" + rec["cell"])
        assert out["remediation_steps"] == [s["text"] for s in cell["remediation_steps"]]
        for step in cell["remediation_steps"]:
            assert step["source"]
            if step.get("forced_piece"):
                assert 5 <= tk.words(step["text"]) <= 30


def test_inventory_and_compact_schema():
    assert len(T["cells"]) == 1084 and len(T["policies"]) == 102
    assert len({(r["policy_id"], r["cell"]) for r in CASES}) == 1084
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for rec in CASES:
        validator.validate(baseline_case(rec)[1])


def test_inherited_steps_match_independent_frozen_source_pins():
    pins = json.loads(gzip.decompress((FIX / "source-step-pins.json.gz").read_bytes()))
    changes = json.loads((ROOT / "tests/fixtures/explainer/integration/command-steps-change.json").read_text())["changes"]
    assert set(pins) == {c["id"] for c in T["cells"]}
    for cell in T["cells"]:
        for key in ("remediation_steps", "remediation_steps_full"):
            # Reconstruct the frozen S strings from the exact reviewed R4 delta.
            steps = [s["text"] for s in cell[key]]
            selected = [c for c in changes if (c["policy"], c["cell"], c["form"]) == (cell["policy_id"], cell["cell"], key)]
            for change in reversed(selected):
                start = change["new_start"]
                assert steps[start:start + len(change["new_text"])] == change["new_text"]
                steps[start:start + len(change["new_text"])] = change["old_text"]
            assert tk.digest(steps) == pins[cell["id"]][key]


def test_missing_evidence_references_remain_absent():
    for rec in CASES:
        if rec["verdict"] == "not_assessed":
            view = view_for(rec, missing=True)
            assert render(rec, view, templates=T)["evidence_refs"] == ["e0"]


def test_null_citations_mean_all_required_sections():
    count = 0
    for rec in CASES:
        if rec["cited_sections"] == T["policies"][rec["policy_id"]]["sections"]:
            null = dict(rec, cited_sections=None)
            assert render(null, view_for(null), templates=T) == render(rec, view_for(rec), templates=T)
            count += 1
    assert count > 100


@pytest.mark.parametrize("field,value", [("reason_text", "Requirement met: invented."), ("reason_code", "invented"),
    ("verdict", "not_met"), ("cell", "unknown"), ("cell", None), ("cited_sections", []),
    ("cited_sections", ["uncited"]), ("cited_sections", "authentication_method")])
def test_rejects_bad_rule_record(field, value):
    rec = deepcopy(CASES[0]); view = view_for(rec); rec[field] = value
    with pytest.raises((KeyError, ValueError)):
        render(rec, view, templates=T)


@pytest.mark.parametrize("mutation", ["extra", "reason", "policy", "requirement", "criticality", "duplicate", "uncited", "id", "order", "remediation", "cap", "raw_email"])
def test_rejects_bad_view(mutation):
    rec = next(r for r in CASES if len(r["cited_sections"]) >= 2)
    view = view_for(rec)
    if mutation == "extra": view["detail"] = "never read"
    if mutation == "reason": view["reason_text"] += " changed"
    if mutation == "policy": view["evidence"][0]["observed"]["policy_id"] = "unknown"
    if mutation == "requirement": view["evidence"][0]["observed"]["requirement"] = "invented"
    if mutation == "criticality": view["evidence"][0]["observed"]["criticality"] = "invented"
    if mutation == "duplicate": view["evidence"].append(deepcopy(view["evidence"][1]))
    if mutation == "uncited": view["evidence"][1]["section"] = "secret"
    if mutation == "id": view["evidence"][1]["id"] = "e0"
    if mutation == "order": view["evidence"][1:] = reversed(view["evidence"][1:])
    if mutation == "remediation": view["approved_remediation"] = ["Click Save."]
    if mutation == "cap": view["evidence"][1]["observed"] = "x" * 6001
    if mutation == "raw_email": view["evidence"][1]["observed"] = "jane@example.com"
    with pytest.raises(ValueError): render(rec, view, templates=T)


def test_pairing_is_not_cartesian_and_citation_order_exceptions():
    cell = next(c for c in T["cells"] if c["cell"] == "orphan_sub_domain")
    a, b = cell["reason_pairs"]
    rec = {"policy_id": cell["policy_id"], "cell": cell["cell"], "verdict": cell["verdict"], **a, "cited_sections": cell["cited"]}
    bad = dict(rec, reason_code=b["reason_code"])
    with pytest.raises(ValueError): render(bad, view_for(bad), templates=T)
    for pid in ("MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"):
        rec = next(r for r in CASES if r["policy_id"] == pid and r["cell"] == "preset_rule_unusable")
        out = render(rec, view_for(rec), templates=T)
        assert out["evidence_refs"][1:] != sorted(out["evidence_refs"][1:])
        bad = dict(rec, cited_sections=list(reversed(rec["cited_sections"])))
        with pytest.raises(ValueError): render(bad, view_for(bad), templates=T)


def fault_record(pid="MS.AAD.5.6v1"):
    return {"policy_id": pid, **{k: tk.FAULT[k] for k in ("verdict", "cell", "reason_code", "reason_text")},
            "cited_sections": T["policies"][pid]["sections"]}


def test_shared_fault_on_every_policy():
    assert set(T["shared_exceptions"]) == {"rule_evaluation_failed", "rule_not_implemented"}
    for pid in T["policies"]:
        rec = fault_record(pid); view = view_for(rec)
        out = render(rec, view, templates=T)
        assert out["explanation"] == tk.FAULT["explanation"]
        assert out["remediation_steps"] == tk.FAULT["remediation_steps"]
        assert len(out["evidence_refs"]) == len(rec["cited_sections"]) + 1
        assert render_full(rec, view, templates=T) == out


@pytest.mark.parametrize("field,value", [("cell", "rule_evaluation_failed"), ("reason_text", "Product failed: secret"),
    ("verdict", "met"), ("reason_code", "rule_evaluation_failed_counterfeit"), ("cited_sections", []), ("policy_id", "unknown")])
def test_shared_fault_rejects_counterfeits(field, value):
    rec = fault_record(); view = view_for(rec); rec[field] = value
    with pytest.raises((KeyError, ValueError)): render(rec, view, templates=T)


def test_shared_fault_rejects_collection_and_diagnostics():
    rec = fault_record()
    for bad in ([], ["Collect evidence."], ["Report this fault to the product team at contact+auditex@magrathean.uk. Diagnostic: secret"]):
        view = view_for(rec); view["approved_remediation"] = bad
        with pytest.raises(ValueError): render(rec, view, templates=T)
    view = view_for(rec); view["evidence"].pop()
    with pytest.raises(ValueError): render(rec, view, templates=T)


def test_constructed_malformed_lifetimes_render_only_the_fixed_fault():
    rows = [json.loads(line) for line in (FIX / "fault-vectors.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    for row in rows:
        rec = row["expected_record"]
        order = T["policies"][rec["policy_id"]]["sections"]
        view = build_view(rec, row["sections"], order, baselines=B, collection=C)
        out = render(rec, view, templates=T)
        assert out["explanation"] == tk.FAULT["explanation"]
        assert out["remediation_steps"] == tk.FAULT["remediation_steps"]
        assert "SYNTHETIC_FAULT_INPUT_DO_NOT_ECHO" not in tk.canonical(out)
        for evidence in view["evidence"][1:]:
            oversized = len(tk.canonical(row["sections"][evidence["section"]])) > 6000
            assert (evidence["observed"] == {"not_shown": "size"}) == oversized


def test_injected_fault_is_a_record_input_and_renderer_errors_stay_errors():
    rec = fault_record()
    rec["detail"] = {"exception": "SYNTHETIC_DIAGNOSTIC_DO_NOT_ECHO"}
    out = render(rec, view_for(rec), templates=T)
    assert "DIAGNOSTIC" not in tk.canonical(out)
    # This part does not implement or catch evaluator exceptions. A deterministic
    # injected product-fault record bypasses ordinary cell and prefix handling.
    bad = deepcopy(T); bad["limits"]["max_steps"] = 7
    with pytest.raises(ValueError): render(rec, view_for(rec), templates=bad)


def test_source_drop_accounting_xrefs_and_url_cut():
    assert sum(len(p["preamble_units_dropped"]) for p in T["policies"].values()) == 30
    assert len([p for p in T["policies"].values() if p["instructions_cross_reference"]]) == 15  # PP 3.2 is outside the rule catalogue
    assert len({c["policy_id"] for c in T["cells"] if c["remediation_truncated"]}) == 30
    policy = T["policies"]["MS.AAD.6.1v1"]
    assert policy["shown_steps_cut_before_url_step"] is not None
    rec = next(r for r in CASES if r["policy_id"] == "MS.AAD.6.1v1" and r["verdict"] == "not_met")
    shown = render(rec, view_for(rec), templates=T); full = render_full(rec, view_for(rec), templates=T)
    assert not any("https://" in s for s in shown["remediation_steps"])
    assert any("https://" in s for s in full["remediation_steps"])
    assert len(full["remediation_steps"]) == 4  # three prose steps plus one whole command block
    # Whole command blocks can meet the structural array cap; compact runtime
    # validation still rejects the expanded public URL-bearing command.
    with pytest.raises(ValueError):
        _validate_output(full, rec["verdict"], command_units=policy["command_units"])
    # AAD 7.1 has zero margin: no added navigation/configuration steps.
    rec = next(r for r in CASES if r["policy_id"] == "MS.AAD.7.1v1" and r["verdict"] == "not_met")
    view = view_for(rec)
    assert len(render(rec, view, templates=T)["remediation_steps"]) <= len(view["approved_remediation"]) + 2


def test_load_is_explicit_once_and_rejects_corruption():
    calls = []
    def read(path):
        calls.append(path); return (ROOT / path).read_text()
    templates = load_templates(read)
    render(CASES[0], view_for(CASES[0]), templates=templates)
    assert calls == ["configs/explainer-template.json"]
    with pytest.raises(ValueError): load_templates(lambda _: '{"schema_version":1,"schema_version":1}')
    bad = deepcopy(T); bad["cells"].append(bad["cells"][0])
    with pytest.raises(ValueError): load_templates(lambda _: json.dumps(bad))


def test_runtime_uses_this_worktree_without_io_or_network(monkeypatch):
    import builtins
    import inspect
    import socket
    assert Path(inspect.getfile(render)).is_relative_to(ROOT / "src")
    rec = CASES[0]; view = view_for(rec)
    def forbidden(*args, **kwargs):
        raise AssertionError("runtime attempted I/O")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert render(rec, view, templates=T)["evidence_refs"]


@pytest.mark.parametrize("bad", ["M\u0435t", "Review __setting__.", "Read [link](target).", "1. Review setting.", "Review setting.\x85"])
def test_output_plain_text_guard_rejects_unicode_and_markdown(bad):
    with pytest.raises(ValueError):
        _validate_output({"explanation": bad, "remediation_steps": [], "evidence_refs": ["e0"]}, "met")


def test_fallbacks_are_whole_sentences_and_limits_fail_closed():
    rec = CASES[0]; view = view_for(rec); bad = deepcopy(T)
    cell = next(c for c in bad["cells"] if c["id"] == rec["policy_id"] + "/" + rec["cell"])
    fallback = "What the evidence shows: {finding}."
    cell["explanation_template"] = "Word " * 81 + "."
    cell["explanation_template_fallbacks"] = [fallback]
    assert render(rec, view, templates=bad)["explanation"] == fallback.format(finding=tk.split_reason(rec["reason_text"])[2])
    cell["explanation_template_fallbacks"] = []
    with pytest.raises(ValueError): render(rec, view, templates=bad)
    cell["explanation_template"] = "{unfilled}"
    with pytest.raises(ValueError): render(rec, view, templates=bad)


@pytest.mark.parametrize("bad_step", ["word " * 31, "Read https://example.com/fix.", "{unknown}", "Review `Setting`."])
def test_corrupt_baseline_template_steps_fail_closed(bad_step):
    rec = next(r for r in CASES if r["verdict"] == "not_met")
    view = view_for(rec); bad = deepcopy(T)
    cell = next(c for c in bad["cells"] if c["id"] == rec["policy_id"] + "/" + rec["cell"])
    cell["remediation_steps"][0]["text"] = bad_step
    # Runtime strips harmless markdown from a trusted baseline string, matching S.
    if "`" in bad_step:
        assert render(rec, view, templates=bad)["remediation_steps"][0] == "Review Setting."
    else:
        with pytest.raises(ValueError): render(rec, view, templates=bad)


@pytest.mark.parametrize("n", [31, 59, 61, 89])
def test_balanced_splits_keep_every_word_without_tiny_tail(n):
    text = " ".join(f"word{i}" for i in range(n))
    parts = tk.split_balanced(text, 30)
    assert " ".join(parts) == text
    assert all(5 <= tk.words(s) <= 30 for s in parts)


@pytest.mark.parametrize("kind", ["empty_refs", "external_refs", "url", "placeholder", "em_dash", "number", "name", "email", "guid", "infrastructure", "overlong", "steps_on_met", "opposite", "hedge", "no_conclusion", "collection_change", "invented_step"])
def test_planted_self_test_negative_controls(kind):
    verdict = "not_assessed" if kind in ("hedge", "no_conclusion", "collection_change") else "not_met" if kind == "invented_step" else "met"
    rec = next(r for r in CASES if r["verdict"] == verdict)
    view = view_for(rec); out = render(rec, view, templates=T)
    if kind == "empty_refs": out["evidence_refs"] = []
    if kind == "external_refs": out["evidence_refs"].append("e99")
    additions = {"url": " See https://example.com/fix.", "placeholder": " {finding}", "em_dash": " \u2014 bad.",
        "number": " Set the value to 4242.", "name": " Review EnableMagicSwitch.", "email": " Contact jane@example.com.",
        "guid": " Group 99999999-8888-7777-6666-555555555555.", "infrastructure": " The Rego decided this.",
        "overlong": " word" * 81, "opposite": " The requirement is not met.", "hedge": " The policy probably fails."}
    out["explanation"] += additions.get(kind, "")
    if kind == "steps_on_met": out["remediation_steps"] = ["Click Save."]
    if kind == "no_conclusion": out["explanation"] = "The evidence is unavailable."
    if kind == "collection_change": out["remediation_steps"] = ["Delete the policy."]
    if kind == "invented_step": out["remediation_steps"] = ["Click Imaginary Menu."]
    with pytest.raises((ValueError, AssertionError)):
        assert_source_constraints(out, rec, view)
        if verdict == "not_assessed": assert out["remediation_steps"] == view["approved_remediation"]
        if verdict == "not_met": assert "Imaginary" not in " ".join(out["remediation_steps"])


def test_all_source_self_test_planted_controls_on_every_applicable_case():
    """All 19 S/B/selftest.py mutation types, over the catalogue-derived corpus.

    Reuse deterministic base outputs, then mutate copies. No checker package or
    vector-discovered inventory is imported. Part 4 owns the independent checks.
    """
    def explanation(fn):
        def mutate(out, rec):
            out["explanation"] = fn(out["explanation"], rec)
        return mutate
    def step(text):
        return lambda out, rec: out["remediation_steps"].__setitem__(0, text)
    def drop_section(out, rec):
        name = rec["cited_sections"][0]
        out["explanation"] = out["explanation"].replace(name, "the data")
        out["remediation_steps"] = [s.replace(name, "the data") for s in out["remediation_steps"]]
    mutants = {
        "met_says_not_met": ({"met"}, explanation(lambda s, r: s + " The requirement is not met.")),
        "not_met_says_met": ({"not_met"}, explanation(lambda s, r: s + " The tenant complies with the requirement.")),
        "not_assessed_says_complies": ({"not_assessed"}, explanation(lambda s, r: s.replace("No conclusion was reached either way, so this policy was not assessed.", "The tenant complies."))),
        "not_assessed_hedged_guess": ({"not_assessed"}, explanation(lambda s, r: s + " The policy probably fails.")),
        "not_applicable_loses_phrase": ({"not_applicable"}, explanation(lambda s, r: s.replace("does not apply", "is relevant"))),
        "invented_number": (None, explanation(lambda s, r: s + " Set the value to 4242.")),
        "invented_setting_name": (None, explanation(lambda s, r: s + " Review the EnableMagicSwitch setting.")),
        "invented_guid": (None, explanation(lambda s, r: s + " Group 99999999-8888-7777-6666-555555555555 is affected.")),
        "invented_email": (None, explanation(lambda s, r: s + " Contact jane.doe@example.com.")),
        "url": (None, explanation(lambda s, r: s + " See https://example.com/fix.")),
        "unfilled_placeholder": (None, explanation(lambda s, r: s + " {finding}")),
        "infrastructure_word": (None, explanation(lambda s, r: s + " The Rego decided this.")),
        "em_dash": (None, explanation(lambda s, r: s.replace(":", " \u2014", 1))),
        "met_gets_steps": ({"met", "not_applicable"}, lambda out, rec: out.update(remediation_steps=["Click Save."])),
        "not_met_step_invented": ({"not_met"}, step("Click Settings > Imaginary Menu and select Fix.")),
        "not_assessed_section_dropped": ({"not_assessed"}, drop_section),
        "not_assessed_tenant_change": ({"not_assessed"}, step("Delete the policy and check the evidence.")),
        "refs_outside_prompt": (None, lambda out, rec: out["evidence_refs"].append("e99")),
        "refs_empty": (None, lambda out, rec: out.update(evidence_refs=[])),
    }
    applied = {name: 0 for name in mutants}
    for rec in CASES:
        view, base = baseline_case(rec)
        for name, (verdicts, mutate) in mutants.items():
            if verdicts and rec["verdict"] not in verdicts:
                continue
            if name == "not_assessed_section_dropped" and not rec["cited_sections"]:
                continue
            out = deepcopy(base)
            mutate(out, rec)
            with pytest.raises((AssertionError, ValueError)):
                assert_source_constraints(out, rec, view)
            applied[name] += 1
    assert len(applied) == 19 and all(applied.values())
    # 28,964 over the fixture-built template (1,771 catalogue texts); the product catalogue's closed text sets also hold
    # every reachable subset text (2,209 texts), which adds 6,036 applicable mutants.
    assert sum(applied.values()) == 35000
