"""Integration gates; product v3.9.1 migration and report wiring remain explicit."""
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tomllib
import zipfile

import jsonschema
import pytest

from azure_tenant_audit import explainer, resources
from azure_tenant_audit.explainer.adapter import adapt_record
from azure_tenant_audit.explainer import textkit
from azure_tenant_audit.explainer.textkit import canonical, shared_exceptions
from azure_tenant_audit.shipped_content import SHIPPED_CONTENT_AREAS

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/explainer"
PIN = FIX / "renderer/catalogue-v391-fixture.json.gz"
CAT = json.loads(gzip.decompress(PIN.read_bytes()))
T = textkit.expand_template(json.loads((ROOT / "configs/explainer-template.json").read_text()))


def catalogue_gap(product, fixture):
    """The live difference between the shipped catalogue and the spec's byte-exact v3.9.1 cell catalogue."""
    actual = product["policies"]
    actual_cells = {(pid, cell) for pid, policy in actual.items() for cell in policy["cells"]}
    desired_cells = {(pid, cell) for pid, policy in fixture.items() for cell in policy["cells"]}
    changed = {}
    for pid in sorted(set(actual) & set(fixture)):
        left, right = actual[pid], fixture[pid]
        cells = {}
        for cell in sorted(set(left["cells"]) & set(right["cells"])):
            a, b = left["cells"][cell], right["cells"][cell]
            differences = {k: {"product": a.get(k), "v391": b.get(k),
                               "product_present": k in a, "v391_present": k in b}
                           for k in sorted(a.keys() | b.keys()) if a.get(k) != b.get(k) or (k in a) != (k in b)}
            if differences:
                cells[cell] = differences
        fields = {key: {"product_present": key in left, "v391_present": key in right,
                        **({} if key == "params" else {"product": left.get(key), "v391": right.get(key)})}
                  for key in sorted(left.keys() | right.keys()) if key != "cells"
                  and (left.get(key) != right.get(key) or (key in left) != (key in right))}
        if cells or fields:
            changed[pid] = {"cells": cells, "policy_fields": fields}
    return {
        "product_spec": product["spec_version"], "fixture_spec": "v3.9.1",
        "product_policies": len(actual), "fixture_policies": len(fixture),
        "product_cells": len(actual_cells), "fixture_cells": len(desired_cells),
        "missing_policies": sorted(set(fixture) - set(actual)),
        "extra_policies": sorted(set(actual) - set(fixture)),
        "missing_cells": [list(x) for x in sorted(desired_cells - actual_cells)],
        "extra_cells": [list(x) for x in sorted(actual_cells - desired_cells)],
        "changed_cells": changed,
        "wrapper_metadata": {k: v for k, v in product.items() if k != "policies"},
        "canonical_sha256": {"product": hashlib.sha256(canonical(product).encode()).hexdigest(),
                             "fixture": hashlib.sha256(canonical(fixture).encode()).hexdigest()},
    }


def record(code="rule_evaluation_failed", pid="MS.AAD.5.6v1"):
    return {"policy_id": pid, **{k: shared_exceptions()[code][k]
            for k in ("verdict", "cell", "reason_code", "reason_text")},
            "cited_sections": list(T["policies"][pid]["sections"])}


def sections_for(rec):
    return {name: [] for name in T["policies"][rec["policy_id"]]["sections"]}


def test_resource_glob_parity():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    declared = project["tool"]["setuptools"]["data-files"]
    for area in SHIPPED_CONTENT_AREAS:
        assert declared[area.package_target] == list(area.package_patterns)
    assert "configs/explainer-*.json" in declared["auditex/configs"]
    assert "schemas/explainer.schema.json" in declared["auditex/schemas"]
    found = resources.shipped_resource_manifest()["resources"]
    for name in ("baselines", "template", "what-to-collect"):
        assert f"configs/explainer-{name}.json" in found
    assert "schemas/explainer.schema.json" in found


def test_installed_wheel_resources_offline(tmp_path):
    """Build with the existing venv backend; extract actual wheel data outside checkout."""
    project = tmp_path / "project"
    project.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copyfile(ROOT / name, project / name)
    shutil.copytree(ROOT / "src", project / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    for area in SHIPPED_CONTENT_AREAS:
        for pattern in area.package_patterns:
            for source in ROOT.glob(pattern):
                if source.is_file():
                    dest = project / source.relative_to(ROOT)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, dest)
    dist = tmp_path / "dist"
    dist.mkdir()
    code = "from setuptools.build_meta import build_wheel; build_wheel(" + repr(str(dist)) + ")"
    built = subprocess.run([sys.executable, "-B", "-I", "-c", code], cwd=project, capture_output=True, text=True, timeout=90)
    assert built.returncode == 0, built.stderr[-3000:]
    wheel = next(dist.glob("*.whl"))
    # Install wheel code/data by the standard schemes into a fresh venv.
    # Reuse only dependencies from the existing repo venv; no pip or network.
    import venv
    installed = tmp_path / "installed"
    venv.EnvBuilder(with_pip=False).create(installed)
    python = installed / "bin/python"
    paths = json.loads(subprocess.check_output(
        [str(python), "-B", "-I", "-c", "import sysconfig,json; print(json.dumps(sysconfig.get_paths()))"],
        text=True))
    site = Path(paths["purelib"])
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.namelist():
            if member.endswith("/"):
                continue
            relative = Path(member)
            if ".data" in relative.parts[0]:
                scheme, *tail = relative.parts[1:]
                assert scheme == "data", member
                target = installed.joinpath(*tail)
            else:
                target = site / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
    code = r"""
import hashlib, json
from azure_tenant_audit import resources, explainer
from azure_tenant_audit.explainer.textkit import FAULT
adapters = resources._resource_adapters()
assert adapters and all(a.name == "installed" for a in adapters), adapters
names = ("configs/explainer-baselines.json", "configs/explainer-template.json",
         "configs/explainer-what-to-collect.json", "schemas/explainer.schema.json")
hashes = {n: hashlib.sha256(resources.open_text_resource(n).encode()).hexdigest() for n in names}
t = json.loads(resources.open_text_resource(names[1]))
pid = "MS.AAD.5.6v1"
order = t["policies"][pid]["sections"]
rec = {"policy_id": pid, **{k: FAULT[k] for k in ("verdict","cell","reason_code","reason_text")},
       "cited_sections": order}
assert explainer.explain(rec, {s: [] for s in order}, order)["explanation"] == FAULT["reason_text"]
print(json.dumps(hashes))
"""
    # The loader adds a "dev" adapter for any cwd ancestor that looks like a checkout. When pytest's
    # basetemp sits inside one (a gate run with TMPDIR under the repo), run from the filesystem root
    # instead, so the subprocess still has no dev or env route and must resolve from the wheel data.
    cwd = tmp_path / "empty"
    cwd.mkdir()
    if any(resources._looks_like_dev_root(p) for p in (cwd, *cwd.parents)):
        cwd = Path(cwd.anchor)
    assert not resources._looks_like_dev_root(cwd), cwd
    import os
    env = dict(os.environ)
    env.pop(resources.RESOURCE_ROOT_ENV, None)
    import sysconfig
    code = "import sys; sys.path.append(" + repr(sysconfig.get_paths()["purelib"]) + ")\n" + code
    code += "\nfrom pathlib import Path; assert Path(resources.__file__).is_relative_to(" + repr(str(installed)) + ")\n"
    run = subprocess.run([str(python), "-B", "-I", "-c", code], cwd=cwd, env=env,
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr
    for name, digest in json.loads(run.stdout).items():
        assert digest == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()


GAP = json.loads((FIX / "integration/catalogue-gap.json").read_text())


def test_gap_record_holds_the_pre_migration_measure_and_the_live_residual_exactly():
    product = json.loads((ROOT / "configs/scuba-value-rules.json").read_text())
    # The independent pin is the spec's byte-exact v3.9.1 catalogue: its hash is the one the pre-migration record names.
    assert hashlib.sha256(gzip.decompress(PIN.read_bytes())).hexdigest() == GAP["before_migration"]["measured"]["v391_sha256"]
    assert catalogue_gap(product, CAT)["fixture_spec"] == "v3.9.1"
    before = GAP["before_migration"]
    assert (before["measured"]["product_commit"], before["measured"]["product_spec"]) == ("e1ee9df", "v3.9")
    assert before["product_policies"] == before["v391_policies"] == 102
    assert before["product_cells"] == before["v391_cells"] == 1084
    assert before["missing_policies"] == before["extra_policies"] == before["missing_cells"] == before["extra_cells"] == []
    assert before["changed_cell_counts_by_key"] == {
        "cited": 102, "cited_variants": 6, "evidence_kind": 746, "limitations": 746, "reason_codes": 1,
        "reason_texts": 18, "reason_texts_by_code": 1, "recommendations": 746}
    assert before["product_only_wrapper"]["rule_failure"]["cell"] == "rule_evaluation_failed"


def test_residual_differences_are_only_the_documented_classes():
    """What the shipped catalogue keeps from product, each consistent with v3.9.1, A1 and A2."""
    residual = catalogue_gap(json.loads((ROOT / "configs/scuba-value-rules.json").read_text()), CAT)
    assert residual["product_spec"] == "v3.9.1" and residual["missing_policies"] == residual["extra_policies"] == []
    assert residual["missing_cells"] == residual["extra_cells"] == []
    assert residual["product_policies"] == residual["fixture_policies"] == 102
    assert residual["product_cells"] == residual["fixture_cells"] == 1084
    kinds = {}
    for pid, entry in residual["changed_cells"].items():
        for cell, keys in entry["cells"].items():
            for key, diff in keys.items():
                kinds.setdefault(key, []).append((pid, cell))
                if key == "cited":  # the spec's own words for the dynamic list: unavailable sections, in order
                    assert cell == "section_not_collected" and diff["product"] == T["policies"][pid]["sections"]
                    assert diff["v391"] == "the unavailable sections of `sections`, in section order"
                elif key == "reason_texts":  # closed lists naming any subset: the shipped list contains every text seen
                    assert set(diff["v391"]) < set(diff["product"])
                elif key == "cited_variants":  # A2 and the three SS 7.x reference orders
                    assert diff["product_present"]
                    assert all(v in diff["product"] for v in (diff["v391"] or []))
                else:
                    assert key in {"reason_texts_by_code"}, key
    assert {k: len(v) for k, v in kinds.items()} == {
        "cited": 102, "reason_texts": 18, "cited_variants": 6, "reason_texts_by_code": 1}
    assert {pid for pid, _ in kinds["cited_variants"]} == {
        "MS.SECURITYSUITE.1.3v1", "MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1",
        "MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"}
    for pid, entry in residual["changed_cells"].items():
        assert set(entry["policy_fields"]) <= {"kind", "optional_sections", "params", "rule_id"}, pid


def test_product_catalogue_is_v391_and_agrees_with_the_independent_pin_on_every_decision():
    product = json.loads((ROOT / "configs/scuba-value-rules.json").read_text())
    assert product["spec_version"] == "v3.9.1"
    assert set(product["policies"]) == set(CAT)
    assert "rule_failure" not in product and "cell_contracts" not in product
    for pid, pin in CAT.items():
        row = product["policies"][pid]
        assert row["sections"] == pin["sections"]
        assert set(row["cells"]) == set(pin["cells"])
        for name, expected in pin["cells"].items():
            cell = row["cells"][name]
            for key in ("verdict", "reason_code", "evidence_kind", "limitations", "recommendations"):
                assert cell.get(key) == expected.get(key), (pid, name, key)
            if name != "section_not_collected":
                assert cell["cited"] == expected["cited"], (pid, name)


@pytest.mark.parametrize("code", shared_exceptions())
def test_shared_adapter_exactness_no_mutation(code):
    rec = record(code)
    rec["detail"] = {"exception": "DO_NOT_ECHO"}
    original = deepcopy(rec)
    normalized = adapt_record(rec, templates=T)
    assert normalized == record(code)
    assert rec == original and "detail" not in normalized
    out = explainer.explain(rec, sections_for(rec), list(sections_for(rec)))
    assert out["explanation"] == shared_exceptions()[code]["explanation"]
    assert out["remediation_steps"] == shared_exceptions()[code]["remediation_steps"]
    assert "DO_NOT_ECHO" not in canonical(out)
    jsonschema.validate(out, json.loads((ROOT / "schemas/explainer.schema.json").read_text()))


@pytest.mark.parametrize("code", shared_exceptions())
def test_old_cell_named_sentinel_is_rejected_with_a_clear_error(code):
    """Before A1 the product answered a failed rule with a cell named after its reason code; nothing accepts it now."""
    rec = record(code)
    rec["cell"] = code
    original = deepcopy(rec)
    with pytest.raises(ValueError, match="legacy rule-failure sentinel rejected"):
        adapt_record(rec, templates=T)
    b, c, _ = explainer._resources()
    with pytest.raises(ValueError):
        explainer.build_view(rec, sections_for(rec), list(sections_for(rec)), baselines=b, collection=c)
    with pytest.raises(explainer.ExplainerError, match="^Explanation unavailable.$"):
        explainer.explain(rec, sections_for(rec), list(sections_for(rec)))
    assert rec == original


@pytest.mark.parametrize("code", shared_exceptions())
@pytest.mark.parametrize("change", [
    {"cell": "fabricated"}, {"verdict": "met"}, {"reason_text": "Diagnostic: secret"},
    {"reason_code": "rule_evaluation_failed_counterfeit"}, {"cited_sections": []},
    {"policy_id": "unknown"},
])
def test_shared_hostile_records_fail_closed(code, change):
    rec = dict(record(code), **change)
    with pytest.raises(explainer.ExplainerError, match="^Explanation unavailable.$"):
        explainer.explain(rec, {}, [])


@pytest.mark.parametrize("code", shared_exceptions())
@pytest.mark.parametrize("change", [
    {"explanation": "Collect evidence."},
    {"explanation": "Not assessed: secret"},
    {"remediation_steps": ["Collect the missing evidence."]},
    {"remediation_steps": ["Change the tenant setting."]},
])
def test_shared_hostile_outputs_rejected_by_independent_checks(code, change):
    from explainer_checks import corpus
    from explainer_checks.driver import run_pair
    from explainer_checks.support import corpus_resources
    pair = next(p for p in corpus.shared_pairs() if p["prompt"]["record"]["reason_code"] == code)
    pair["output"].update(change)
    results = run_pair(pair, corpus_resources())
    assert all(results[check]["pass"] is False for check in ("a", "c", "e"))


def test_old_note_and_mutated_product_sentinel_rejected():
    old = "The policy was not assessed because its check could not be completed; report this to the product team."
    for cell, text in [(None, old), ("rule_evaluation_failed", old),
                       ("rule_evaluation_failed", record()["reason_text"] + " secret")]:
        rec = dict(record(), cell=cell, reason_text=text)
        with pytest.raises(ValueError):
            adapt_record(rec, templates=T)


def test_explain_no_network_cited_only_null_resolution_and_bounds(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("network access")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    rec = record()
    rec["cited_sections"] = None
    sections = sections_for(rec)
    order = ["extra_uncited", *sections]
    sections["extra_uncited"] = {"secret": "FORBIDDEN"}
    b, c, _ = explainer._resources()
    adapted = adapt_record(rec, templates=T)
    view = explainer.build_view(adapted, sections, order, baselines=b, collection=c)
    assert "FORBIDDEN" not in canonical(view)
    assert [e["id"] for e in view["evidence"]] == ["e0", "e2", "e3"]
    assert explainer.explain(rec, sections, order)["evidence_refs"] == ["e0", "e2", "e3"]
    sections[order[1]] = "x" * 7000
    view = explainer.build_view(adapted, sections, order, baselines=b, collection=c)
    assert view["evidence"][1]["observed"] == {"not_shown": "size"}
    with pytest.raises(explainer.ExplainerError):
        explainer.explain(rec, {}, order)


def test_renderer_failure_is_controlled_and_never_a_new_verdict(monkeypatch):
    rec = record()
    original = deepcopy(rec)
    def broken(*args, **kwargs):
        raise ValueError("PRIVATE_DIAGNOSTIC")
    monkeypatch.setattr(explainer, "render", broken)
    with pytest.raises(explainer.ExplainerError) as error:
        explainer.explain(rec, sections_for(rec), list(sections_for(rec)))
    assert str(error.value) == "Explanation unavailable."
    assert rec == original
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(explainer, "render", interrupted)
    with pytest.raises(KeyboardInterrupt):
        explainer.explain(rec, sections_for(rec), list(sections_for(rec)))


def runtime_replay(tmp_path, *, with_twins):
    """Every generated base pair through the real pipeline: engine record, build_view, explain, the eight checks."""
    from time import perf_counter
    from explainer_checks import corpus
    from explainer_checks.support import integration_result
    start = perf_counter()
    from explainer_checks.canary import audit_twins
    from explainer_checks.driver import run_pair
    from explainer_checks.support import corpus_resources
    b, c, templates = explainer._resources()
    resources_ = corpus_resources()
    rows = corpus.base_pairs()
    vectors = {v["vector_id"]: v for v in __import__("explainer_checks.pool", fromlist=["pool"]).pool()}
    digest = hashlib.sha256()
    replay = []
    failures = []
    canary_seconds = 0.0
    rejected_twins = 0
    for pair in rows:
        sections = vectors[pair["vector_id"]]["sections"]
        rec = adapt_record(pair["prompt"]["record"], templates=templates)
        order = list(dict.fromkeys([*templates["policies"][rec["policy_id"]]["sections"], *sections]))
        def build(r, s, o):
            return explainer.build_view(r, s, o, baselines=b, collection=c)
        if with_twins:
            canary_start = perf_counter()
            audit = audit_twins(build, rec, sections, order, fixed_sections=templates["policies"][rec["policy_id"]]["sections"])
            canary_seconds += perf_counter() - canary_start
            assert audit["ok"], (pair["id"], audit)
            rejected_twins += len(audit["rejected"])
        view = build(rec, sections, order)
        result = explainer.explain(rec, sections, order)
        actual = {"id": pair["id"], "prompt": {"record": rec, "data": view, "full_record_terms": []}, "output": result}
        checked = run_pair(actual, resources_)
        failures += [(pair["id"], k, v) for k, v in checked.items() if v["pass"] is not True]
        replay.append(canonical(actual))
        digest.update((canonical(actual) + "\n").encode())
        assert {ev["section"] for ev in view["evidence"][1:]} <= set(templates["policies"][rec["policy_id"]]["sections"])
    integration_result("runtime-replay-timing", {"seconds": perf_counter() - start, "pairs": len(rows), "canary_seconds": canary_seconds, "rejected_twins": rejected_twins, "failures": failures}, root=tmp_path)
    assert not failures, failures[:5]
    integration_result("runtime-replay", "\n".join(replay) + "\n", root=tmp_path)
    print(f"runtime {len(rows)} pairs / {5 * len(rows) if with_twins else 0} twins ({rejected_twins} forbidden citations rejected); {perf_counter() - start:.3f} s; SHA256=" + digest.hexdigest())


def _fresh_process(target, with_twins, timeout):
    code = ("import sys; from pathlib import Path; sys.path[:0] = "
            + repr([str(ROOT / "src"), str(ROOT / "tests")])
            + "; from test_explainer_integration import runtime_replay; runtime_replay(Path("
            + repr(str(target)) + "), with_twins=" + repr(with_twins) + ")")
    result = subprocess.run([sys.executable, "-B", "-I", "-c", code], capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    print(result.stdout)
    return (target / "runtime-replay.jsonl").read_bytes()


@pytest.mark.explainer_acceptance
def test_all_generated_pairs_runtime_canary_twins_and_independent_checks(tmp_path):
    """One fresh process: five twins per base pair with the real builder, then the eight checks on the runtime output."""
    from explainer_checks import corpus
    manifest = corpus.load_manifest()["pairs"]
    data = _fresh_process(tmp_path / "twins", True, 280)
    assert len(data.splitlines()) == manifest["base"]
    timing = json.loads((tmp_path / "twins" / "runtime-replay-timing.json").read_text())
    assert 0 < timing["rejected_twins"] <= 2 * manifest["base"] and not timing["failures"]


@pytest.mark.explainer_acceptance
def test_runtime_replay_is_byte_identical_across_fresh_processes(tmp_path):
    first = _fresh_process(tmp_path / "first", False, 140)
    second = _fresh_process(tmp_path / "second", False, 140)
    assert first == second, "fresh-process runtime replay bytes changed"


def test_existing_report_writers_preserve_synthetic_identifiers(tmp_path, monkeypatch):
    """Local writers preserve these values; explainer output wiring remains separate."""
    from azure_tenant_audit.output import AuditWriter
    from auditex import reporting
    payload = {"explainer": {"explanation": "SYNTHETIC_SECRET alice@example.com 01234567-89ab-cdef-0123-456789abcdef",
                             "remediation_steps": [], "evidence_refs": ["e0"]}}
    writer = AuditWriter.__new__(AuditWriter)
    writer.run_dir = tmp_path
    target = tmp_path / "report-pack.json"
    writer._write_json_atomic(target, payload)
    assert json.loads(target.read_text()) == payload
    captured = {}
    def private_write(path, content):
        captured["content"] = content
    monkeypatch.setattr(reporting, "write_private_text", private_write)
    monkeypatch.setattr(reporting, "preview_report", lambda **kwargs: {
        "content": json.dumps(payload), "sections": ["explainer"]})
    reporting.render_report(run_dir=str(tmp_path), format_name="json", profile="local")
    assert json.loads(captured["content"]) == payload


def test_generator_default_regenerates_the_shipped_template_from_the_product_catalogue():
    got = subprocess.run([sys.executable, "-B", "-I", str(ROOT / "scripts/generate-explainer.py"), "--check"],
                         cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert got.returncode == 0, got.stderr
    assert T["input_sha256"]["catalogue"] == hashlib.sha256(
        canonical(json.loads((ROOT / "configs/scuba-value-rules.json").read_text())).encode()).hexdigest()


def test_generator_still_refuses_a_product_catalogue_that_is_not_v391():
    from azure_tenant_audit.explainer import generate_template
    product = json.loads((ROOT / "configs/scuba-value-rules.json").read_text())
    b, c, _ = explainer._resources()
    product["spec_version"] = "v3.9"
    with pytest.raises(ValueError, match="reconciled to v3.9.1"):
        generate_template(product, b, c)


@pytest.mark.parametrize("code", shared_exceptions())
def test_both_shared_reasons_accept_exact_literals(code):
    from explainer_checks import corpus
    from explainer_checks.driver import run_pair
    from explainer_checks.support import corpus_resources
    pair = next(p for p in corpus.shared_pairs() if p["prompt"]["record"]["reason_code"] == code)
    result = run_pair(pair, corpus_resources())
    assert all(item["pass"] is True for item in result.values()), result
    for pid in T["policies"]:
        rec = record(code, pid)
        out = explainer.explain(rec, sections_for(rec), list(sections_for(rec)))
        assert out["explanation"] == shared_exceptions()[code]["explanation"]
        assert out["remediation_steps"] == shared_exceptions()[code]["remediation_steps"]
