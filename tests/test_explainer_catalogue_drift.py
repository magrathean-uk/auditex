"""Canonical regeneration and honest integration gates for the disjoint port."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from azure_tenant_audit.explainer import generate_template
from azure_tenant_audit.explainer import textkit as tk

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/explainer/renderer"
# The shipped product catalogue (spec v3.9.1) is the generator's catalogue input; the spec's byte-exact catalogue
# (renderer/catalogue-v391-fixture.json.gz) stays only as the independent pin used by test_explainer_integration.
CATALOGUE = ROOT / "configs/scuba-value-rules.json"
CAT = json.loads(CATALOGUE.read_text())
B, C = (json.loads((ROOT / "configs" / f).read_text()) for f in ("explainer-baselines.json", "explainer-what-to-collect.json"))
SHIPPED = ROOT / "configs/explainer-template.json"


def shipped():
    """The shipped file expanded to TemplateData (the file stores each repeated value once)."""
    return tk.expand_template(json.loads(SHIPPED.read_text()))


def shipped_bytes(template):
    return (tk.canonical(tk.compact_template(template)) + "\n").encode()


def test_canonical_regeneration_and_input_hashes():
    inputs = deepcopy((CAT, B, C))
    rebuilt = generate_template(CAT, B, C)
    assert shipped_bytes(rebuilt) == SHIPPED.read_bytes()
    assert rebuilt == shipped()
    assert (CAT, B, C) == inputs
    for key, data in (("catalogue", CAT), ("baselines", B), ("collection", C), ("shared_exceptions", rebuilt["shared_exceptions"])):
        assert rebuilt["input_sha256"][key] == hashlib.sha256(tk.canonical(data).encode()).hexdigest()


def test_same_count_catalogue_edit_is_detected():
    changed = deepcopy(CAT)
    cell = next(iter(next(iter(changed["policies"].values()))["cells"].values()))
    cell["reason_texts"][0] += " Changed."
    rebuilt = generate_template(changed, B, C)
    old = shipped()
    assert len(rebuilt["cells"]) == len(old["cells"])
    assert rebuilt["input_sha256"]["catalogue"] != old["input_sha256"]["catalogue"]
    assert tk.canonical(rebuilt) != tk.canonical(old)


def test_shared_exception_edit_is_detected(monkeypatch):
    changed = deepcopy(tk.FAULT); changed["explanation"] += " Changed."
    monkeypatch.setattr(tk, "FAULT", changed)
    rebuilt = generate_template(CAT, B, C)
    old = shipped()
    assert rebuilt["input_sha256"]["shared_exceptions"] != old["input_sha256"]["shared_exceptions"]
    assert rebuilt["cells"] == old["cells"]
    assert tk.canonical(rebuilt) != tk.canonical(old)


def test_all_inputs_and_wrapper_metadata_are_hashed():
    old = shipped()
    for field in ("baselines", "collection"):
        b, c = deepcopy(B), deepcopy(C)
        (b if field == "baselines" else c)["review_note"] = "changed"
        assert generate_template(CAT, b, c)["input_sha256"][field] != old["input_sha256"][field]
    a = generate_template({**CAT, "shared_reasons": {"note": "old"}}, B, C)
    b = generate_template({**CAT, "shared_reasons": {"note": "new"}}, B, C)
    assert a["cells"] == b["cells"] and a["input_sha256"]["catalogue"] != b["input_sha256"]["catalogue"]


def test_final_scrub_audit_and_fixture_pins():
    assert shipped()["scrub"] == []
    manifest = json.loads((FIX / "provenance.json").read_text())
    for name, expected in manifest["fixture_sha256"].items():
        assert hashlib.sha256(__import__("explainer_checks.support", fromlist=["x"]).read_bytes(FIX / name)).hexdigest() == expected
    assert manifest["historical_counts"] == {"R_preamble_occurrences": 29, "S_preamble_occurrences": 30, "S_truncated_policies": 30}


def test_generator_check_mode_and_fresh_isolated_processes_do_not_write_inputs(tmp_path):
    before = {p: p.read_bytes() for p in (CATALOGUE, ROOT / "configs/explainer-baselines.json", ROOT / "configs/explainer-what-to-collect.json")}
    outputs = []
    # Explicit repository venv, serial subprocesses; no other test files invoked.
    # -I ignores PYTHONHASHSEED: these interpreters use fresh random hash seeds.
    for attempt in ("first", "second"):
        import os
        env = dict(os.environ)
        output = tmp_path / (attempt + ".json")
        cmd = [sys.executable, "-B", "-I", str(ROOT / "scripts/generate-explainer.py"), "--catalogue", str(CATALOGUE),
               "--baselines", str(ROOT / "configs/explainer-baselines.json"), "--collection", str(ROOT / "configs/explainer-what-to-collect.json"), "--output", str(output)]
        subprocess.run(cmd, check=True, cwd=ROOT, env=env, capture_output=True)
        outputs.append(output.read_bytes())
        subprocess.run(cmd + ["--check"], check=True, cwd=ROOT, env=env, capture_output=True)
    assert outputs[0] == outputs[1] == SHIPPED.read_bytes()
    assert all(p.read_bytes() == content for p, content in before.items())


def test_generator_refuses_to_overwrite_collection():
    cmd = [sys.executable, "-B", "-I", str(ROOT / "scripts/generate-explainer.py"), "--collection", str(ROOT / "configs/explainer-what-to-collect.json"), "--output", str(ROOT / "configs/explainer-what-to-collect.json")]
    got = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    assert got.returncode == 2 and "must not overwrite" in got.stderr


def test_missing_or_duplicate_collection_entry_rejected():
    changed = deepcopy(C); changed["cells"].append(changed["cells"][0])
    with pytest.raises(ValueError): generate_template(CAT, B, changed)
    changed = deepcopy(C); changed["cells"] = [e for e in changed["cells"] if not e["applies"]]
    with pytest.raises(KeyError): generate_template(CAT, B, changed)


def test_catalogue_sourced_without_vectors_or_rule_implementation():
    from azure_tenant_audit.explainer import generate
    source = Path(generate.__file__).read_text()
    assert "import ref_impl" not in source and "cell-tables.md" not in source
    assert "open(" not in source and "read_text(" not in source
    changed = deepcopy(B); changed["source_commit"] = "unknown"
    with pytest.raises(ValueError): generate_template(CAT, changed, C)


def test_product_inputs_regenerate_shipped_template():
    """Required integration gate: the shipped template is the generator's output for the shipped product inputs.

    Any change to configs/scuba-value-rules.json, the baselines or the collection wording that is not followed by
    ``scripts/generate-explainer.py`` fails here.
    """
    paths = [ROOT / "configs/explainer-baselines.json", ROOT / "configs/explainer-what-to-collect.json"]
    inputs = [json.loads(p.read_text()) for p in paths]
    assert CAT["spec_version"] == "v3.9.1"
    assert shipped_bytes(generate_template(CAT, *inputs)) == SHIPPED.read_bytes()
