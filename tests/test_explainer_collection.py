"""Standalone collection tests; public contracts only, no live source checkout."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from azure_tenant_audit.explainer import collection

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/explainer/collection"
RESOURCE = ROOT / collection.RESOURCE_PATH
RAW = json.loads(RESOURCE.read_text(encoding="utf-8"))
# The spec's byte-exact v3.9.1 cell catalogue is the independent pin (stored compressed, shared with the renderer tests).
CATALOGUE = json.loads(gzip.decompress((ROOT / "tests/fixtures/explainer/renderer/catalogue-v391-fixture.json.gz").read_bytes()))
RECONCILIATION = json.loads(gzip.decompress((FIXTURES / "reconciliation.json.gz").read_bytes()))


def citation_cases():
    """Every (policy, cell, cited sections) the allowed vector pool exercises, plus each cell's static catalogue citation."""
    from explainer_checks import pool
    seen = {(v["policy"], v["cell"], None if v["cited"] is None else tuple(v["cited"])) for v in pool.pool()}
    for policy, row in CATALOGUE.items():
        for cell, entry in row["cells"].items():
            if isinstance(entry.get("cited"), list):
                seen.add((policy, cell, tuple(entry["cited"])))
    return [{"policy_id": p, "cell": c, "cited_sections": None if s is None else list(s)}
            for p, c, s in sorted(seen, key=lambda x: (x[0], x[1], x[2] is not None, x[2] or ()))]


CITATIONS = citation_cases()


def load(data):
    return collection.load_collection(lambda name: json.dumps(data))


@pytest.fixture(scope="module")
def data():
    return load(RAW)


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def test_worktree_import_and_one_injected_resource_read():
    assert Path(collection.__file__).resolve() == ROOT / "src/azure_tenant_audit/explainer/collection.py"
    requested = []

    def read_text(name):
        requested.append(name)
        return RESOURCE.read_text(encoding="utf-8")

    assert collection.load_collection(read_text) == RAW
    assert requested == ["configs/explainer-what-to-collect.json"]


def test_resource_errors_propagate_and_loads_do_not_share_state():
    def missing(name):
        raise FileNotFoundError(name)

    with pytest.raises(FileNotFoundError):
        collection.load_collection(missing)
    first, second = load(RAW), load(RAW)
    first["cells"][0]["text"] = "Changed in caller."
    assert second == RAW


def test_complete_v391_inventory_and_source_reconciliation(data):
    expected = {f"{p}/{cell}": c["verdict"] for p, policy in CATALOGUE.items() for cell, c in policy["cells"].items()}
    assert len(CATALOGUE) == 102
    assert len(expected) == len(data["cells"]) == 1084
    assert data["cell_inventory"] == expected
    assert {r["id"]: r["verdict"] for r in data["cells"]} == expected
    assert data["policy_sections"] == {p: v["sections"] for p, v in CATALOGUE.items()}
    active = [r for r in data["cells"] if r["applies"]]
    assert len(active) == 761
    assert len({r["cell"] for r in active}) == 122
    assert len(data["cells"]) - len(RECONCILIATION["source_entry_sha256"]) == 165
    assert len(CITATIONS) >= 1084
    assert {(r["policy_id"], r["cell"]) for r in CITATIONS} == {
        (p, cell) for p, v in CATALOGUE.items() for cell in v["cells"]}


def test_all_919_source_entries_preserved_including_wording_and_dependencies(data):
    by_id = {e["id"]: e for e in data["cells"]}
    for ident, digest in RECONCILIATION["source_entry_sha256"].items():
        entry = copy.deepcopy(by_id[ident])
        if not entry["applies"]:
            for key in ("rerun_text", "placeholders", "source"):
                del entry[key]
        assert f"sha256:{canonical_sha(entry)}" == digest, ident


def test_every_wording_entry_is_product_owned_and_pinned(data):
    assert data["ownership"]["owner"] == "Auditex"
    assert data["ownership"]["wording_file"] == collection.RESOURCE_PATH
    assert data["ownership"]["review_status"] == "pending_owner_review"
    assert hashlib.sha256(RESOURCE.read_bytes()).hexdigest() == RECONCILIATION["product_data_sha256"]
    pin = ROOT / "tests/fixtures/explainer/renderer/catalogue-v391-fixture.json.gz"
    assert hashlib.sha256(gzip.decompress(pin.read_bytes())).hexdigest() == RECONCILIATION["catalogue_pin_sha256"]
    assert data["rules_spec"] == "v3.9.1"
    assert data["input_sha256"] == RECONCILIATION["source_sha256"]


@pytest.mark.parametrize("case", CITATIONS, ids=lambda c: f"{c['policy_id']}/{c['cell']}:{c['cited_sections']}")
def test_all_vector_citation_cases(data, case):
    p, cell, cites = case["policy_id"], case["cell"], case["cited_sections"]
    steps = collection.collection_steps(data, p, cell, cites)
    entry = next(e for e in data["cells"] if e["id"] == f"{p}/{cell}")
    if CATALOGUE[p]["cells"][cell]["verdict"] != "not_assessed":
        assert steps == []
        return
    names = CATALOGUE[p]["sections"] if cites is None else cites
    assert steps == [entry["text"].replace("{sections}", ", ".join(names)),
                     entry["rerun_text"].replace("{sections}", ", ".join(names))]
    assert len(steps) == 2
    for step in steps:
        assert 0 < len(step.split()) <= 30
        assert "{" not in step and "}" not in step
        assert "http" not in step and "`" not in step
        assert all(ord(char) >= 32 for char in step)
        assert step.endswith(".")
        assert step.startswith(("Check ", "Collect ", "Confirm ", "Run "))


def test_none_uses_full_policy_sections_and_preserves_supplied_order(data):
    p, cell = "MS.SECURITYSUITE.7.1v1", "preset_rule_unusable"
    cites = ["protection_policy_rules", "atp_policy_rules"]
    before_data, before_cites = copy.deepcopy(data), list(cites)
    assert "protection_policy_rules, atp_policy_rules" in collection.collection_steps(data, p, cell, cites)[0]
    full = ", ".join(data["policy_sections"][p])
    assert full in collection.collection_steps(data, p, cell, None)[0]
    assert data == before_data and cites == before_cites


def test_minimal_injected_mapping_needs_no_other_part():
    entry = copy.deepcopy(next(e for e in RAW["cells"] if e["applies"]))
    minimal = {"schema_version": 1, "version": "test", "dependency_text": {}, "cells": [entry]}
    data = load(minimal)
    assert collection.collection_steps(data, entry["policy_id"], entry["cell"], None) == [
        "Check that the conditional_access_policies evidence holds the entries this policy reads (the export returned none), then export it again.",
        "Run the assessment again once the conditional_access_policies evidence is complete."]


@pytest.mark.parametrize("cites", [[], "conditional_access_policies", ["conditional_access_policies"] * 2,
                                    ["owner@example.test"], [{"DisplayName": "DO_NOT_ECHO"}],
                                    ["conditional_access_policies\nDO_NOT_ECHO"], ["transport_config"], [None], [1]])
def test_input_values_and_unknown_or_malformed_sections_are_rejected(data, cites):
    with pytest.raises(ValueError) as exc:
        collection.collection_steps(data, "MS.AAD.1.1v1", "no_usable_items", cites)
    assert "DO_NOT_ECHO" not in str(exc.value)
    assert "owner@example.test" not in str(exc.value)


@pytest.mark.parametrize("p,cell", [("unknown", "no_usable_items"), ("MS.AAD.1.1v1", "unknown"),
                                   ("MS.AAD.1.1v1", None), ("MS.AAD.1.1v1", "rule_evaluation_failed"),
                                   ("MS.AAD.1.1v1", "rule_not_implemented")])
def test_unknown_keys_and_shared_reasons_never_invent_collection_steps(data, p, cell):
    with pytest.raises(KeyError):
        collection.collection_steps(data, p, cell, ["conditional_access_policies"])


def test_no_inactive_cell_ever_acquires_steps(data):
    inactive = [r for r in data["cells"] if not r["applies"]]
    assert len(inactive) == 323
    for r in inactive:
        assert collection.collection_steps(data, r["policy_id"], r["cell"], None) == []


def test_dependencies_are_metadata_and_a1_blocked_wording_is_fixed(data):
    for r in data["cells"]:
        if not r["applies"]:
            continue
        ce = CATALOGUE[r["policy_id"]]["cells"][r["cell"]]
        assert r["recommendations"] == ce.get("recommendations", [])
        assert set(r["product_dependencies"]) <= data["dependency_text"].keys()
        if "check_licence_or_permissions" in r["recommendations"]:
            assert r["text"] == data["recommendation_text"]["check_licence_or_permissions"]
        text = " ".join(collection.collection_steps(data, r["policy_id"], r["cell"], None))
        for dep in r["product_dependencies"]:
            assert dep not in text.split()
            assert data["dependency_text"][dep] not in text


@pytest.mark.parametrize("placeholder", ["{detail}", "{sections[0]}", "{sections.__class__}",
                                           "{sections!r}", "{sections:>30}", "{{sections}}", "{", "}"])
@pytest.mark.parametrize("field", ["text", "rerun_text"])
def test_placeholder_rejection(placeholder, field):
    data = copy.deepcopy(RAW)
    next(e for e in data["cells"] if e["applies"])[field] = f"Collect {placeholder} evidence."
    with pytest.raises(ValueError):
        load(data)


@pytest.mark.parametrize("mutation", ["duplicate", "missing_active", "missing_inactive", "missing_field",
                                      "wrong_id", "unknown_dependency", "unknown_collect", "active_met",
                                      "inactive_action", "bad_source", "bad_placeholders", "bad_schema",
                                      "bad_sections", "shared_cell", "bad_recommendation_placeholder"])
def test_invalid_collection_data_fails_closed(mutation):
    data = copy.deepcopy(RAW)
    active = next(e for e in data["cells"] if e["applies"])
    inactive = next(e for e in data["cells"] if not e["applies"])
    if mutation == "duplicate":
        data["cells"].append(copy.deepcopy(active))
    elif mutation == "missing_active":
        data["cells"].remove(active)
    elif mutation == "missing_inactive":
        data["cells"].remove(inactive)
    elif mutation == "missing_field":
        del active["rerun_text"]
    elif mutation == "wrong_id":
        active["id"] = "wrong"
    elif mutation == "unknown_dependency":
        active["product_dependencies"] = ["P999"]
    elif mutation == "unknown_collect":
        active["collect"] = ["input_derived_value"]
    elif mutation == "active_met":
        active["verdict"] = "met"
    elif mutation == "inactive_action":
        inactive["text"] = "Collect evidence."
    elif mutation == "bad_source":
        active["source"] = {}
    elif mutation == "bad_placeholders":
        active["placeholders"] = {"detail": "record.detail"}
    elif mutation == "bad_schema":
        data["schema_version"] = True
    elif mutation == "bad_sections":
        data["policy_sections"][active["policy_id"]] = ["arbitrary_value"]
    elif mutation == "shared_cell":
        active["cell"] = "rule_evaluation_failed"
        active["id"] = f"{active['policy_id']}/rule_evaluation_failed"
    elif mutation == "bad_recommendation_placeholder":
        data["recommendation_text"]["recollect_unusable_evidence"] = "Collect {detail}."
    with pytest.raises(ValueError):
        load(data)


@pytest.mark.parametrize("raw", ["{", "[]", "null", '{"schema_version":1,"schema_version":1}',
                                 '{"schema_version":NaN}', '{"schema_version":1}'])
def test_malformed_or_incomplete_json_rejected(raw):
    with pytest.raises(ValueError):
        collection.load_collection(lambda _: raw)
