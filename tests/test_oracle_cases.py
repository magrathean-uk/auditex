"""Oracle-case miner and splitter: pure functions on inline fixtures, plus an end-to-end run when OPA and ScubaGear exist.

Nothing here needs OPA or ScubaGear except the tests marked `needs_oracle`. They run only when these are exported:

    AUDITEX_TEST_OPA                OPA 1.20.2 binary
    AUDITEX_TEST_SCUBAGEAR          PowerShell/ScubaGear directory of a ScubaGear checkout at the pinned commit
    AUDITEX_TEST_ORACLE_REFERENCE   optional: a prototype cases-powerplatform.jsonl to compare labels against

Unset or missing, those tests are skipped; there are no machine-specific defaults.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from auditex.model_training import distinct_prompt_sha256, validate_case, validate_cases

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


OPA = _env_path("AUDITEX_TEST_OPA")
SCUBA = _env_path("AUDITEX_TEST_SCUBAGEAR")
REFERENCE = _env_path("AUDITEX_TEST_ORACLE_REFERENCE")
PINNED_COMMIT = "2446ad723b7f55031cc02c8aca244d731d468cba"
PINNED_OPA = "1.20.2"
needs_oracle = pytest.mark.skipif(
    not (OPA and OPA.is_file() and SCUBA and SCUBA.is_dir()),
    reason="export AUDITEX_TEST_OPA (OPA 1.20.2) and AUDITEX_TEST_SCUBAGEAR (PowerShell/ScubaGear at the pinned commit)")
needs_reference = pytest.mark.skipif(not (REFERENCE and REFERENCE.is_file()), reason="export AUDITEX_TEST_ORACLE_REFERENCE to compare with a prototype output")


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def miner():
    return _load("build_oracle_cases", "build-oracle-cases.py")


@pytest.fixture(scope="module")
def splitter():
    return _load("split_oracle_cases", "split-oracle-cases.py")


def _evaluations(inputs: list[dict], policies: dict[str, list[bool]]) -> list[tuple[dict, list[dict]]]:
    """Fake oracle output: variant i of every policy carries verdict policies[pid][i]."""
    out = []
    for index, value in enumerate(inputs):
        variant = {"name": "base" if index == 0 else f"demo_test:variant_{index}", "input": value, "sha256": f"{index:064x}"}
        results = [{"PolicyId": pid, "Criticality": "Shall", "RequirementMet": verdicts[index], "ReportDetails": f"detail {index}"}
                   for pid, verdicts in policies.items()]
        out.append((variant, results))
    return out


def _mined(miner, product: str, groups: int, *, every: int = 1000) -> list[dict]:
    """Cases for one product with `groups` policy groups: each policy sees a base and one mutated variant."""
    inputs = [{"sec_a": {"enabled": True}}, {"sec_a": {"enabled": False}}]
    pids = {f"MS.{product.upper()}.{group}.1v1": [True, False] for group in range(1, groups + 1)}
    sections = {pid: ["sec_a"] for pid in pids}
    cases, _ = miner.build_cases(product, _evaluations(inputs, pids), sections, {}, inputs[0], commit="abcdef123456",
                                 opa_version="1.20.2", config_name=f"{product}Config.rego", not_collected_every=every)
    return cases


def _duplicate_prone(miner) -> list[dict]:
    """Four variants differing only in the first section; every second case masks that section, so the not-collected
    cases (indexes 1 and 3) share one prompt and answer under different ids."""
    inputs = [{"sec_a": {"v": value}, "sec_b": {"fixed": True}} for value in range(4)]
    pid = "MS.DUP.1.1v1"
    cases, _ = miner.build_cases("dup", _evaluations(inputs, {pid: [True, False, True, False]}), {pid: ["sec_a", "sec_b"]}, {},
                                 inputs[0], commit="abcdef123456", opa_version="1.20.2", config_name="DupConfig.rego", not_collected_every=2)
    return cases


# --- miner: pure functions --------------------------------------------------------------------------------------


def test_snake_keeps_acronyms_together(miner):
    assert miner.snake("SPOTenant") == "spo_tenant"
    assert miner.snake("AtpPolicyForO365") == "atp_policy_for_o365"
    assert miner.snake("ConditionalAccessPolicies") == "conditional_access_policies"


def test_patch_replay_applies_add_remove_replace(miner):
    doc = {"setting": True, "items": [{"id": 1}, {"id": 2}], "nested": {"keep": 1, "drop": 2}}
    ops = [
        {"op": "add", "path": "extra", "value": 5},                      # leading slash optional, as in OPA
        {"op": "replace", "path": "/setting", "value": False},
        {"op": "add", "path": "/items/-", "value": {"id": 3}},
        {"op": "add", "path": "/items/0", "value": {"id": 0}},
        {"op": "remove", "path": "/items/2"},
        {"op": "remove", "path": "/nested/drop"},
        {"op": "remove", "path": "/nested/missing"},                      # removing an absent key is a no-op
    ]
    assert miner.apply_patch(doc, ops) == {"setting": False, "extra": 5, "items": [{"id": 0}, {"id": 1}, {"id": 3}], "nested": {"keep": 1}}


@pytest.mark.parametrize("ops", [
    [{"op": "move", "path": "/a", "value": 1}],
    [{"op": "replace", "path": "/", "value": 1}],
    [{"op": "replace", "path": "/a/b", "value": 1}],
    [{"op": "replace", "path": "/items/9", "value": 1}],
])
def test_patch_replay_rejects_what_it_cannot_replay(miner, ops):
    with pytest.raises(miner.PATCH_ERRORS):
        miner.apply_patch({"a": True, "items": [1]}, ops)


def test_literals_are_read_when_json_compatible(miner):
    text = (
        'Plain := {"enabled": true, "n": [1, 2]}  # trailing comment\n'
        "Listed := [\n  {\"a\": null}  # note\n]\n"
        'Computed := {"value": concat("", ["a", "b"])}\n'
    )
    assert miner.extract_literals(text) == {"Plain": {"enabled": True, "n": [1, 2]}, "Listed": [{"a": None}]}


def test_literals_survive_escaped_quotes_and_hashes_inside_strings(miner):
    text = (
        'Quoted := {"a": "say \\"hi]\\" now", "b": ["x}"]}\n'
        'Hash := {"url": "https://example.test/#fragment", "n": 1}  # real comment\n'
        'Commented := [\n  # an unbalanced { in a comment\n  {"ok": true}\n]\n'
        'Backslash := {"path": "C:\\\\temp\\\\", "after": 2}\n'
    )
    assert miner.extract_literals(text) == {
        "Quoted": {"a": 'say "hi]" now', "b": ["x}"]},
        "Hash": {"url": "https://example.test/#fragment", "n": 1},
        "Commented": [{"ok": True}],
        "Backslash": {"path": "C:\\temp\\", "after": 2},
    }


def test_comment_stripping_only_applies_outside_strings(miner):
    assert miner.strip_rego_comments('{"a": "#not", "b": 1} # gone\n# whole line\n[2]') == '{"a": "#not", "b": 1} \n\n[2]'
    assert miner.strip_rego_comments('"escaped \\" # still inside" # outside') == '"escaped \\" # still inside" '
    assert miner.rego_literal_to_json('[{"op": "add", "path": "x", "value": "#1"}]  # comment') == [{"op": "add", "path": "x", "value": "#1"}]


def test_harvest_replays_unit_test_mutations_into_variants(miner, tmp_path):
    tests_dir = tmp_path / "Unit"
    tests_dir.mkdir()
    (tests_dir / "Demo_01_test.rego").write_text('''package demo_test
import rego.v1

Extra := {"flag": false}

test_off_Incorrect if {
    Patched := json.patch(Setting, [{"op": "replace", "path": "enabled", "value": false}])
    Output := demo.tests with input.sec_a as [Patched]
    TestResult("MS.DEMO.1.1v1", Output, FAIL, false) == true
}

test_same_Correct if {
    Output := demo.tests with input.sec_a as [Setting]
    TestResult("MS.DEMO.1.1v1", Output, PASS, true) == true
}

test_literal_Correct if {
    Output := demo.tests with input.sec_b as Extra
    TestResult("MS.DEMO.1.1v1", Output, PASS, true) == true
}

test_unknown_source if {
    Patched := json.patch(Nowhere, [{"op": "add", "path": "x", "value": 1}])
    Output := demo.tests with input.sec_a as [Patched]
    true
}

test_bad_patch if {
    Patched := json.patch(Setting, [{"op": "replace", "path": "enabled/deep", "value": 1}])
    Output := demo.tests with input.sec_a as [Patched]
    true
}
''', encoding="utf-8")
    meta = {"tests_dir": tests_dir, "keys": ["sec_a", "sec_b"], "wrap": {"sec_a": True, "sec_b": False}}
    base_objects = {"Setting": {"enabled": True}}
    base_input = {"sec_a": [{"enabled": True}], "sec_b": {}}
    variants, skipped = miner.harvest_variants(meta, base_objects, copy.deepcopy(base_input))
    assert [v["name"] for v in variants] == ["base", "Demo_01_test:off_Incorrect", "Demo_01_test:literal_Correct"]
    assert variants[1]["input"] == {"sec_a": [{"enabled": False}], "sec_b": {}}
    assert variants[2]["input"] == {"sec_a": [{"enabled": True}], "sec_b": {"flag": False}}
    assert dict(skipped) == {"identical_to_base": 1, "unknown_patch_source": 1, "unparsable_patch": 1}
    assert base_objects == {"Setting": {"enabled": True}}  # patches never mutate the shared fixture


def test_rego_dependencies_follow_helper_rules_and_baseline_text_is_read(miner, tmp_path):
    rego = tmp_path / "Rego"
    (rego / "Utils").mkdir(parents=True)
    (rego / "DemoConfig.rego").write_text('''package demo

tests contains {
    "PolicyId": "MS.DEMO.1.1v1",
    "ActualValue": Helper,
    "RequirementMet": Status
} if {
    Status := true
}

tests contains {
    "PolicyId": "MS.DEMO.1.2v1",
    "ActualValue": input.sec_b,
    "RequirementMet": true
} if {
    true
}

tests contains {
    "PolicyId": "MS.DEMO.1.3v1",
    "RequirementMet": Status
} if {
    Status := count(input.sec_c) > 0
}

Helper := count(Inner) if {
    true
}

Inner := input.sec_a if {
    true
}
''', encoding="utf-8")
    (rego / "Utils" / "Key.rego").write_text("package utils.key\n", encoding="utf-8")
    baselines = tmp_path / "baselines"
    baselines.mkdir()
    (baselines / "demo.md").write_text("#### MS.DEMO.1.1v1\nThe setting SHALL\nbe enabled.\n<!--Policy: MS.DEMO.1.1v1-->\n\n#### MS.DEMO.1.2v1\nSecond.\n### Next\n", encoding="utf-8")
    meta = {"config": rego / "DemoConfig.rego", "keys": ["sec_a", "sec_b", "sec_c"], "baseline": baselines / "demo.md"}
    # Helper rules are followed two levels deep. Only the head of each policy rule is scanned, so a reference that
    # appears solely in the `if { ... }` body (1.3) is not a declared dependency; derive_sections widens such views.
    assert miner.rego_dependencies(meta) == {"MS.DEMO.1.1v1": {"sec_a"}, "MS.DEMO.1.2v1": {"sec_b"}, "MS.DEMO.1.3v1": set()}
    assert miner.policy_text(meta) == {"MS.DEMO.1.1v1": "The setting SHALL be enabled.", "MS.DEMO.1.2v1": "Second."}
    assert miner.policy_text({"baseline": tmp_path / "missing.md"}) == {}


def test_evidence_view_widens_until_identical_views_agree(miner):
    inputs = [
        {"dep": {"x": 1}, "hidden": {"mode": "a"}, "other": 1},
        {"dep": {"x": 1}, "hidden": {"mode": "b"}, "other": 1},
        {"dep": {"x": 2}, "hidden": {"mode": "a"}, "other": 1},
    ]
    evaluations = _evaluations(inputs, {"MS.DEMO.1.1v1": [True, False, True], "MS.DEMO.1.2v1": [True, True, True]})
    evaluations[0][1].append({"PolicyId": "MS.DEMO.1.3v1", "Criticality": "Shall/3rd Party", "RequirementMet": "N/A"})
    deps = {"MS.DEMO.1.1v1": {"dep"}, "MS.DEMO.1.2v1": {"dep"}, "MS.DEMO.1.3v1": {"dep"}}
    sections = miner.derive_sections(deps, evaluations, ["dep", "hidden", "other"])
    assert sections["MS.DEMO.1.1v1"] == ["dep", "hidden"]   # `hidden` flips the verdict, so the view must include it
    assert sections["MS.DEMO.1.2v1"] == ["dep"]             # already consistent: no widening
    assert "MS.DEMO.1.3v1" not in sections                  # non-boolean verdicts are never labelled


def test_mutation_family_reports_changed_fields_without_values(miner):
    base = {"sec_a": [{"enabled": True, "name": "x"}], "sec_b": {"k": 1}, "sec_c": [1, 2]}
    assert miner.mutation_family(base, copy.deepcopy(base), ["sec_a", "sec_b"]) == "base"
    changed = {"sec_a": [{"enabled": False, "name": "x"}], "sec_b": {"k": 1}, "sec_c": [1, 2, 3]}
    assert miner.mutation_family(base, changed, ["sec_a", "sec_b"]) == "replace:sec_a.*.enabled"
    other = {**changed, "sec_a": [{"enabled": True, "name": "y"}]}
    assert miner.mutation_family(base, other, ["sec_a"]) == "replace:sec_a.*.name"
    structural = {"sec_a": [{"enabled": True}, {"enabled": True}], "sec_b": {"k": 1, "new": 2}, "sec_c": [1]}
    assert miner.mutation_family(base, structural, ["sec_a", "sec_b", "sec_c"]) == \
        "add:sec_a.*+add:sec_b.new+remove:sec_a.*.name+remove:sec_c.*"
    # a value change and the same change elsewhere in the list share a family; booleans never equal integers
    assert miner.mutation_family({"s": [True]}, {"s": [1]}, ["s"]) == "replace:s.*"


def test_long_mutation_families_stay_distinct_and_deterministic(miner):
    base = {"s": {f"k{i}": 0 for i in range(8)}}
    first = {"s": {f"k{i}": 1 for i in range(8)}}
    second = {"s": {**{f"k{i}": 1 for i in range(7)}, "k7": 0, "extra": 1}}
    family = miner.mutation_family(base, first, ["s"])
    assert family.startswith("replace:s.k0+replace:s.k1+replace:s.k2+5more-")
    assert family == miner.mutation_family(base, first, ["s"])
    assert family != miner.mutation_family(base, second, ["s"])


def test_template_key_is_product_policy_family(miner):
    assert miner.template_key("PowerPlatform", "MS.POWERPLATFORM.1.1v1", "base") == "powerplatform/MS.POWERPLATFORM.1.1v1/base"


def test_cases_carry_template_and_masked_prompt_digest(miner):
    cases = _mined(miner, "aad", 2)
    assert [c["provenance"]["template"] for c in cases] == [
        "aad/MS.AAD.1.1v1/base", "aad/MS.AAD.2.1v1/base",
        "aad/MS.AAD.1.1v1/replace:sec_a.enabled", "aad/MS.AAD.2.1v1/replace:sec_a.enabled"]
    assert [c["family"] for c in cases] == ["scuba-aad-ms-aad-1", "scuba-aad-ms-aad-2"] * 2
    assert [c["expected"]["claims"][0]["value"] for c in cases] == [True, True, False, False]
    assert all(c["provenance"]["review_status"] == "unreviewed" and c["split"] == "train" for c in cases)
    assert all(c["provenance"]["source"].startswith("oracle:cisa-scubagear@abcdef123456 aadConfig.rego MS.AAD.") for c in cases)
    validate_cases(cases)


def test_prompt_digest_ignores_the_case_id_but_not_the_evidence(miner):
    case = _mined(miner, "aad", 1)[0]
    renamed = copy.deepcopy(case)
    renamed["id"] = "scuba-aad-renamed"
    renamed["messages"][1]["content"] = renamed["messages"][1]["content"].replace(f'"{case["id"]}"', '"scuba-aad-renamed"')
    assert renamed["messages"][1]["content"] != case["messages"][1]["content"]
    assert distinct_prompt_sha256(renamed) == distinct_prompt_sha256(case) == case["provenance"]["distinct_prompt_sha256"]
    other = copy.deepcopy(case)
    other["messages"][1]["content"] = other["messages"][1]["content"].replace('"enabled":true', '"enabled":false')
    assert distinct_prompt_sha256(other) != distinct_prompt_sha256(case)
    assert len(distinct_prompt_sha256(case)) == 64


def test_not_collected_cases_expect_unknown_and_use_the_not_collected_template(miner):
    cases = _duplicate_prone(miner)
    assert [c["expected"]["claims"][0]["status"] for c in cases] == ["confirmed", "unknown", "confirmed", "unknown"]
    nc = cases[1]
    assert nc["id"].endswith("-nc") and nc["expected"]["limitations"] == ["required_evidence_section_not_collected"]
    assert nc["provenance"]["template"] == "dup/MS.DUP.1.1v1/not_collected:sec_a"
    assert json.loads(nc["messages"][1]["content"])["evidence"][1]["observed"] == {"collection_status": "not_collected"}
    assert cases[1]["provenance"]["distinct_prompt_sha256"] == cases[3]["provenance"]["distinct_prompt_sha256"]
    assert cases[0]["provenance"]["distinct_prompt_sha256"] != cases[2]["provenance"]["distinct_prompt_sha256"]


def test_template_key_can_be_disabled_and_cases_still_validate(miner):
    inputs = [{"sec_a": {"enabled": True}}]
    cases, stats = miner.build_cases("aad", _evaluations(inputs, {"MS.AAD.1.1v1": [True]}), {"MS.AAD.1.1v1": ["sec_a"]}, {}, inputs[0],
                                     commit="abcdef123456", opa_version="1.20.2", config_name="AADConfig.rego",
                                     not_collected_every=4, template=False)
    assert set(cases[0]["provenance"]) == {"source", "synthetic", "review_status"} and stats["met"] == 1
    validate_cases(cases)


def test_policies_without_a_derived_view_and_repeated_views_are_counted_not_emitted(miner):
    inputs = [{"sec_a": 1}, {"sec_a": 1}]
    evaluations = _evaluations(inputs, {"MS.AAD.1.1v1": [True, True]})
    evaluations[0][1].append({"PolicyId": "MS.AAD.9.9v1", "Criticality": "Shall", "RequirementMet": True})
    cases, stats = miner.build_cases("aad", evaluations, {"MS.AAD.1.1v1": ["sec_a"]}, {}, inputs[0], commit="abcdef123456",
                                     opa_version="1.20.2", config_name="AADConfig.rego", not_collected_every=4)
    assert len(cases) == 1 and stats["duplicate_view"] == 1 and stats["policy_skipped"] == 1


def _fake_opa(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "opa"
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_opa_json_returns_the_value_of_one_query(miner, tmp_path):
    opa = _fake_opa(tmp_path, 'echo \'{"result":[{"expressions":[{"value":[1,2]}]}]}\'')
    assert miner.opa_json(opa, ["data.demo.tests"]) == [1, 2]


@pytest.mark.parametrize("body", ["echo '{}'", "echo 'not json'", 'echo \'{"result":[]}\'', 'echo \'{"result":[{"expressions":[]}]}\''])
def test_opa_json_reports_undefined_or_malformed_results_clearly(miner, tmp_path, body):
    with pytest.raises(miner.OpaError, match="no usable result.*data.demo.tests"):
        miner.opa_json(_fake_opa(tmp_path, body), ["-d", "x.rego", "data.demo.tests"])


def test_opa_json_times_out_and_surfaces_failed_evaluations(miner, tmp_path, monkeypatch):
    monkeypatch.setattr(miner, "OPA_TIMEOUT", 0.3)
    with pytest.raises(miner.OpaError, match="timed out after 0.3 s: data.demo.tests"):
        miner.opa_json(_fake_opa(tmp_path, "exec sleep 5"), ["data.demo.tests"])
    with pytest.raises(subprocess.CalledProcessError):
        miner.opa_json(_fake_opa(tmp_path, "echo boom >&2; exit 3"), ["data.demo.tests"])
    assert issubclass(miner.OpaError, ValueError)  # a failed base fixture is a product error in main


def test_a_variant_whose_evaluation_fails_is_counted_and_the_run_continues(miner, tmp_path, monkeypatch):
    base = {"sec_a": {"enabled": True}}
    meta = {"name": "Demo", "config": tmp_path / "DemoConfig.rego", "package": "demo", "keys": ["sec_a"]}
    variants = [{"name": "base", "input": base}, {"name": "demo_test:broken", "input": {"sec_a": {"enabled": False}}}]
    monkeypatch.setattr(miner, "product_meta", lambda scuba, name: meta)
    monkeypatch.setattr(miner, "load_base", lambda opa, m: (base, {}, {"mapped": {}, "unmatched_fixture_objects": []}))
    monkeypatch.setattr(miner, "harvest_variants", lambda m, objects, inp: (variants, Counter()))
    monkeypatch.setattr(miner, "policy_text", lambda m: {})
    monkeypatch.setattr(miner, "rego_dependencies", lambda m: {"MS.DEMO.1.1v1": {"sec_a"}})
    calls = []

    def fake_opa(opa, args):
        calls.append(args)
        if len(calls) == 1:
            return [{"PolicyId": "MS.DEMO.1.1v1", "Criticality": "Shall", "RequirementMet": True}]
        raise miner.OpaError("opa eval returned no usable result (undefined query or malformed output): data.demo.tests")

    monkeypatch.setattr(miner, "opa_json", fake_opa)
    out = tmp_path / "out"
    out.mkdir()
    cases, summary = miner.mine_product("Demo", tmp_path, tmp_path / "opa", out, 4, commit="abcdef123456", opa_version="1.20.2")
    assert len(cases) == 1 and summary["stats"]["variants_failed"] == 1 and len(calls) == 2
    assert "no usable result" in (out / "first-eval-error-demo.txt").read_text(encoding="utf-8")


# --- provenance contract ----------------------------------------------------------------------------------------


def test_case_contract_accepts_template_and_digest_but_nothing_else(miner):
    case = _mined(miner, "aad", 1)[0]
    assert validate_case(copy.deepcopy(case)) == case
    for mutate, message in (
        (lambda c: c["provenance"].update(extra="x"), "provenance requires"),
        (lambda c: c["provenance"].update(distinct_prompt_sha256="XYZ"), "SHA-256"),
        (lambda c: c["provenance"].update(distinct_prompt_sha256="A" * 64), "SHA-256"),
        (lambda c: c["provenance"].update(template=" "), "template"),
    ):
        broken = copy.deepcopy(case)
        mutate(broken)
        with pytest.raises(ValueError, match=message):
            validate_case(broken)


# --- miner: command line ----------------------------------------------------------------------------------------


@pytest.fixture
def fake_oracle(tmp_path, miner, monkeypatch):
    scuba = tmp_path / "ScubaGear"
    scuba.mkdir()
    opa = tmp_path / "opa"
    opa.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(miner, "tool_versions", lambda scuba_dir, opa_bin: ("abcdef123456", "a" * 40, True, "1.20.2"))

    def fake_mine(name, scuba_dir, opa_bin, out, every, *, commit, opa_version, template=True):
        if name == "EXO":
            raise ValueError("boom")
        cases = _mined(miner, name.lower(), 1)
        return cases, {"product": name, "variants": 2, "harvest_skipped": {}, "cases": len(cases), "stats": {}}

    monkeypatch.setattr(miner, "mine_product", fake_mine)
    return scuba, opa


def _miner_args(scuba, opa, out, *extra):
    return ["--scuba", str(scuba), "--opa", str(opa), "--output-dir", str(out), *extra]


def test_miner_requires_explicit_inputs(miner, tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        miner.main(["--products", "AAD"])
    assert exc.value.code == 2 and "--scuba" in capsys.readouterr().err


def test_miner_checks_inputs_before_creating_the_output(miner, fake_oracle, tmp_path):
    scuba, opa = fake_oracle
    out = tmp_path / "out"
    for args in (_miner_args(tmp_path / "missing", opa, out), _miner_args(scuba, tmp_path / "no-opa", out),
                 _miner_args(scuba, opa, out, "--not-collected-every", "1"), _miner_args(scuba, opa, out, "--products", "Nope")):
        with pytest.raises(SystemExit) as exc:
            miner.main(args)
        assert exc.value.code == 2
    assert not out.exists()


def test_miner_refuses_an_existing_output_directory(miner, fake_oracle, tmp_path, capsys):
    scuba, opa = fake_oracle
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep.txt").write_text("keep", encoding="utf-8")
    assert miner.main(_miner_args(scuba, opa, out, "--products", "AAD")) == 2
    assert "already exists" in capsys.readouterr().err
    assert sorted(p.name for p in out.iterdir()) == ["keep.txt"]


def test_miner_refuses_output_inside_a_finalized_audit_run(miner, fake_oracle, tmp_path):
    scuba, opa = fake_oracle
    run = tmp_path / "run"
    run.mkdir()
    (run / "run-manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        miner.main(_miner_args(scuba, opa, run / "cases"))
    assert exc.value.code == 2 and not (run / "cases").exists()


def test_miner_writes_the_documented_layout_and_fails_when_a_product_fails(miner, fake_oracle, tmp_path, capsys):
    scuba, opa = fake_oracle
    out = tmp_path / "out"
    assert miner.main(_miner_args(scuba, opa, out, "--products", "AAD", "EXO", "Teams")) == 1
    assert sorted(p.name for p in out.iterdir()) == ["cases-aad.jsonl", "cases-teams.jsonl", "cases.jsonl", "summary.json"]
    rows = [json.loads(line) for line in (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 4 and {r["family"] for r in rows} == {"scuba-aad-ms-aad-1", "scuba-teams-ms-teams-1"}
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["total_cases"] == 4 and summary["products"]["EXO"] == {"error": "ValueError: boom"}
    assert summary["oracle"]["commit"] == "a" * 40 and summary["oracle"]["licence"] == "CC0-1.0" and summary["template_key"] is True
    captured = capsys.readouterr()
    assert "boom" in captured.out
    assert "EXO failed" in captured.err and "incomplete" in captured.err


def test_an_unexpected_failure_says_the_output_is_incomplete(miner, fake_oracle, tmp_path, monkeypatch, capsys):
    scuba, opa = fake_oracle
    out = tmp_path / "out"

    def explode(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(miner, "mine_product", explode)
    with pytest.raises(RuntimeError):
        miner.main(_miner_args(scuba, opa, out, "--products", "AAD"))
    assert out.is_dir() and not (out / "summary.json").exists()
    err = capsys.readouterr().err
    assert "did not finish" in err and "incomplete" in err and "should be deleted" in err


def test_miner_exits_zero_and_can_drop_the_template_key(miner, fake_oracle, tmp_path):
    scuba, opa = fake_oracle
    out = tmp_path / "out"
    assert miner.main(_miner_args(scuba, opa, out, "--products", "AAD", "--no-template-key")) == 0
    assert json.loads((out / "summary.json").read_text(encoding="utf-8"))["template_key"] is False


# --- splitter ---------------------------------------------------------------------------------------------------


def test_default_split_assigns_whole_policy_groups_per_product(miner, splitter):
    cases = _mined(miner, "aad", 5) + _mined(miner, "exo", 2)
    out, report = splitter.split_cases(cases)
    split_of = {c["family"]: c["split"] for c in out}
    assert [split_of[f"scuba-aad-ms-aad-{g}"] for g in range(1, 6)] == ["train", "train", "train", "validation", "test"]
    assert {split_of["scuba-exo-ms-exo-1"], split_of["scuba-exo-ms-exo-2"]} == {"train"}   # fewer than three groups stay in train
    assert all(len({c["split"] for c in out if c["family"] == family}) == 1 for family in split_of)
    assert report["leakage"] == {"families_in_multiple_splits": 0, "templates_in_multiple_splits": 0, "distinct_prompts_in_multiple_splits": 0}
    assert [c["id"] for c in out] == [c["id"] for c in cases]   # input order is preserved


def test_a_template_shared_by_two_groups_keeps_them_in_one_split(miner, splitter):
    cases = _mined(miner, "aad", 5)
    shared = "aad/shared/replace:sec_a.enabled"
    for case in cases:
        if case["family"] in {"scuba-aad-ms-aad-4", "scuba-aad-ms-aad-5"} and case["provenance"]["template"].endswith("replace:sec_a.enabled"):
            case["provenance"]["template"] = shared
    atoms = splitter.split_atoms(cases)
    assert atoms["scuba-aad-ms-aad-5"] == atoms["scuba-aad-ms-aad-4"] == "scuba-aad-ms-aad-4"
    assert atoms["scuba-aad-ms-aad-3"] == "scuba-aad-ms-aad-3"
    out, report = splitter.split_cases(cases)
    split_of = {c["family"]: c["split"] for c in out}
    # groups 4 and 5 form one atom, which is the last (test); group 3 is the one before it (validation)
    assert [split_of[f"scuba-aad-ms-aad-{g}"] for g in range(1, 6)] == ["train", "train", "validation", "test", "test"]
    by_template: dict[str, set[str]] = {}
    for case in out:
        by_template.setdefault(case["provenance"]["template"], set()).add(case["split"])
    assert all(len(splits) == 1 for splits in by_template.values()) and report["leakage"]["templates_in_multiple_splits"] == 0


def test_without_templates_groups_split_independently(miner, splitter):
    cases = _mined(miner, "aad", 5)
    for case in cases:
        del case["provenance"]["template"]
        del case["provenance"]["distinct_prompt_sha256"]
    out, report = splitter.split_cases(cases)
    assert {c["family"]: c["split"] for c in out}["scuba-aad-ms-aad-4"] == "validation"
    assert report["splits"]["test"]["distinct_templates"] == 0 and report["splits"]["test"]["distinct_prompts"] == report["splits"]["test"]["cases"]


def test_leakage_check_detects_a_template_in_two_splits(splitter):
    cases = [
        {"id": "a", "family": "f1", "split": "train", "provenance": {"template": "t"}, "messages": [{"role": "user", "content": "x"}]},
        {"id": "b", "family": "f2", "split": "test", "provenance": {"template": "t"}, "messages": [{"role": "user", "content": "y"}]},
    ]
    digests = {"a": "1", "b": "2"}
    assert splitter.leakage(cases, digests) == {"families_in_multiple_splits": 0, "templates_in_multiple_splits": 1, "distinct_prompts_in_multiple_splits": 0}


def test_duplicates_are_dropped_keeping_the_first_occurrence(miner, splitter):
    cases = _duplicate_prone(miner)
    kept, dropped = splitter.dedupe(copy.deepcopy(cases))
    assert [c["id"] for c in kept] == [cases[0]["id"], cases[1]["id"], cases[2]["id"]]
    assert dropped == [{"dropped": cases[3]["id"], "kept": cases[1]["id"]}]
    out, report = splitter.split_cases(cases)
    assert len(out) == 3 and report["input_cases"] == 4 and report["cases"] == 3
    assert report["duplicates_dropped"] == {"count": 1, "pairs": dropped}
    assert report["splits"]["train"]["distinct_prompts"] == 3


def test_duplicates_with_conflicting_answers_are_an_error(miner, splitter):
    cases = _duplicate_prone(miner)
    cases[3]["expected"]["claims"][0] = {"id": "requirement_met", "status": "confirmed", "value": True, "evidence_ids": ["e1"]}
    with pytest.raises(ValueError, match="conflicting labels"):
        splitter.dedupe(cases)


def test_stale_stored_digest_is_an_error(miner, splitter):
    cases = _mined(miner, "aad", 1)
    cases[0]["provenance"]["distinct_prompt_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="stale"):
        splitter.split_cases(cases)


def test_approve_as_oracle_records_the_oracle_reviewer_exactly(miner, splitter):
    cases = _mined(miner, "aad", 5)
    plain, _ = splitter.split_cases(cases)
    assert {c["provenance"]["review_status"] for c in plain} == {"unreviewed"} and all("reviewer" not in c["provenance"] for c in plain)
    approved, report = splitter.split_cases(cases, approve_as_oracle=True)
    reviewer = "oracle:cisa-scubagear@abcdef123456/opa-1.20.2; deterministic policy evaluation, no human review"
    assert {c["provenance"]["review_status"] for c in approved} == {"approved"}
    assert {c["provenance"]["reviewer"] for c in approved} == {reviewer}
    assert report["approve_as_oracle"] is True
    assert [c["expected"] for c in approved] == [c["expected"] for c in plain]   # labels are never touched
    assert all(c["provenance"]["review_status"] == "unreviewed" for c in cases)   # the input is not mutated


def test_approval_leaves_human_reviews_alone_and_refuses_non_oracle_sources(miner, splitter):
    cases = _mined(miner, "aad", 2)
    cases[0]["provenance"].update(review_status="approved", reviewer="a human")
    out, report = splitter.split_cases(cases, approve_as_oracle=True)
    assert out[0]["provenance"]["reviewer"] == "a human" and report["already_approved_untouched"] == 1
    assert out[1]["provenance"]["reviewer"].startswith("oracle:cisa-scubagear@")
    cases[1]["provenance"]["source"] = "hand written"
    with pytest.raises(ValueError, match="not a ScubaGear oracle source"):
        splitter.split_cases(cases, approve_as_oracle=True)


@pytest.mark.parametrize("source", [
    "oracle:anything goes",
    "oracle:cisa-scubagear@abcdef12345 aadConfig.rego MS.AAD.1.1v1; variant=base; opa=1.20.2; sections=sec_a",     # 11 hex digits
    "oracle:cisa-scubagear@ABCDEF123456 aadConfig.rego MS.AAD.1.1v1; variant=base; opa=1.20.2; sections=sec_a",    # upper case
    "oracle:cisa-scubagear@" + "a" * 41 + " aadConfig.rego MS.AAD.1.1v1; variant=base; opa=1.20.2; sections=sec_a",  # too long
    "oracle:cisa-scubagear@abcdef123456 aadConfig.rego MS.AAD.1.1v1; variant=base; sections=sec_a",                # no opa=
    "oracle:cisa-scubagear@abcdef123456 aadConfig.rego MS.AAD.1.1v1; variant=base; opa=latest; sections=sec_a",    # not x.y.z
    "oracle:cisa-scubagear@abcdef123456 aadConfig.rego MS.AAD.1.1v1; variant=base; opa=1.20; sections=sec_a",
    "other:cisa-scubagear@abcdef123456 aadConfig.rego MS.AAD.1.1v1; variant=base; opa=1.20.2; sections=sec_a",
    "hand written",
])
def test_approval_only_accepts_the_miners_source_form(splitter, miner, source):
    with pytest.raises(ValueError, match="not a ScubaGear oracle source"):
        splitter.oracle_reviewer(source)
    case = _mined(miner, "aad", 1)[0]
    case["provenance"]["source"] = source
    with pytest.raises(ValueError, match="not a ScubaGear oracle source"):
        splitter.split_cases([case], approve_as_oracle=True)
    assert splitter.split_cases([case])[0][0]["provenance"]["review_status"] == "unreviewed"   # plain splitting is unaffected


def test_reviewer_carries_the_commit_and_opa_version_of_the_source(splitter):
    for commit in ("abcdef123456", "a" * 40):
        source = f"oracle:cisa-scubagear@{commit} aadConfig.rego MS.AAD.1.1v1; variant=base; opa=1.21.0; input_sha256={'0' * 64}"
        assert splitter.oracle_reviewer(source) == \
            f"oracle:cisa-scubagear@{commit}/opa-1.21.0; deterministic policy evaluation, no human review"


def test_approval_refuses_to_replace_a_named_reviewer_or_approve_non_synthetic_cases(miner, splitter):
    named = _mined(miner, "aad", 1)
    named[0]["provenance"]["reviewer"] = "a human"
    with pytest.raises(ValueError, match="refusing to replace the reviewer of unreviewed case"):
        splitter.split_cases(named, approve_as_oracle=True)
    assert splitter.split_cases(named)[0][0]["provenance"]["reviewer"] == "a human"   # untouched when not approving
    real = _mined(miner, "aad", 1)
    real[0]["provenance"]["synthetic"] = False
    with pytest.raises(ValueError, match="not marked synthetic"):
        splitter.split_cases(real, approve_as_oracle=True)


def test_duplicates_whose_claims_are_only_reordered_are_still_duplicates(miner, splitter):
    cases = _duplicate_prone(miner)
    cases[3]["expected"]["claims"].reverse()
    kept, dropped = splitter.dedupe(cases)
    assert len(kept) == 3 and dropped == [{"dropped": cases[3]["id"], "kept": cases[1]["id"]}]


def _cases_file(miner, tmp_path, groups=3):
    source = tmp_path / "cases.jsonl"
    source.write_text("".join(json.dumps(c) + "\n" for c in _mined(miner, "aad", groups)), encoding="utf-8")
    return source


def test_outputs_are_created_exclusively_with_private_modes(miner, splitter, tmp_path):
    source = _cases_file(miner, tmp_path)
    out = tmp_path / "new" / "deeper" / "cases.jsonl"
    old = os.umask(0o022)
    try:
        assert splitter.main(["--cases", str(source), "--output", str(out)]) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and stat.S_IMODE((out.parent / "split-report.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(out.parent.stat().st_mode) == 0o700 and stat.S_IMODE(out.parent.parent.stat().st_mode) == 0o700


def test_files_never_exist_with_looser_modes_while_being_written(miner, splitter, tmp_path, monkeypatch):
    modes = []
    real_open = os.open

    def spy(path, flags, mode=0o777, **kwargs):
        if flags & os.O_CREAT:
            modes.append((flags & os.O_EXCL != 0, mode))
        return real_open(path, flags, mode, **kwargs)

    monkeypatch.setattr(splitter.os, "open", spy)
    old = os.umask(0)   # even with no umask the creation mode is 0600
    try:
        assert splitter.main(["--cases", str(_cases_file(miner, tmp_path)), "--output", str(tmp_path / "out.jsonl")]) == 0
    finally:
        os.umask(old)
    assert modes == [(True, 0o600), (True, 0o600)]
    assert stat.S_IMODE((tmp_path / "out.jsonl").stat().st_mode) == 0o600


def test_report_must_differ_from_output(miner, splitter, tmp_path, capsys):
    out = tmp_path / "same.json"
    assert splitter.main(["--cases", str(_cases_file(miner, tmp_path)), "--output", str(out), "--report", str(out)]) == 2
    assert not out.exists() and "must be a different file" in capsys.readouterr().err
    assert splitter.main(["--cases", str(_cases_file(miner, tmp_path)), "--output", str(out), "--report", str(tmp_path / "." / "same.json")]) == 2
    assert not out.exists()


@pytest.mark.parametrize("which", ["output", "report"])
def test_a_symlink_counts_as_an_existing_file(miner, splitter, tmp_path, capsys, which):
    source = _cases_file(miner, tmp_path)
    target = tmp_path / "elsewhere.txt"
    link = tmp_path / "link"
    link.symlink_to(target)            # dangling
    out, report = (link, tmp_path / "r.json") if which == "output" else (tmp_path / "o.jsonl", link)
    assert splitter.main(["--cases", str(source), "--output", str(out), "--report", str(report)]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
    assert not target.exists() and not (tmp_path / "o.jsonl").exists() and not (tmp_path / "r.json").exists()


def test_a_failed_write_removes_what_it_created(miner, splitter, tmp_path, monkeypatch, capsys):
    source = _cases_file(miner, tmp_path)
    real_open = splitter._private_open
    opened = []

    def flaky(path):
        if opened:
            raise PermissionError("disk says no")
        opened.append(path)
        return real_open(path)

    monkeypatch.setattr(splitter, "_private_open", flaky)
    out, report = tmp_path / "out.jsonl", tmp_path / "split-report.json"
    assert splitter.main(["--cases", str(source), "--output", str(out)]) == 2
    assert not out.exists() and not report.exists() and "nothing was left behind" in capsys.readouterr().err


def test_splitter_refuses_to_write_inside_a_finalized_audit_run(miner, splitter, tmp_path, capsys):
    source = _cases_file(miner, tmp_path)
    run = tmp_path / "run"
    run.mkdir()
    (run / "run-manifest.json").write_text("{}", encoding="utf-8")
    assert splitter.main(["--cases", str(source), "--output", str(run / "out.jsonl")]) == 2
    assert "inside a finalized audit run" in capsys.readouterr().err and sorted(p.name for p in run.iterdir()) == ["run-manifest.json"]
    assert splitter.main(["--cases", str(source), "--output", str(tmp_path / "ok.jsonl"), "--report", str(run / "sub" / "report.json")]) == 2
    assert not (tmp_path / "ok.jsonl").exists() and not (run / "sub").exists()


def test_explicit_families_move_their_whole_atom(miner, splitter):
    cases = _mined(miner, "aad", 5)
    out, _ = splitter.split_cases(cases, holdout_families=["scuba-aad-ms-aad-1"], validation_families=["scuba-aad-ms-aad-2"])
    split_of = {c["family"]: c["split"] for c in out}
    assert split_of["scuba-aad-ms-aad-1"] == "test" and split_of["scuba-aad-ms-aad-2"] == "validation"
    assert split_of["scuba-aad-ms-aad-5"] == "test" and split_of["scuba-aad-ms-aad-4"] == "validation"   # defaults stay
    with pytest.raises(ValueError, match="unknown family"):
        splitter.split_cases(cases, holdout_families=["scuba-aad-ms-aad-99"])
    with pytest.raises(ValueError, match="both test and validation"):
        splitter.split_cases(cases, holdout_families=["scuba-aad-ms-aad-1"], validation_families=["scuba-aad-ms-aad-1"])


def test_only_oracle_families_can_be_split(miner, splitter):
    case = _mined(miner, "aad", 1)[0]
    case["family"] = "other-family"
    with pytest.raises(ValueError, match="not an oracle family"):
        splitter.split_cases([case])


def test_split_report_has_counts_distinct_counts_and_the_frozen_holdout_hash(miner, splitter, tmp_path):
    cases = _mined(miner, "aad", 5) + _duplicate_prone(miner)
    source = tmp_path / "cases.jsonl"
    source.write_text("".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8")
    out = tmp_path / "split" / "approved.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(out), "--approve-as-oracle"]) == 0
    report = json.loads((tmp_path / "split" / "split-report.json").read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert report["input_cases"] == 14 and report["cases"] == len(rows) == 13 and report["duplicates_dropped"]["count"] == 1
    assert [report["splits"][s]["cases"] for s in ("train", "validation", "test")] == [9, 2, 2]
    assert report["splits"]["test"]["families"] == ["scuba-aad-ms-aad-5"] and report["splits"]["validation"]["families"] == ["scuba-aad-ms-aad-4"]
    assert report["splits"]["test"]["labels"] == {"false": 1, "true": 1}
    assert report["splits"]["train"]["labels"] == {"false": 3, "true": 5, "unknown": 1}
    assert report["splits"]["train"]["families"] == ["scuba-aad-ms-aad-1", "scuba-aad-ms-aad-2", "scuba-aad-ms-aad-3", "scuba-dup-ms-dup-1"]
    assert report["per_product"] == {"aad": {"train": 6, "validation": 2, "test": 2}, "dup": {"train": 3}}
    assert report["leakage"] == {"families_in_multiple_splits": 0, "templates_in_multiple_splits": 0, "distinct_prompts_in_multiple_splits": 0}
    test_lines = "".join(line + "\n" for line in out.read_text(encoding="utf-8").splitlines() if json.loads(line)["split"] == "test")
    assert report["test_sha256"] == hashlib.sha256(test_lines.encode("utf-8")).hexdigest()
    test_ids = sorted(r["id"] for r in rows if r["split"] == "test")
    assert report["test_ids_sha256"] == hashlib.sha256("\n".join(test_ids).encode("utf-8")).hexdigest()
    validate_cases(rows)


def test_holdout_hash_is_stable_across_runs_and_changes_with_the_holdout(miner, splitter):
    cases = _mined(miner, "aad", 5)
    first = splitter.split_cases(cases)[1]
    assert first["test_sha256"] == splitter.split_cases(cases)[1]["test_sha256"]
    moved = splitter.split_cases(cases, holdout_families=["scuba-aad-ms-aad-1"])[1]
    assert moved["test_ids_sha256"] != first["test_ids_sha256"] and moved["test_sha256"] != first["test_sha256"]


def test_splitter_refuses_to_overwrite_existing_files(miner, splitter, tmp_path, capsys):
    source = tmp_path / "cases.jsonl"
    source.write_text("".join(json.dumps(c) + "\n" for c in _mined(miner, "aad", 3)), encoding="utf-8")
    out = tmp_path / "out.jsonl"
    out.write_text("keep", encoding="utf-8")
    assert splitter.main(["--cases", str(source), "--output", str(out)]) == 2
    assert out.read_text(encoding="utf-8") == "keep" and not (tmp_path / "split-report.json").exists()
    fresh = tmp_path / "fresh.jsonl"
    report = tmp_path / "report.json"
    report.write_text("keep", encoding="utf-8")
    assert splitter.main(["--cases", str(source), "--output", str(fresh), "--report", str(report)]) == 2
    assert not fresh.exists() and "refusing to overwrite" in capsys.readouterr().err


def test_splitter_reports_invalid_input_without_writing(miner, splitter, tmp_path, capsys):
    cases = _mined(miner, "aad", 3)
    cases[0]["provenance"]["distinct_prompt_sha256"] = "0" * 64
    source = tmp_path / "cases.jsonl"
    source.write_text("".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8")
    out = tmp_path / "out.jsonl"
    assert splitter.main(["--cases", str(source), "--output", str(out)]) == 1
    assert not out.exists() and "stale" in capsys.readouterr().err


def test_splitter_rejects_unreadable_or_malformed_input_without_writing(splitter, tmp_path, capsys):
    out = tmp_path / "out.jsonl"
    assert splitter.main(["--cases", str(tmp_path / "missing.jsonl"), "--output", str(out)]) == 1
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id":"first","id":"second"}\n', encoding="utf-8")
    assert splitter.main(["--cases", str(bad), "--output", str(out)]) == 1
    assert not out.exists() and not (tmp_path / "split-report.json").exists() and "duplicate JSON key" in capsys.readouterr().err


# --- end to end against the real oracle (skipped unless OPA and ScubaGear are present) --------------------------


def _git_head(path: Path) -> str:
    done = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
    return done.stdout.strip() if done.returncode == 0 else ""


@pytest.fixture(scope="module")
def powerplatform_run(miner, splitter, tmp_path_factory):
    if _git_head(SCUBA) != PINNED_COMMIT:
        pytest.skip(f"ScubaGear is not at the pinned commit {PINNED_COMMIT}")
    version = subprocess.run([str(OPA), "version"], capture_output=True, text=True).stdout.splitlines()[0].split()[-1]
    if version != PINNED_OPA:
        pytest.skip(f"OPA {version} is not the pinned {PINNED_OPA}")
    out = tmp_path_factory.mktemp("oracle") / "mined"
    assert miner.main(["--scuba", str(SCUBA), "--opa", str(OPA), "--output-dir", str(out), "--products", "PowerPlatform"]) == 0
    split_dir = out.parent / "split"
    assert splitter.main(["--cases", str(out / "cases.jsonl"), "--output", str(split_dir / "cases.jsonl"), "--approve-as-oracle"]) == 0
    return out, split_dir


@needs_oracle
def test_powerplatform_end_to_end_yields_152_cases(powerplatform_run):
    out, _ = powerplatform_run
    assert sorted(p.name for p in out.iterdir()) == ["cases-powerplatform.jsonl", "cases.jsonl", "summary.json", "variants-powerplatform"]
    rows = [json.loads(line) for line in (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 152 and rows == [json.loads(line) for line in (out / "cases-powerplatform.jsonl").read_text(encoding="utf-8").splitlines()]
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    product = summary["products"]["PowerPlatform"]
    assert summary["total_cases"] == 152 and product["variants"] == 20
    assert {k: product["stats"][k] for k in ("met", "not_met", "unknown", "duplicate_view", "variants_failed")} == \
        {"met": 76, "not_met": 38, "unknown": 38, "duplicate_view": 8, "variants_failed": 0}
    assert summary["oracle"]["commit"] == PINNED_COMMIT and summary["oracle"]["opa_version"] == PINNED_OPA
    assert len(list((out / "variants-powerplatform").glob("variant-*.json"))) == 20
    assert all(r["provenance"]["template"].startswith("powerplatform/MS.POWERPLATFORM.") for r in rows)
    assert all(r["provenance"]["distinct_prompt_sha256"] == distinct_prompt_sha256(r) for r in rows)
    validate_cases(rows)


@needs_oracle
def test_powerplatform_split_holds_whole_groups_out(powerplatform_run):
    _, split_dir = powerplatform_run
    report = json.loads((split_dir / "split-report.json").read_text(encoding="utf-8"))
    assert report["input_cases"] == 152 and report["cases"] + report["duplicates_dropped"]["count"] == 152
    assert report["splits"]["test"]["families"] == ["scuba-powerplatform-ms-powerplatform-6"]
    assert report["splits"]["validation"]["families"] == ["scuba-powerplatform-ms-powerplatform-5"]
    assert report["splits"]["train"]["families"] == [f"scuba-powerplatform-ms-powerplatform-{g}" for g in (1, 2, 3)]
    assert not any(report["leakage"].values())
    rows = [json.loads(line) for line in (split_dir / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(r["provenance"]["reviewer"].startswith(f"oracle:cisa-scubagear@{PINNED_COMMIT[:12]}/opa-{PINNED_OPA};") for r in rows)


@needs_oracle
@needs_reference
def test_powerplatform_labels_match_the_prototype_reference(powerplatform_run):
    out, _ = powerplatform_run
    mined = {r["id"]: r for r in map(json.loads, (out / "cases-powerplatform.jsonl").read_text(encoding="utf-8").splitlines())}
    reference = {r["id"]: r for r in map(json.loads, REFERENCE.read_text(encoding="utf-8").splitlines())}
    assert mined.keys() == reference.keys() and len(mined) == 152
    assert all(mined[i]["expected"] == reference[i]["expected"] for i in reference)
    assert all(mined[i]["messages"] == reference[i]["messages"] and mined[i]["family"] == reference[i]["family"] for i in reference)
