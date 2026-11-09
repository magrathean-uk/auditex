"""Stage-8 Power Platform vectors, rule-view shapes, privacy and pinned oracle."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

from azure_tenant_audit.model_evidence import NOT_COLLECTED
from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for
from azure_tenant_audit.value_rules.catalogue import row_for
from azure_tenant_audit.value_rules.record import checked
from test_value_rules_oracle import _outcome_v3, pinned  # noqa: F401 - shared pytest fixture
from test_value_rules_vectors import _rows, _strip_names, STAGE8_POLICIES

FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-s8.jsonl.xz"
MANIFEST = FIXTURE.with_name("manifest-s8.json")
DEFAULT_POLICY = "MS.POWERPLATFORM.2.1v1"
COVERAGE_POLICY = "MS.POWERPLATFORM.2.2v1"


@pytest.fixture(scope="module")
def rows():
    return list(_rows(FIXTURE))


def _check_vector(vector):
    policy, sections = vector["policy"], vector["sections"]
    rule = row_for(policy)
    record = assess(policy, sections)
    expected = (vector["rule_verdict"], vector["rule_cell"], vector["rule_reason_code"],
                vector["rule_reason_text"], vector["rule_cited_sections"] or rule["sections"])
    assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
            record["cited_sections"] or rule["sections"]) == expected, vector["vector_id"]
    detail = precheck_policy(policy, sections, list(sections), value_rules=True, absent_fields=True, empty_lists=True)
    assert detail["class"] == "value_rule" and detail["rule_id"] == rule["rule_id"]
    assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == expected[1:]
    criticality = vector.get("criticality") or json.loads(open_text_resource("configs/scuba-policy-sections.json"))[
        "policies"][policy]["policy_item"]["criticality"]
    response = precheck_response(detail, {"policy_id": policy, "criticality": criticality}, list(sections),
                                 named_limitations=False)
    assert response == as_pack_response(record, criticality, list(sections), legacy=True)
    if vector.get("gold_response") is not None and vector.get("disagreement") is None:
        assert response == vector["gold_response"], vector["vector_id"]
    assert vector.get("disagreement") is None or vector["disagreement"].startswith("expected:")
    assert (vector.get("disagreement") is None) is (vector["rule_verdict"] == vector["gold_verdict"])
    assert assess(policy, _strip_names(sections)) == record
    return record["cell"]


@pytest.mark.parametrize("policy", sorted(STAGE8_POLICIES))
def test_vectors_match_reference_and_reach_every_cell(policy, rows):
    reached = {_check_vector(vector) for vector in rows if vector["policy"] == policy}
    assert reached == set(cells_for(policy))


def test_manifest_and_split_exclusions(rows):
    manifest = json.loads(MANIFEST.read_text())[FIXTURE.name]
    assert sha256(FIXTURE.read_bytes()).hexdigest() == manifest["sha256"]
    assert manifest["spec_version"] == "v3.9.1" and manifest["stage"] == 8
    assert len(rows) == manifest["rows"] == 298
    assert len({row["vector_id"] for row in rows}) == len(rows)
    assert dict(Counter(row["policy"] for row in rows)) == manifest["by_policy"]
    assert set(manifest["by_policy"]) == STAGE8_POLICIES
    assert dict(Counter(f"{row['policy']}:{row['rule_cell']}" for row in rows)) == manifest["by_cell"]
    assert len(manifest["by_cell"]) == 50
    assert dict(Counter(row["rule_verdict"] for row in rows)) == manifest["by_verdict"]
    assert dict(Counter(row["source_kind"] for row in rows)) == manifest["by_source"] == {
        "constructed": 219, "pack-train": 72, "pack-validation": 7}
    assert sum(row.get("gold_response") is not None and row.get("disagreement") is None
               for row in rows if row["source_kind"] != "constructed") == 62


def test_builder_reuses_shared_split_filter(tmp_path, rows):
    path = Path(__file__).parents[1] / "scripts/build-value-rule-fixture-s8.py"
    spec = importlib.util.spec_from_file_location("stage8_fixture", path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    keep = {**next(row for row in rows if row["source_kind"] == "constructed"),
            "origin": "constructed", "source_file": "constructed by build_vectors.py", "split": None}
    held_out = {**keep, "vector_id": "held-out", "source_kind": "pack-test", "split": "test",
                "source_file": "20261030-oracle-pack-v10/test.jsonl"}
    sealed = {**keep, "vector_id": "sealed", "source_kind": "aad-frozen", "split": "test"}
    source, target = tmp_path / "source.jsonl", tmp_path / "out.jsonl.xz"
    source.write_text("".join(json.dumps(row) + "\n" for row in (keep, held_out, sealed)))
    manifest = builder.build(source, target)
    assert manifest["rows"] == 1
    assert [row["vector_id"] for row in _rows(target)] == [keep["vector_id"]]
    assert manifest["source_sha256"] == sha256(source.read_bytes()).hexdigest()
    source.write_text(json.dumps({**keep, "disagreement": "UNEXPECTED"}) + "\n")
    with pytest.raises(ValueError, match="UNEXPECTED"):
        builder.build(source, target)


@pytest.mark.parametrize("cell,value", [("section_not_a_list", None), ("no_usable_items", [])])
@pytest.mark.parametrize("section", ["dlp_policies", "environment_list"])
def test_pp22_citation_variants_accept_only_the_relevant_section(cell, value, section):
    sections = {"dlp_policies": [{"value": []}], "environment_list": [{"EnvironmentName": "e", "IsDefault": False}]}
    sections[section] = value
    record = assess(COVERAGE_POLICY, sections)
    assert record["cell"] == cell and record["cited_sections"] == [section]
    with pytest.raises(ValueError, match="wrong section"):
        checked({**record, "cited_sections": ["dlp_policies", "environment_list"]})
    with pytest.raises(ValueError, match="wrong section"):
        checked({**record, "cited_sections": ["unrelated"]})


@pytest.mark.parametrize("kind", ["OnlyEnvironments", "ExceptEnvironments"])
@pytest.mark.parametrize("policy", [DEFAULT_POLICY, COVERAGE_POLICY])
def test_missing_collector_environment_names_are_unusable(kind, policy):
    sections = {"dlp_policies": [{"value": [{"environmentType": kind, "displayName": "synthetic"}]}],
                "tenant_id": "synthetic", "environment_list": [{"EnvironmentName": "e", "IsDefault": False}]}
    assert assess(policy, sections)["cell"] == "dlp_structure_unusable"


def test_tenant_id_and_environment_names_are_case_sensitive():
    sections = {"tenant_id": "ABC", "dlp_policies": [{"value": [{"environmentType": "OnlyEnvironments",
                "displayName": "synthetic", "environments": [{"name": "Default-ABC"}]}]}]}
    assert assess(DEFAULT_POLICY, sections)["cell"] == "default_environment_covered"
    sections["tenant_id"] = "abc"
    assert assess(DEFAULT_POLICY, sections)["cell"] == "default_environment_not_covered"


@pytest.mark.parametrize("policy", sorted(STAGE8_POLICIES))
def test_uncollected_markers_precede_rule_values(policy):
    for section in row_for(policy)["sections"]:
        sections = {name: None for name in row_for(policy)["sections"]}
        sections[section] = NOT_COLLECTED
        record = assess(policy, sections)
        assert record["cell"] == "section_not_collected"
        assert record["cited_sections"] == [section]


@pytest.mark.parametrize("coverage_shape,coverage_cell", [("objects", "all_environments_covered"),
                                                         ("empty", "no_usable_items"),
                                                         ("null", "section_not_a_list")])
def test_served_outputs_and_logs_do_not_contain_rule_view_evidence(
        tmp_path, monkeypatch, caplog, coverage_shape, coverage_cell):
    from auditex.model_serving import ModelClient, ModelConfig, assess_run
    from azure_tenant_audit.model_assessment import validate_assessment
    from test_model_serving import fake_projection

    canary, display_name = "s8.person@example.invalid", "Stage Eight Canary Display Name"
    sections = {"tenant_id": canary,
                "environment_creation": [{"disableEnvironmentCreationByNonAdminUsers": False,
                    "disableTrialEnvironmentCreationByNonAdminUsers": True, "disablePortalsCreationByNonAdminUsers": False,
                    "powerPlatform": {"powerApps": {"disableShareWithEveryone": False}}, "Owner": canary}],
                "tenant_isolation": [{"properties": {"isDisabled": True}, "DisplayName": display_name}],
                "dlp_policies": [{"value": [{"environmentType": "OnlyEnvironments", "displayName": display_name,
                    "name": canary, "environments": [{"name": "Default-" + canary}, {"name": display_name}]}]}],
                "environment_list": [{"EnvironmentName": display_name, "IsDefault": False, "Owner": canary}]}
    if coverage_shape != "objects":
        sections["environment_list"] = [] if coverage_shape == "empty" else None
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage8"}')

    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update(deepcopy(sections))
        return projection

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.model_serving.project_run", projected)
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("Power Platform called the model"))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=sorted(STAGE8_POLICIES))
    validate_assessment(result)
    assert len(result["policies"]) == 8
    assert all(row["rule_precheck"]["class"] == "value_rule" for row in result["policies"])
    assert {row["policy_id"]: row["rule_precheck"]["cell"] for row in result["policies"]} == {
        "MS.POWERPLATFORM.1.1v1": "flag_bad", "MS.POWERPLATFORM.1.2v1": "all_clear",
        DEFAULT_POLICY: "default_environment_covered", COVERAGE_POLICY: coverage_cell,
        "MS.POWERPLATFORM.2.3v1": "no_baseline_text", "MS.POWERPLATFORM.3.1v1": "flag_bad",
        "MS.POWERPLATFORM.5.1v1": "flag_bad", "MS.POWERPLATFORM.6.1v1": "flag_bad"}
    outputs = [json.dumps(result), caplog.text]
    outputs.extend(path.read_text() for path in tmp_path.rglob("*") if path.is_file())
    outputs.extend(json.dumps(assess(policy, sections)) for policy in sorted(STAGE8_POLICIES))
    assert all(canary not in output and display_name not in output for output in outputs)


def test_optional_full_stage8_vectors():
    source = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS_V391")
    if not source:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS_V391 unset")
    reached = defaultdict(set)
    for vector in _rows(Path(source)):
        if vector["policy"] in STAGE8_POLICIES:
            reached[vector["policy"]].add(_check_vector(vector))
    assert set(reached) == STAGE8_POLICIES
    assert all(reached[policy] == set(cells_for(policy)) for policy in STAGE8_POLICIES)


@pytest.mark.skipif(not (os.getenv("AUDITEX_TEST_OPA") and os.getenv("AUDITEX_TEST_SCUBAGEAR")),
                    reason="set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
def test_stage8_cells_against_pinned_opa(rows, tmp_path, pinned):  # noqa: F811 - shared pytest fixture injected by name
    # Reuse the shared pin checks and the v3 oracle result vocabulary.
    rego = pinned
    opa = os.getenv("AUDITEX_TEST_OPA")
    if not opa:
        pytest.skip("AUDITEX_TEST_OPA unset")
    groups = defaultdict(list)
    for row in rows:
        if row.get("gold_source") == "opa-replay":
            groups[(row["policy"], row["rule_cell"])].append(row)
    assert {policy for policy, _ in groups} == STAGE8_POLICIES
    assert len(groups) == 43
    selected = [sorted(group, key=lambda row: row["vector_id"])[0] for _, group in sorted(groups.items())]
    extra = int(os.getenv("AUDITEX_TEST_VALUE_RULE_SAMPLE", "0"))
    remaining = sorted((row for group in groups.values() for row in sorted(group, key=lambda r: r["vector_id"])[1:]),
                       key=lambda row: row["vector_id"])
    selected.extend(remaining[:max(extra, 0)])
    for row in selected:
        path = tmp_path / "input.json"
        path.write_text(json.dumps(row["sections"]))
        process = subprocess.run([opa, "eval", "-f", "json", "-d", str(rego / "PowerPlatformConfig.rego"),
                                  "-d", str(rego / "Utils"), "-i", str(path), "data.powerplatform.tests"],
                                 capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(process.stdout)
        except ValueError:
            result = {"errors": [process.stderr[:200]]}
        assert _outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        actual = assess(row["policy"], row["sections"])["verdict"]
        assert (actual == row["gold_verdict"]) is (row.get("disagreement") is None), row["vector_id"]
