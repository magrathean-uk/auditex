"""Stage 6: v3.9 SharePoint, authorisation and privileged-user contracts."""
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

from azure_tenant_audit.scuba_precheck import check_gate, precheck_policy, precheck_response, rule_catalogue
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for
from azure_tenant_audit.value_rules.catalogue import catalogue
from azure_tenant_audit.value_rules.gates import closed_gate
from test_value_rules_vectors import STAGE6_POLICIES, _grouped, _rows, _strip_names

FIXTURE = Path(__file__).parent / "fixtures/value-rules/vectors-s6.jsonl.xz"


@pytest.fixture(scope="module")
def rows_s6():
    return _grouped(FIXTURE)


def _check_rows(policy, rows):
    rule = catalogue()["policies"][policy]
    reached = set()
    for row in rows:
        sections = row["sections"]
        before = deepcopy(sections)
        record = assess(policy, sections)
        assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
                record["cited_sections"] or rule["sections"]) == (
            row["rule_verdict"], row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"],
            row["rule_cited_sections"] or rule["sections"]), row["vector_id"]
        detail = precheck_policy(policy, sections, list(sections), value_rules=True,
                                 absent_fields=True, empty_lists=True)
        assert detail["class"] == "value_rule", row["vector_id"]
        assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == (
            record["cell"], record["reason_code"], record["reason_text"],
            record["cited_sections"] or rule["sections"]), row["vector_id"]
        response = precheck_response(detail, {"policy_id": policy, "criticality": row["criticality"]},
                                     list(sections), named_limitations=False)
        assert response == as_pack_response(record, row["criticality"], list(sections)), row["vector_id"]
        if row.get("gold_response") is not None and row.get("disagreement") is None:
            assert response == row["gold_response"], row["vector_id"]
        assert row.get("disagreement") is None or row["disagreement"].startswith("expected:"), row["vector_id"]
        assert (row.get("disagreement") is None) is (record["verdict"] == row["gold_verdict"]), row["vector_id"]
        assert record["detail"] == {}  # divergence tags belong in the fixture only
        assert assess(policy, _strip_names(sections)) == record, row["vector_id"]
        assert sections == before, row["vector_id"]
        reached.add(record["cell"])
    assert reached == set(cells_for(policy))


@pytest.mark.parametrize("policy", sorted(STAGE6_POLICIES))
def test_v39_stage6_vectors(policy, rows_s6):
    _check_rows(policy, rows_s6[policy])


def test_manifest_hash_counts_and_complete_cell_coverage(rows_s6):
    manifest = json.loads(FIXTURE.with_name("manifest-s6.json").read_text())[FIXTURE.name]
    rows = [row for group in rows_s6.values() for row in group]
    assert sha256(FIXTURE.read_bytes()).hexdigest() == manifest["sha256"]
    assert set(rows_s6) == STAGE6_POLICIES
    assert manifest["spec_version"] == catalogue()["spec_version"] == "v3.9"
    assert manifest["rows"] == len(rows) == 1208
    assert manifest["by_policy"] == {policy: len(group) for policy, group in rows_s6.items()}
    assert manifest["by_cell"] == dict(Counter(f"{row['policy']}:{row['rule_cell']}" for row in rows))
    assert len(manifest["by_cell"]) == sum(len(cells_for(p)) for p in STAGE6_POLICIES) == 118
    assert manifest["by_source"] == dict(Counter(row["source_kind"] for row in rows)) == {
        "constructed": 588, "pack-train": 383, "pack-validation": 237}
    assert manifest["by_verdict"] == dict(Counter(row["rule_verdict"] for row in rows))
    assert sum(row.get("gold_response") is not None and row.get("disagreement") is None
               for row in rows if row["source_kind"] != "constructed") == 595


def test_optional_full_stage6_source():
    source = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS")
    if not source:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS unset")
    grouped = _grouped(Path(source))
    from azure_tenant_audit.resources import open_text_resource
    items = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
    for policy in STAGE6_POLICIES:
        # Full sources omit criticality on some constructed rows.
        rows = [{"criticality": items[policy]["policy_item"]["criticality"], **row} for row in grouped[policy]]
        _check_rows(policy, rows)


@pytest.mark.parametrize("policy", sorted(p for p in STAGE6_POLICIES if p.startswith("MS.SHAREPOINT.")))
def test_sharepoint_fields_are_consistent_and_unreachable(policy, monkeypatch):
    import azure_tenant_audit.scuba_precheck as precheck
    fields = {name for name in catalogue()["policies"][policy]["params"].get("fields", [])}
    if not fields:
        fields.add(catalogue()["policies"][policy]["params"]["field"])
    configured = {r["path"][0] for r in rule_catalogue()["field_rules"] if r["policy_id"] == policy}
    assert fields == configured
    monkeypatch.setattr(precheck, "check_fields", lambda *a: pytest.fail("legacy field_rules reached"))
    monkeypatch.setattr(precheck, "check_lists", lambda *a: pytest.fail("legacy list_rules reached"))
    for sections in ({}, {"SPO_tenant": [{}]}, {"SPO_tenant": [{"SharingCapability": 0}]}):
        assert precheck_policy(policy, sections, ["SPO_tenant"], value_rules=True,
                               absent_fields=True, empty_lists=True)["class"] == "value_rule"


@pytest.mark.parametrize("slider", [0, 3, 0.0, 3.0])
def test_sp13_gate_wins_before_absent_fields(slider):
    sections = {"SPO_tenant": [{"SharingCapability": slider}]}
    assert check_gate("MS.SHAREPOINT.1.3v1", sections)["class"] == "closed_gate"
    assert assess("MS.SHAREPOINT.1.3v1", sections)["cell"] == "closed_gate"


@pytest.mark.parametrize("environment,closes", [("commercial", False), ("gcc", False),
                                               ("gcchigh", True), ("dod", True)])
def test_aad91_config_gate_is_ready_for_stage7(environment, closes):
    sections = {"scuba_config": {"M365Environment": environment}}
    gate = check_gate("MS.AAD.9.1v1", sections)
    assert (gate is not None and gate["class"] == "closed_gate") is closes
    rendered = closed_gate("MS.AAD.9.1v1", sections)
    assert (rendered is not None) is closes
    if rendered:
        assert rendered["reason_text"] == "Not applicable: the policy does not apply to GCC High or DOD environments."


def test_fixture_builder_excludes_every_test_and_pilot_origin(tmp_path, rows_s6):
    spec = importlib.util.spec_from_file_location(
        "fixture_s6", Path(__file__).parents[1] / "scripts/build-value-rule-fixture-s6.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    row = rows_s6["MS.AAD.5.1v1"][0]
    def vector(kind, source_file, split):
        return {**row, "vector_id": kind, "origin": "synthetic builder regression",
                "source_kind": kind, "source_file": source_file, "split": split}
    rows = [vector("constructed", "constructed by v39_vectors.py", None),
            vector("pack-train", "20261030-oracle-pack-v10/train.jsonl", "train"),
            vector("pack-validation", "20261030-oracle-pack-v10/validation.jsonl", "validation"),
            vector("pack-test", "20261030-oracle-pack-v10/test.jsonl", "test")]
    rows += [vector(f"{prefix}-{kind}", "sealed pilot", "test")
             for prefix in ("aad", "pbi", "ss6") for kind in ("frozen", "diagnostic", "dropped")]
    source, target = tmp_path / "source.jsonl", tmp_path / "fixture.jsonl.xz"
    source.write_text("".join(json.dumps(row) + "\n" for row in rows))
    manifest = builder.build(source, target)
    assert manifest["rows"] == 3
    assert {row["vector_id"] for row in _rows(target)} == {"constructed", "pack-train", "pack-validation"}
    assert manifest["source_sha256"] == sha256(source.read_bytes()).hexdigest()
    for key, value in (("source_file", "unknown"), ("split", "test"), ("disagreement", "UNEXPECTED"),
                       ("gold_verdict", None)):
        bad = {**rows[0], key: value}
        source.write_text(json.dumps(bad) + "\n")
        with pytest.raises(ValueError):
            builder.build(source, target)


@pytest.mark.parametrize("policy", sorted(STAGE6_POLICIES))
def test_no_stage6_evidence_echo(policy):
    canary_email, canary_name = "canary.person@example.invalid", "Canary Display Name"
    name = catalogue()["policies"][policy]["sections"][0]
    # Plant both unbounded fields and identities on all objects the rules read.
    sections = {name: [{"DisplayName": canary_name, "Id": canary_email, "roles": [canary_name],
                        "OnPremisesImmutableId": canary_email, "GuestUserRoleId": canary_email,
                        "AllowInvitesFrom": canary_email, "SharingCapability": 2,
                        "DefaultUserRolePermissions": {"AllowedToCreateApps": True}}]}
    for field in catalogue()["policies"][policy]["params"].get("fields", []):
        sections[name][0][field] = canary_email
    if "field" in catalogue()["policies"][policy]["params"]:
        sections[name][0][catalogue()["policies"][policy]["params"]["field"]] = canary_email
    record = assess(policy, sections)
    detail = precheck_policy(policy, sections, [name], value_rules=True)
    response = as_pack_response(record, "Shall", [name])
    dumped = json.dumps([record, detail, response])
    assert canary_email not in dumped and canary_name not in dumped


def test_canary_rule_view_never_persists_or_logs(tmp_path, monkeypatch, caplog):
    from auditex.model_serving import ModelClient, ModelConfig, assess_run
    from azure_tenant_audit.model_assessment import validate_assessment
    from test_model_serving import fake_projection
    canary_email, canary_name = "canary.person@example.invalid", "Canary Display Name"
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage6"}')
    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update({
            "SPO_tenant": [{"SharingCapability": 2, "Owner": canary_email, "DisplayName": canary_name}],
            "authorization_policies": [{"Id": canary_email, "DisplayName": canary_name,
                                        "DefaultUserRolePermissions": {"AllowedToCreateApps": True}}],
            "privileged_users": {canary_email: {"DisplayName": canary_name,
                                  "OnPremisesImmutableId": canary_email, "roles": ["Global Administrator"]}},
        })
        return projection
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.model_serving.project_run", projected)
    monkeypatch.setattr(ModelClient, "assess", lambda *a: pytest.fail("value rule called model"))
    result = assess_run(tmp_path, ModelConfig(model_name="test-model"), policies=sorted(STAGE6_POLICIES))
    validate_assessment(result)
    assert all(row["rule_precheck"]["class"] == "value_rule" for row in result["policies"])
    for output in [json.dumps(result), caplog.text, *(p.read_text() for p in tmp_path.rglob("*") if p.is_file())]:
        assert canary_email not in output and canary_name not in output


def test_stratified_stage6_cells_against_pinned_rego(rows_s6, tmp_path):
    from test_value_rules_oracle import OPA, SCUBA, REGO_SHA256, _outcome_v3
    if not (OPA and OPA.is_file() and SCUBA and (SCUBA / "Rego").is_dir()):
        pytest.skip("set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
    version = subprocess.run([str(OPA), "version"], capture_output=True, text=True, timeout=30)
    assert version.returncode == 0 and "Version: 1.20.2" in version.stdout.splitlines()
    rego = SCUBA / "Rego"
    assert all(sha256((rego / name).read_bytes()).hexdigest() == digest for name, digest in REGO_SHA256.items())
    groups = defaultdict(list)
    for policy, rows in rows_s6.items():
        for row in rows:
            if row.get("gold_source") == "opa-replay":
                groups[(policy, row["rule_cell"])].append(row)
    assert {policy for policy, _ in groups} == STAGE6_POLICIES
    assert len(groups) == 104
    for key, rows in sorted(groups.items()):
        row = min(rows, key=lambda r: r["vector_id"])
        package, config = (("sharepoint", "SharePointConfig.rego") if row["policy"].startswith("MS.SHAREPOINT.")
                           else ("aad", "AADConfig.rego"))
        path = tmp_path / "input.json"
        path.write_text(json.dumps(row["sections"]))
        proc = subprocess.run([str(OPA), "eval", "-f", "json", "-d", str(rego / config),
                               "-d", str(rego / "Utils"), "-i", str(path), f"data.{package}.tests"],
                              capture_output=True, text=True, timeout=120)
        result = json.loads(proc.stdout) if proc.stdout else {"errors": [proc.stderr[:200]]}
        assert _outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        actual = assess(row["policy"], row["sections"])["verdict"]
        assert (actual == row["gold_verdict"]) is (row.get("disagreement") is None), row["vector_id"]
