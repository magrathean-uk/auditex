"""The three rules built early (SS 1.1, 6.1, 6.2) are enabled: rows, evidence supply on both paths, product-route replay.

Offline and synthetic only: no sign-in, no tenant. The prepared rows stay in
``held-rows-s4.json`` and ``held-rows-s5.json`` as the record of what was reviewed.
"""
from __future__ import annotations

import json
import lzma
from collections import Counter
from copy import deepcopy
from pathlib import Path

import pytest
from test_scuba_adapters_defender import bundle, cases, fixture_document, operation  # noqa: F401 (fixtures)
from test_value_rules_s4 import _serve_rule

from auditex.rule_assessment import (
    assess_run,
    assess_scubagear_export,
    policy_catalogue,
)
from auditex.scuba_projection import NOT_COLLECTED, project_run, rule_policy_section
from auditex.scubagear_export import load_export, project_export
from azure_tenant_audit.scuba_assessment import validate_assessment
from azure_tenant_audit.value_rules import (
    as_pack_response,
    assess,
    cells_for,
    rule_policies,
)
from azure_tenant_audit.value_rules.catalogue import catalogue
from azure_tenant_audit.value_rules.record import checked

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/value-rules"
PROVIDER = ROOT / "tests/fixtures/scubagear-export/mocktenant-provider-export.json"
SS11, SS61, SS62 = "MS.SECURITYSUITE.1.1v1", "MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"
POLICIES = (SS11, SS61, SS62)
PREPARED = {**json.loads((FIXTURES / "held-rows-s5.json").read_text()),
            **json.loads((FIXTURES / "held-rows-s4.json").read_text())}
A1_EVIDENCE_FIELDS = ("evidence_kind", "limitations", "recommendations")
AREA_COUNTS = {"AAD": 31, "EXO": 12, "POWERBI": 8, "POWERPLATFORM": 8, "SECURITYSUITE": 21, "SHAREPOINT": 8, "TEAMS": 14}


def _vectors():
    rows = []
    for name in ("vectors-s4.jsonl.xz", "vectors-s5.jsonl.xz"):
        with lzma.open(FIXTURES / name, "rt") as handle:
            rows += [row for line in handle if (row := json.loads(line))["policy"] in POLICIES]
    rows += [row for line in (FIXTURES / "vectors-a2-constructed.jsonl").read_text().splitlines()
             if (row := json.loads(line))["policy"] in POLICIES]
    return rows


VECTORS = _vectors()


def _expected(row, policy):
    return (row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"],
            row["rule_cited_sections"] or catalogue()["policies"][policy]["sections"])


def test_rows_are_enabled_as_prepared_plus_the_a1_evidence_fields_and_the_file_is_canonical():
    path = ROOT / "configs/scuba-value-rules.json"
    data = json.loads(path.read_text())
    assert path.read_text() == json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    assert list(data["policies"]) == sorted(data["policies"])
    assert set(PREPARED) == set(POLICIES)
    for policy in POLICIES:
        assert policy in rule_policies()
        # v3.9.1 (A1) adds the evidence fields to every not-assessed cell. The SS 6.1 and 6.2 record predates them;
        # the SS 1.1 record already carries them. Either way the shipped row equals the record plus, where the record
        # lacks them, exactly those three additive fields.
        shipped = deepcopy(data["policies"][policy])
        for name, cell in shipped["cells"].items():
            for key in A1_EVIDENCE_FIELDS:
                if key not in PREPARED[policy]["cells"][name]:
                    cell.pop(key, None)
        assert shipped == PREPARED[policy]
        assert set(cells_for(policy)) == set(PREPARED[policy]["cells"])
    assert len(data["policies"]) == 102 == len(policy_catalogue()["policies"])
    assert set(data["policies"]) == set(policy_catalogue()["policies"])
    assert dict(Counter(policy.split(".")[1] for policy in data["policies"])) == AREA_COUNTS


def test_fixture_covers_the_three_policies_and_every_cell():
    assert Counter(row["policy"] for row in VECTORS) == {SS11: 190, SS61: 293, SS62: 267}
    for policy in POLICIES:
        assert {row["rule_cell"] for row in VECTORS if row["policy"] == policy} == set(cells_for(policy))
    # The A2 constructed rows reach the rule_scope_unusable [protection_policy_rules] variant of SS 6.x.
    a2 = [row for row in VECTORS if row["vector_id"].startswith("a2-constructed:") and row["policy"] != "MS.SECURITYSUITE.1.3v1"]
    assert {(row["policy"], tuple(row["rule_cited_sections"])) for row in a2} == {
        (SS61, ("protection_policy_rules",)), (SS62, ("protection_policy_rules",))}


@pytest.mark.parametrize("policy", POLICIES)
def test_every_vector_through_the_serving_dispatcher(policy, monkeypatch):
    """Rule dispatch, closed-contract checker, precheck detail, pack response and the served claim all agree."""
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    criticality = policy_catalogue()["policies"][policy]["policy_item"]["criticality"]
    rows = [row for row in VECTORS if row["policy"] == policy]
    reached, mismatches, failures = set(), [], []
    for row in rows:
        sections = row["sections"]
        record = checked(assess(policy, deepcopy(sections)))
        served = _serve_rule(policy, deepcopy(sections))
        detail = served["rule_precheck"]
        assert detail["class"] == "value_rule" and detail["rule_id"] == catalogue()["policies"][policy]["rule_id"]
        actual = (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"])
        if "rule_evaluation_failed" in actual[:2]:
            failures.append(row["vector_id"])
        if actual != _expected(row, policy) or (record["verdict"], record["cell"]) != (
                row["rule_verdict"], row["rule_cell"]):
            mismatches.append(row["vector_id"])
        claim = served["claims"][0]
        assert (claim["status"], claim["value"]) == (
            ("unknown", None) if row["rule_verdict"] == "not_assessed" else ("confirmed", row["rule_verdict"] == "met"))
        assert as_pack_response(record, criticality, list(policy_catalogue()["policies"][policy]["sections"])), row["vector_id"]
        reached.add(detail["cell"])
    assert not failures
    assert not mismatches
    assert reached == set(cells_for(policy))
    assert len(rows) == {SS11: 190, SS61: 293, SS62: 267}[policy]


def test_run_path_supplies_every_section_the_three_rules_read(bundle, cases, monkeypatch):  # noqa: F811
    operation(bundle, "acceptedDomains", [{"Name": "tenant.invalid", "DomainName": "tenant.invalid"}])
    projection = project_run(bundle, redact=False)
    for policy in POLICIES:
        names = catalogue()["policies"][policy]["sections"]
        evidence = {name: rule_policy_section(projection, policy, name) for name in names}
        assert all(value != NOT_COLLECTED and isinstance(value, list) for value in evidence.values()), policy
        checked(assess(policy, evidence))
        assert assess(policy, evidence)["cell"] != "section_not_collected"
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    result = assess_run(bundle, policies=list(POLICIES))
    for row in result["policies"]:
        assert row["rule_precheck"]["class"] == "value_rule"
        assert row["rule_precheck"]["reason_code"] != "rule_evaluation_failed"
        assert row["rule_precheck"]["cell"] != "section_not_collected"
    validate_assessment(result)


def _export_source(tmp_path, policy, sections, failed=()):
    raw = json.loads(PROVIDER.read_text())
    raw.update(deepcopy(sections))
    raw["securitysuite_unsuccessful_commands"] = list(failed)
    path = tmp_path / "export.json"
    path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
    return path


@pytest.mark.parametrize("policy", POLICIES)
def test_export_path_supplies_and_serves_every_vector_cell(policy, tmp_path, monkeypatch):
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    chosen = {}
    for row in VECTORS:
        if row["policy"] == policy and not row["vector_id"].startswith("a2-constructed:"):
            chosen.setdefault(row["rule_cell"], row)
    for cell, row in chosen.items():
        if cell == "section_not_collected":
            continue  # the export holds a section as a value or not at all; absence is covered by the ledger test
        sections = {name: value for name, value in row["sections"].items()
                    if not (isinstance(value, dict) and value == NOT_COLLECTED)}
        out = tmp_path / policy / cell
        out.mkdir(parents=True)
        source = _export_source(out, policy, sections)
        projection, _ = project_export(load_export(source), policy_catalogue()["policies"])
        for name, value in sections.items():
            assert rule_policy_section(projection, policy, name) == value, (policy, cell, name)
        result = assess_scubagear_export(source, out / "assessed", policies=[policy])
        detail = result["policies"][0]["rule_precheck"]
        assert detail["class"] == "value_rule"
        # accepted_domains is collected by the mock export itself, so a vector that omits it can differ only there.
        if "accepted_domains" in row["sections"]:
            assert (detail["cell"], detail["reason_code"], detail["reason_text"]) == _expected(row, policy)[:3], row["vector_id"]
        assert detail["reason_code"] != "rule_evaluation_failed"
        validate_assessment(result)


@pytest.mark.parametrize("failed", [["Get-HostedContentFilterRule"], ["Get-EOPProtectionPolicyRule"], ["Get-MalwareFilterRule"]])
def test_failed_export_command_is_never_read_as_an_empty_list(failed, tmp_path, monkeypatch):
    """A failed Security Suite command withholds every section, so the three rules say 'not collected', never 'none'."""
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    for policy in POLICIES:
        row = next(r for r in VECTORS if r["policy"] == policy and r["rule_verdict"] == "met")
        out = tmp_path / policy
        out.mkdir()
        source = _export_source(out, policy, row["sections"], failed)
        projection, _ = project_export(load_export(source), policy_catalogue()["policies"])
        assert projection.rule_sections["securitysuite_unsuccessful_commands"] == failed
        for name in catalogue()["policies"][policy]["sections"]:
            if name != "accepted_domains":
                assert rule_policy_section(projection, policy, name) == NOT_COLLECTED, (policy, name)
        result = assess_scubagear_export(source, out / "assessed", policies=[policy])
        detail = result["policies"][0]["rule_precheck"]
        assert (detail["class"], detail["cell"]) == ("value_rule", "section_not_collected")
        assert result["policies"][0]["claims"][0]["status"] == "unknown"
