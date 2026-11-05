"""Stage 4: v3.9.1 DNS, Safe Links and anti-spam rules; synthetic/offline only."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
import importlib.util
from itertools import combinations
import json
import lzma
import os
from pathlib import Path
import subprocess

import pytest

from azure_tenant_audit.resources import open_text_resource
from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import assess, as_pack_response, cells_for, rule_policies
from azure_tenant_audit.value_rules.catalogue import catalogue
from azure_tenant_audit.value_rules.defender_spam import KINDS as SPAM_KINDS
from azure_tenant_audit.value_rules.dns import parse_dmarc, parse_uris
from azure_tenant_audit.value_rules.helpers import PRESET_RE
from azure_tenant_audit.value_rules.record import checked

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/value-rules"
FIXTURE = FIXTURES / "vectors-s4.jsonl.xz"
# SS 6.1 and 6.2 were prepared in this stage and enabled by the held-rule stage; the fixture keeps the rows
# as prepared, and a test below pins the shipped rows to them.
PREPARED = json.loads((FIXTURES / "held-rows-s4.json").read_text())
SS6 = tuple(sorted(PREPARED))
LIVE = {"MS.EXO.3.1v1", "MS.EXO.4.1v1", "MS.EXO.4.2v1", "MS.EXO.4.3v1", "MS.EXO.4.4v1",
        "MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1",
        "MS.SECURITYSUITE.7.1v1", "MS.SECURITYSUITE.7.2v1", "MS.SECURITYSUITE.7.3v1"}
POLICIES = LIVE
POLICY_ITEMS = json.loads(open_text_resource("configs/scuba-policy-sections.json"))["policies"]
CANARY_EMAIL = "stage4-canary-private@example.invalid"
CANARY_NAME = "Stage Four Private DisplayName"


def _rows(path):
    with (lzma.open(path, "rt") if path.suffix == ".xz" else path.open()) as handle:
        for line in handle:
            yield json.loads(line)


@pytest.fixture(scope="module")
def vectors():
    grouped = defaultdict(list)
    for row in _rows(FIXTURE):
        grouped[row["policy"]].append(row)
    return grouped


def _rule(policy):
    return catalogue()["policies"][policy]


def _evaluate(policy, sections):
    return assess(policy, sections)


def _check_vector(row):
    policy, sections = row["policy"], row["sections"]
    rule = _rule(policy)
    record = _evaluate(policy, sections)
    actual = (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
              record["cited_sections"] or rule["sections"])
    expected = (row["rule_verdict"], row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"],
                row["rule_cited_sections"] or rule["sections"])
    assert actual == expected, row["vector_id"]
    entry = rule["cells"][record["cell"]]
    assert (record["verdict"], record["reason_code"]) == (entry["verdict"], entry["reason_code"])
    assert record["reason_text"] in entry["reason_texts"], row["vector_id"]
    if record["cell"] != "section_not_collected":
        assert actual[-1] in entry.get("cited_variants", [entry["cited"]]), row["vector_id"]
    criticality = row.get("criticality", POLICY_ITEMS[policy]["policy_item"]["criticality"])
    response = as_pack_response(record, criticality, list(sections), legacy=True)
    if policy in LIVE:
        detail = precheck_policy(policy, sections, list(sections), value_rules=True,
                                 absent_fields=True, empty_lists=True)
        assert detail["class"] == "value_rule" and detail["rule_id"] == rule["rule_id"]
        assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == actual[1:]
        assert precheck_response(detail, {"policy_id": policy, "criticality": criticality},
                                 list(sections), named_limitations=False) == response
    if row.get("gold_response") is not None and row.get("disagreement") is None:
        assert response == row["gold_response"], row["vector_id"]
    assert row.get("gold_verdict") is not None, row["vector_id"]
    assert row.get("disagreement") is None or row["disagreement"].startswith("expected:"), row["vector_id"]
    assert (row.get("disagreement") is None) is (record["verdict"] == row["gold_verdict"]), row["vector_id"]
    if "pack_null_section_met" in row.get("flags", []):
        assert record["verdict"] == row["expected_verdict"] == "not_assessed"
    return record["cell"]


@pytest.mark.parametrize("policy", sorted(POLICIES))
def test_stage4_vectors_and_every_cell(policy, vectors):
    reached = {_check_vector(row) for row in vectors[policy]}
    assert reached == set(_rule(policy)["cells"])
    if policy in LIVE:
        assert reached == set(cells_for(policy))


def test_fixture_manifest_and_exclusions(vectors):
    manifest = json.loads((FIXTURES / "manifest-s4.json").read_text())[FIXTURE.name]
    rows = [row for group in vectors.values() for row in group]
    assert sha256(FIXTURE.read_bytes()).hexdigest() == manifest["sha256"]
    assert manifest["spec_version"] == "v3.9.1"
    assert len(rows) == manifest["rows"] == 1687
    assert set(vectors) == POLICIES
    assert dict(Counter(row["policy"] for row in rows)) == manifest["by_policy"]
    assert dict(Counter(f"{row['policy']}:{row['rule_cell']}" for row in rows)) == manifest["by_cell"]
    assert dict(Counter(row["source_kind"] for row in rows)) == manifest["by_source"]
    assert set(manifest["by_source"]) == {"constructed", "pack-train", "pack-validation"}
    assert len(manifest["by_cell"]) == 160
    assert sum("pack_null_section_met" in row.get("flags", []) for row in rows) == 24


def test_prepared_anti_spam_rows_are_enabled_exactly_as_prepared():
    assert set(PREPARED) == {"MS.SECURITYSUITE.6.1v1", "MS.SECURITYSUITE.6.2v1"}
    for policy, row in PREPARED.items():
        assert policy in rule_policies()
        # The prepared record predates A1: the shipped row is the record plus exactly its three additive evidence fields.
        shipped = deepcopy(catalogue()["policies"][policy])
        for name, cell in shipped["cells"].items():
            for key in ("evidence_kind", "limitations", "recommendations"):
                if key not in row["cells"][name]:
                    cell.pop(key, None)
        assert shipped == row
        assert assess(policy, {}) is not None
        assert cells_for(policy) == tuple(row["cells"])
        assert row["kind"] in SPAM_KINDS
        assert row["rule_id"] == policy + ".spam_cascade"


@pytest.mark.parametrize("policy", sorted(POLICIES))
@pytest.mark.parametrize("missing_state", ["absent", "marked", "mixed"])
def test_every_missing_section_combination_is_catalogued(policy, missing_state, vectors, monkeypatch):
    from azure_tenant_audit.model_evidence import NOT_COLLECTED
    import azure_tenant_audit.value_rules.catalogue as loader

    data = deepcopy(catalogue())
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    try:
        rule = _rule(policy)
        missing_sets = [list(subset) for size in range(1, len(rule["sections"]) + 1)
                        for subset in combinations(rule["sections"], size)]
        texts = ["Data unavailable: required evidence section(s) not collected: "
                 + ", ".join(missing) + "." for missing in missing_sets]
        assert rule["cells"]["section_not_collected"]["reason_texts"] == sorted(texts)
        base = next(row["sections"] for row in vectors[policy] if row["rule_verdict"] == "met")
        for missing, text in zip(missing_sets, texts):
            sections = deepcopy(base)
            for index, name in enumerate(missing):
                if missing_state == "marked" or missing_state == "mixed" and index % 2:
                    sections[name] = dict(NOT_COLLECTED)
                else:
                    sections.pop(name, None)
            record = checked(_evaluate(policy, sections))
            assert (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
                    record["cited_sections"]) == (
                "not_assessed", "section_not_collected", "required_evidence_section_not_collected", text, missing)
            if policy in LIVE:
                detail = precheck_policy(policy, sections, rule["sections"], value_rules=True)
                assert (detail["class"], detail["cell"], detail["reason_code"], detail["reason_text"],
                        detail["section"]) == (
                    "value_rule", "section_not_collected", "required_evidence_section_not_collected", text, missing)
    finally:
        loader.catalogue.cache_clear()


def test_citation_variants_are_closed(vectors, monkeypatch):
    import azure_tenant_audit.value_rules.catalogue as loader
    data = deepcopy(catalogue())
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    try:
        loader.catalogue()
        for policy in POLICIES:
            for row in vectors[policy]:
                record = _evaluate(policy, row["sections"])
                checked(record)
        record = assess("MS.EXO.3.1v1", {"dkim_config": [{}], "dkim_records": None, "spf_records": [{}]})
        assert record["cited_sections"] == ["dkim_records"]
        with pytest.raises(ValueError, match="wrong section"):
            checked({**record, "cited_sections": ["dkim_config", "dkim_records"]})
        data["policies"]["MS.EXO.3.1v1"]["cells"]["section_not_a_list"]["cited_variants"].append(["unknown_section"])
        loader.catalogue.cache_clear()
        with pytest.raises(ValueError, match="citation"):
            loader.catalogue()
    finally:
        loader.catalogue.cache_clear()


@pytest.fixture(scope="module")
def external_vectors():
    path = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS")
    if not path:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS unset")
    grouped = defaultdict(list)
    for row in _rows(Path(path)):
        if row["policy"] in POLICIES:
            grouped[row["policy"]].append(row)
    return grouped


@pytest.mark.parametrize("policy", sorted(POLICIES))
def test_full_external_stage4_vectors(policy, external_vectors):
    rows = external_vectors[policy]
    assert rows
    assert {_check_vector(row) for row in rows} == set(_rule(policy)["cells"])


def test_full_external_counts_include_pilot_and_flagged_rows(external_vectors):
    rows = [row for group in external_vectors.values() for row in group]
    assert len(rows) == 3615
    assert sum(row["source_kind"].startswith("ss6-") for row in rows) == 1928
    assert sum("pack_null_section_met" in row.get("flags", []) for row in rows) == 24


@pytest.mark.parametrize("policy", SS6)
def test_a2_unreadable_preset_scope_is_accepted_and_wrong_citation_rejected(policy, vectors):
    row = next(row for row in vectors[policy] if row["rule_cell"] == "strict_covers_compliant")
    sections = deepcopy(row["sections"])
    strict = next(rule for rule in sections["protection_policy_rules"] if PRESET_RE[0].search(rule["Identity"]))
    strict.pop("SentTo", None)
    record = _evaluate(policy, sections)
    assert record["cell"] == "rule_scope_unusable"
    assert record["cited_sections"] == ["protection_policy_rules"]
    # A2 adds this preset-only list to A1's closed domain; the predicate is unchanged.
    assert record["cited_sections"] in catalogue()["policies"][policy]["cells"][record["cell"]]["cited_variants"]
    assert checked(record) == record
    with pytest.raises(ValueError, match="wrong section"):
        checked({**record, "cited_sections": ["accepted_domains"]})


@pytest.mark.parametrize("policy", sorted(LIVE & {f"MS.SECURITYSUITE.7.{i}v1" for i in (1, 2, 3)}))
def test_accepted_domains_is_optional_and_not_cited_when_absent(policy, vectors):
    for row in vectors[policy]:
        if row["rule_cell"] in {"policy_flags_ok", "preset_covers"}:
            sections = deepcopy(row["sections"])
            sections.pop("accepted_domains", None)
            record = assess(policy, sections)
            assert "accepted_domains" not in (record["cited_sections"] or _rule(policy)["sections"])
            assert record["cell"] != "section_not_collected"
    assert "accepted_domains" not in _rule(policy)["sections"]
    assert {"defender_license", "atp_policy_rules"} <= set(_rule(policy)["sections"])


def _serve_rule(policy, sections):
    from auditex.model_serving import _assess_policies, policy_catalogue
    from auditex.scuba_projection import Projection

    # The public/model view has no evidence: serving must use the private rule view.
    projection = Projection()
    projection.rule_sections = deepcopy(sections)
    projection.rule_views = {}
    if "scuba_config" in sections:
        projection.rule_views[policy] = {"scuba_config": deepcopy(sections["scuba_config"])}
    records, prompts = _assess_policies(
        projection, [policy], policy_catalogue(), "2026-11-05T00:00:00Z",
        dry_run=False, baseline={})
    assert not prompts
    assert projection.rule_sections == sections
    return records[0]


@pytest.mark.parametrize("policy", [f"MS.SECURITYSUITE.7.{i}v1" for i in (1, 2, 3)])
def test_safelinks_vectors_through_serving(policy, vectors, monkeypatch):
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    assert _rule(policy)["optional_sections"] == ["accepted_domains"]
    reached = set()
    for row in vectors[policy]:
        served = _serve_rule(policy, row["sections"])
        detail = served["rule_precheck"]
        assert (detail["cell"], detail["reason_code"], detail["reason_text"], detail["section"]) == (
            row["rule_cell"], row["rule_reason_code"], row["rule_reason_text"],
            row["rule_cited_sections"] or _rule(policy)["sections"]), row["vector_id"]
        claim = served["claims"][0]
        assert (claim["status"], claim["value"]) == (
            ("unknown", None) if row["rule_verdict"] == "not_assessed"
            else ("confirmed", row["rule_verdict"] == "met")), row["vector_id"]
        assert "accepted_domains" not in detail["section"]
        reached.add(detail["cell"])
    assert reached == set(cells_for(policy))


@pytest.mark.parametrize("policy", [f"MS.SECURITYSUITE.7.{i}v1" for i in (1, 2, 3)])
@pytest.mark.parametrize("scope,cell", [
    ("covering", "preset_covers"), ("partial", "policy_flags_ok"),
    ("absent", "preset_rule_unusable"), ("not_collected", "preset_rule_unusable"),
])
def test_safelinks_optional_domain_scopes_through_serving(policy, scope, cell, vectors, monkeypatch):
    from azure_tenant_audit.model_evidence import NOT_COLLECTED

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    suffix = "preset_domain_partial_builtin_ok" if scope == "partial" else "preset_domain_covers_all_accepted"
    vector = next(row for row in vectors[policy] if row["vector_id"].endswith(":" + suffix))
    sections = deepcopy(vector["sections"])
    if scope == "absent":
        sections.pop("accepted_domains")
    elif scope == "not_collected":
        sections["accepted_domains"] = dict(NOT_COLLECTED)
    detail = _serve_rule(policy, sections)["rule_precheck"]
    assert detail["cell"] == cell
    assert "accepted_domains" not in detail["section"]


@pytest.mark.parametrize("optional", ["accepted_domains", [None], [""],
                                      ["accepted_domains", "accepted_domains"], ["defender_license"]])
def test_catalogue_rejects_invalid_optional_sections(optional, monkeypatch):
    import azure_tenant_audit.value_rules.catalogue as loader

    data = deepcopy(catalogue())
    data["policies"]["MS.SECURITYSUITE.7.1v1"]["optional_sections"] = optional
    monkeypatch.setattr(loader, "open_text_resource", lambda _: json.dumps(data))
    loader.catalogue.cache_clear()
    try:
        with pytest.raises(ValueError, match="optional"):
            loader.catalogue()
    finally:
        loader.catalogue.cache_clear()


def test_dmarc_uri_and_agency_contact_edges():
    assert parse_uris(" MAILTO:A@EXAMPLE.INVALID!10m, mailto:reports@dmarc.cyber.dhs.gov!2G ") == (
        ["a@example.invalid", "reports@dmarc.cyber.dhs.gov"], 0)
    assert parse_uris("a@example.invalid, https://example.invalid, mailto:a@example.invalid!bogus")[1] == 3
    assert parse_dmarc("v=DMARC1") is not None
    assert parse_dmarc("v=dmarc1;p=reject") is None
    policy = "MS.EXO.4.4v1"
    def evaluate(text):
        return assess(policy, {"dmarc_records": [{"domain": "example.invalid", "rdata": [text]}]})
    assert evaluate("v=DMARC1;rua=mailto:reports@dmarc.cyber.dhs.gov,mailto:reports@dmarc.cyber.dhs.gov;"
                    "ruf=mailto:reports@dmarc.cyber.dhs.gov")["cell"] == "domain_noncompliant.agency_contact_missing"
    assert evaluate("v=DMARC1;rua=mailto:a@example.invalid,mailto:b@example.invalid;"
                    "ruf=mailto:c@example.invalid")["verdict"] == "met"


def _taint(value):
    if isinstance(value, dict):
        return {**{key: _taint(item) for key, item in value.items()},
                "PrivateEmail": CANARY_EMAIL, "DisplayName": CANARY_NAME}
    if isinstance(value, list):
        return [_taint(item) for item in value]
    return value


def _replace_strings(value, replacement):
    if isinstance(value, dict):
        return {key: _replace_strings(item, replacement) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_strings(item, replacement) for item in value]
    return replacement if isinstance(value, str) else value


@pytest.mark.parametrize("policy", sorted(POLICIES))
def test_rule_outputs_never_echo_evidence(policy, vectors):
    for row in vectors[policy]:
        sections = _taint(row["sections"])
        record = _evaluate(policy, sections)
        for output in (record, as_pack_response(record, row["criticality"], list(sections), legacy=True)):
            rendered = json.dumps(output)
            assert CANARY_EMAIL not in rendered and CANARY_NAME not in rendered
        # Taint actual labels and values, not just unused fields.
        for canary in (CANARY_EMAIL, CANARY_NAME):
            mutated = _replace_strings(row["sections"], canary)
            record = _evaluate(policy, mutated)
            assert canary not in json.dumps(record)
            if policy in LIVE:
                detail = precheck_policy(policy, mutated, list(mutated), value_rules=True)
                assert canary not in json.dumps(detail)


@pytest.mark.parametrize("policy,cell,cited", [
    ("MS.EXO.3.1v1", "section_not_a_list", ["dkim_records"]),
    ("MS.SECURITYSUITE.7.1v1", "preset_rule_unusable", ["protection_policy_rules", "atp_policy_rules"]),
    ("MS.SECURITYSUITE.7.2v1", "preset_covers", None),
    ("MS.EXO.4.4v1", "domain_noncompliant.agency_contact_missing", None),
])
def test_served_answers_validate_and_persist_no_canaries(policy, cell, cited, vectors, tmp_path, monkeypatch, caplog):
    from auditex.model_serving import ModelClient, ModelConfig, assess_run
    from azure_tenant_audit.model_assessment import validate_assessment
    from test_model_serving import fake_projection

    vector = next(row for row in vectors[policy] if row["rule_cell"] == cell
                  and (cited is None or row["rule_cited_sections"] == cited)
                  and (cell != "preset_covers" or "accepted_domains" in row["sections"]))
    sections = _taint(vector["sections"])
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage4"}')
    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update(sections)
        return projection
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.model_serving.project_run", projected)
    monkeypatch.setattr(ModelClient, "assess", lambda *args: pytest.fail("value rule called the model"))
    result = assess_run(tmp_path, ModelConfig(model_name="unused"), policies=[policy])
    assert result["policies"][0]["rule_precheck"]["cell"] == cell
    validate_assessment(result)
    rendered = json.dumps(result) + caplog.text
    for path in tmp_path.rglob("*"):
        if path.is_file():
            rendered += path.read_text()
    assert CANARY_EMAIL not in rendered and CANARY_NAME not in rendered
    tampered = deepcopy(result)
    tampered["policies"][0]["rule_precheck"]["section"] *= 2
    with pytest.raises(ValueError):
        validate_assessment(tampered)


def _builder():
    spec = importlib.util.spec_from_file_location("stage4_fixture", ROOT / "scripts/build-value-rule-fixture-s4.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_builder_round_trips_committed_fixture_bytes(tmp_path):
    # Origin metadata is discarded by the builder; restore valid metadata for each retained source kind.
    rows = []
    for original in _rows(FIXTURE):
        row = {**original, "origin": "fixture-round-trip"}
        if row["source_kind"] == "constructed":
            row.update(source_file="constructed by v39_vectors.py", split=None)
        else:
            split = {"pack-train": "train", "pack-validation": "validation"}[row["source_kind"]]
            row.update(source_file=f"20261030-oracle-pack-v10/{split}.jsonl", split=split)
        rows.append(row)
    source, target = tmp_path / "source.jsonl", tmp_path / FIXTURE.name
    source.write_text("".join(json.dumps(row) + "\n" for row in rows))
    expected = json.loads((FIXTURES / "manifest-s4.json").read_text())[FIXTURE.name]
    for _ in range(2):
        manifest = _builder().build(source, target)
        assert target.read_bytes() == FIXTURE.read_bytes()
        assert {key: value for key, value in manifest.items() if key != "source_sha256"} == {
            key: value for key, value in expected.items() if key != "source_sha256"}


def test_builder_rejects_unexpected_and_excludes_all_pilots_and_test_rows(vectors, tmp_path):
    row = deepcopy(vectors["MS.EXO.4.1v1"][0])
    row.update(source_kind="constructed", source_file="constructed by v39_vectors.py", split=None, origin="constructed")
    rows = [row]
    for i, (kind, split, file) in enumerate([
        ("pack-train", "train", "20261030-oracle-pack-v10/train.jsonl"),
        ("pack-validation", "validation", "20261030-oracle-pack-v10/validation.jsonl"),
        ("pack-test", "test", "20261030-oracle-pack-v10/test.jsonl"),
        ("ss6-frozen", None, "pilot"), ("ss6-diagnostic", None, "pilot"),
        ("ss6-dropped", None, "pilot"), ("aad-frozen", None, "sealed"),
    ]):
        rows.append({**row, "vector_id": f"s4-{i}", "source_kind": kind, "split": split, "source_file": file})
    source, target = tmp_path / "source.jsonl", tmp_path / "vectors.jsonl.xz"
    source.write_text("".join(json.dumps(r) + "\n" for r in rows))
    manifest = _builder().build(source, target)
    assert manifest["rows"] == 3
    assert manifest["spec_version"] == "v3.9.1"
    before = target.read_bytes()
    assert _builder().build(source, target) == manifest
    assert target.read_bytes() == before
    row["disagreement"] = "UNEXPECTED"
    source.write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="UNEXPECTED"):
        _builder().build(source, target)
    assert target.read_bytes() == before


def test_stage4_stratified_opa_replay(vectors, tmp_path):
    import test_value_rules_oracle as oracle
    if not (oracle.OPA and oracle.OPA.is_file() and oracle.SCUBA and (oracle.SCUBA / "Rego").is_dir()):
        pytest.skip("set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
    version = subprocess.run([str(oracle.OPA), "version"], capture_output=True, text=True, timeout=30)
    if version.returncode or "Version: 1.20.2" not in version.stdout.splitlines():
        pytest.skip("OPA is not pinned version 1.20.2")
    rego = oracle.SCUBA / "Rego"
    for name, digest in oracle.REGO_SHA256.items():
        if sha256((rego / name).read_bytes()).hexdigest() != digest:
            pytest.skip("ScubaGear Rego differs from pinned revision 2446ad72")
    groups = defaultdict(list)
    for policy, rows in vectors.items():
        for row in rows:
            if row.get("gold_source") == "opa-replay":
                groups[(policy, row["rule_cell"])].append(row)
    assert {policy for policy, _ in groups} == POLICIES
    selected = [min(rows, key=lambda r: r["vector_id"]) for _, rows in sorted(groups.items())]
    extra = int(os.getenv("AUDITEX_TEST_VALUE_RULE_SAMPLE", "0"))
    remaining = sorted((row for rows in groups.values() for row in rows if row not in selected),
                       key=lambda r: r["vector_id"])
    selected.extend(remaining[:max(0, extra)])
    for row in selected:
        package, config = next(value for prefix, value in oracle.PACKAGES.items() if row["policy"].startswith(prefix))
        path = tmp_path / "input.json"
        path.write_text(json.dumps(row["sections"]), encoding="utf-8")
        proc = subprocess.run([str(oracle.OPA), "eval", "-f", "json", "-d", str(rego / config),
                               "-d", str(rego / "Utils"), "-i", str(path), f"data.{package}.tests"],
                              capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            result = {"errors": [proc.stderr[:200]]}
        assert oracle._outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        _check_vector(row)
