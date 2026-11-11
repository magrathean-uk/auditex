"""Stage 5: v3.9.1+A1 vectors, SS 1.1, strict integration and offline oracle."""
from __future__ import annotations

import importlib.util
import json
import lzma
import os
import subprocess
from collections import Counter, defaultdict
from copy import deepcopy
from functools import cache
from hashlib import sha256
from itertools import combinations
from pathlib import Path
from time import perf_counter

import pytest

from azure_tenant_audit.scuba_precheck import precheck_policy, precheck_response
from azure_tenant_audit.value_rules import as_pack_response, assess, rule_policies
from azure_tenant_audit.value_rules.catalogue import catalogue
from azure_tenant_audit.value_rules.defender_cascade import policy_cascade
from azure_tenant_audit.value_rules.defender_dlp import (
    DLP_LOCATIONS,
    DLP_TYPES,
    dlp_rules,
)
from azure_tenant_audit.value_rules.defender_phish import phish_exists
from azure_tenant_audit.value_rules.exo_open import exo_forwarding
from azure_tenant_audit.value_rules.gates import closed_gate
from azure_tenant_audit.value_rules.record import _not_collected

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "tests/fixtures/value-rules"
FIXTURE = DIRECTORY / "vectors-s5.jsonl.xz"
SS11 = "MS.SECURITYSUITE.1.1v1"  # prepared here, enabled by the held-rule stage
POLICIES = frozenset({"MS.EXO.1.1v2"} | {
    f"MS.SECURITYSUITE.{major}.{minor}v1"
    for major, minors in ((1, range(1, 4)), (2, range(1, 5)), (3, range(1, 5)))
    for minor in minors
})
FUNCTIONS = {"policy_cascade": policy_cascade, "phish_exists": phish_exists,
             "dlp_rules": dlp_rules, "exo_forwarding": exo_forwarding}
CANARIES = ("stage5-private-person@tenant.invalid", "Stage5 Private Display Name")
C2_VECTOR = "constructed:MS.EXO.1.1v2:v33_open_case_differs"


class CountedRows(list):
    """Count full-list walks as a load-independent guard against nested joins."""

    def __init__(self, values):
        super().__init__(values)
        self.walks = 0

    def __iter__(self):
        self.walks += 1
        return super().__iter__()


def scale_sections(kind, size, *, shared_name=False):
    scope = {key: [] for key in ("SentTo", "SentToMemberOf", "RecipientDomainIs",
                                 "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")}
    if kind == "phish":
        return {"defender_license": True, "accepted_domains": [{"DomainName": "tenant.invalid"}],
                "protection_policy_rules": [], "atp_policy_rules": [],
                "anti_phish_policies": CountedRows([
                    {"Identity": "Default", "IsDefault": True, "Enabled": False}, *[
                        {"Identity": f"custom-{i}", "Name": "shared" if shared_name else f"name-{i}",
                         "IsDefault": False, "Enabled": True, "EnableOrganizationDomainsProtection": True,
                         "TargetedDomainProtectionAction": "Quarantine"} for i in range(size)]]),
                "anti_phish_rules": CountedRows([
                    {**scope, "State": "Enabled", "AntiPhishPolicy": "shared" if shared_name else f"name-{i}"}
                    for i in range(size)])}
    if kind == "dlp":
        return {"defender_dlp_license": True,
                "dlp_compliance_policies": CountedRows([
                    {"Name": f"parent-{i}", "Enabled": True, "Mode": "Enable",
                     "Workload": "Exchange SharePoint OneDriveForBusiness Teams EndpointDevices",
                     **{key: ["All"] for _, key, _ in DLP_LOCATIONS}} for i in range(size)]),
                "dlp_compliance_rules": CountedRows([
                    {"Name": f"rule-{i}", "ParentPolicyName": f"parent-{i}", "Disabled": False,
                     "IsAdvancedRule": False, "ContentContainsSensitiveInformation": [{"name": t} for t in DLP_TYPES],
                     "BlockAccess": True, "BlockAccessScope": "All", "NotifyUser": ["LastModifier"],
                     "NotifyUserType": "NotSet"} for i in range(size)])}
    assert kind == "cascade"
    return {"accepted_domains": [{"DomainName": "tenant.invalid"}], "protection_policy_rules": [],
            "anti_malware_policies": CountedRows([
                {"Identity": "Default", "ZapEnabled": True}, *[
                    {"Identity": f"custom-{i}", "ZapEnabled": True} for i in range(size)]]),
            "anti_malware_rules": CountedRows([
                {**scope, "SentTo": ["somebody@tenant.invalid"], "State": "Enabled", "Priority": i,
                 "MalwareFilterPolicy": f"custom-{i}"} for i in range(size)])}


def straightforward_compliant_result(policy, sections, kind):
    """Small-input oracle for these compliant shapes, using literal nested joins.

    Deliberately no index, coverage cache or qualifier sets. The general edge
    cases are covered separately by the fixture and raw-equality tests.
    """
    if kind == "dlp":
        parents = []
        for rule in sections["dlp_compliance_rules"]:
            matches = [p for p in sections["dlp_compliance_policies"] if p.get("Name") == rule["ParentPolicyName"]]
            assert len(matches) == 1 and matches[0]["Enabled"] and matches[0]["Mode"] == "Enable"
            assert all(t in [item["name"] for item in rule["ContentContainsSensitiveInformation"]] for t in DLP_TYPES)
            assert rule["BlockAccess"] and rule["BlockAccessScope"] == "All" and rule["NotifyUser"]
            parents.append(matches[0])
        assert all(any("All" in p[key] and product in p["Workload"] for p in parents)
                   for _, key, product in DLP_LOCATIONS)
        cell = {"types": "all_types_protected", "locations": "all_locations_covered",
                "blocking": "all_rules_block", "notify": "all_rules_notify"}.get(rule_rows()[policy]["params"]["need"])
        assert cell is not None
    elif kind == "phish":
        qualifiers = []
        for p in sections["anti_phish_policies"]:
            if not p["Enabled"]:
                continue
            matches = [r for r in sections["anti_phish_rules"] if r["State"] == "Enabled" and
                       (r.get("AntiPhishPolicy") == p.get("Name") or r.get("AntiPhishPolicy") == p["Identity"])]
            if any(all(r[key] == [] for key in ("SentTo", "SentToMemberOf", "RecipientDomainIs",
                                                "ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs"))
                   for r in matches) and p["EnableOrganizationDomainsProtection"] and p["TargetedDomainProtectionAction"] == "Quarantine":
                qualifiers.append(p)
        assert qualifiers
        cell = "custom_qualifies"
    else:
        for r in sections["anti_malware_rules"]:
            matches = [p for p in sections["anti_malware_policies"] if p["Identity"] == r["MalwareFilterPolicy"]]
            assert r["SentTo"] and len(matches) == 1 and matches[0]["ZapEnabled"]
        assert next(p for p in sections["anti_malware_policies"] if p["Identity"] == "Default")["ZapEnabled"]
        cell = "default_compliant"
    entry = rule_rows()[policy]["cells"][cell]
    assert len(entry["reason_texts"]) == 1
    return {"policy_id": policy, "verdict": "met", "cell": cell, "reason_code": entry["reason_code"],
            "reason_text": entry["reason_texts"][0], "cited_sections": None, "detail": {}}


@pytest.mark.parametrize("kind,policy,shared_name", [
    ("phish", "MS.SECURITYSUITE.2.2v1", False), ("phish", "MS.SECURITYSUITE.2.2v1", True),
    *[("dlp", f"MS.SECURITYSUITE.3.{n}v1", False) for n in range(1, 5)],
    ("cascade", "MS.SECURITYSUITE.1.2v1", False)])
def test_indexed_joins_scale_and_match_straightforward_result(kind, policy, shared_name, record_property):
    small = scale_sections(kind, 25, shared_name=shared_name)
    expected = straightforward_compliant_result(policy, small, kind)
    assert direct(policy, small) == expected
    large = scale_sections(kind, 5000, shared_name=shared_name)
    started = perf_counter()
    actual = direct(policy, large)
    elapsed = perf_counter() - started
    record_property("evaluation_seconds", elapsed)
    assert actual == expected
    assert elapsed < 5, f"{kind}: {elapsed:.3f}s for 5,000 rows"
    assert all(value.walks < 20 for value in large.values() if isinstance(value, CountedRows))


def read_rows(path):
    with (lzma.open(path, "rt") if path.suffix == ".xz" else path.open()) as handle:
        return [row for line in handle if (row := json.loads(line))["policy"] in POLICIES]


@pytest.fixture(scope="module")
def rows():
    return read_rows(FIXTURE)


@cache
def rule_rows():
    return catalogue()["policies"]


def direct(policy, sections):
    """The ordinary precheck order through the rule modules, before the dispatch checker."""
    row = rule_rows()[policy]
    return (closed_gate(policy, sections) or _not_collected(policy, sections, row["sections"])
            or FUNCTIONS[row["kind"]](policy, row, sections))


def assert_vector(vector, record):
    policy = vector["policy"]
    names = rule_rows()[policy]["sections"]
    actual = (record["verdict"], record["cell"], record["reason_code"], record["reason_text"],
              record["cited_sections"] or names)
    expected = (
                vector["rule_verdict"], vector["rule_cell"], vector["rule_reason_code"],
                vector["rule_reason_text"], vector["rule_cited_sections"] or names)
    assert actual == expected, vector["vector_id"]
    entry = rule_rows()[policy]["cells"][record["cell"]]
    assert record["reason_text"] in entry["reason_texts"], vector["vector_id"]
    assert (entry["verdict"], entry["reason_code"]) == (record["verdict"], record["reason_code"])
    cited = record["cited_sections"] or names
    assert cited and cited == [name for name in names if name in cited]
    assert record["verdict"] != "deferred"
    assert vector.get("disagreement") is None or vector["disagreement"].startswith("expected:")
    assert (vector.get("disagreement") is None) is (record["verdict"] == vector["gold_verdict"])


def strip_annotations(value):
    if isinstance(value, dict):
        return {key: strip_annotations(item) for key, item in value.items() if not key.endswith("_name")}
    if isinstance(value, list):
        return [strip_annotations(item) for item in value]
    return value


@pytest.mark.parametrize("policy", sorted(POLICIES))
def test_vectors_and_every_cell(policy, rows):
    selected = [row for row in rows if row["policy"] == policy]
    reached = set()
    for vector in selected:
        record = direct(policy, vector["sections"])
        assert_vector(vector, record)
        assert direct(policy, strip_annotations(vector["sections"])) == record
        reached.add(record["cell"])
    assert selected and reached == set(rule_rows()[policy]["cells"])


def test_manifest_and_stage_registration(rows):
    manifest = json.loads((DIRECTORY / "manifest-s5.json").read_text())
    assert manifest["spec_version"] == "v3.9.1+A1"
    assert manifest["sha256"] == sha256(FIXTURE.read_bytes()).hexdigest()
    assert len(rows) == manifest["rows"] == 2298
    assert Counter(row["policy"] for row in rows) == manifest["by_policy"]
    assert Counter(f"{row['policy']}:{row['rule_cell']}" for row in rows) == manifest["by_cell"]
    assert Counter(row["source_kind"] for row in rows) == manifest["by_source"]
    assert manifest["by_source"]["packlic-train"] == 48
    assert set(manifest["by_source"]) == {"constructed", "pack-train", "pack-validation", "packlic-train"}
    assert {policy: len(rule_rows()[policy]["cells"]) for policy in POLICIES} == manifest["cells_reached"]
    assert sum(manifest["cells_reached"].values()) == 202
    assert set(rule_policies()) & POLICIES == POLICIES
    assert assess(SS11, {}) is not None
    assert list(catalogue()["policies"]) == sorted(catalogue()["policies"])


def test_closed_missing_and_location_texts():
    for policy in POLICIES:
        row = rule_rows()[policy]
        names = row["sections"]
        expected = {"Data unavailable: required evidence section(s) not collected: " + ", ".join(subset) + "."
                    for size in range(1, len(names) + 1) for subset in combinations(names, size)}
        assert set(row["cells"]["section_not_collected"]["reason_texts"]) == expected
    row = rule_rows()["MS.SECURITYSUITE.3.2v1"]
    assert len(row["cells"]["location_not_covered"]["reason_texts"]) == 31
    assert "scuba_config" not in row["sections"]


def test_p1_sections_and_atp_preset_dependencies():
    rules = rule_rows()
    assert "defender_license" in rules["MS.SECURITYSUITE.1.3v1"]["sections"]
    for minor in (1, 3, 4):
        assert "defender_dlp_license" in rules[f"MS.SECURITYSUITE.3.{minor}v1"]["sections"]
    for minor in (1, 2, 3):
        assert "atp_policy_rules" in rules[f"MS.SECURITYSUITE.2.{minor}v1"]["sections"]
    assert "atp_policy_rules" not in rules["MS.SECURITYSUITE.2.4v1"]["sections"]


@pytest.mark.parametrize("policy", sorted(POLICIES))
def test_product_dispatch_vectors(policy, rows):
    for vector in (row for row in rows if row["policy"] == policy):
        sections = vector["sections"]
        record = assess(policy, sections)
        assert_vector(vector, record)
        detail = precheck_policy(policy, sections, list(sections), value_rules=True, absent_fields=True, empty_lists=True)
        assert detail["class"] == "value_rule"
        assert detail["section"] == (record["cited_sections"] or rule_rows()[policy]["sections"])
        assert precheck_response(detail, {"policy_id": policy, "criticality": vector["criticality"]},
                                 list(sections), named_limitations=False) == as_pack_response(
                                     record, vector["criticality"], list(sections), legacy=True)


@pytest.mark.parametrize("policy", ["MS.SECURITYSUITE.1.3v1", *[f"MS.SECURITYSUITE.2.{n}v1" for n in range(1, 5)],
                                    *[f"MS.SECURITYSUITE.3.{n}v1" for n in range(1, 5)]])
def test_missing_licence_is_section_not_collected(policy, rows):
    names = rule_rows()[policy]["sections"]
    key = "defender_dlp_license" if ".3." in policy else "defender_license"
    sections = deepcopy(next(row["sections"] for row in rows if row["policy"] == policy and row["rule_verdict"] == "met"))
    sections.pop(key)
    record = assess(policy, sections)
    assert record["cell"] == "section_not_collected" and record["cited_sections"] == [key]
    sections[key] = False
    assert assess(policy, sections)["cell"] == "licence_false"
    assert key in names


def test_exo_case_sensitive_exact_allowance():
    policy = "MS.EXO.1.1v2"
    sections = {"remote_domains": [{"DomainName": "Partner.Example", "AutoForwardEnabled": True}],
                "scuba_config": {"Exo": {policy: {"AllowedForwardingDomains": ["PARTNER.EXAMPLE", "*"]}}}}
    original = deepcopy(sections)
    assert assess(policy, sections)["cell"] == "forwarder_not_allowed"
    assert sections == original
    sections["scuba_config"]["Exo"][policy]["AllowedForwardingDomains"] = ["Partner.Example", "*"]
    assert assess(policy, sections)["cell"] == "forwarders_all_allowed"
    sections["remote_domains"][0]["DomainName"] = "sub.partner.example"
    assert assess(policy, sections)["cell"] == "forwarder_not_allowed"
    sections["remote_domains"][0]["DomainName"] = " partner.example "
    assert assess(policy, sections)["cell"] == "forwarder_not_allowed"


def test_raw_exo_reference_case_agrees_with_c2(rows):
    vector = next(row for row in rows if row["vector_id"] == C2_VECTOR)
    record = direct(vector["policy"], vector["sections"])
    assert record["verdict"] == vector["rule_verdict"]


def test_agreeing_pack_response_parity(rows):
    # Evidence IDs come from the frozen case catalogue, not from the amended
    # rule read set or licensed-twin view (plan 2.3). The original pack has no
    # evidence slot for the P1-added licence keys.
    cases = json.loads((ROOT / "configs/scuba-policy-sections.json").read_text())["policies"]
    checked = 0
    for vector in rows:
        if vector.get("gold_response") is None or vector.get("disagreement") is not None:
            continue
        record = direct(vector["policy"], vector["sections"])
        actual = as_pack_response(record, vector["criticality"], cases[vector["policy"]]["sections"], legacy=True)
        assert actual == vector["gold_response"], vector["vector_id"]
        checked += 1
    assert checked == 255


def _canary(value):
    if isinstance(value, dict):
        return {**{key: _canary(item) for key, item in value.items()}, "DisplayName": CANARIES[1]}
    if isinstance(value, list):
        return [_canary(item) for item in value]
    return CANARIES[0] if isinstance(value, str) else value


@pytest.mark.parametrize("policy", sorted(POLICIES))
def test_rule_view_canaries_never_leave_records_or_responses(policy, rows, capsys, caplog):
    # One representative of every cell; replace every string leaf as well as
    # adding DisplayName, covering config emails, rule links and free text.
    samples = {}
    for row in rows:
        if row["policy"] == policy:
            samples.setdefault(row["rule_cell"], row)
    touched = set()
    for vector in samples.values():
        for section, value in vector["sections"].items():
            sections = deepcopy(vector["sections"])
            sections[section] = _canary(value)
            touched.add(section)
            record = direct(policy, sections)
            response = as_pack_response(record, vector["criticality"], list(sections))
            outputs = [record, response, precheck_policy(policy, sections, list(sections), value_rules=True)]
            captured = capsys.readouterr()
            rendered = json.dumps(outputs) + caplog.text + captured.out + captured.err
            assert all(canary not in rendered for canary in CANARIES)
            assert record["reason_text"] in rule_rows()[policy]["cells"][record["cell"]]["reason_texts"]
    assert touched >= set(rule_rows()[policy]["sections"])


@pytest.mark.parametrize("policy,cell", [
    ("MS.EXO.1.1v2", "forwarders_all_allowed"),
    ("MS.SECURITYSUITE.2.2v1", "custom_qualifies"),
    ("MS.SECURITYSUITE.3.1v1", "all_types_protected"),
    ("MS.SECURITYSUITE.3.2v1", "all_locations_covered"),
    ("MS.SECURITYSUITE.3.3v1", "all_rules_block"),
    ("MS.SECURITYSUITE.3.4v1", "all_rules_notify")])
def test_linked_success_canaries_never_persist(policy, cell, tmp_path, monkeypatch, capsys, caplog):
    from test_model_serving import case_texts, fake_projection

    from auditex.rule_assessment import assess_run
    from azure_tenant_audit.scuba_assessment import validate_assessment

    caplog.set_level("DEBUG")
    if policy.startswith("MS.EXO."):
        sections = {"remote_domains": [{"DomainName": CANARIES[0], "AutoForwardEnabled": True,
                                        "DisplayName": CANARIES[1]}],
                    "scuba_config": {"Exo": {policy: {"AllowedForwardingDomains": [CANARIES[0]]}}}}
    elif ".2." in policy:
        sections = scale_sections("phish", 1)
        sections["anti_phish_policies"][1].update(Name=CANARIES[0], DisplayName=CANARIES[1])
        sections["anti_phish_rules"][0]["AntiPhishPolicy"] = CANARIES[0]
    else:
        sections = scale_sections("dlp", 1)
        sections["dlp_compliance_policies"][0].update(Name=CANARIES[0], DisplayName=CANARIES[1])
        sections["dlp_compliance_rules"][0].update(ParentPolicyName=CANARIES[0], Name=CANARIES[1])
    record = direct(policy, sections)
    assert record["cell"] == cell and record["verdict"] == "met"
    (tmp_path / "run-manifest.json").write_text('{"run_id":"linked-canary"}')

    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update(sections)
        if "scuba_config" in sections:
            projection.rule_views.setdefault(policy, {})["scuba_config"] = sections["scuba_config"]
        return projection

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.rule_assessment.project_run", projected)
    result = assess_run(tmp_path, policies=[policy])
    assert result["policies"][0]["rule_precheck"]["cell"] == cell
    validate_assessment(result)
    persisted = tmp_path / "model_assessment.json"
    assert json.loads(persisted.read_text()) == result
    cases = case_texts(tmp_path, [policy])
    captured = capsys.readouterr()
    rendered = json.dumps([record, result, cases]) + caplog.text + captured.out + captured.err
    rendered += "".join(path.read_text() for path in tmp_path.rglob("*") if path.is_file())
    assert all(canary not in rendered for canary in CANARIES)


def test_dlp_join_preserves_raw_json_equality_and_duplicate_semantics():
    from azure_tenant_audit.value_rules.defender_cascade import _join_key

    policy = "MS.SECURITYSUITE.3.1v1"
    values = [None, False, 0, 0.0, True, 1, 1.0, "Parent", "parent", " Parent ", [], {},
              [1, {"a": False, "b": ["x"]}], [True, {"b": ["x"], "a": 0}],
              {"a": [1, False], "b": None}, {"b": None, "a": [True, 0]}]
    for name in values:
        for link in values:
            assert (_join_key(name) == _join_key(link)) is (name == link)
            sections = scale_sections("dlp", 1)
            sections["dlp_compliance_policies"][0]["Name"] = name
            sections["dlp_compliance_rules"][0]["ParentPolicyName"] = link
            assert direct(policy, sections)["cell"] == ("all_types_protected" if name == link else "sensitive_rule_unusable")
        sections["dlp_compliance_rules"][0]["ParentPolicyName"] = deepcopy(name)
        sections["dlp_compliance_policies"].append(deepcopy(sections["dlp_compliance_policies"][0]))
        assert direct(policy, sections)["cell"] == "sensitive_rule_unusable"


def test_validator_accepts_ss13_defender_licence_citation(tmp_path, monkeypatch):
    from test_model_serving import fake_projection

    from auditex.rule_assessment import assess_run
    from azure_tenant_audit.scuba_assessment import validate_assessment

    policy = "MS.SECURITYSUITE.1.3v1"
    (tmp_path / "run-manifest.json").write_text('{"run_id":"stage5"}')

    def projected(root, **options):
        projection = fake_projection(root, {})
        projection.rule_sections.update({name: [] for name in rule_rows()[policy]["sections"]})
        projection.rule_sections["defender_license"] = False
        return projection

    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    monkeypatch.setattr("auditex.rule_assessment.project_run", projected)
    result = assess_run(tmp_path, policies=[policy])
    assert result["policies"][0]["rule_precheck"]["section"] == ["defender_license"]
    validate_assessment(result)


def test_optional_full_vectors():
    source = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS_V391")
    if not source:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS_V391 unset")
    rows = read_rows(Path(source))
    reached = defaultdict(set)
    for row in rows:
        record = direct(row["policy"], row["sections"])
        assert_vector(row, record)
        reached[row["policy"]].add(record["cell"])
    assert set(reached) == POLICIES
    assert all(reached[policy] == set(rule_rows()[policy]["cells"]) for policy in POLICIES)


def test_stratified_s5_cells_against_pinned_rego(rows, tmp_path):
    # Reuse the pin verification and outcome reader without modifying the
    # stage-3 oracle harness or embedding any machine paths.
    from test_value_rules_oracle import OPA, SCUBA, _outcome_v3, pinned
    if not (OPA and OPA.is_file() and SCUBA and (SCUBA / "Rego").is_dir()):
        pytest.skip("set AUDITEX_TEST_OPA and AUDITEX_TEST_SCUBAGEAR for pinned offline replay")
    rego = pinned.__wrapped__()
    chosen = {}
    for row in rows:
        if row.get("gold_source") == "opa-replay":
            chosen.setdefault((row["policy"], row["rule_cell"]), row)
    assert {policy for policy, _ in chosen} == POLICIES
    for row in chosen.values():
        package, config = (("exo", "EXOConfig.rego") if row["policy"].startswith("MS.EXO.")
                           else ("securitysuite", "SecuritySuiteConfig.rego"))
        path = tmp_path / "input.json"
        path.write_text(json.dumps(row["sections"]))
        proc = subprocess.run([str(OPA), "eval", "-f", "json", "-d", str(rego / config),
                               "-d", str(rego / "Utils"), "-i", str(path), f"data.{package}.tests"],
                              capture_output=True, text=True, timeout=120)
        try:
            result = json.loads(proc.stdout)
        except ValueError:
            result = {"errors": [proc.stderr[:200]]}
        assert _outcome_v3(row["policy"], result) == row["gold_verdict"], row["vector_id"]
        record = direct(row["policy"], row["sections"])
        assert_vector(row, record)


def test_optional_builder_reproduces_fixture(tmp_path):
    source = os.getenv("AUDITEX_TEST_VALUE_RULE_VECTORS_V391")
    if not source:
        pytest.skip("AUDITEX_TEST_VALUE_RULE_VECTORS_V391 unset")
    spec = importlib.util.spec_from_file_location("stage5_builder", ROOT / "scripts/build-value-rule-fixture-s5.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    output = tmp_path / "vectors.jsonl.xz"
    manifest = builder.build(Path(source), output)
    assert output.read_bytes() == FIXTURE.read_bytes()
    assert manifest == json.loads((DIRECTORY / "manifest-s5.json").read_text())


def test_held_fixture_provenance_excludes_test_and_pilot_rows():
    spec = importlib.util.spec_from_file_location("stage5_builder", ROOT / "scripts/build-value-rule-fixture-s5.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    shared = builder.shared_builder()
    row = {"origin": "v3.7 vectors-base", "source_kind": "constructed",
           "source_file": "constructed by build_vectors.py", "split": None,
           "disagreement": None, "gold_verdict": "met"}
    assert builder.include_held(row, shared)
    for kind, split in shared.V3_PACK.items():
        candidate = {**row, "source_kind": kind, "source_file": shared.V3_PACK_PREFIX + "synthetic.jsonl", "split": split}
        assert builder.include_held(candidate, shared) is (split != "test")
    for kind in shared.V3_PILOT:
        assert not builder.include_held({**row, "source_kind": kind}, shared)
    for changes in ({"source_file": "unknown.jsonl"}, {"split": "test"}, {"source_kind": "unknown"},
                    {"disagreement": "UNEXPECTED"}, {"gold_verdict": None}):
        with pytest.raises(ValueError):
            builder.include_held({**row, **changes}, shared)
    del row["origin"]
    with pytest.raises(ValueError, match="without origin"):
        builder.include_held(row, shared)
