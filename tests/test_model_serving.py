from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

import jsonschema
import pytest

from auditex.cli import main
from auditex.rule_assessment import assess_run
from auditex.rule_assessment import PolicyUnavailable, build_case, canonical, policy_catalogue
from auditex.scuba_projection import project_run
from azure_tenant_audit.bundle_integrity import verify_bundle_hashes
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.contracts import build_validation_report, contract_schema_manifest
from azure_tenant_audit.scuba_assessment import validate_assessment
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.resources import shipped_resource_manifest
from azure_tenant_audit.run_files import UnsafeRunFileError

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = [json.loads(line) for line in (ROOT / "tests/fixtures/model-serving-cases.jsonl").read_text().splitlines()]
POLICY = "MS.AAD.7.3v1"


def fake_projection(root, values):
    projection = project_run(root)
    for key, value in values.items():
        if key in projection:
            previous = projection.report["sections"].get(key, {})
            projection[key] = value
            projection.rule_sections[key] = deepcopy(value)
            projection.report["sections"][key] = {
                "status": "projected" if value != NOT_COLLECTED else "not_collected",
                "reason": None if value != NOT_COLLECTED else "incomplete_shape",
                "source": ["raw/synthetic.json"],
            }
            # scuba_config is synthesised, never read: a faked value keeps the real synthesis record (and the
            # per-policy views the readers see) so the entry stays consistent with what the validator requires.
            if key == "scuba_config" and value != NOT_COLLECTED and "synthesis" in previous:
                projection.report["sections"][key]["synthesis"] = previous["synthesis"]
            # A faked section is what every reader sees: drop the per-policy views the real projection kept for it.
            for views in getattr(projection, "views", {}).values():
                views.pop(key, None)
            for views in projection.rule_views.values():
                views.pop(key, None)
    return projection


def case_texts(run_dir, policies):
    """Canonical case bytes per policy: the user message the retired dry-run prompt export carried."""
    from auditex import rule_assessment
    catalogue = policy_catalogue()
    projection = rule_assessment.project_run(Path(run_dir), redact=True)
    return [canonical(build_case(pid, projection, "unused", catalogue=catalogue)) for pid in policies]


def sample_case():
    return json.loads(SAMPLES[0]["messages"][1]["content"])


def sample_answer():
    return json.loads(SAMPLES[0]["messages"][2]["content"])


def missing_answer():
    return {"claims": [
        {"id": "requirement_met", "status": "unknown", "value": None, "evidence_ids": ["e0", "e1"]},
        {"id": "policy_criticality", "status": "confirmed", "value": "Shall", "evidence_ids": ["e0"]},
    ], "limitations": ["required_evidence_section_not_collected"], "recommendations": ["collect_missing_evidence_section"]}


def test_projection_missing_sections_and_explicit_null_are_distinct(tmp_path):
    assert all(value == NOT_COLLECTED for value in project_run(tmp_path).values())
    case = build_case(POLICY, {}, "2026-10-27")
    assert case["evidence"][1]["observed"] == NOT_COLLECTED
    assert build_case(POLICY, {"privileged_users": None}, "2026-10-27")["evidence"][1]["observed"] is None
    assert set(case) == {"case_id", "evidence", "limitation_ids", "policy_id", "recommendation_ids", "requested_claims"}


def test_named_enums_are_added_without_changing_numbers():
    case = build_case("MS.SHAREPOINT.1.1v1", {"SPO_tenant": [{"SharingCapability": 0}]}, "2026-10-27")
    observed = case["evidence"][1]["observed"][0]
    assert observed == {"SharingCapability": 0, "SharingCapability_name": "disabled (Only people in your organization)"}


def test_catalogue_preserves_all_trained_policy_items():
    data = policy_catalogue()
    assert len(data["policies"]) == 102
    assert all(isinstance(p["policy_item"]["baseline_text"], str) for p in data["policies"].values())
    assert sum("applicability" in p["policy_item"] for p in data["policies"].values()) == 8
    assert data["policies"]["MS.POWERPLATFORM.2.3v1"]["policy_item"]["baseline_text"] == ""
    for pid, entry in data["policies"].items():
        assert build_case(pid, {}, "2026-10-27")["evidence"][0]["observed"] == entry["policy_item"]
    assert data["limitation_ids"] == sample_case()["limitation_ids"]
    assert data["recommendation_ids"] == sample_case()["recommendation_ids"]
    with pytest.raises(PolicyUnavailable, match="policy_not_in_catalogue"):
        build_case("unknown", {}, "2026-10-27")


@pytest.fixture
def demo_bundle(tmp_path):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, "p1", "demo", plane="full", as_of=DEMO_AS_OF) == 0
    return tmp_path / "p1-demo"


@pytest.fixture
def optional_collection_bundle(demo_bundle):
    # These tests exercise value rules/legacy schemas, rather than the no-opt-in reason.
    path = demo_bundle / "run-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["selected_collectors"] = [*manifest.get("selected_collectors", []), "power_bi", "power_platform"]
    path.write_text(json.dumps(manifest))
    return demo_bundle


def snapshot(root):
    return {p.relative_to(root).as_posix(): sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_assessment_writes_valid_optional_artifact_and_unknown_totals(demo_bundle, monkeypatch):
    before = snapshot(demo_bundle)
    result = assess_run(demo_bundle)
    assert result["totals"] == {"answered": 24, "unknown": 78, "invalid": 0, "skipped": 0, "rule_answered": 102,
                                "scope_narrowed": 0}
    assert result["limitations"] == []
    assert {name for name, detail in result["projection"]["sections"].items()
            if detail["status"] == "projected"} == {"service_plans", "tenant_id", "privileged_users", "scuba_config",
                                                    "accepted_domains"}
    # Every catalogue policy has a value rule, so every demo row is a rule answer and none is uncovered.
    assert all(row["reason"] == "rule_precheck" for row in result["policies"])
    assert all(row["attempts"] == 0 for row in result["policies"])
    assert result["endpoint_host"] == "none" and result["model_name"] == "rules-only" and result["run_id"] == "demo"
    assert "serving" not in result
    validate_assessment(result)
    schema = json.loads((ROOT / "schemas/model_assessment.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(result, schema)
    assert json.loads((demo_bundle / "model_assessment.json").read_text()) == result
    assert (demo_bundle / "model_assessment.json").stat().st_mode & 0o777 == 0o600
    assert all(snapshot(demo_bundle)[path] == digest for path, digest in before.items())
    assert build_validation_report(run_dir=demo_bundle, read_only=True)["valid"] is True
    assert verify_bundle_hashes(demo_bundle)["status"] == "verified"
    result["totals"]["unknown"] = 999
    (demo_bundle / "model_assessment.json").write_text(canonical(result))
    report = build_validation_report(run_dir=demo_bundle, read_only=True)
    assert "invalid_model_assessment" in {issue["code"] for issue in report["issues"]}


@pytest.mark.parametrize("rule_status,value,expected", [("pass", True, "agree"), ("pass", False, "disagree"),
                                                       ("fail", False, "agree"), ("accepted_risk", False, "not_assessed")])
def test_assessment_baseline_comparison(tmp_path, monkeypatch, rule_status, value, expected):
    pid = "MS.EXO.13.1v1"
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports/report-pack.json").write_text(canonical({"baseline_alignment": {"frameworks": {
        "cisa_scuba": {"controls": [{"control_id": pid, "status": rule_status}]}}}}))
    monkeypatch.setattr("auditex.rule_assessment.project_run", lambda root, **kwargs: fake_projection(
        root, {"org_config": [{"Name": "Synthetic", "AuditDisabled": not value}], "scuba_config": {}}))
    result = assess_run(tmp_path, policies=[pid])
    assert result["policies"][0]["comparison"]["result"] == expected
    assert result["policies"][0]["reason"] == "rule_precheck" and result["policies"][0]["attempts"] == 0
    assert result["totals"]["answered"] == 1


def test_invalid_policy_fails_and_assessment_needs_no_model(tmp_path, capsys):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    assert main(["assess", str(tmp_path), "--policies", "unknown"]) == 2
    assert not (tmp_path / "model_assessment.json").exists()
    assert not (tmp_path / "model_assessment_prompts.jsonl").exists()
    assert main(["assess", str(tmp_path)]) == 0


def test_sealed_or_symlink_output_is_refused(tmp_path):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    (tmp_path / "bundle-hashes.json").write_text('{"artifacts":[{"path":"model_assessment.json"}]}')
    with pytest.raises(ValueError, match="sealed"):
        assess_run(tmp_path)
    (tmp_path / "bundle-hashes.json").unlink()
    target = tmp_path / "model_assessment.json"
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    target.symlink_to(outside)
    with pytest.raises(ValueError, match="symbolic"):
        assess_run(tmp_path)
    assert outside.read_text() == "untouched"


def test_assessment_resources_are_shipped_and_schema_is_registered():
    resources = shipped_resource_manifest()["resources"]
    assert "configs/scuba-policy-sections.json" in resources
    assert "configs/scuba-rule-precheck.json" in resources
    assert "configs/scuba-value-rules.json" in resources
    assert "configs/scuba-scope-blind.json" in resources
    assert "schemas/model_assessment-2026-10-27.1.schema.json" in resources
    assert "schemas/model_assessment-2026-10-28.schema.json" in resources
    assert "schemas/model_assessment-2026-10-29.schema.json" in resources
    assert "schemas/model_assessment.schema.json" in resources
    assert "model_assessment.schema.json" in contract_schema_manifest()["schemas"]


def test_value_rule_schema_rejects_wrong_cell_code_section_and_text(optional_collection_bundle, monkeypatch):
    monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)
    result = assess_run(optional_collection_bundle, policies=["MS.POWERBI.1.1v1"])
    assert result["schema_version"] == "2026-11-05"
    detail = result["policies"][0]["rule_precheck"]
    assert detail["class"] == "value_rule" and detail["cell"] == "section_not_collected"
    validate_assessment(result)
    for key, bad in (("cell", "off.enabled"), ("reason_code", "wrong_code"),
                     ("reason_text", "tenant@example.com"), ("section", ["privileged_users"])):
        tampered = deepcopy(result)
        tampered["policies"][0]["rule_precheck"][key] = bad
        with pytest.raises(ValueError):
            validate_assessment(tampered)

    from azure_tenant_audit.scuba_precheck import precheck_response
    from azure_tenant_audit.value_rules.catalogue import row_for
    tampered = deepcopy(result)
    policy_row = tampered["policies"][0]
    detail = policy_row["rule_precheck"]
    cell = row_for("MS.POWERBI.1.1v1")["cells"]["licence_false"]
    detail.update(cell="licence_false", reason_code=cell["reason_code"],
                  reason_text=cell["reason_texts"][0], section=["powerbi_tenant_settings"])
    policy_row.update(precheck_response(detail, {"policy_id": policy_row["policy_id"],
                                        "criticality": policy_row["claims"][1]["value"]},
                                        row_for("MS.POWERBI.1.1v1")["sections"]))
    with pytest.raises(ValueError, match="wrong section"):
        validate_assessment(tampered)
    for key in ("cell", "reason_code", "reason_text"):
        missing = deepcopy(result)
        del missing["policies"][0]["rule_precheck"][key]
        with pytest.raises(ValueError, match="Missing value-rule"):
            validate_assessment(missing)


def test_value_rule_still_requires_current_schema(optional_collection_bundle):
    result = assess_run(optional_collection_bundle, policies=["MS.POWERBI.1.1v1"])
    assert result["policies"][0]["rule_precheck"]["class"] == "value_rule"
    result["schema_version"] = "2026-10-29"
    with pytest.raises(ValueError):
        validate_assessment(result)


@pytest.mark.parametrize("switch", [" 1 ", "y", "disable", " 0 ", "false", ""])
def test_value_rule_legacy_switch_is_ignored(optional_collection_bundle, monkeypatch, capsys, switch):
    expected = assess_run(optional_collection_bundle, policies=["MS.POWERBI.1.1v1"])
    capsys.readouterr()
    monkeypatch.setenv("AUDITEX_DISABLE_VALUE_RULES", switch)
    result = assess_run(optional_collection_bundle, policies=["MS.POWERBI.1.1v1"])
    assert result["policies"] == expected["policies"]
    # The legacy-option warning left with the model layer; the switch is still read by nothing.
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("mutation", ["evidence", "criticality", "policy", "comparison", "nonfinite", "boolean_number"])
def test_optional_artifact_validation_rejects_tampering(tmp_path, monkeypatch, mutation):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    monkeypatch.setattr("auditex.rule_assessment.project_run", lambda root, **kwargs: fake_projection(root, {"privileged_users": {}}))
    result = assess_historical_model(tmp_path, sample_answer(), policies=[POLICY])
    row = result["policies"][0]
    if mutation == "evidence":
        row["claims"][0]["evidence_ids"].append("e999")
    elif mutation == "criticality":
        row["claims"][1]["value"] = "May"
    elif mutation == "policy":
        row["policy_id"] = "MS.FAKE.99.99v1"
    elif mutation == "comparison":
        row["comparison"] = {"baseline_status": "pass", "model_status": "fail", "result": "agree"}
    elif mutation == "nonfinite":
        row["latency_ms"] = float("inf")
    elif mutation == "boolean_number":
        row["attempts"] = True
    with pytest.raises(ValueError):
        validate_assessment(result)


def test_rule_rows_carry_no_finish_reason(tmp_path, monkeypatch):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    result = assess_run(tmp_path, policies=[POLICY])
    row = result["policies"][0]
    assert row["reason"] == "rule_precheck" and "finish_reason" not in row
    row["finish_reason"] = "stop"
    with pytest.raises(ValueError, match="model rows only"):
        validate_assessment(result)


def test_assessment_schema_checker_handles_large_json_integer(tmp_path, monkeypatch):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    # This checks numeric range handling, independently of zero-latency rule provenance.
    monkeypatch.setattr("auditex.rule_assessment.project_run",
                        lambda root, **kwargs: fake_projection(root, {"privileged_users": {}}))
    result = assess_historical_model(tmp_path, missing_answer(), policies=[POLICY])
    result["policies"][0]["latency_ms"] = 10 ** 400
    validate_assessment(result)  # Finite integers must not overflow a float conversion.


def test_optional_assessment_with_malformed_manifest_is_refused_not_reported(demo_bundle, monkeypatch):
    """A malformed required manifest is a fixed UnsafeRunFileError refusal, never an optional-artifact issue."""
    assess_run(demo_bundle, policies=["MS.AAD.1.1v1"])
    assessment = demo_bundle / "model_assessment.json"
    before = assessment.read_bytes()
    (demo_bundle / "run-manifest.json").write_text("[]")
    with pytest.raises(UnsafeRunFileError):
        build_validation_report(run_dir=demo_bundle, read_only=True)
    assert assessment.read_bytes() == before
    assert (demo_bundle / "run-manifest.json").read_text() == "[]"


@pytest.mark.parametrize('pack', [None, [], {}, {'baseline_alignment': None}, {'baseline_alignment': []},
    {'baseline_alignment': {'frameworks': None}},
    {'baseline_alignment': {'frameworks': {'cisa_scuba': {'controls': None}}}},
    {'baseline_alignment': {'frameworks': {'cisa_scuba': {'controls': [None, [], {}, {'control_id': POLICY},
        {'control_id': POLICY, 'status': None}, {'control_id': POLICY, 'status': {}}]}}}}, 'broken JSON'])
def test_malformed_report_pack_does_not_break_assessment(tmp_path, monkeypatch, pack):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    (tmp_path / 'reports').mkdir()
    (tmp_path / 'reports/report-pack.json').write_text(pack if isinstance(pack, str) else canonical(pack))
    result = assess_run(tmp_path, policies=[POLICY])
    assert result['policies'][0]['comparison']['baseline_match'] == 'none'


@pytest.mark.parametrize('policy_id,baseline_id,match', [
    ('MS.AAD.3.2v2', 'MS.AAD.3.2v1', 'version_mismatch'),
    ('MS.EXO.2.2v3', 'MS.EXO.2.2v2', 'version_mismatch'),
    (POLICY, POLICY, 'exact'), (POLICY, 'MS.AAD.1.1v1', 'none')])
def test_baseline_version_matching(tmp_path, monkeypatch, policy_id, baseline_id, match):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    (tmp_path / 'reports').mkdir()
    controls = [{'control_id': baseline_id, 'status': 'pass'}]
    (tmp_path / 'reports/report-pack.json').write_text(canonical({'baseline_alignment': {'frameworks': {
        'cisa_scuba': {'controls': controls}}}}))
    result = assess_run(tmp_path, policies=[policy_id])
    assert result['policies'][0]['comparison']['baseline_match'] == match


def test_absent_catalogue_policy_is_defensively_skipped(tmp_path, monkeypatch):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    result = assess_run(tmp_path, policies=['MS.UNKNOWN.1.1v1'])
    assert result['totals']['skipped'] == 1
    assert result['policies'][0]['reason'] == 'policy_not_in_catalogue'


@pytest.mark.parametrize('mutation', ['future_version', 'bad_version', 'invalid_json'])
def test_malformed_optional_assessment_warns_without_changing_gate(demo_bundle, monkeypatch, mutation):
    from auditex.gate import gate_findings
    before = gate_findings(run_dir=str(demo_bundle), fail_on='critical')
    result = assess_run(demo_bundle, policies=[POLICY])
    result['schema_version'] = '2099-01-01' if mutation == 'future_version' else None
    (demo_bundle / 'model_assessment.json').write_text('{' if mutation == 'invalid_json' else canonical(result))
    after = gate_findings(run_dir=str(demo_bundle), fail_on='critical')
    assert after['status'] == before['status'] != 'blocked'
    assert after['pass'] == before['pass']
    report = build_validation_report(run_dir=demo_bundle, read_only=True)
    assert report['valid'] is True
    assert any(i['code'] == 'invalid_model_assessment' and i['severity'] == 'warning' for i in report['issues'])


def test_known_older_optional_assessment_uses_its_recorded_schema(tmp_path, monkeypatch):
    (tmp_path / 'run-manifest.json').write_text('{"run_id":"run"}')
    # Legacy schema dispatch is checked using an actual model row.
    monkeypatch.setattr('auditex.rule_assessment.project_run',
                        lambda root, **kwargs: fake_projection(root, {'privileged_users': {}}))
    result = assess_historical_model(tmp_path, missing_answer(), policies=[POLICY])
    result['schema_version'] = '2026-10-27'
    del result['limitations'], result['projection'], result['totals']['rule_answered']
    del result['scope_post_check'], result['totals']['scope_narrowed'], result['serving']
    row = result['policies'][0]
    del row['thinking_disabled'], row['thinking_stripped'], row['comparison']['baseline_match']
    with pytest.raises(ValueError, match='Unexpected'):
        validate_assessment(result)  # finish_reason is newer than 2026-10-27
    del row['finish_reason']
    validate_assessment(result)
    row['thinking_disabled'] = True
    with pytest.raises(ValueError, match='Unexpected'):
        validate_assessment(result)


def test_absent_field_rule_is_served_and_validated(tmp_path, monkeypatch):
    """The SharePoint value rule now pre-empts the legacy absent-field rule.
    Its missing-field answer validates; a tampered class or foreign rule id is rejected."""
    import json as _json
    from copy import deepcopy as _deepcopy
    from pathlib import Path as _Path
    import jsonschema as _jsonschema
    from auditex.rule_assessment import assess_run as _assess
    from auditex.rule_assessment import policy_catalogue as _catalogue
    from azure_tenant_audit.scuba_assessment import validate_assessment as _validate
    (tmp_path / "run-manifest.json").write_text('{"run_id":"run"}')
    values = {section: {} for section in _catalogue()["policies"]["MS.SHAREPOINT.1.1v1"]["sections"]}
    values["SPO_tenant"] = [{"SharingDomainRestrictionMode": 0}]  # collected, but SharingCapability (Rego-read) is missing
    monkeypatch.setattr("auditex.rule_assessment.project_run", lambda root, **options: fake_projection(root, values))
    result = _assess(tmp_path, policies=["MS.SHAREPOINT.1.1v1"])
    row = result["policies"][0]
    assert row["reason"] == "rule_precheck" and row["rule_precheck"]["class"] == "value_rule"
    assert row["rule_precheck"]["rule_id"] == "MS.SHAREPOINT.1.1v1.sp_scalar"
    assert row["rule_precheck"]["cell"] == "field_absent"
    assert row["rule_precheck"]["section"] == ["SPO_tenant"] and row["rule_precheck"]["value"] is None
    assert next(c for c in row["claims"] if c["id"] == "requirement_met")["status"] == "unknown"
    _validate(result)
    _jsonschema.validate(result, _json.loads(_Path("schemas/model_assessment.schema.json").read_text(encoding="utf-8")))
    tampered = _deepcopy(result)
    tampered["policies"][0]["rule_precheck"]["class"] = "closed_gate"
    with pytest.raises(ValueError):
        _validate(tampered)
    tampered = _deepcopy(result)
    tampered["policies"][0]["rule_precheck"]["rule_id"] = "MS.SHAREPOINT.1.2v1.ODBSharingCapability_absent"
    with pytest.raises(ValueError):
        _validate(tampered)


def assess_historical_model(root, answer, *, policies, **kwargs):
    """Build a historical model-answered fixture as the retired client recorded it, outside product assessment."""
    from auditex.rule_assessment import _comparison, _totals
    result = assess_run(root, policies=policies, **kwargs)
    records = []
    for pid in policies:
        row = {"policy_id": pid, "claims": deepcopy(answer["claims"]), "limitations": list(answer["limitations"]),
               "recommendations": list(answer["recommendations"]), "validation_status": "valid", "reason": None,
               "attempts": 1, "latency_ms": 0.17, "prompt_sha256": "0" * 64, "response_sha256": "1" * 64,
               "finish_reason": None, "thinking_disabled": True, "thinking_stripped": False}
        row["comparison"] = _comparison(pid, row, {})
        records.append(row)
    result.update(policies=records, totals=_totals(records), endpoint_host="127.0.0.1", model_name="test-model",
                  serving={"cache_prompt": "disabled", "response_format": "json_object"})
    return result
