"""The template explainer's product boundary, validation and report integration."""
from collections import Counter
from copy import deepcopy
import json
import logging
from pathlib import Path
import time

import jsonschema
import pytest

from auditex import model_precheck, model_serving
from auditex.model_precheck import precheck_case
from auditex.model_serving import assess_run, build_case
from auditex.reporting import load_report_bundle, preview_report
from azure_tenant_audit.cli import run_offline
from azure_tenant_audit.explainer import ExplainerError
from azure_tenant_audit.model_assessment import ASSESSMENT_SCHEMAS, validate_assessment, value_rule_verdict
from azure_tenant_audit.output_redaction import RedactionContext

ROOT = Path(__file__).resolve().parents[1]
PBI = "MS.POWERBI.1.1v1"
SHAREPOINT = "MS.SHAREPOINT.3.1v1"


def case_for(verdict):
    if verdict == "not_applicable":
        return build_case(SHAREPOINT, {"SPO_tenant": [{"SharingCapability": 0}]}, "unused")
    value = {"met": False, "not_met": True, "not_assessed": None}[verdict]
    return build_case(PBI, {"powerbi_license_found": True, "powerbi_access_denied_reason": "",
                            "powerbi_tenant_settings": [{"settingName": "PublishToWeb", "enabled": value}]}, "unused")


def explained(verdict):
    return precheck_case(case_for(verdict), value_rules=True, explain=True, redaction_context=RedactionContext())


@pytest.fixture
def assessment(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "run-manifest.json").write_text('{"run_id":"wire-test"}')
    return assess_run(root, policies=[PBI])


def assessment_with_row(template, verdict):
    payload = deepcopy(template)
    row = explained(verdict)
    row["comparison"] = model_serving._comparison(row["policy_id"], row, {})
    payload["policies"] = [row]
    payload["totals"] = model_serving._totals([row])
    validate_assessment(payload)
    return payload


@pytest.mark.parametrize("verdict", ["met", "not_met", "not_assessed", "not_applicable"])
def test_four_verdicts_follow_rule_and_use_real_explainer(verdict):
    case = case_for(verdict)
    without = precheck_case(case, value_rules=True)
    with_explainer = precheck_case(case, value_rules=True, explain=True, redaction_context=RedactionContext())
    assert value_rule_verdict(with_explainer) == verdict
    result = with_explainer.pop("explainer")
    assert with_explainer == without
    assert result["evidence_refs"][0] == "e0"
    assert set(result["evidence_refs"]) <= set(with_explainer["claims"][0]["evidence_ids"])
    assert bool(result["remediation_steps"]) == (verdict in {"not_met", "not_assessed"})


@pytest.mark.parametrize("error", [ExplainerError, ValueError, KeyError, RecursionError])
def test_explainer_failures_are_suppressed_and_log_no_values(monkeypatch, caplog, error):
    secret = "sensitive-person@example.invalid"
    def broken(*args, **kwargs):
        raise error(secret)
    monkeypatch.setattr(model_precheck, "render_explanation", broken)
    caplog.set_level(logging.DEBUG, logger=model_precheck.__name__)
    row = precheck_case(case_for("not_met"), value_rules=True, explain=True)
    assert "explainer" not in row and value_rule_verdict(row) == "not_met"
    assert len(caplog.records) == 1
    log = caplog.records[0]
    assert log.getMessage() == f"Explainer {PBI} failed ({error.__name__})"
    assert log.exc_info is None and secret not in repr(log.__dict__)


def test_redaction_failure_suppresses_explainer_and_logs_only_class_and_policy(monkeypatch, caplog):
    secret = "person@example.invalid"
    def broken(*args, **kwargs):
        raise RuntimeError(secret)
    monkeypatch.setattr(model_precheck, "redact_output", broken)
    caplog.set_level(logging.DEBUG, logger=model_precheck.__name__)
    row = precheck_case(case_for("not_met"), value_rules=True, explain=True)
    assert "explainer" not in row
    assert [r.getMessage() for r in caplog.records] == [f"Explainer {PBI} failed (RuntimeError)"]
    assert secret not in repr(caplog.records[0].__dict__)


def test_invalid_redacted_result_is_suppressed(monkeypatch, caplog):
    monkeypatch.setattr(model_precheck, "redact_output", lambda *args, **kwargs: {"explanation": "bad"})
    caplog.set_level(logging.DEBUG, logger=model_precheck.__name__)
    row = precheck_case(case_for("not_met"), value_rules=True, explain=True)
    assert "explainer" not in row and value_rule_verdict(row) == "not_met"
    assert [r.getMessage() for r in caplog.records] == [f"Explainer {PBI} failed (ValueError)"]


def test_a_failing_explainer_cannot_mutate_the_rule_answer_or_case(monkeypatch):
    case = case_for("not_met")
    original = deepcopy(case)
    expected = precheck_case(case, value_rules=True)
    def broken(record, sections, order):
        record["cited_sections"].clear()
        sections["powerbi_tenant_settings"].clear()
        order.clear()
        raise RuntimeError("discarded")
    monkeypatch.setattr(model_precheck, "render_explanation", broken)
    assert precheck_case(case, value_rules=True, explain=True) == expected
    assert case == original


def test_incomplete_identity_context_suppresses_explanation(caplog):
    caplog.set_level(logging.DEBUG, logger=model_precheck.__name__)
    row = precheck_case(case_for("not_met"), value_rules=True, explain=True,
                        redaction_context=RedactionContext(incomplete=True))
    assert "explainer" not in row
    assert [r.getMessage() for r in caplog.records] == [f"Explainer {PBI} failed (ContextIncompleteError)"]


def test_context_creation_failure_disables_explainer_without_leaking(tmp_path, monkeypatch, caplog):
    (tmp_path / "run-manifest.json").write_text('{"run_id":"context"}')
    def broken(*args):
        raise RuntimeError("sensitive-person@example.invalid")
    monkeypatch.setattr(model_serving, "context_for_run", broken)
    caplog.set_level(logging.DEBUG, logger=model_serving.__name__)
    result = assess_run(tmp_path, policies=[PBI])
    assert "explainer" not in result["policies"][0]
    assert [r.getMessage() for r in caplog.records if r.name == model_serving.__name__] == [
        f"Explainer {PBI} failed (RuntimeError)"]
    assert "sensitive-person" not in caplog.text


def test_private_rule_view_cannot_be_read_by_explainer(monkeypatch):
    case = case_for("not_met")
    secret = "private-rule-view-canary"
    class PoisonView(dict):
        frozen = False
        def get(self, key, default=None):
            if self.frozen:
                raise AssertionError("explainer read the private rule view")
            return super().get(key, default)
        def __getitem__(self, key):
            if self.frozen:
                raise AssertionError("explainer read the private rule view")
            return super().__getitem__(key)
        def __iter__(self):
            if self.frozen:
                raise AssertionError("explainer read the private rule view")
            return super().__iter__()
    private = PoisonView({item["section"]: deepcopy(item["observed"]) for item in case["evidence"][1:]})
    private["private_only"] = secret
    original = model_precheck.render_explanation
    calls = []
    def spy(record, sections, order):
        private.frozen = True
        calls.append((record, sections, order))
        assert sections is not private and secret not in repr((record, sections, order))
        assert set(record) == {"policy_id", "verdict", "cell", "reason_code", "reason_text", "cited_sections"}
        assert sections == {item["section"]: item["observed"] for item in case["evidence"][1:]}
        return original(record, sections, order)
    monkeypatch.setattr(model_precheck, "render_explanation", spy)
    result = precheck_case(case, value_rules=True, rule_projection=private, explain=True)
    assert len(calls) == 1 and "explainer" in result and secret not in repr(result)


def test_complete_result_is_redacted_with_explainer_profile(monkeypatch):
    address = "hidden-person@example.invalid"
    guid = "71d4f4ae-3641-43b4-aeb4-bb3eb8c1c0ae"
    credential = "unseen-credential-value"
    run_path = "/private/tenant-run"
    text = f"{address} {guid} password={credential} {run_path}/evidence"
    fake = {"explanation": text, "remediation_steps": [text], "evidence_refs": ["e0"]}
    context = RedactionContext(salt="wire-test", run_paths=(run_path,))
    real_redact = model_precheck.redact_output
    calls = []
    def redact_spy(value, *, profile, context):
        calls.append((value, profile, context))
        return real_redact(value, profile=profile, context=context)
    monkeypatch.setattr(model_precheck, "render_explanation", lambda *args: fake)
    monkeypatch.setattr(model_precheck, "redact_output", redact_spy)
    result = precheck_case(case_for("not_met"), value_rules=True, explain=True, redaction_context=context)["explainer"]
    assert calls == [(fake, "explainer", context)]
    serial = json.dumps(result)
    assert all(secret not in serial for secret in (address, guid, credential, run_path))
    assert result["evidence_refs"] == ["e0"]


def test_shared_rule_failure_only_explains_complete_collected_model_view(monkeypatch, caplog):
    from azure_tenant_audit import value_rules
    def broken(*args):
        raise RuntimeError("rule-secret")
    monkeypatch.setattr(value_rules, "assess", broken)
    full = case_for("not_met")
    caplog.set_level(logging.DEBUG)
    row = precheck_case(full, value_rules=True, explain=True)
    assert row["rule_precheck"]["reason_code"] == "rule_evaluation_failed"
    assert row["explainer"]["remediation_steps"] and "rule-secret" not in caplog.text
    missing = deepcopy(full)
    missing["evidence"][1]["observed"] = {"collection_status": "not_collected"}
    assert "explainer" not in precheck_case(missing, value_rules=True, explain=True)


def test_explanation_is_deterministic_and_does_not_mutate_case():
    case = case_for("not_met")
    original = deepcopy(case)
    first = precheck_case(case, value_rules=True, explain=True)
    second = precheck_case(case, value_rules=True, explain=True)
    assert first == second and case == original


def test_default_precheck_and_dry_run_never_call_explainer(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("explainer was called without opt-in")
    monkeypatch.setattr(model_precheck, "render_explanation", forbidden)
    row = precheck_case(case_for("not_met"), value_rules=True)
    assert "explainer" not in row
    monkeypatch.setattr(model_serving, "context_for_run", forbidden)
    (tmp_path / "run-manifest.json").write_text('{"run_id":"dry"}')
    assert assess_run(tmp_path, policies=[PBI], dry_run=True)["prompts"] == 1


@pytest.mark.parametrize("kind,policy,projection", [
    ("closed_gate", SHAREPOINT, {"SPO_tenant": [{"SharingCapability": 0}]}),
    ("absent_section", "MS.AAD.1.1v1", {}),
    ("absent_field", "MS.POWERBI.7.1v1", {"powerbi_access_denied_reason": None,
                                              "powerbi_license_found": True, "powerbi_tenant_settings": []}),
    ("empty_required_list", "MS.AAD.1.1v1", {"conditional_access_policies": [], "scuba_config": {}}),
])
def test_legacy_precheck_kinds_are_never_explained(monkeypatch, kind, policy, projection):
    calls = []
    monkeypatch.setattr(model_precheck, "render_explanation", lambda *args: calls.append(args))
    row = precheck_case(build_case(policy, projection, "unused"), absent_fields=True, empty_lists=True, explain=True)
    assert row["rule_precheck"]["class"] == kind
    assert "explainer" not in row and not calls


@pytest.mark.parametrize("suffix", ["1.3", "2.1", "2.2", "2.3", "3.1", "3.3", "3.4", "7.1", "7.2", "7.3"])
def test_securitysuite_without_complete_model_case_is_always_suppressed(monkeypatch, suffix):
    from azure_tenant_audit.value_rules.catalogue import row_for
    policy = f"MS.SECURITYSUITE.{suffix}v1"
    case = build_case(policy, {}, "unused")
    available = {entry["section"] for entry in case["evidence"][1:]}
    rule = row_for(policy)
    assert set(rule["sections"]) - available
    # Even a cell whose own citations fit must not bypass the complete-read-set requirement.
    cell_name, cell = next((name, cell) for name, cell in rule["cells"].items()
                           if isinstance(cell.get("cited"), list) and set(cell["cited"]) <= available)
    detail = {"class": "value_rule", "rule_id": rule["rule_id"], "section": cell["cited"],
              "field": None, "value": None, "cell": cell_name, "reason_code": cell["reason_code"],
              "reason_text": cell["reason_texts"][0]}
    monkeypatch.setattr(model_precheck, "precheck_policy", lambda *args, **kwargs: detail)
    calls = []
    monkeypatch.setattr(model_precheck, "render_explanation", lambda *args: calls.append(args))
    result = precheck_case(case, value_rules=True, explain=True)
    assert "explainer" not in result and not calls


def test_demo_budget_and_suppressed_rows(tmp_path):
    from auditex.demo import DEMO_AS_OF, DEMO_SAMPLE
    assert run_offline(ROOT / DEMO_SAMPLE, tmp_path, "p1", "demo", plane="full", as_of=DEMO_AS_OF) == 0
    start = time.monotonic()
    result = assess_run(tmp_path / "p1-demo")
    elapsed = time.monotonic() - start
    rows = result["policies"]
    assert len(rows) == 102 and elapsed < 10
    assert Counter(value_rule_verdict(row) for row in rows) == {
        "met": 3, "not_met": 21, "not_assessed": 78}
    assert sum("explainer" in row for row in rows) == 76
    optional = [row for row in rows if row["rule_precheck"].get("reason_code") == "optional_collection_not_enabled"]
    assert len(optional) == 16 and all("explainer" not in row for row in optional)
    suppressed = {f"MS.SECURITYSUITE.{suffix}v1" for suffix in
                  ("1.3", "2.1", "2.2", "2.3", "3.1", "3.3", "3.4", "7.1", "7.2", "7.3")}
    assert all("explainer" not in row for row in rows if row["policy_id"] in suppressed)
    assert len([row for row in rows if row["policy_id"] in suppressed]) == 10
    validate_assessment(result)


def test_schema_mirrors_standalone_and_explainer_is_optional(assessment):
    standalone = json.loads((ROOT / "schemas/explainer.schema.json").read_text())
    current = json.loads((ROOT / "schemas/model_assessment.schema.json").read_text())
    assert current["$defs"]["explainer"] == {k: standalone[k] for k in
                                               ("type", "additionalProperties", "required", "properties")}
    payload = assessment_with_row(assessment, "not_met")
    jsonschema.validate(payload, current)
    del payload["policies"][0]["explainer"]
    jsonschema.validate(payload, current)
    validate_assessment(payload)


@pytest.mark.parametrize("version", ["2026-10-27", "2026-10-27.1", "2026-10-28", "2026-10-29"])
def test_each_legacy_schema_rejects_explainer_as_an_addition(assessment, version):
    schema = json.loads((ROOT / ASSESSMENT_SCHEMAS[version]).read_text())
    current = assessment_with_row(assessment, "not_met")["policies"][0]
    allowed = schema["$defs"]["policy"]["properties"]
    legacy_row = {k: v for k, v in current.items() if k in allowed and k != "explainer"}
    comparison_keys = allowed["comparison"]["properties"]
    legacy_row["comparison"] = {k: v for k, v in legacy_row["comparison"].items() if k in comparison_keys}
    if "rule_precheck" not in allowed:
        legacy_row["reason"] = None
    else:
        legacy_row["rule_precheck"] = {"class": "absent_section", "rule_id": "required_sections_present",
                                       "section": ["powerbi_license_found"], "field": None, "value": None}
    validator = jsonschema.Draft202012Validator(schema).evolve(schema={"$ref": "#/$defs/policy"})
    validator.validate(legacy_row)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**legacy_row, "explainer": current["explainer"]})


def test_legacy_assessment_still_validates_before_and_after_upgrade(tmp_path, monkeypatch):
    original = model_serving.precheck_case
    monkeypatch.setattr(model_serving, "precheck_case", lambda case, **kw: original(
        case, **{**kw, "value_rules": False, "explain": False}))
    (tmp_path / "run-manifest.json").write_text('{"run_id":"legacy"}')
    result = assess_run(tmp_path, policies=[PBI])
    result["schema_version"] = "2026-10-29"
    result.pop("scope_post_check", None)
    result["totals"].pop("scope_narrowed", None)
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / ASSESSMENT_SCHEMAS["2026-10-29"]).read_text()))
    result["schema_version"] = "2026-11-05"
    validate_assessment(result)
    jsonschema.validate(result, json.loads((ROOT / ASSESSMENT_SCHEMAS["2026-11-05"]).read_text()))


@pytest.mark.parametrize("mutation", ["extra", "missing", "empty_refs", "duplicate_refs", "bad_ref", "outside_claim",
                                      "no_e0", "empty_step", "too_many_steps", "too_many_words", "too_many_sentences",
                                      "invalid_unicode"])
def test_validator_rejects_damaged_explainer(assessment, mutation):
    result = assessment_with_row(assessment, "not_met")
    item = result["policies"][0]["explainer"]
    if mutation == "extra": item["extra"] = "unapproved"
    elif mutation == "missing": del item["explanation"]
    elif mutation == "empty_refs": item["evidence_refs"] = []
    elif mutation == "duplicate_refs": item["evidence_refs"] = ["e0", "e0"]
    elif mutation == "bad_ref": item["evidence_refs"] = ["e0", "e-1"]
    elif mutation == "outside_claim": item["evidence_refs"] = ["e0", "e999"]
    elif mutation == "no_e0": item["evidence_refs"] = ["e1"]
    elif mutation == "empty_step": item["remediation_steps"] = [""]
    elif mutation == "too_many_steps": item["remediation_steps"] = ["Do this."] * 7
    elif mutation == "too_many_words": item["explanation"] = " ".join(["word"] * 81)
    elif mutation == "too_many_sentences": item["explanation"] = "One. Two. Three. Four."
    elif mutation == "invalid_unicode": item["explanation"] = "invalid \ud800 text"
    with pytest.raises(ValueError):
        validate_assessment(result)


@pytest.mark.parametrize("verdict", ["met", "not_applicable"])
def test_validator_rejects_steps_for_non_action_verdicts(assessment, verdict):
    payload = assessment_with_row(assessment, verdict)
    payload["policies"][0]["explainer"]["remediation_steps"] = ["Change a setting."]
    with pytest.raises(ValueError): validate_assessment(payload)


def test_validator_requires_steps_for_not_met(assessment):
    payload = assessment_with_row(assessment, "not_met")
    payload["policies"][0]["explainer"]["remediation_steps"] = []
    with pytest.raises(ValueError): validate_assessment(payload)


def test_no_rule_has_no_explainer_and_schema_rejects_one(tmp_path, monkeypatch):
    from azure_tenant_audit.value_rules import catalogue
    original = catalogue.row_for
    monkeypatch.setattr(catalogue, "row_for", lambda policy: None if policy == PBI else original(policy))
    (tmp_path / "run-manifest.json").write_text('{"run_id":"no-rule"}')
    payload = assess_run(tmp_path, policies=[PBI])
    assert payload["policies"][0]["reason"] == "rule_not_implemented"
    assert "explainer" not in payload["policies"][0]
    payload["policies"][0]["explainer"] = {"explanation": "Unavailable.", "remediation_steps": [], "evidence_refs": ["e0"]}
    schema = json.loads((ROOT / "schemas/model_assessment.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError): jsonschema.validate(payload, schema)
    with pytest.raises(ValueError): validate_assessment(payload)


def make_report_run(tmp_path, assessment, verdict="not_met"):
    root = tmp_path / "report"
    root.mkdir()
    (root / "run-manifest.json").write_text('{"run_id":"wire-test"}')
    payload = assessment_with_row(assessment, verdict)
    (root / "model_assessment.json").write_text(json.dumps(payload))
    return root, payload


@pytest.mark.parametrize("damage", ["invalid_json", "invalid_utf8", "duplicate_key", "nonfinite", "schema", "run_id",
                                     "invalid_unicode", "symlink", "hardlink", "directory", "oversize"])
def test_report_loader_rejects_damaged_assessments(tmp_path, assessment, damage):
    root = tmp_path / "report"
    root.mkdir()
    (root / "run-manifest.json").write_text('{"run_id":"wire-test"}')
    path = root / "model_assessment.json"
    payload = assessment_with_row(assessment, "not_met")
    if damage == "schema": payload["policies"][0]["explainer"]["evidence_refs"] = ["e999"]
    if damage == "run_id": payload["run_id"] = "different"
    if damage == "invalid_unicode": payload["policies"][0]["explainer"]["explanation"] = "invalid \ud800 text"
    text = json.dumps(payload)
    if damage == "invalid_json": path.write_text("{")
    elif damage == "invalid_utf8": path.write_bytes(b"\xff")
    elif damage == "duplicate_key": path.write_text(text[:-1] + ', "run_id": "wire-test"}')
    elif damage == "nonfinite": path.write_text(text[:-1] + ', "nonfinite": NaN}')
    elif damage in {"symlink", "hardlink"}:
        other = root / "other.json"
        other.write_text(text)
        if damage == "symlink": path.symlink_to(other)
        else: path.hardlink_to(other)
    elif damage == "directory": path.mkdir()
    elif damage == "oversize":
        from azure_tenant_audit.run_files import MAX_RUN_DATA_BYTES
        with path.open("wb") as stream: stream.truncate(MAX_RUN_DATA_BYTES + 1)
    else: path.write_text(text)
    assert "policy_explanations" not in load_report_bundle(root)["sections"]


def test_report_loader_suppresses_explanations_when_context_is_incomplete(tmp_path, assessment, monkeypatch):
    import auditex.reporting as reporting
    root, _ = make_report_run(tmp_path, assessment)
    monkeypatch.setattr(reporting, "context_for_run", lambda _: RedactionContext(incomplete=True))
    assert "policy_explanations" not in load_report_bundle(root)["sections"]


def test_report_loader_suppresses_explanations_if_identity_snapshot_changes(tmp_path, assessment, monkeypatch):
    import auditex.reporting as reporting
    root, _ = make_report_run(tmp_path, assessment)
    def changed(*args):
        raise reporting.ContextIncompleteError((("<run>", reporting.REASON_CHANGED),))
    monkeypatch.setattr(reporting, "assert_snapshot_stable", changed)
    assert "policy_explanations" not in load_report_bundle(root)["sections"]


@pytest.mark.parametrize("profile", ["local", "shareable"])
def test_report_escapes_markup_and_redacts_assessment_again(tmp_path, assessment, profile, monkeypatch):
    root, payload = make_report_run(tmp_path, assessment)
    row = payload["policies"][0]["explainer"]
    row["explanation"] = '<script>alert(1)</script> **bold** hidden-person@example.invalid'
    row["remediation_steps"] = ['<img src=x onerror=alert(1)> [click](https://example.invalid) password=canaryvalue']
    validate_assessment(payload)
    (root / "model_assessment.json").write_text(json.dumps(payload))
    # Isolate the escaping and redaction layers: the integrity re-derivation is covered separately below.
    monkeypatch.setattr("azure_tenant_audit.model_assessment.derive_explainer", lambda _row: deepcopy(row))
    outputs = {fmt: preview_report(run_dir=str(root), format_name=fmt, profile=profile) for fmt in ("json", "md", "html")}
    for output in outputs.values():
        assert "policy_explanations" in output["sections"]
        assert "hidden-person" not in output["content"] and "canaryvalue" not in output["content"]
    parsed = json.loads(outputs["json"]["content"])["sections"]["policy_explanations"]
    assert set(parsed[0]) == {"policy_id", "verdict", "explainer"}
    assert "<script>" in parsed[0]["explainer"]["explanation"]
    assert "&lt;script&gt;" in outputs["md"]["content"] and "<script>" not in outputs["md"]["content"]
    assert r"\*\*bold\*\*" in outputs["md"]["content"] and r"\[click\]" in outputs["md"]["content"]
    assert "&lt;script&gt;" in outputs["html"]["content"] and "<script>" not in outputs["html"]["content"]
    assert "&lt;img" in outputs["html"]["content"] and "<img" not in outputs["html"]["content"]
    assert "What this means" in outputs["md"]["content"] and "What to do" in outputs["html"]["content"]


@pytest.mark.parametrize("fmt", ["json", "md", "html", "csv", "sarif", "oscal"])
def test_no_explainer_keeps_report_unchanged(tmp_path, assessment, fmt, monkeypatch):
    import datetime
    class FrozenDateTime(datetime.datetime):
        @classmethod
        def now(cls, tz=None): return cls(2026, 1, 1, tzinfo=tz)
    monkeypatch.setattr(datetime, "datetime", FrozenDateTime)
    root = tmp_path / "report"
    root.mkdir()
    (root / "run-manifest.json").write_text('{"run_id":"wire-test"}')
    before = preview_report(run_dir=str(root), format_name=fmt, profile="local")
    payload = assessment_with_row(assessment, "not_met")
    del payload["policies"][0]["explainer"]
    (root / "model_assessment.json").write_text(json.dumps(payload))
    after = preview_report(run_dir=str(root), format_name=fmt, profile="local")
    assert after == before


def test_markdown_keeps_apostrophes_but_escapes_markup():
    from auditex.reporting import _markdown_plain
    text = _markdown_plain("(formerly 'All cloud apps') baseline's <b>x</b> & y")
    assert "'All cloud apps'" in text and "baseline's" in text
    assert "&#x27;" not in text and "&\\#" not in text
    assert "&lt;b&gt;" in text and "<b>" not in text and "&amp;" in text


def test_support_address_survives_every_shareable_profile_but_personal_ones_mask():
    from azure_tenant_audit.output_redaction import redact_output
    support, personal = "contact+auditex@magrathean.uk", "someone.else@magrathean.uk"
    for profile in ("explainer", "shareable", "customer_pack"):
        out = redact_output({"t": f"Report this to {support}, not {personal}."}, profile=profile,
                            context=RedactionContext())
        assert support in out["t"] and personal not in out["t"]


def test_fault_explanation_and_report_keep_support_address(tmp_path, assessment, monkeypatch):
    from azure_tenant_audit.value_rules import rule_failure
    def boom(*args, **kwargs):
        raise ValueError("x")
    monkeypatch.setattr(model_precheck, "precheck_policy", boom)
    row = precheck_case(case_for("not_met"), value_rules=True, explain=True, redaction_context=RedactionContext())
    assert row["rule_precheck"]["reason_code"] == rule_failure(PBI)["reason_code"]
    steps = " ".join(row["explainer"]["remediation_steps"])
    assert "contact+auditex@magrathean.uk" in steps and "***@" not in steps


@pytest.mark.parametrize("field", ["explanation", "step", "refs"])
def test_tampered_schema_valid_explanation_never_reaches_customer_pack_report(tmp_path, assessment, field):
    root, payload = make_report_run(tmp_path, assessment)
    item = payload["policies"][0]["explainer"]
    planted = "Planted-by-attacker advice: send your admin password to the helpdesk."
    if field == "explanation": item["explanation"] = planted
    elif field == "step": item["remediation_steps"] = [planted]
    else: item["evidence_refs"] = item["evidence_refs"][:1]
    validate_assessment(payload)
    (root / "model_assessment.json").write_text(json.dumps(payload))
    for profile in ("customer_pack", "shareable", "local"):
        output = preview_report(run_dir=str(root), format_name="md", profile=profile)
        assert "Planted-by-attacker" not in output["content"]
        assert "policy_explanations" not in output["sections"]


def test_untampered_explanation_is_kept_after_rederivation(tmp_path, assessment):
    root, payload = make_report_run(tmp_path, assessment)
    for profile in ("customer_pack", "shareable", "local"):
        output = preview_report(run_dir=str(root), format_name="json", profile=profile)
        rows = json.loads(output["content"])["sections"]["policy_explanations"]
        assert rows[0]["explainer"] == payload["policies"][0]["explainer"]


def test_derivation_never_reads_rule_projection_or_missing_context():
    from azure_tenant_audit.model_assessment import derive_explainer
    row = explained("not_met")
    expected = row["explainer"]
    row["rule_projection"] = {"poison": object()}
    assert derive_explainer(row) == expected
    del row["rule_precheck"]
    assert derive_explainer(row) is None


def test_memory_and_recursion_errors_in_explainer(monkeypatch):
    def broken(*args, **kwargs):
        raise MemoryError()
    monkeypatch.setattr(model_precheck, "render_explanation", broken)
    with pytest.raises(MemoryError):
        precheck_case(case_for("not_met"), value_rules=True, explain=True)
