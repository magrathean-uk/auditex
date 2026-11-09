"""A6: run-only optional collection reasons, closed customer text and compatibility."""
from hashlib import sha256
import json
from pathlib import Path

import pytest

from auditex.rule_assessment import precheck_case
from auditex.rule_assessment import assess_run, assess_scubagear_export
from auditex.rule_assessment import build_case, canonical, policy_catalogue
from auditex.scuba_projection import project_run
from auditex.scubagear_export import load_export, project_export
from azure_tenant_audit.scuba_assessment import validate_assessment
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.scuba_precheck import optional_collection_entry

CODE = "optional_collection_not_enabled"
TEXT = "Not assessed: the optional Power BI / Power Platform collection was not enabled for this run."
ENTRY = optional_collection_entry()
POLICIES = sorted(ENTRY["policies"])
OPTIONAL_SECTIONS = {s for p in ENTRY["policies"].values() for s in p["sections"]}
ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_NAMES = sorted(json.loads((ROOT / "configs/collector-definitions.json").read_text())["collectors"])
AMBIGUOUS_SELECTIONS = [
    ("boolean-true", True),
    ("boolean-false", False),
    ("dict", {"identity": True}),
    ("duplicates", ["identity", "identity"]),
    ("optional-duplicates", ["power_bi", "power_bi"]),
    ("mixed-case", ["POWER_BI", "POWER_PLATFORM"]),
    ("part-mixed-case", ["identity", "Power_Bi"]),
    ("leading-whitespace", [" power_bi", "identity"]),
    ("trailing-whitespace", ["power_platform "]),
    ("embedded-whitespace", ["power bi"]),
    ("empty-string", [""]),
    ("part-empty-string", ["identity", ""]),
    ("non-string-element", ["identity", 1]),
    ("boolean-element", ["identity", True]),
    ("dict-element", [{"identity": True}]),
    ("nested-list", [["identity"]]),
    ("null-element", [None]),
    ("null", None),
    ("empty-list", []),
    ("string", "identity"),
    ("unknown-canonical-name", ["unknown_collector"]),
    ("punctuation", ["power-bi"]),
]


@pytest.fixture(autouse=True, params=[False, True], ids=["legacy-switch-unset", "legacy-switch-ignored"])
def offline(monkeypatch, request):
    if request.param:
        monkeypatch.setenv("AUDITEX_DISABLE_VALUE_RULES", "1")
    else:
        monkeypatch.delenv("AUDITEX_DISABLE_VALUE_RULES", raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("A6 must not call a model or network")

    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("socket.socket.connect", forbidden)


def manifest(root, **metadata):
    (root / "run-manifest.json").write_text(json.dumps({"run_id": "synthetic-a6", "platform": "m365", **metadata}))


def answer(root, policies=POLICIES):
    return assess_run(root, policies=policies)


def test_catalogue_exact_scope_and_constant():
    expected = {p for p in policy_catalogue()["policies"] if p.startswith(("MS.POWERBI.", "MS.POWERPLATFORM."))}
    assert set(POLICIES) == expected
    assert len(POLICIES) == 16  # Launch's 15 counts only seven of the eight Power BI policies.
    assert ENTRY["reason_code"] == CODE and ENTRY["reason_text"] == TEXT
    assert OPTIONAL_SECTIONS == {"powerbi_access_denied_reason", "powerbi_tenant_settings",
                                 "environment_creation", "environment_list", "dlp_policies", "tenant_isolation"}
    assert all(set(p["sections"]) <= set(policy_catalogue()["policies"][pid]["sections"])
               for pid, p in ENTRY["policies"].items())


@pytest.mark.parametrize("metadata,omitted", [
    ({"selected_collectors": ["identity", "licensing"]}, {"power_bi", "power_platform"}),
    ({"collectors": ["identity"]}, {"power_bi", "power_platform"}),
    ({"selected_collectors": ["power_bi"]}, {"power_platform"}),
    ({"selected_collectors": ["power_platform"]}, {"power_bi"}),
    ({"selected_collectors": ["power_bi", "power_platform"]}, set()),
    ({"collectors": ["power_bi"]}, {"power_platform"}),
    ({"collectors": ["power_platform"]}, {"power_bi"}),
    ({"collectors": ["power_bi", "power_platform"]}, set()),
    ({"selected_collectors": COLLECTOR_NAMES}, set()),
    ({"collectors": COLLECTOR_NAMES}, set()),
    ({"selected_collectors": [c for c in COLLECTOR_NAMES if c not in {"power_bi", "power_platform"}]},
     {"power_bi", "power_platform"}),
    ({"selected_collectors": ["identity"], "collectors": ["power_bi", "power_platform"]},
     {"power_bi", "power_platform"}),
    ({}, set()),
    *[pytest.param({key: selection}, set(), id=f"{key}-{label}")
      for key in ("selected_collectors", "collectors") for label, selection in AMBIGUOUS_SELECTIONS],
    *[pytest.param({"selected_collectors": selection, "collectors": ["identity"]}, set(),
                   id=f"invalid-selection-overrides-fallback-{label}")
      for label, selection in AMBIGUOUS_SELECTIONS],
])
def test_selection_cases(tmp_path, metadata, omitted):
    manifest(tmp_path, **metadata)
    result = answer(tmp_path)
    validate_assessment(result)
    projection = project_run(tmp_path)
    for row in result["policies"]:
        entry = ENTRY["policies"][row["policy_id"]]
        new_reason = entry["collector"] in omitted
        assert (row["rule_precheck"].get("reason_code") == CODE) == new_reason
        assert row["claims"][0]["status"] == "unknown"
        if new_reason:
            assert row["rule_precheck"]["class"] == "absent_section"
            assert row["rule_precheck"]["reason_text"] == TEXT
            assert row["rule_precheck"]["section"] == entry["sections"]
            assert row["limitations"] == [CODE]
            assert row["recommendations"] == []
        else:
            assert CODE not in row["limitations"]
            assert "required_evidence_section_not_collected" in row["limitations"]
            assert row["recommendations"] == ["collect_missing_evidence_section"]
        for section in entry["sections"]:
            assert projection[section] == NOT_COLLECTED
            reason = projection.report["sections"][section]["reason"]
            assert reason == (CODE if new_reason else "missing_artifact")
    for section in ("tenant_id", "powerbi_license_found"):
        assert projection.report["sections"][section]["reason"] != CODE


@pytest.mark.parametrize("tags", [{"executed_by": "auditex_probe"}, {"probe_mode": "readiness"}])
def test_probe_retains_generic_reason(tmp_path, tags):
    manifest(tmp_path, selected_collectors=["identity"], **tags)
    result = answer(tmp_path)
    validate_assessment(result)
    assert all(s["reason"] != CODE for s in result["projection"]["sections"].values())
    assert all(CODE not in r["limitations"] for r in result["policies"])


def test_selected_but_failed_keeps_existing_reason(tmp_path):
    manifest(tmp_path, selected_collectors=["power_bi", "power_platform"])
    raw = tmp_path / "raw"
    raw.mkdir()
    failures = {
        "power_bi": ["tenantSettings", "accessState"],
        "power_platform": ["environmentCreation", "environments", "dlpPolicyScopes", "tenantIsolation"],
    }
    for collector, operations in failures.items():
        (raw / f"{collector}.json").write_text(json.dumps({
            op: {"value": [], "status": "failed", "error_class": "insufficient_permissions"}
            for op in operations}))
    result = answer(tmp_path)
    validate_assessment(result)
    for section in OPTIONAL_SECTIONS:
        detail = result["projection"]["sections"][section]
        assert detail["reason"] == "collector_error"
        assert detail["detail"]["error_class"] == "insufficient_permissions"
    assert all(CODE not in row["limitations"] for row in result["policies"])


def test_scubagear_export_unchanged(tmp_path):
    source = ROOT / "tests/fixtures/scubagear-export/mocktenant-provider-export.json"
    projection, _ = project_export(load_export(source), policy_catalogue()["policies"])
    assert all(s["reason"] != CODE for s in projection.report["sections"].values())
    for pid in POLICIES:
        case = build_case(pid, projection, "synthetic")
        row = precheck_case(case, value_rules=True, rule_projection=projection.rule_sections)
        assert row is not None and CODE not in row["limitations"]
    result = assess_scubagear_export(source, tmp_path / "assessment",
                                     policies=POLICIES)
    validate_assessment(result)
    assert all(s["reason"] != CODE for s in result["projection"]["sections"].values())
    assert all(CODE not in row["limitations"] for row in result["policies"])


@pytest.mark.parametrize("mutation", ["other_section", "projected", "other_policy", "other_citation",
                                      "generic_projection", "text", "field", "class", "recommendation",
                                      "missing_metadata", "non_rule", "legacy_version"])
def test_validator_rejects_reason_outside_contract(tmp_path, mutation):
    manifest(tmp_path, selected_collectors=["identity"])
    result = answer(tmp_path, ["MS.POWERBI.1.1v1"])
    validate_assessment(result)
    row = result["policies"][0]
    detail = row["rule_precheck"]
    if mutation == "other_section":
        result["projection"]["sections"]["service_plans"]["reason"] = CODE
    elif mutation == "projected":
        result["projection"]["sections"]["powerbi_tenant_settings"].update(status="projected", source=["raw/power_bi.json"])
    elif mutation == "other_policy":
        row["policy_id"] = "MS.AAD.3.4v1"
    elif mutation == "other_citation":
        detail["section"] = ["powerbi_license_found"]
    elif mutation == "generic_projection":
        result["projection"]["sections"][detail["section"][0]]["reason"] = "missing_artifact"
    elif mutation == "text":
        detail["reason_text"] += " tenant@example.invalid"
    elif mutation == "field":
        detail["field"] = "name"
    elif mutation == "class":
        detail["class"] = "value_rule"
    elif mutation == "recommendation":
        row["recommendations"] = ["collect_missing_evidence_section"]
    elif mutation == "missing_metadata":
        del detail["reason_code"]
        del detail["reason_text"]
    elif mutation == "legacy_version":
        result["schema_version"] = "2026-10-29"
    else:
        row.pop("rule_precheck")
        row["reason"] = None
    with pytest.raises(ValueError):
        validate_assessment(result)


def test_legacy_bundles_validate(tmp_path, monkeypatch):
    from auditex.rule_assessment import precheck_case
    monkeypatch.setattr("auditex.rule_assessment.precheck_case", lambda case, **kw: precheck_case(
        case, **{**kw, "value_rules": False}))
    manifest(tmp_path, selected_collectors=["power_bi", "power_platform"])
    result = answer(tmp_path)
    result["schema_version"] = "2026-10-29"
    validate_assessment(result)


def test_model_fixture_bytes_and_other_policy_outputs_unchanged(tmp_path):
    rows = []
    for line in (ROOT / "tests/fixtures/model-serving-cases.jsonl").read_text().splitlines():
        item = json.loads(line)
        case = json.loads(next(m["content"] for m in item["messages"] if m["role"] == "user"))
        # The fixture records the retired prompt; its first two messages equal what messages_for built.
        rows.append({"precheck": precheck_case(case), "messages": item["messages"][:2]})
    assert sha256(canonical(rows).encode()).hexdigest() == "efd8c647e7982248916068d1c40c0d798c2c47dec5aa958cc990faa0a3ce1882"
    manifest(tmp_path)
    before = project_run(tmp_path)
    manifest(tmp_path, selected_collectors=["identity"])
    after = project_run(tmp_path)
    for pid in policy_catalogue()["policies"]:
        cases = [build_case(pid, p, "synthetic") for p in (before, after)]
        assert canonical(cases[0]) == canonical(cases[1])
        if pid in POLICIES:
            continue
        outputs = [precheck_case(c, value_rules=True, rule_projection=p.rule_sections)
                   for c, p in zip(cases, (before, after))]
        assert canonical(outputs[0]) == canonical(outputs[1])
