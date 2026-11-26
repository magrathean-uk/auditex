"""Google assessment wire, dispatch and privacy regression tests."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from test_gws_scuba_projection import (
    CUSTOMER,
    _policy,
    dns_only,
    good_domain,
    load,
    replay,
    write,
)

from auditex.cli import main
from auditex.google_workspace.scuba_projection import project_gws_run
from auditex.reporting import _load_policy_explanations
from auditex.rule_assessment import assess_run
from azure_tenant_audit.scuba_assessment import (
    derive_explainer,
    validate_assessment,
    value_rule_verdict,
)
from azure_tenant_audit.value_rules import gws

pytest_plugins = ("test_gws_scuba_projection",)
SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "schemas/model_assessment.schema.json").read_text())
POLICY = "GWS.GMAIL.4.1v1"
DMARC = "v=DMARC1; p=reject; rua=mailto:reports@example.com"


def test_google_assessment_writes_only_the_public_rule_answer(bundle: Path) -> None:
    dns_only(bundle, good_domain(dmarc={
        "query_name": "_dmarc.example.com", "inherited": False, "records": [DMARC],
    }))
    before = {path: path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
    assert "v=DMARC1" in json.dumps(project_gws_run(bundle)["gws_dns"])
    assert main(["assess", str(bundle), "--policies", POLICY]) == 0
    result = load(bundle, "model_assessment.json")
    assert result["schema_version"] == "2026-11-27"
    assert result["baseline"] == "cisa-scubagoggles-v1.1.0"
    assert result["scope_post_check"] == {"status": "not_applicable"}
    assert result["totals"] == {
        "answered": 1, "unknown": 0, "invalid": 0, "skipped": 0, "rule_answered": 1, "scope_narrowed": 0,
    }
    assert result["projection"]["sections"]["gws_dns"]["status"] == "projected"
    assert set(result["projection"]["sections"]["gws_dns"]) == {"status", "reason", "source"}
    [row] = result["policies"]
    assert row["policy_id"] == POLICY
    assert row["rule_precheck"]["class"] == "value_rule"
    assert row["rule_precheck"]["reason_code"] == "no_domain_violates"
    assert row["claims"] == [
        {"id": "requirement_met", "status": "confirmed", "value": True, "evidence_ids": ["e0", "e1"]},
        {"id": "policy_criticality", "status": "confirmed", "value": "SHALL", "evidence_ids": ["e0"]},
    ]
    assert row["explainer"]["evidence_refs"] == ["e0", "e1"]
    assert row["explainer"] == derive_explainer(row)
    assert _load_policy_explanations(bundle, {"run_id": "synthetic"}) == [
        {"policy_id": POLICY, "verdict": "met", "explainer": row["explainer"]},
    ]
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    jsonschema.validate(result, SCHEMA)
    validate_assessment(result)
    after = {path: path.read_bytes() for path in bundle.rglob("*") if path.is_file()}
    new = after.pop(bundle / "model_assessment.json")
    assert after == before
    for value in ("v=DMARC1", "mailto:", "reports@example.com", CUSTOMER):
        assert value.encode() not in new


@pytest.mark.parametrize("bounds,reason,verdict", [
    pytest.param([], None, "met", id="google-defaults"),
    pytest.param(["--projection-max-items", "40"], "oversize", "not_assessed", id="explicit-items"),
    pytest.param(["--projection-max-chars", "12000"], "oversize", "not_assessed", id="explicit-chars"),
])
def test_assess_cli_budgets_for_300_google_policy_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bounds: list[str], reason: str | None, verdict: str,
) -> None:
    groups = [{"id": f"group{i:03d}", "email": f"group{i:03d}@example.com"} for i in range(299)]
    password = {"minimumLength": 16}
    run = replay(tmp_path, [
        _policy("security.password", password),
        *(_policy("security.password", password, group=group["id"], order=2) for group in groups),
    ], groups=groups)

    assert main(["assess", str(run), *bounds]) == 0
    capsys.readouterr()
    assessment = load(run, "model_assessment.json")
    section = assessment["projection"]["sections"]["gws_policies"]
    assert section["status"] == ("projected" if reason is None else "not_collected")
    assert section["reason"] == reason
    row = next(row for row in assessment["policies"] if row["policy_id"] == "GWS.COMMONCONTROLS.5.3v1")
    assert value_rule_verdict(row) == verdict


@pytest.mark.parametrize("mutation", [
    "missing_baseline", "missing_scope", "section_payload", "unsafe_source", "integer_redaction_flag",
])
def test_google_schema_refuses_invalid_metadata(tmp_path: Path, mutation: str) -> None:
    write(tmp_path, "run-manifest.json", {"run_id": "google", "platform": "google_workspace"})
    result = assess_run(tmp_path, policies=[POLICY])
    if mutation == "missing_baseline":
        del result["baseline"]
    elif mutation == "missing_scope":
        del result["scope_post_check"]
    elif mutation == "integer_redaction_flag":
        result["projection"]["redaction"]["enabled"] = 1
    else:
        dns = result["projection"]["sections"]["gws_dns"]
        if mutation == "section_payload":
            dns["records"] = [DMARC]
        else:
            dns["source"] = ["raw/../private.json"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(result, SCHEMA)
    with pytest.raises(ValueError):
        validate_assessment(result)


def test_gws_row_is_refused_in_an_explicit_m365_baseline(tmp_path: Path) -> None:
    google = tmp_path / "google"
    write(google, "run-manifest.json", {"run_id": "google", "platform": "google_workspace"})
    gws_result = assess_run(google, policies=[POLICY])
    write(tmp_path, "run-manifest.json", {"run_id": "m365"})
    m365 = assess_run(tmp_path, policies=["MS.POWERBI.1.1v1"])
    m365.update(schema_version="2026-11-27", baseline="cisa-scuba-m365-v3.9.1")
    validate_assessment(m365)
    m365["policies"] = gws_result["policies"]
    with pytest.raises(ValueError, match="policy does not match baseline"):
        validate_assessment(m365)


@pytest.mark.parametrize("platform,selection", [
    ("google_workspace", "MS.POWERBI.1.1v1"),
    ("google_workspace", "GWS.GMAIL.4.1v1,MS.POWERBI.1.1v1"),
    ("m365", "GWS.GMAIL.4.1v1"),
    ("m365", "MS.POWERBI.1.1v1,GWS.GMAIL.4.1v1"),
    ("google_workspace", "GWS.GMAIL.4.1v1,GWS.GMAIL.4.1v1"),
])
def test_cli_refuses_foreign_and_duplicate_policy_selections(tmp_path: Path, platform: str, selection: str) -> None:
    write(tmp_path, "run-manifest.json", {"run_id": "sample", "platform": platform})
    assert main(["assess", str(tmp_path), "--policies", selection]) == 2
    assert not (tmp_path / "model_assessment.json").exists()


def test_cli_refuses_an_ambiguous_manifest(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "run-manifest.json").write_text(
        '{"run_id":"sample","platform":"google_workspace","platform":"m365"}')
    assert main(["assess", str(tmp_path)]) == 2
    assert capsys.readouterr().err == "Assessment failed: Run manifest is not valid JSON\n"
    assert not (tmp_path / "model_assessment.json").exists()


def test_unimplemented_rule_is_an_uncovered_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path, "run-manifest.json", {"run_id": "google", "platform": "google_workspace"})
    monkeypatch.setattr(gws, "assess", lambda *_: None)
    result = assess_run(tmp_path, policies=[POLICY])
    [row] = result["policies"]
    assert row["reason"] == "rule_not_implemented"
    assert row["validation_status"] == "unknown"
    assert "rule_precheck" not in row
    assert result["totals"]["rule_answered"] == 0


@pytest.mark.parametrize("contents", ["null", "[]", '"DMARC"', "{"])
def test_malformed_dns_input_abstains(bundle: Path, contents: str) -> None:
    (bundle / "normalized/google_dns_posture.json").write_text(contents)
    [row] = assess_run(bundle, policies=[POLICY])["policies"]
    assert row["rule_precheck"]["cell"] == "section_not_collected"
    assert row["claims"][0] == {
        "id": "requirement_met", "status": "unknown", "value": None, "evidence_ids": ["e0", "e1"],
    }
