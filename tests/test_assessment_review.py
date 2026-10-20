from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from auditex.assessment_review import compare_external_assessments
from auditex import mcp_server


TENANT = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT = "22222222-2222-4222-8222-222222222222"
CONTROL = "MS.AAD.3.1v1"


def _check(check_id: str, status: str = "pass", control: str | None = CONTROL, **overrides) -> dict:
    return {
        "id": check_id,
        "title": "Authentication posture",
        "status": status,
        "severity": "high",
        "control_ids": [control] if control else [],
        "resource_ids": [],
        "evidence_refs": [],
        **overrides,
    }


def _assessment(tmp_path: Path, source: str, checks: list[dict], **overrides) -> Path:
    digest = sha256(source.encode()).hexdigest()
    for index, check in enumerate(checks):
        if not check["evidence_refs"]:
            check["evidence_refs"] = [{"source": source, "input_sha256": digest, "json_pointer": f"/Results/{index}"}]
    payload = {
        "schema_version": "2026-10-18",
        "source": source,
        "source_version": "1.0",
        "tenant_id": TENANT,
        "assessed_at": "2026-10-18T10:00:00Z",
        "provenance": {"input_sha256": digest, "input_name": f"{source}.json", "identity_source": "source"},
        "checks": checks,
        **overrides,
    }
    path = tmp_path / f"{source}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_compare_preserves_original_and_canonical_evidence_without_writing(tmp_path: Path) -> None:
    left = _assessment(tmp_path, "maester", [_check("MT.1"), _check("MT.2", "fail", "MS.AAD.3.2v1")])
    right = _assessment(tmp_path, "scubagear", [_check("SC.1"), _check("SC.2", "pass", "MS.AAD.3.2v1")])
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}

    result = compare_external_assessments([left, right], expected_tenant_id=TENANT)

    assert result["summary"] == {
        "assessment_count": 2, "shared_control_count": 2,
        "agreement_pair_count": 1, "disagreement_pair_count": 1, "coverage_gap_count": 0,
    }
    assert result["agreements"][0]["left_check_ids"] == ["MT.1"]
    assert result["disagreements"][0]["right_check_ids"] == ["SC.2"]
    support = result["controls"][0]["assessments"][0]["checks"][0]
    assert support["evidence_refs"][0]["json_pointer"] == "/Results/0"
    assert support["canonical_ref"] == {
        "artifact_path": str(left), "input_sha256": sha256(left.read_bytes()).hexdigest(), "json_pointer": "/checks/0",
    }
    assert result["read_only"] is True
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("status", ["unknown", "error", "not_applicable"])
def test_nondecisive_results_are_never_agreement_or_disagreement(tmp_path: Path, status: str) -> None:
    paths = [
        _assessment(tmp_path, "maester", [_check("MT.1", status)]),
        _assessment(tmp_path, "scubagear", [_check("SC.1", status)]),
    ]
    result = compare_external_assessments(paths)
    assert result["agreements"] == []
    assert result["disagreements"] == []
    assert result["coverage_gaps"][0]["reason"] == "nondecisive_or_mixed_status"


def test_mixed_pass_and_unknown_does_not_collapse_to_pass(tmp_path: Path) -> None:
    paths = [
        _assessment(tmp_path, "maester", [_check("MT.1"), _check("MT.2", "unknown")]),
        _assessment(tmp_path, "scubagear", [_check("SC.1")]),
    ]
    result = compare_external_assessments(paths)
    assert result["controls"][0]["assessments"][0]["status"] == "mixed"
    assert not result["agreements"]


def test_control_versions_and_titles_are_not_fuzzy_joined(tmp_path: Path) -> None:
    paths = [
        _assessment(tmp_path, "maester", [_check("MT.1", control="CISA.MS.AAD.3.1"), _check("MT.2", control=None)]),
        _assessment(tmp_path, "scubagear", [_check("SC.1")]),
    ]
    result = compare_external_assessments(paths)
    assert not result["controls"]
    assert {gap["reason"] for gap in result["coverage_gaps"]} == {"check_has_no_explicit_control_id", "control_not_shared"}
    assert any("No exact shared" in caveat for caveat in result["caveats"])


@pytest.mark.parametrize("left_resources,right_resources", [(["u1"], ["u2"]), (["u1"], [])])
def test_different_resource_scope_cannot_confirm_agreement(tmp_path: Path, left_resources: list, right_resources: list) -> None:
    paths = [
        _assessment(tmp_path, "maester", [_check("MT.1", resource_ids=left_resources)]),
        _assessment(tmp_path, "scubagear", [_check("SC.1", resource_ids=right_resources)]),
    ]
    result = compare_external_assessments(paths)
    assert not result["agreements"]
    assert result["coverage_gaps"][0]["reason"] == "different_or_unverified_resource_scope"


def test_third_assessment_missing_control_is_explicit(tmp_path: Path) -> None:
    paths = [
        _assessment(tmp_path, "maester", [_check("MT.1")]),
        _assessment(tmp_path, "scubagear", [_check("SC.1")]),
        _assessment(tmp_path, "monkey365", [_check("M.1", control="cis_m365_v7:1.1.3")]),
    ]
    result = compare_external_assessments(paths)
    assert len(result["agreements"]) == 1
    missing = next(gap for gap in result["coverage_gaps"] if gap["reason"] == "control_absent_from_assessments")
    assert missing["assessment_ids"] == ["external:2"]


@pytest.mark.parametrize("other_id,expected", [(OTHER_TENANT, None), (TENANT, OTHER_TENANT), (None, TENANT)])
def test_refuses_cross_tenant_or_missing_identity(tmp_path: Path, other_id: str | None, expected: str | None) -> None:
    paths = [
        _assessment(tmp_path, "maester", [_check("MT.1")]),
        _assessment(tmp_path, "scubagear", [_check("SC.1")], tenant_id=other_id),
    ]
    with pytest.raises(ValueError, match="tenant"):
        compare_external_assessments(paths, expected_tenant_id=expected)


def test_strict_json_and_canonical_validation(tmp_path: Path) -> None:
    left = _assessment(tmp_path, "maester", [_check("MT.1")])
    right = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    payload = json.loads(right.read_text())
    payload["checks"][0]["status"] = "passed-ish"
    right.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        compare_external_assessments([left, right])
    right.write_text('{"source":"scubagear","source":"maester"}')
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        compare_external_assessments([left, right])


def test_duplicate_assessment_is_not_independent_support(tmp_path: Path) -> None:
    path = _assessment(tmp_path, "maester", [_check("MT.1")])
    with pytest.raises(ValueError, match="Duplicate assessment"):
        compare_external_assessments([path, path])
    copy = tmp_path / "copy.json"
    copy.write_bytes(path.read_bytes())
    with pytest.raises(ValueError, match="Duplicate assessment source hashes"):
        compare_external_assessments([path, copy])


def test_operator_attribution_and_missing_timestamp_are_disclosed(tmp_path: Path) -> None:
    left = _assessment(tmp_path, "maester", [_check("MT.1")], assessed_at=None)
    payload = json.loads(left.read_text())
    payload["provenance"]["identity_source"] = "operator"
    left.write_text(json.dumps(payload))
    right = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    result = compare_external_assessments([left, right])
    assert any("operator" in caveat for caveat in result["caveats"])
    assert any("no collection timestamp" in caveat for caveat in result["caveats"])


def _auditex_bundle(tmp_path: Path) -> Path:
    from azure_tenant_audit.finalize import finalize_bundle_contract
    from test_finalize_idempotent import _prepare_bundle_for_finalize

    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    kwargs["bundle_metadata"]["tenant_id"] = TENANT
    kwargs["run_metadata"]["tenant_id"] = TENANT
    writer.write_raw("identity", {"organization": {"value": [{"id": TENANT}]}})
    pack_path = writer.run_dir / "reports" / "report-pack.json"
    pack = json.loads(pack_path.read_text())
    pack["baseline_alignment"] = {"frameworks": {"cisa_scuba": {"controls": [
        {"control_id": CONTROL, "title": "MFA", "status": "pass", "rule_ids": ["identity.test"], "finding_ids": []},
        {"control_id": "MS.AAD.3.2v1", "title": "MFA alternative", "status": "accepted_risk", "rule_ids": [], "finding_ids": []},
    ]}}}
    writer.write_report_pack(pack)
    finalize_bundle_contract(**kwargs)
    return writer.run_dir


def test_completed_auditex_baselines_compared_without_mutating_bundle(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1"), _check("SC.2", control="MS.AAD.3.2v1")])
    before = {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}

    result = compare_external_assessments([assessment], run_dir=run_dir)

    assert result["summary"]["agreement_pair_count"] == 1
    assert result["summary"]["disagreement_pair_count"] == 0
    assert result["assessments"][1]["source_version"] is None
    assert result["assessments"][1]["schema_contract_version"] == "2026-10-20"
    identity_ref = result["assessments"][1]["provenance"]["identity_ref"]
    assert identity_ref["json_pointer"] == "/tenant_id"
    assert identity_ref["input_sha256"] == sha256((run_dir / "run-manifest.json").read_bytes()).hexdigest()
    accepted = result["controls"][1]["assessments"][1]
    assert accepted["status"] == "unknown"
    assert accepted["checks"][0]["reported_status"] == "accepted_risk"
    assert accepted["checks"][0]["evidence_refs"][0]["json_pointer"] == "/baseline_alignment/frameworks/cisa_scuba/controls/1"
    assert {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()} == before


def test_rejects_invalid_or_cross_tenant_auditex_bundle(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")], tenant_id=OTHER_TENANT)
    with pytest.raises(ValueError, match="different tenant"):
        compare_external_assessments([assessment], run_dir=run_dir)
    (run_dir / "ai_context.json").unlink()
    with pytest.raises(ValueError, match="Incomplete"):
        compare_external_assessments([assessment], run_dir=run_dir)


def test_auditex_tenant_conflict_cannot_fall_back_to_a_display_name(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["tenant_id"] = OTHER_TENANT
    summary_path.write_text(json.dumps(summary))
    with pytest.raises(ValueError, match="Conflicting tenant IDs"):
        compare_external_assessments([assessment], run_dir=run_dir)


@pytest.mark.parametrize("artifact,keys", [
    ("ai_context.json", ("run", "tenant_id")),
    ("reports/report-pack.json", ("tenant_id",)),
    ("reports/report-pack.json", ("summary", "tenant_id")),
])
@pytest.mark.parametrize("identity", [OTHER_TENANT, "tenant-display-name", None])
def test_rejects_conflicting_or_invalid_bundle_metadata_identities_without_writes(
    tmp_path: Path, artifact: str, keys: tuple[str, ...], identity: str | None,
) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    artifact_path = run_dir / artifact
    payload = json.loads(artifact_path.read_text())
    target = payload
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = identity
    artifact_path.write_text(json.dumps(payload))
    before = {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}

    with pytest.raises(ValueError, match="(Conflicting tenant IDs|Invalid tenant ID)"):
        compare_external_assessments([assessment], run_dir=run_dir)

    assert {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()} == before


def test_matching_explicit_report_identity_and_partner_evidence_are_accepted(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    pack_path = run_dir / "reports" / "report-pack.json"
    pack = json.loads(pack_path.read_text())
    pack["tenant_id"] = pack["summary"]["tenant_id"] = TENANT
    pack["public_footprint"] = {"partner_tenant_id": OTHER_TENANT}
    pack_path.write_text(json.dumps(pack))
    before = {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}

    result = compare_external_assessments([assessment], run_dir=run_dir)

    assert result["summary"]["agreement_pair_count"] == 1
    assert {str(path.relative_to(run_dir)): path.read_bytes() for path in run_dir.rglob("*") if path.is_file()} == before


def test_auditex_validation_is_required_and_fresh_mode_identified(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    result = compare_external_assessments([assessment], run_dir=run_dir)
    assert result["assessments"][1]["validation_mode"] == "fresh_read_only"
    assert any("contract validation was rerun" in caveat for caveat in result["caveats"])
    validation_path = run_dir / "validation.json"
    validation = json.loads(validation_path.read_text())
    validation["valid"] = False
    validation_path.write_text(json.dumps(validation))
    with pytest.raises(ValueError, match="completed, valid"):
        compare_external_assessments([assessment], run_dir=run_dir)


def test_stale_valid_marker_does_not_hide_contract_damage(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    context_path = run_dir / "ai_context.json"
    context_path.write_text("{}")
    with pytest.raises(ValueError, match="no longer passes"):
        compare_external_assessments([assessment], run_dir=run_dir)


def test_legacy_bundle_without_baselines_reports_comparison_gap(tmp_path: Path) -> None:
    run_dir = _auditex_bundle(tmp_path / "bundle")
    assessment = _assessment(tmp_path, "scubagear", [_check("SC.1")])
    pack_path = run_dir / "reports" / "report-pack.json"
    pack = json.loads(pack_path.read_text())
    del pack["baseline_alignment"]
    pack_path.write_text(json.dumps(pack))
    result = compare_external_assessments([assessment], run_dir=run_dir)
    assert not result["agreements"] and not result["disagreements"]
    assert any("no baseline_alignment" in caveat for caveat in result["caveats"])
    assert any(gap["reason"] == "assessment_has_no_checks" for gap in result["coverage_gaps"])


def test_mcp_review_helpers_delegate_in_memory(monkeypatch, tmp_path: Path) -> None:
    import auditex.external_assessments as external
    import auditex.assessment_review as review

    calls = []
    monkeypatch.setattr(external, "import_assessment", lambda source, path, tenant_id=None: calls.append((source, path, tenant_id)) or {"normalized": True})
    monkeypatch.setattr(review, "compare_external_assessments", lambda paths, **kwargs: calls.append((paths, kwargs)) or {"compared": True})
    assert mcp_server.normalize_external_assessment("maester", "input.json", TENANT) == {"normalized": True}
    assert mcp_server.compare_external_assessment_files(["normalized.json"], TENANT) == {"compared": True}
    assert calls == [("maester", "input.json", TENANT), (["normalized.json"], {"expected_tenant_id": TENANT, "run_dir": None})]
    assert not list(tmp_path.iterdir())
