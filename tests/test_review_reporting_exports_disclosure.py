"""Deep-review lane reporting-exports-disclosure: SARIF/OSCAL, sections, CSV and report wording."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.reporting import preview_report, render_sarif
from azure_tenant_audit.output_redaction import ensure_pseudonym_key

TENANT_ID = "9a8b7c6d-1111-4222-8333-444455556666"
APP_ID = "11111111-2222-4333-8444-555555555555"
APP_FINDING = {
    "id": f"app_credentials:{APP_ID}:secret_expired",
    "rule_id": "app_credentials.secret_expired",
    "title": "Application secret is expired",
    "severity": "critical",
    "status": "open",
    "category": "application",
    "collector": "app_credentials",
    "affected_objects": [APP_ID],
    "evidence_refs": [
        {"artifact_path": "normalized/users.json", "artifact_kind": "normalized_section", "record_key": f"application_credentials:{APP_ID}"}
    ],
}


def _write_run(run_dir: Path, findings: list[dict[str, Any]], *, tenant_id: str | None = TENANT_ID,
               action_plan: list[dict[str, Any]] | None = None) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"tenant_name": "acme", "run_id": f"run-{run_dir.name}", "overall_status": "ok"}
    if tenant_id:
        manifest["tenant_id"] = tenant_id
    (run_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    for folder in ("reports", "findings", "normalized"):
        (run_dir / folder).mkdir(exist_ok=True)
    pack = {
        "summary": {"tenant_name": "acme", "overall_status": "ok", "finding_count": len(findings)},
        "findings": findings,
        "action_plan": action_plan if action_plan is not None else [],
    }
    (run_dir / "reports" / "report-pack.json").write_text(json.dumps(pack), encoding="utf-8")
    (run_dir / "findings" / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (run_dir / "normalized" / "users.json").write_text(json.dumps({"kind": "users", "records": []}), encoding="utf-8")
    return run_dir


def _sarif_results(run_dir: Path, profile: str = "shareable") -> list[dict[str, Any]]:
    content = preview_report(run_dir=str(run_dir), format_name="sarif", profile=profile)["content"]
    return json.loads(content)["runs"][0]["results"]


def _oscal(run_dir: Path, profile: str = "shareable") -> dict[str, Any]:
    content = preview_report(run_dir=str(run_dir), format_name="oscal", profile=profile)["content"]
    return json.loads(content)["assessment-results"]["results"][0]


# R066 ---------------------------------------------------------------------------------------------------------------

def test_r066_shareable_sarif_fingerprints_are_stable_across_runs_of_one_tenant(tmp_path: Path) -> None:
    runs = [_write_run(tmp_path / name, [dict(APP_FINDING)]) for name in ("run-a", "run-b")]
    for run in runs:
        ensure_pseudonym_key(run)
    first, second = (_sarif_results(run)[0] for run in runs)
    assert first["fingerprints"] == second["fingerprints"]
    assert first["partialFingerprints"] == second["partialFingerprints"]
    # The stable values never carry the raw object id.
    assert APP_ID not in json.dumps(first["fingerprints"]) + json.dumps(first["partialFingerprints"])


def test_r066_shareable_oscal_uuids_are_stable_across_runs_of_one_tenant(tmp_path: Path) -> None:
    runs = [_write_run(tmp_path / name, [dict(APP_FINDING)]) for name in ("run-a", "run-b")]
    for run in runs:
        ensure_pseudonym_key(run)
    first, second = (_oscal(run) for run in runs)
    assert first["observations"][0]["uuid"] == second["observations"][0]["uuid"]
    assert first["findings"][0]["uuid"] == second["findings"][0]["uuid"]
    assert first["observations"][0]["subjects"][0]["subject-uuid"] == second["observations"][0]["subjects"][0]["subject-uuid"]


def test_r066_shareable_fingerprints_differ_between_tenants(tmp_path: Path) -> None:
    run_a = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    run_b = _write_run(tmp_path / "run-b", [dict(APP_FINDING)], tenant_id="0f0e0d0c-aaaa-4bbb-8ccc-dddddddddddd")
    for run in (run_a, run_b):
        ensure_pseudonym_key(run)
    assert _sarif_results(run_a)[0]["fingerprints"] != _sarif_results(run_b)[0]["fingerprints"]


def test_r066_local_sarif_fingerprint_is_unchanged(tmp_path: Path) -> None:
    run = _write_run(tmp_path / "run-a", [dict(APP_FINDING)])
    direct = render_sarif(findings=[dict(APP_FINDING)], summary={}, manifest={})["runs"][0]["results"][0]
    assert _sarif_results(run, profile="local")[0]["fingerprints"] == direct["fingerprints"]


# R125 ---------------------------------------------------------------------------------------------------------------

def _waived(status: str, expires_on: str = "2999-01-01") -> dict[str, Any]:
    return {
        **APP_FINDING,
        "status": status,
        "waiver_applied": True,
        "waiver": {"finding_id": APP_FINDING["id"], "owner": "security", "reason": "Vendor app retired next month",
                   "expires_on": expires_on},
    }


@pytest.mark.parametrize("status", ["accepted_risk", "accepted", "waived"])
def test_r125_sarif_suppresses_accepted_findings(status: str) -> None:
    result = render_sarif(findings=[_waived(status)], summary={}, manifest={})["runs"][0]["results"][0]
    assert result["suppressions"] == [
        {"kind": "external", "status": "accepted", "justification": "Vendor app retired next month"}
    ]


def test_r125_sarif_keeps_an_expired_waiver_open() -> None:
    result = render_sarif(findings=[_waived("accepted_risk", expires_on="2000-01-01")], summary={}, manifest={})
    assert "suppressions" not in result["runs"][0]["results"][0]


@pytest.mark.parametrize("status", ["closed", "resolved"])
def test_r125_sarif_leaves_out_closed_findings(status: str) -> None:
    finding = {**APP_FINDING, "status": status}
    assert render_sarif(findings=[finding], summary={}, manifest={})["runs"][0]["results"] == []


def test_r125_open_finding_has_no_suppression() -> None:
    result = render_sarif(findings=[dict(APP_FINDING)], summary={}, manifest={})["runs"][0]["results"][0]
    assert "suppressions" not in result


def test_r125_oscal_records_the_accepted_status(tmp_path: Path) -> None:
    from auditex.reporting import render_oscal

    finding = render_oscal(findings=[_waived("accepted_risk")], summary={}, manifest={})["assessment-results"]["results"][0]["findings"][0]
    props = {prop["name"]: prop["value"] for prop in finding["props"]}
    assert props["auditex.status"] == "accepted_risk"
    assert "accepted risk" in finding["target"]["status"]["remarks"].lower()
