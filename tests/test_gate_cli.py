from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from gate_support import (
    SAMPLE_COLLECTORS,
    completed_in_summary,
    finding,
    offline_run,
    read_json,
    set_coverage,
    set_findings_file,
    set_pack_findings,
    write_findings,
)


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    return offline_run(tmp_path)


def _gate(args: list[str]) -> tuple[int, str]:
    from auditex.cli import main

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = main(args)
    return rc, buffer.getvalue()


def _blocked(args: list[str], capsys: pytest.CaptureFixture[str], code: str) -> dict:
    rc, output = _gate(args)
    payload = json.loads(output)
    assert rc == 2
    assert payload["pass"] is False
    assert payload["status"] == "blocked"
    assert payload["code"] == code, payload["reason"]
    assert payload["reason"]
    assert f"blocked ({code})" in capsys.readouterr().err
    return payload


def test_gate_passes_when_no_findings_meet_threshold(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "low"), finding("f2", "medium")])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 0
    payload = json.loads(output)
    assert payload["pass"] is True
    assert payload["status"] == "pass"
    assert payload["fail_on"] == "high"
    assert payload["counts_at_or_above_threshold"] == 0
    assert payload["contract"]["valid"] is True
    assert payload["coverage"]["complete"] is True


def test_gate_fails_when_finding_meets_threshold(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "high")])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 2
    payload = json.loads(output)
    assert payload["pass"] is False
    assert payload["status"] == "fail"
    assert payload["counts_at_or_above_threshold"] == 1
    assert payload["threshold_findings"][0]["id"] == "f1"


def test_gate_critical_threshold_does_not_fail_on_high(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "high"), finding("f2", "high")])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "critical"])

    assert rc == 0
    assert json.loads(output)["pass"] is True


def test_gate_returns_severity_breakdown(run_dir: Path) -> None:
    write_findings(
        run_dir,
        [finding("f1", "critical"), finding("f2", "high"), finding("f3", "medium"), finding("f4", "low")],
    )

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "medium"])

    assert rc == 2
    payload = json.loads(output)
    assert payload["counts_by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 1}
    assert payload["counts_at_or_above_threshold"] == 3


def test_gate_passes_a_clean_run_with_no_findings_file(run_dir: Path) -> None:
    write_findings(run_dir, [], file=False)  # what the writer produces for a run with no findings
    assert not (run_dir / "findings" / "findings.json").exists()

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "low"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["pass"] is True
    assert payload["counts_by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}


@pytest.mark.parametrize("status", ["accepted_risk", "accepted", "waived"])
def test_gate_counts_accepted_findings_without_failing(run_dir: Path, status: str) -> None:
    waiver = {"owner": "ciso", "reason": "approved", "expires_on": "2999-01-01"}
    write_findings(run_dir, [finding("f1", "critical", status=status, waiver=waiver), finding("f2", "low")])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["accepted_count"] == 1
    assert payload["accepted_by_severity"]["critical"] == 1
    assert payload["counts_by_severity"]["critical"] == 0
    assert payload["accepted_risk_summary"]["count"] == 1
    assert payload["warnings"] == []


def test_gate_counts_closed_findings_without_failing(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "critical", status="resolved")])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["closed_count"] == 1


def test_gate_treats_an_unknown_status_as_open(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "critical", status="needs-review")])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    assert rc == 2
    assert json.loads(output)["counts_by_severity"]["critical"] == 1


def test_gate_fails_on_a_stale_accepted_risk_at_the_threshold(run_dir: Path) -> None:
    waiver = {"owner": "ciso", "reason": "approved", "expires_on": "2020-01-01"}
    write_findings(run_dir, [finding("f1", "critical", status="accepted_risk", waiver=waiver)])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    payload = json.loads(output)
    assert rc == 2
    assert payload["status"] == "fail"
    assert payload["stale_accepted_risk_count_at_or_above_threshold"] == 1
    assert payload["threshold_findings"][0]["reason"] == "stale_accepted_risk"


def test_gate_warns_about_accepted_risk_without_owner_reason_or_expiry(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_findings(run_dir, [finding("f1", "high", status="accepted_risk", waiver={"rule_id": "rule.f1"})])

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["warnings"] == ["accepted risk f1 has no owner, reason, expires_on"]
    assert payload["accepted_risk_summary"]["without_owner_count"] == 1
    assert "warning: accepted risk f1 has no owner, reason, expires_on" in capsys.readouterr().err


def test_gate_rejects_an_unknown_threshold(run_dir: Path) -> None:
    from auditex.cli import gate_findings

    with pytest.raises(ValueError, match="unsupported --fail-on"):
        gate_findings(run_dir=str(run_dir), fail_on="bogus")


# ---- fail closed on missing, empty, unreadable or invalid input ------------------------------------


def test_gate_fails_on_a_missing_run_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _blocked(["gate", str(tmp_path / "does-not-exist"), "--fail-on", "low"], capsys, "run_dir_missing")


def test_gate_fails_on_an_empty_run_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()

    _blocked(["gate", str(empty), "--fail-on", "low"], capsys, "missing_manifest")


@pytest.mark.parametrize("content", ["", "not json", "[]", "{}", '"text"'])
def test_gate_fails_on_an_empty_or_unreadable_manifest(
    run_dir: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    (run_dir / "run-manifest.json").write_text(content, encoding="utf-8")

    _blocked(["gate", str(run_dir), "--fail-on", "low"], capsys, "unreadable_manifest")


def test_gate_fails_when_the_contract_was_recorded_invalid(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    validation = read_json(run_dir / "validation.json")
    validation["valid"] = False
    (run_dir / "validation.json").write_text(json.dumps(validation), encoding="utf-8")

    _blocked(["gate", str(run_dir), "--fail-on", "low"], capsys, "contract_invalid")


def test_gate_fails_when_validation_json_is_missing(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (run_dir / "validation.json").unlink()

    _blocked(["gate", str(run_dir), "--fail-on", "low"], capsys, "contract_invalid")


def test_gate_recomputes_the_contract_instead_of_trusting_the_recorded_result(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # validation.json still says valid, but a finding now has no evidence reference.
    broken = finding("f1", "low")
    broken["evidence_refs"] = []
    write_findings(run_dir, [broken])
    assert read_json(run_dir / "validation.json")["valid"] is True

    payload = _blocked(["gate", str(run_dir), "--fail-on", "high"], capsys, "contract_invalid")

    assert payload["contract"]["valid"] is False
    assert "missing_evidence_refs" in payload["contract"]["issue_codes"]


def test_gate_fails_when_a_required_artifact_is_deleted(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (run_dir / "reports" / "report-pack.json").unlink()

    _blocked(["gate", str(run_dir), "--fail-on", "low"], capsys, "contract_invalid")


@pytest.mark.parametrize("content", ["", "not json", "{}", '[1, 2]'])
def test_gate_fails_on_an_empty_or_unreadable_findings_file(
    run_dir: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    (run_dir / "findings").mkdir(exist_ok=True)
    (run_dir / "findings" / "findings.json").write_text(content, encoding="utf-8")

    _blocked(["gate", str(run_dir), "--fail-on", "low"], capsys, "unreadable_findings")


def test_gate_fails_when_the_findings_file_is_missing_but_the_report_pack_has_findings(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_findings(run_dir, [finding("f1", "critical")], file=False)

    _blocked(["gate", str(run_dir), "--fail-on", "high"], capsys, "missing_findings")


def test_gate_fails_when_the_manifest_declares_a_findings_file_that_is_missing(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_findings(run_dir, [], file=False)
    manifest = read_json(run_dir / "run-manifest.json")
    manifest["findings_path"] = "findings/findings.json"
    manifest["findings_count"] = 3
    (run_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    _blocked(["gate", str(run_dir), "--fail-on", "high"], capsys, "missing_findings")


def test_gate_fails_when_the_findings_file_and_report_pack_disagree(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_findings_file(run_dir, [finding("f1", "critical")])
    set_pack_findings(run_dir, [])

    _blocked(["gate", str(run_dir), "--fail-on", "high"], capsys, "findings_inconsistent")


def test_gate_fails_when_a_finding_has_no_id(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    nameless = finding("f1", "critical")
    nameless["id"] = ""
    write_findings(run_dir, [nameless])

    _blocked(["gate", str(run_dir), "--fail-on", "high"], capsys, "unreadable_findings")


def test_gate_fails_when_every_collector_was_blocked_and_no_findings_were_emitted(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_coverage(run_dir, {name: "blocked_permission" for name in SAMPLE_COLLECTORS}, overall_status="partial")

    payload = _blocked(["gate", str(run_dir), "--fail-on", "low"], capsys, "no_completed_collectors")

    assert len(payload["coverage"]["incomplete_collectors"]) == len(SAMPLE_COLLECTORS)


def test_gate_still_fails_with_no_completed_collector_when_partial_is_allowed(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    set_coverage(run_dir, {name: "failed_runtime" for name in SAMPLE_COLLECTORS}, overall_status="partial")

    _blocked(["gate", str(run_dir), "--fail-on", "low", "--allow-partial"], capsys, "no_completed_collectors")


def test_gate_fails_closed_on_partial_coverage_by_default(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    statuses = {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS} | {"teams": "partial_success"}
    set_coverage(run_dir, statuses, overall_status="partial")

    payload = _blocked(["gate", str(run_dir), "--fail-on", "high"], capsys, "incomplete_coverage")

    assert payload["coverage"]["incomplete_collectors"] == [{"collector": "teams", "status": "partial_success"}]
    assert "--allow-partial" in payload["reason"]


def test_gate_does_not_let_an_accepted_collector_issue_hide_a_coverage_gap(
    run_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Accepting the collector.issue finding drops the gap from the risk score; the gate still sees the ledger.
    waiver = {"owner": "ciso", "reason": "known licence gap", "expires_on": "2999-01-01"}
    accepted_issue = finding(
        "teams:issue", "high", rule_id="collector.issue.permission", status="accepted_risk", collector="teams", waiver=waiver
    )
    write_findings(run_dir, [accepted_issue])
    statuses = {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS} | {"teams": "blocked_permission"}
    set_coverage(run_dir, statuses, overall_status="partial")

    payload = _blocked(["gate", str(run_dir), "--fail-on", "critical"], capsys, "incomplete_coverage")

    assert payload["coverage"]["incomplete_collectors"] == [{"collector": "teams", "status": "blocked_permission"}]


def test_gate_allow_partial_passes_but_reports_the_gap(run_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    statuses = {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS} | {"teams": "partial_success"}
    set_coverage(run_dir, statuses, overall_status="partial")

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high", "--allow-partial"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["coverage"]["incomplete_collectors"] == [{"collector": "teams", "status": "partial_success"}]
    assert any("--allow-partial" in warning for warning in payload["warnings"])
    assert "--allow-partial" in capsys.readouterr().err


def test_gate_does_not_treat_a_not_applicable_collector_as_a_gap(run_dir: Path) -> None:
    statuses = {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS} | {"teams": "not_applicable"}
    set_coverage(run_dir, statuses)

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "high"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["coverage"]["not_applicable_collectors"] == ["teams"]


def test_gate_uses_summary_collectors_when_the_bundle_has_no_coverage_ledger(run_dir: Path) -> None:
    (run_dir / "normalized" / "coverage_ledger.json").unlink()
    expected = sorted(completed_in_summary(run_dir))
    assert expected

    rc, output = _gate(["gate", str(run_dir), "--fail-on", "low"])

    payload = json.loads(output)
    assert rc == 0
    assert payload["coverage"]["completed_collectors"] == expected


def test_gate_works_on_a_google_workspace_bundle(tmp_path: Path) -> None:
    from gate_support import REPO_ROOT

    from auditex.cli import main

    out = tmp_path / "google"
    sample = REPO_ROOT / "examples" / "google_workspace_sample.json"
    assert main(["google", "run", "--offline", "--sample", str(sample), "--domain", "example.com",
                 "--tenant-name", "g", "--run-name", "g", "--out", str(out)]) == 0
    google_run = next(out.iterdir())

    rc, output = _gate(["gate", str(google_run), "--fail-on", "critical"])

    payload = json.loads(output)
    assert rc == 0, payload
    assert payload["contract"]["valid"] is True
    assert payload["coverage"]["completed_collectors"]
