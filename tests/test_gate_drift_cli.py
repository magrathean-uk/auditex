from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from gate_support import SAMPLE_COLLECTORS, finding, offline_run, read_json, set_coverage, write_findings


def _gate(args: list[str]) -> tuple[int, str]:
    from auditex.cli import main

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = main(args)
    return rc, buffer.getvalue()


def _drift(baseline: Path, current: Path, *extra: str) -> tuple[int, dict]:
    rc, output = _gate(
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high", *extra]
    )
    return rc, json.loads(output)


@pytest.fixture
def baseline_and_current(tmp_path: Path) -> tuple[Path, Path]:
    baseline = offline_run(tmp_path / "baseline", "baseline")
    current = offline_run(tmp_path / "current", "current")
    return baseline, current


def _complete_except(**overrides: str) -> dict[str, str]:
    return {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS} | overrides


def test_gate_drift_passes_when_no_new_findings(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    findings = [finding("f1", "high")]
    write_findings(baseline, findings)
    write_findings(current, findings)

    rc, payload = _drift(baseline, current)

    assert rc == 0
    assert payload["pass"] is True
    assert payload["status"] == "pass"
    assert payload["new_count_at_or_above_threshold"] == 0
    assert payload["collector_parity"]["lost"] == []


def test_gate_drift_fails_when_new_high_finding_appears(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [])
    write_findings(current, [finding("f1", "high"), finding("f2", "low")])

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["pass"] is False
    assert payload["status"] == "fail"
    assert payload["new_count_at_or_above_threshold"] == 1
    assert payload["new"][0]["id"] == "f1"


def test_gate_drift_classifies_resolved_findings(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [finding("f1", "high"), finding("f2", "medium")])
    write_findings(current, [finding("f2", "medium"), finding("f3", "low")])

    rc, payload = _drift(baseline, current)

    assert payload["resolved_count"] == 1
    assert payload["new_count"] == 1
    assert payload["persisting_count"] == 1
    assert payload["not_reassessed_count"] == 0
    assert payload["resolved"][0]["id"] == "f1"
    assert rc == 0  # only a low-severity new finding, threshold is high


def test_gate_drift_fails_when_accepted_risk_reopens_above_threshold(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    waiver = {"owner": "ciso", "reason": "temporary", "expires_on": "2099-01-01", "comment": "Temporary exception"}
    write_findings(baseline, [finding("f1", "high", status="accepted_risk", waiver=waiver)])
    write_findings(current, [finding("f1", "high")])

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["pass"] is False
    assert payload["reactivated_count_at_or_above_threshold"] == 1
    assert payload["reactivated_at_or_above_threshold"][0]["id"] == "f1"
    assert payload["state_transitions"][0]["from_status"] == "accepted_risk"
    assert payload["state_transitions"][0]["to_status"] == "open"


def test_gate_drift_fails_when_current_accepted_risk_is_stale(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [])
    waiver = {"owner": "ciso", "reason": "old", "expires_on": "2020-01-01", "comment": "Old exception"}
    write_findings(current, [finding("f1", "critical", status="accepted_risk", waiver=waiver)])

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["pass"] is False
    assert payload["stale_accepted_risk_count_at_or_above_threshold"] == 1
    assert payload["stale_accepted_risks_at_or_above_threshold"][0]["id"] == "f1"
    assert payload["accepted_risk_summary"]["stale_count"] == 1


def test_gate_drift_reports_a_new_accepted_finding_without_failing(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    waiver = {"owner": "ciso", "reason": "approved", "expires_on": "2999-01-01"}
    write_findings(baseline, [])
    write_findings(current, [finding("f1", "critical", status="accepted_risk", waiver=waiver)])

    rc, payload = _drift(baseline, current)

    assert rc == 0
    assert payload["new_count"] == 1
    assert payload["new_count_at_or_above_threshold"] == 0
    assert payload["new_accepted_count"] == 1
    assert payload["new_accepted"][0]["id"] == "f1"


def test_gate_drift_warns_about_accepted_risk_without_accountability(
    baseline_and_current: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [])
    write_findings(current, [finding("f1", "high", status="accepted_risk", waiver={"rule_id": "rule.f1"})])

    rc, payload = _drift(baseline, current)

    assert rc == 0
    assert payload["warnings"] == ["accepted risk f1 has no owner, reason, expires_on"]
    assert "warning: accepted risk f1 has no owner, reason, expires_on" in capsys.readouterr().err


# ---- coverage loss is not remediation -----------------------------------------------------------------


def test_gate_drift_blocks_when_the_current_run_lost_a_collector(
    baseline_and_current: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [finding("f1", "critical", collector="teams")])
    write_findings(current, [])
    set_coverage(current, _complete_except(teams="blocked_permission"), overall_status="partial")

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["status"] == "blocked"
    assert payload["code"] == "incomplete_coverage"
    assert "blocked (incomplete_coverage)" in capsys.readouterr().err


def test_gate_drift_reports_not_reassessed_not_resolved_when_partial_is_allowed(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [finding("f1", "critical", collector="teams"), finding("f2", "high", collector="identity")])
    write_findings(current, [])
    set_coverage(current, _complete_except(teams="blocked_permission"), overall_status="partial")

    rc, payload = _drift(baseline, current, "--allow-partial")

    assert rc == 0
    assert [row["id"] for row in payload["resolved"]] == ["f2"]
    assert payload["resolved_count"] == 1
    assert payload["not_reassessed_count"] == 1
    assert payload["not_reassessed"][0]["id"] == "f1"
    assert payload["not_reassessed"][0]["reason"] == "collector_blocked_permission"
    assert payload["collector_parity"]["lost"] == ["teams"]
    assert any("lost: teams" in warning for warning in payload["warnings"])


def test_gate_drift_blocks_when_the_current_run_did_not_run_a_baseline_collector(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [finding("f1", "critical", collector="teams")])
    write_findings(current, [])
    set_coverage(current, {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS if name != "teams"})

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["status"] == "blocked"
    assert payload["code"] == "collector_parity_lost"
    assert payload["collector_parity"]["lost"] == ["teams"]


def test_gate_drift_marks_a_collector_that_was_not_run_as_not_reassessed(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [finding("f1", "critical", collector="teams")])
    write_findings(current, [])
    set_coverage(current, {name: "complete_exact_scope" for name in SAMPLE_COLLECTORS if name != "teams"})

    rc, payload = _drift(baseline, current, "--allow-partial")

    assert rc == 0
    assert payload["resolved_count"] == 0
    assert payload["not_reassessed"][0]["reason"] == "collector_not_run"


def test_gate_drift_does_not_resolve_a_finding_whose_collector_is_unknown(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    unattributed = finding("f1", "high")
    unattributed.pop("collector")
    write_findings(baseline, [unattributed])
    write_findings(current, [])

    rc, payload = _drift(baseline, current)

    assert rc == 0
    assert payload["resolved_count"] == 0
    assert payload["not_reassessed"][0]["reason"] == "collector_unknown"


def test_gate_drift_still_blocks_when_no_current_collector_completed(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    set_coverage(current, {name: "failed_runtime" for name in SAMPLE_COLLECTORS}, overall_status="partial")

    rc, payload = _drift(baseline, current, "--allow-partial")

    assert rc == 2
    assert payload["code"] == "no_completed_collectors"


def test_gate_drift_passes_new_collectors_without_flagging_parity(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    set_coverage(baseline, {"identity": "complete_exact_scope"})
    set_coverage(current, _complete_except())

    rc, payload = _drift(baseline, current)

    assert rc == 0
    assert payload["collector_parity"]["lost"] == []
    assert payload["collector_parity"]["gained"] == ["intune", "security", "teams"]


# ---- fail closed on missing, empty, unreadable or invalid input -------------------------------------


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_gate_drift_blocks_on_a_missing_run(
    baseline_and_current: tuple[Path, Path], tmp_path: Path, side: str
) -> None:
    baseline, current = baseline_and_current
    missing = tmp_path / "missing"
    rc, payload = _drift(missing if side == "baseline" else baseline, missing if side == "current" else current)

    assert rc == 2
    assert payload["status"] == "blocked"
    assert payload["code"] == "run_dir_missing"
    assert side in payload["reason"]


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_gate_drift_blocks_on_an_empty_run_directory(
    baseline_and_current: tuple[Path, Path], tmp_path: Path, side: str
) -> None:
    baseline, current = baseline_and_current
    empty = tmp_path / "empty"
    empty.mkdir()

    rc, payload = _drift(empty if side == "baseline" else baseline, empty if side == "current" else current)

    assert rc == 2
    assert payload["code"] == "missing_manifest"


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_gate_drift_blocks_on_an_invalid_contract(baseline_and_current: tuple[Path, Path], side: str) -> None:
    baseline, current = baseline_and_current
    broken = finding("f1", "low")
    broken["evidence_refs"] = []
    write_findings(baseline if side == "baseline" else current, [broken])

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["code"] == "contract_invalid"
    assert side in payload["reason"]


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_gate_drift_blocks_on_an_unreadable_findings_file(baseline_and_current: tuple[Path, Path], side: str) -> None:
    baseline, current = baseline_and_current
    target = baseline if side == "baseline" else current
    (target / "findings").mkdir(exist_ok=True)
    (target / "findings" / "findings.json").write_text("", encoding="utf-8")

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["code"] == "unreadable_findings"


def test_gate_drift_blocks_on_a_tenant_mismatch(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    manifest = read_json(current / "run-manifest.json")
    manifest["tenant_name"] = "someone-else"
    (current / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["status"] == "blocked"
    assert payload["code"] == "tenant_guard"


def _mfa_finding() -> dict:
    # The finding's own collector is auth_methods; the rule also reads role assignments from identity.
    return finding(
        "identity:global_admin_mfa_not_registered:u1",
        "critical",
        rule_id="identity.global_admin_mfa_not_registered",
        collector="auth_methods",
    )


def test_gate_drift_does_not_resolve_a_finding_when_another_collector_its_rule_reads_was_blocked(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [_mfa_finding()])
    write_findings(current, [])
    set_coverage(baseline, {"auth_methods": "complete_exact_scope", "identity": "complete_exact_scope"})
    set_coverage(current, {"auth_methods": "complete_exact_scope", "identity": "blocked_permission"}, overall_status="partial")

    rc, payload = _drift(baseline, current, "--allow-partial")

    assert rc == 0
    assert payload["resolved_count"] == 0
    assert [row["id"] for row in payload["not_reassessed"]] == ["identity:global_admin_mfa_not_registered:u1"]
    assert payload["not_reassessed"][0]["reason"] == "rule_collector_blocked_permission:identity"


def test_gate_drift_resolves_the_same_finding_when_every_collector_its_rule_reads_completed(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [_mfa_finding()])
    write_findings(current, [])
    both = {"auth_methods": "complete_exact_scope", "identity": "complete_exact_scope"}
    set_coverage(baseline, both)
    set_coverage(current, both)

    rc, payload = _drift(baseline, current)

    assert rc == 0
    assert payload["resolved_count"] == 1
    assert payload["not_reassessed"] == []


def test_gate_drift_reports_a_rule_collector_that_was_not_run_at_all(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    write_findings(baseline, [_mfa_finding()])
    write_findings(current, [])
    set_coverage(baseline, {"auth_methods": "complete_exact_scope", "identity": "complete_exact_scope"})
    set_coverage(current, {"auth_methods": "complete_exact_scope"})

    rc, payload = _drift(baseline, current, "--allow-partial")

    assert rc == 0
    assert payload["not_reassessed"][0]["reason"] == "rule_collector_not_run:identity"
