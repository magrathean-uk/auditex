from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_findings(run_dir: Path, findings: list[dict[str, object]]) -> None:
    findings_path = run_dir / "findings" / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    findings_path.write_text(json.dumps(findings), encoding="utf-8")
    report_path = run_dir / "reports" / "report-pack.json"
    if report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["findings"] = findings
        report_path.write_text(json.dumps(report), encoding="utf-8")


def _gate(args: list[str]) -> tuple[int, str]:
    from auditex.cli import main

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = main(args)
    return rc, buffer.getvalue()


@pytest.fixture
def baseline_and_current(tmp_path: Path) -> tuple[Path, Path]:
    from azure_tenant_audit.cli import run_offline

    baseline_root = tmp_path / "baseline"
    current_root = tmp_path / "current"
    for root, label in ((baseline_root, "baseline"), (current_root, "current")):
        rc = run_offline(
            REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
            root,
            "contoso",
            label,
            auditor_profile="global-reader",
            plane="inventory",
        )
        assert rc == 0
    return baseline_root / "contoso-baseline", current_root / "contoso-current"


def test_gate_drift_passes_when_no_new_findings(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    findings = [{"id": "f1", "rule_id": "x", "severity": "high", "title": "Same", "status": "open"}]
    _write_findings(baseline, findings)
    _write_findings(current, findings)

    rc, output = _gate(
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"]
    )
    assert rc == 0
    payload = json.loads(output)
    assert payload["pass"] is True
    assert payload["new_count_at_or_above_threshold"] == 0


def test_gate_drift_fails_when_new_high_finding_appears(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    _write_findings(baseline, [])
    _write_findings(
        current,
        [
            {"id": "f1", "rule_id": "x", "severity": "high", "title": "New", "status": "open"},
            {"id": "f2", "rule_id": "y", "severity": "low", "title": "Low", "status": "open"},
        ],
    )

    rc, output = _gate(
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"]
    )
    assert rc == 2
    payload = json.loads(output)
    assert payload["pass"] is False
    assert payload["new_count_at_or_above_threshold"] == 1
    assert payload["new"][0]["id"] == "f1"


def test_gate_drift_classifies_resolved_findings(baseline_and_current: tuple[Path, Path]) -> None:
    baseline, current = baseline_and_current
    _write_findings(
        baseline,
        [
            {"id": "f1", "rule_id": "x", "severity": "high", "title": "Old", "status": "open"},
            {"id": "f2", "rule_id": "y", "severity": "medium", "title": "Stay", "status": "open"},
        ],
    )
    _write_findings(
        current,
        [
            {"id": "f2", "rule_id": "y", "severity": "medium", "title": "Stay", "status": "open"},
            {"id": "f3", "rule_id": "z", "severity": "low", "title": "Newish", "status": "open"},
        ],
    )

    rc, output = _gate(
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"]
    )
    payload = json.loads(output)
    assert payload["resolved_count"] == 1
    assert payload["new_count"] == 1
    assert payload["persisting_count"] == 1
    assert payload["resolved"][0]["id"] == "f1"
    assert rc == 0  # only low-sev new finding, threshold is high


def test_gate_drift_fails_when_accepted_risk_reopens_above_threshold(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    _write_findings(
        baseline,
        [
            {
                "id": "f1",
                "rule_id": "x",
                "severity": "high",
                "title": "Known issue",
                "status": "accepted_risk",
                "waiver": {"expires_on": "2099-01-01", "comment": "Temporary exception"},
            }
        ],
    )
    _write_findings(
        current,
        [
            {
                "id": "f1",
                "rule_id": "x",
                "severity": "high",
                "title": "Known issue",
                "status": "open",
            }
        ],
    )

    rc, output = _gate(
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"]
    )
    payload = json.loads(output)

    assert rc == 2
    assert payload["pass"] is False
    assert payload["reactivated_count_at_or_above_threshold"] == 1
    assert payload["reactivated_at_or_above_threshold"][0]["id"] == "f1"
    assert payload["state_transitions"][0]["from_status"] == "accepted_risk"
    assert payload["state_transitions"][0]["to_status"] == "open"


def test_gate_drift_fails_when_current_accepted_risk_is_stale(
    baseline_and_current: tuple[Path, Path],
) -> None:
    baseline, current = baseline_and_current
    _write_findings(baseline, [])
    _write_findings(
        current,
        [
            {
                "id": "f1",
                "rule_id": "x",
                "severity": "critical",
                "title": "Accepted but expired",
                "status": "accepted_risk",
                "waiver": {"expires_on": "2020-01-01", "comment": "Old exception"},
            }
        ],
    )

    rc, output = _gate(
        ["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", "high"]
    )
    payload = json.loads(output)

    assert rc == 2
    assert payload["pass"] is False
    assert payload["stale_accepted_risk_count_at_or_above_threshold"] == 1
    assert payload["stale_accepted_risks_at_or_above_threshold"][0]["id"] == "f1"
    assert payload["accepted_risk_summary"]["stale_count"] == 1
