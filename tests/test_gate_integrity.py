"""The gates verify the hash manifest, honour only waived statuses, and record the thresholds they compared."""
from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from gate_support import (
    SAMPLE_COLLECTORS,
    _update_manifest,
    finding,
    offline_run,
    read_json,
    rehash,
    set_coverage,
    write_findings,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _main(args: list[str]) -> tuple[int, dict[str, Any]]:
    from auditex.cli import main

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = main(args)
    return rc, json.loads(buffer.getvalue())


def _gate(run_dir: Path, fail_on: str = "low") -> tuple[int, dict[str, Any]]:
    return _main(["gate", str(run_dir), "--fail-on", fail_on])


def _drift(baseline: Path, current: Path, fail_on: str = "low") -> tuple[int, dict[str, Any]]:
    return _main(["gate-drift", "--baseline", str(baseline), "--current", str(current), "--fail-on", fail_on])


def _edit_pack(run_dir: Path, edit: Any) -> None:
    """Edit the report pack the way a person would: with no re-hash, so the manifest no longer matches."""
    path = run_dir / "reports" / "report-pack.json"
    pack = read_json(path)
    edit(pack)
    path.write_text(json.dumps(pack), encoding="utf-8")


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    return offline_run(tmp_path)


@pytest.fixture
def pair(tmp_path: Path) -> tuple[Path, Path]:
    return offline_run(tmp_path / "baseline", "baseline"), offline_run(tmp_path / "current", "current")


# ---- hash manifest ---------------------------------------------------------------------------------------


def test_the_gate_blocks_a_report_pack_edited_after_finalization(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "high"), finding("f2", "critical")])
    assert _gate(run_dir)[0] == 2

    def close_everything(pack: dict[str, Any]) -> None:
        for row in pack["findings"]:
            row["status"] = "closed"

    _edit_pack(run_dir, close_everything)
    rc, payload = _gate(run_dir)

    assert rc == 2
    assert payload["status"] == "blocked"
    assert payload["code"] == "bundle_integrity_mismatch"
    assert payload["integrity"]["modified"] == ["reports/report-pack.json"]


def test_the_gate_compares_status_severity_and_rule_not_only_ids(run_dir: Path) -> None:
    write_findings(run_dir, [finding("f1", "critical")])

    def close_everything(pack: dict[str, Any]) -> None:
        for row in pack["findings"]:
            row["status"] = "closed"

    _edit_pack(run_dir, close_everything)
    rehash(run_dir)  # an editor who also re-hashes still disagrees with findings.json

    rc, payload = _gate(run_dir)

    assert rc == 2
    assert payload["code"] == "findings_inconsistent"
    assert payload["disagreeing_findings"] == ["f1"]


def test_gate_drift_blocks_findings_deleted_after_finalization(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [finding("f1", "high")])
    write_findings(current, [finding("f1", "high")])
    (current / "findings" / "findings.json").write_text("[]", encoding="utf-8")
    _edit_pack(current, lambda pack: pack.update(findings=[]))
    manifest = read_json(current / "run-manifest.json")
    manifest["findings_count"] = 0
    (current / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    rc, payload = _drift(baseline, current)

    assert rc == 2
    assert payload["code"] == "bundle_integrity_mismatch"
    assert "current run" in payload["reason"]


def test_the_gate_blocks_a_deleted_artifact_and_names_it(run_dir: Path) -> None:
    (run_dir / "ai_context.json").unlink()

    rc, payload = _gate(run_dir)

    assert rc == 2
    assert payload["status"] == "blocked"


def test_a_verified_run_reports_its_integrity(run_dir: Path) -> None:
    rc, payload = _gate(run_dir)

    assert rc == 0
    assert payload["contract"]["integrity"]["status"] == "verified"
    assert payload["contract"]["integrity"]["checked_count"] > 0


def test_a_current_bundle_without_a_hash_manifest_is_blocked_and_a_legacy_one_is_warned(run_dir: Path) -> None:
    manifest = read_json(run_dir / "run-manifest.json")
    manifest["artifacts"] = [item for item in manifest["artifacts"] if item != "bundle-hashes.json"]
    (run_dir / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (run_dir / "bundle-hashes.json").unlink()

    rc, payload = _gate(run_dir)

    assert rc == 2
    assert payload["code"] == "bundle_integrity_absent"

    legacy = {**manifest, "schema_contract_version": "2026-10-20"}
    (run_dir / "run-manifest.json").write_text(json.dumps(legacy), encoding="utf-8")
    rc, payload = _gate(run_dir)

    assert rc == 0
    assert any("predates the hash manifest" in warning for warning in payload["warnings"])


def test_a_named_output_added_after_finalization_is_a_warning_not_a_block(run_dir: Path) -> None:
    (run_dir / "reports" / "explorer.html").write_text("<html></html>", encoding="utf-8")

    rc, payload = _gate(run_dir)

    assert rc == 0
    assert payload["contract"]["integrity"]["unlisted_count"] == 1
    assert any("added after finalization" in warning for warning in payload["warnings"])


def test_a_file_added_where_the_product_reads_and_a_symlink_both_block_the_gate(run_dir: Path, tmp_path: Path) -> None:
    (run_dir / "reports" / "extra-note.md").write_text("added later", encoding="utf-8")

    rc, payload = _gate(run_dir)

    assert rc == 2
    assert payload["code"] == "bundle_integrity_mismatch"

    (run_dir / "reports" / "extra-note.md").unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (run_dir / "live-readiness.json").symlink_to(outside)

    rc, payload = _gate(run_dir)

    assert rc == 2
    assert payload["code"] == "bundle_integrity_mismatch"


# ---- finding status ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["closed", "resolved"])
def test_a_closed_status_without_a_matching_waiver_counts_as_open(run_dir: Path, status: str) -> None:
    write_findings(run_dir, [finding("f1", "critical", status=status)])

    rc, payload = _gate(run_dir, "high")

    assert rc == 2, "the engine never writes a closed status, so the finding stays open and a critical one fails the gate"
    assert payload["counts_by_severity"]["critical"] == 1
    assert payload["closed_count"] == 0
    assert payload["unbacked_status_count"] == 1
    assert any("without a matching waiver" in warning for warning in payload["warnings"])


@pytest.mark.parametrize("status", ["accepted_risk", "accepted", "waived"])
def test_an_accepted_status_without_a_matching_waiver_blocks_the_gate(run_dir: Path, status: str) -> None:
    write_findings(run_dir, [finding("f1", "critical", status=status)])

    rc, payload = _gate(run_dir, "high")

    assert rc == 2
    assert payload["status"] == "blocked"
    assert payload["code"] == "contract_invalid"
    assert "unwaived_accepted_status" in payload["contract"]["issue_codes"]


def test_a_waiver_for_another_rule_does_not_back_an_accepted_status(run_dir: Path) -> None:
    row = finding("f1", "critical", status="accepted_risk", waiver={"rule_id": "some.other.rule", "owner": "ciso"})
    write_findings(run_dir, [row])

    rc, payload = _gate(run_dir, "high")

    assert rc == 2
    assert payload["code"] == "contract_invalid"
    assert "unwaived_accepted_status" in payload["contract"]["issue_codes"]


def test_the_status_check_is_independent_of_the_recomputed_contract() -> None:
    from auditex.gate import _status_class, _unbacked_status_rows

    waived = finding("f1", "high", status="accepted_risk", waiver={"owner": "ciso"})
    unwaived = finding("f2", "high", status="accepted_risk")
    unwaived.pop("waiver", None)
    closed = finding("f3", "high", status="closed")

    assert [_status_class(row) for row in (waived, unwaived, closed)] == ["accepted", "open", "open"]
    assert [row["id"] for row in _unbacked_status_rows([waived, unwaived, closed])] == ["f2", "f3"]


def test_a_matching_waiver_still_accepts_the_finding(run_dir: Path) -> None:
    waiver = {"owner": "ciso", "reason": "approved", "expires_on": "2999-01-01"}
    write_findings(run_dir, [finding("f1", "critical", status="accepted_risk", waiver=waiver)])

    rc, payload = _gate(run_dir, "high")

    assert rc == 0
    assert payload["accepted_count"] == 1
    assert payload["unbacked_status_count"] == 0


def test_validation_rejects_an_accepted_status_with_no_matching_waiver(run_dir: Path) -> None:
    from azure_tenant_audit.contracts import build_validation_report

    unwaived = finding("f1", "high", status="accepted_risk")
    unwaived.pop("waiver", None)
    bogus = finding("f2", "high", status="needs-review")
    report = build_validation_report(run_dir=run_dir, findings=[unwaived, bogus, finding("f3", "high")], read_only=True)

    issues = {issue["code"]: issue for issue in report["issues"]}
    assert issues["unwaived_accepted_status"]["severity"] == "error"
    assert issues["unwaived_accepted_status"]["details"] == ["f1"]
    assert issues["unknown_finding_status"]["severity"] == "warning"
    assert issues["unknown_finding_status"]["details"]["status"] == "needs-review"


def test_gate_drift_blocks_an_unwaived_accepted_baseline(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [finding("f1", "critical", status="accepted_risk")])
    write_findings(current, [finding("f1", "critical")])

    rc, payload = _drift(baseline, current, "high")

    assert rc == 2
    assert payload["code"] == "contract_invalid"
    assert "baseline run" in payload["reason"]


# ---- thresholds -------------------------------------------------------------------------------------------


def _stale_account(finding_id: str = "identity:stale_enabled_account:u1") -> dict[str, Any]:
    return finding(finding_id, "medium", rule_id="identity.stale_enabled_account", collector="identity")


def test_the_run_manifest_records_the_rule_windows(run_dir: Path) -> None:
    parameters = read_json(run_dir / "run-manifest.json")["rule_parameters"]

    assert parameters["stale_sync_days"] == 14
    assert parameters["stale_guest_days"] == 90
    assert parameters["stale_account_days"] == 90


def test_a_laxer_later_window_does_not_read_as_resolved(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [_stale_account()])
    write_findings(current, [])
    _update_manifest(baseline, rule_parameters={"stale_account_days": 90})
    _update_manifest(current, rule_parameters={"stale_account_days": 365})

    rc, payload = _drift(baseline, current)

    assert payload["resolved_count"] == 0
    assert payload["not_reassessed"][0]["reason"] == "rule_parameters_laxer:stale_account_days"
    assert payload["rule_parameters"]["changed"] == [{"parameter": "stale_account_days", "baseline": 90, "current": 365}]
    assert any("rule parameters differ" in warning for warning in payload["warnings"])


def test_the_same_or_a_stricter_window_still_resolves(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [_stale_account()])
    write_findings(current, [])
    _update_manifest(baseline, rule_parameters={"stale_account_days": 90})
    _update_manifest(current, rule_parameters={"stale_account_days": 30})

    _, payload = _drift(baseline, current)

    assert payload["resolved_count"] == 1
    assert payload["not_reassessed_count"] == 0


def test_an_unrecorded_window_is_not_reassessed(pair: tuple[Path, Path]) -> None:
    baseline, current = pair
    write_findings(baseline, [_stale_account()])
    write_findings(current, [])
    _update_manifest(baseline, rule_parameters=None)

    _, payload = _drift(baseline, current)

    assert payload["resolved_count"] == 0
    assert payload["not_reassessed"][0]["reason"] == "rule_parameters_unrecorded:stale_account_days"


def test_compare_applies_the_same_window_rule(pair: tuple[Path, Path]) -> None:
    from auditex.compare import build_finding_delta

    baseline, current = pair
    write_findings(baseline, [_stale_account()])
    write_findings(current, [])
    _update_manifest(baseline, rule_parameters={"stale_account_days": 90})
    _update_manifest(current, rule_parameters={"stale_account_days": 3650})

    delta = build_finding_delta({"path": str(baseline)}, {"path": str(current)})

    assert delta["resolved"] == []
    assert delta["not_reassessed"][0]["reason"] == "rule_parameters_laxer:stale_account_days"


def test_the_stale_sync_window_is_recorded_from_the_command_line(tmp_path: Path) -> None:
    from azure_tenant_audit.cli import run_offline

    sample = REPO_ROOT / "examples" / "sample_audit_bundle" / "endpoint_posture_result.json"
    assert run_offline(sample, tmp_path, "contoso", "ep", stale_sync_days=3650) in (0, 1)

    assert read_json(tmp_path / "contoso-ep" / "run-manifest.json")["rule_parameters"]["stale_sync_days"] == 3650


# ---- compare ----------------------------------------------------------------------------------------------


def test_compare_does_not_call_findings_resolved_when_a_run_fails_its_hash_manifest(pair: tuple[Path, Path]) -> None:
    from auditex.compare import build_finding_delta, compare_runs, render_compare_markdown

    baseline, current = pair
    write_findings(baseline, [finding("f1", "high")])
    write_findings(current, [finding("f1", "high")])
    (current / "findings" / "findings.json").write_text("[]", encoding="utf-8")
    _edit_pack(current, lambda pack: pack.update(findings=[]))

    delta = build_finding_delta({"path": str(baseline)}, {"path": str(current)})
    assert delta["resolved"] == []
    assert delta["not_reassessed"][0]["reason"] == "run_unverified:current:bundle_integrity_mismatch"
    assert delta["verification"]["current"]["problem"] == "bundle_integrity_mismatch"

    result = compare_runs([baseline, current])
    assert result["baseline_diff"]["status"] == "blocked"
    assert result["baseline_diff"]["reason"].startswith("run_unverified:")
    assert "run_unverified" in render_compare_markdown(result)


def test_compare_marks_a_recorded_invalid_contract(pair: tuple[Path, Path]) -> None:
    from auditex.compare import build_finding_delta

    baseline, current = pair
    write_findings(baseline, [finding("f1", "high")])
    write_findings(current, [])
    validation = read_json(current / "validation.json")
    validation["valid"] = False
    (current / "validation.json").write_text(json.dumps(validation), encoding="utf-8")
    rehash(current)

    delta = build_finding_delta({"path": str(baseline)}, {"path": str(current)})

    assert delta["resolved"] == []
    assert delta["verification"]["current"]["problem"] == "contract_invalid"


# ---- Google reassessment ----------------------------------------------------------------------------------


def _google_run(tmp_path: Path, name: str, *, drop_org_units: bool = False) -> Path:
    from auditex.google_workspace.run import run_google_offline

    sample = json.loads((REPO_ROOT / "examples" / "google_workspace_sample.json").read_text(encoding="utf-8"))
    if drop_org_units:
        sample["google_directory"].pop("orgUnits", None)
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(sample), encoding="utf-8")
    assert run_google_offline(
        sample_path=path, out=tmp_path / "out", tenant_name="acme", run_name=name, domain="example.com", customer_id=None
    ) in (0, 1)
    return tmp_path / "out" / f"acme-{name}"


def test_a_google_finding_is_not_resolved_when_its_inputs_went_unknown(tmp_path: Path) -> None:
    from auditex.compare import build_finding_delta

    before = _google_run(tmp_path, "g1")
    after = _google_run(tmp_path, "g2", drop_org_units=True)
    assert read_json(after / "normalized" / "snapshot.json")["two_step_policy_status"] == "unknown"

    delta = build_finding_delta({"path": str(before)}, {"path": str(after)})

    resolved_rules = {row["rule_id"] for row in delta["resolved"]}
    reasons = {row["rule_id"]: row["reason"] for row in delta["not_reassessed"]}
    assert "google.org_2sv_policy_not_enforced" not in resolved_rules
    assert reasons["google.org_2sv_policy_not_enforced"] == "rule_inputs:two_step_policy_unknown"


def test_google_reassessment_gap_checks_collectors_and_domains() -> None:
    from auditex.compare import google_reassessment_gap

    complete = {"google_directory": {"complete": True, "status": "complete"}, "google_policies": {"complete": True, "status": "complete"}}
    known = {"snapshot": {"two_step_policy_status": "enforcing", "internal_domains_status": "known"}}
    unknown_domains = {"snapshot": {"two_step_policy_status": "enforcing", "internal_domains_status": "unknown"}}

    assert google_reassessment_gap("google.org_2sv_policy_not_enforced", complete, known) is None
    assert google_reassessment_gap("google.org_2sv_policy_not_enforced", {}, known) == "rule_collector_not_run:google_directory"
    partial = {**complete, "google_directory": {"complete": False, "status": "partial_success"}}
    assert google_reassessment_gap("google.user_2sv_not_enforced", partial, known) == "rule_collector_partial_success:google_directory"
    assert google_reassessment_gap("google.drive_external_permission", complete, unknown_domains) == "rule_inputs:internal_domains_unknown"
    assert google_reassessment_gap("google.drive_external_permission", complete, None) == "rule_inputs:internal_domains_not_collected"
    assert google_reassessment_gap("google.stale_user", complete, None) is None


def test_the_google_external_principal_rules_stay_in_step_with_the_findings_module() -> None:
    from auditex.compare import _GOOGLE_EXTERNAL_PRINCIPAL_RULES
    from auditex.google_workspace.findings import _EXTERNAL_PRINCIPAL_RULES

    assert set(_EXTERNAL_PRINCIPAL_RULES) == set(_GOOGLE_EXTERNAL_PRINCIPAL_RULES)


# ---- legacy cut-off ---------------------------------------------------------------------------------------


def test_the_legacy_cut_off_does_not_move_when_the_contract_version_is_bumped(monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import contracts

    manifest_2026_10_22 = {"schema_contract_version": "2026-10-22"}
    manifest_older = {"schema_contract_version": "2026-10-20"}
    assert contracts._is_legacy_bundle(manifest_2026_10_22) is False
    assert contracts._is_legacy_bundle(manifest_older) is True

    monkeypatch.setattr(contracts, "CONTRACT_VERSION", "2026-11-15")

    assert contracts._is_legacy_bundle(manifest_2026_10_22) is False, "an edited 2026-10-22 citation must not read as legacy"
    assert contracts._is_legacy_bundle(manifest_older) is True
    assert contracts._is_legacy_bundle({}) is False
    assert contracts._is_legacy_bundle({"schema_contract_version": None, "run_id": "x"}) is True


def test_an_unresolved_reference_in_a_2026_10_22_bundle_stays_an_error_after_a_contract_bump(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from azure_tenant_audit import contracts

    row = finding("f1", "high")
    row["evidence_refs"][0]["record_key"] = "no-such-key"
    row["evidence_refs"][0].pop("json_pointer", None)
    write_findings(run_dir, [row])
    assert read_json(run_dir / "run-manifest.json")["schema_contract_version"] == "2026-10-22"
    monkeypatch.setattr(contracts, "CONTRACT_VERSION", "2026-11-15")

    report = contracts.build_validation_report(run_dir=run_dir, read_only=True)

    codes = {issue["code"] for issue in report["issues"]}
    assert "legacy_unresolved_ref" not in codes
    assert report["valid"] is False
