"""A resumed run reports on the whole run folder, and a preflight block is a block (review v3 defects 9 to 12).

``--resume-from`` reuses a run folder. It used to evaluate only the collectors selected in the new session, rewrite
findings and blockers only when there were some, and leave the earlier session's normalized sections, blockers and
time window behind, so it could report on half a bundle. These tests resume real (scripted) runs and read what is on disk.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex.gate import gate_findings
from scripted_collectors import (
    Scripted,
    failed_step,
    load,
    ok_row,
    ok_step,
    run_scripted,
    sample,
)

ADMIN_COLLECTORS = ("identity", "identity_governance", "auth_methods", "licensing")


def _admin_registry() -> dict[str, Scripted]:
    fixture = sample("admin_set_result.json")
    return {name: Scripted(name, ok_step(name, fixture[name])) for name in ADMIN_COLLECTORS}


def _run_dir(tmp_path: Path) -> Path:
    return tmp_path / "acme-resume"


def _finding_ids(run_dir: Path) -> set[str]:
    return {str(item["id"]) for item in load(run_dir / "findings" / "findings.json") or []}


def test_a_resume_that_narrows_the_collector_set_still_reports_on_every_finished_collector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registry = _admin_registry()
    assert run_scripted(monkeypatch, tmp_path, registry, ",".join(ADMIN_COLLECTORS), run_name="resume") == 0
    run_dir = _run_dir(tmp_path)
    first_findings = _finding_ids(run_dir)
    assert first_findings, "the sample raises findings"

    rc = run_scripted(monkeypatch, tmp_path, registry, "licensing", "--resume-from", str(run_dir), run_name="resume")

    assert rc == 0
    # Every finished collector is carried, not only the one selected: nothing ran again.
    assert [registry[name].calls for name in ADMIN_COLLECTORS] == [1, 1, 1, 1]
    manifest = load(run_dir / "run-manifest.json")
    assert set(manifest["selected_collectors"]) == set(ADMIN_COLLECTORS)
    assert _finding_ids(run_dir) == first_findings
    pack = load(run_dir / "reports" / "report-pack.json")
    assert {str(item["id"]) for item in pack["findings"]} == first_findings
    assert manifest["findings_count"] == len(first_findings)
    assert (run_dir / "normalized" / "users.json").exists()
    summary = load(run_dir / "summary.json")
    assert {row["name"] for row in summary["collectors"]} == set(ADMIN_COLLECTORS)
    result = gate_findings(run_dir=str(run_dir), fail_on="critical")
    assert result.get("code") not in {"findings_inconsistent", "contract_invalid"}, result


def test_a_resume_drops_the_normalized_sections_of_a_collector_it_no_longer_holds(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    users = {"users": {"value": [{"id": "u1", "displayName": "U One", "userPrincipalName": "u1@x.test", "accountEnabled": True}]},
             "groups": {"error": "503", "error_class": "service_unavailable"}}
    partial_identity = ("partial", [ok_row("identity", "users"), failed_step("identity", "groups")[1][0]], users)
    registry = {"identity": Scripted("identity", partial_identity), "licensing": Scripted("licensing", ok_step("licensing", {"subscribedSkus": {"value": []}}))}
    assert run_scripted(monkeypatch, tmp_path, registry, "identity,licensing", run_name="resume") == 1
    run_dir = _run_dir(tmp_path)
    assert (run_dir / "normalized" / "users.json").exists()

    rc = run_scripted(monkeypatch, tmp_path, registry, "licensing", "--resume-from", str(run_dir), run_name="resume")

    # identity was partial, so it is neither carried nor selected: the run stays partial and holds none of its evidence.
    assert rc == 1
    assert not (run_dir / "normalized" / "users.json").exists()
    assert "normalized/users.json" not in load(run_dir / "run-manifest.json")["artifacts"]
    assert load(run_dir / "run-manifest.json")["overall_status"] == "partial"
    assert registry["identity"].calls == 1, "a collector outside the session is not re-run, it is reported as a gap"


def test_a_collector_that_succeeds_on_resume_removes_its_old_blocker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    licensing = Scripted("licensing", failed_step("licensing", "subscribedSkus"), ok_step("licensing", {"subscribedSkus": {"value": []}}))
    registry = {"licensing": licensing}
    assert run_scripted(monkeypatch, tmp_path, registry, "licensing", run_name="resume") == 1
    run_dir = _run_dir(tmp_path)
    assert [item["collector"] for item in load(run_dir / "blockers" / "blockers.json")] == ["licensing"]
    assert any(item["rule_id"].startswith("collector.issue.") for item in load(run_dir / "findings" / "findings.json"))

    rc = run_scripted(monkeypatch, tmp_path, registry, "licensing", "--resume-from", str(run_dir), run_name="resume")

    assert rc == 0 and licensing.calls == 2
    assert not (run_dir / "blockers" / "blockers.json").exists()
    assert not (run_dir / "diagnostics.json").exists()
    manifest = load(run_dir / "run-manifest.json")
    assert manifest["overall_status"] == "ok"
    assert "blockers_path" not in manifest and not manifest.get("blocker_count")
    assert not (run_dir / "findings" / "findings.json").exists() and "findings_path" not in manifest
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "pass"


def test_a_resume_after_an_interrupted_session_keeps_the_coverage_and_summary_of_the_finished_collector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    identity_payload = {"users": {"value": [{"id": "u1", "displayName": "U", "userPrincipalName": "u@x.test"}]}}
    registry = {
        "identity": Scripted("identity", ok_step("identity", identity_payload)),
        "licensing": Scripted("licensing", KeyboardInterrupt(), ok_step("licensing", {"subscribedSkus": {"value": []}})),
    }
    with pytest.raises(KeyboardInterrupt):
        run_scripted(monkeypatch, tmp_path, registry, "identity,licensing", run_name="resume")
    run_dir = _run_dir(tmp_path)
    assert not (run_dir / "coverage.json").exists(), "an interrupted session never finalised its coverage"

    rc = run_scripted(monkeypatch, tmp_path, registry, "identity,licensing", "--resume-from", str(run_dir), run_name="resume")

    assert rc == 0
    assert registry["identity"].calls == 1 and registry["licensing"].calls == 2
    coverage = load(run_dir / "coverage.json")
    assert {row["collector"] for row in coverage} == {"identity", "licensing"}
    summary = load(run_dir / "summary.json")
    assert sorted(row["name"] for row in summary["collectors"]) == ["identity", "licensing"]
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir / "normalized" / "coverage_ledger.json")["records"]}
    assert ledger["identity"].startswith("complete")


@pytest.mark.parametrize(("resumed_window", "reruns"), [
    (("2026-10-01T00:00:00Z", "2026-10-01T01:00:00Z"), False),
    ((None, None), True),
    (("2026-10-02T00:00:00Z", "2026-10-02T01:00:00Z"), True),
], ids=["same window", "no window", "another window"])
def test_a_resume_under_another_time_window_re_runs_a_windowed_collector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, resumed_window: tuple[str | None, str | None], reruns: bool
) -> None:
    security = Scripted("security", ok_step("security", {"signIns": {"value": []}, "directoryAudits": {"value": []}}), windowed=True)
    identity = Scripted("identity", ok_step("identity", {"users": {"value": []}}))
    registry = {"security": security, "identity": identity}
    window = ("--since", "2026-10-01T00:00:00Z", "--until", "2026-10-01T01:00:00Z")
    assert run_scripted(monkeypatch, tmp_path, registry, "security,identity", *window, run_name="resume") == 0
    run_dir = _run_dir(tmp_path)
    assert load(run_dir / "checkpoints" / "checkpoint-state.json")["collectors"]["security"]["since"] == "2026-10-01T00:00:00Z"

    extra = [item for key, value in zip(("--since", "--until"), resumed_window) if value for item in (key, value)]
    assert run_scripted(monkeypatch, tmp_path, registry, "security,identity", "--resume-from", str(run_dir), *extra, run_name="resume") == 0

    assert security.calls == (2 if reruns else 1)
    assert identity.calls == 1, "a collector that does not read a window is carried whatever the window"
    manifest = load(run_dir / "run-manifest.json")
    assert (manifest["time_window"]["since"], manifest["time_window"]["until"]) == resumed_window
    recorded = load(run_dir / "checkpoints" / "checkpoint-state.json")["collectors"]["security"]
    assert (recorded["since"], recorded["until"]) == resumed_window


def test_a_checkpoint_from_before_windows_were_recorded_is_re_run_only_under_a_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    security = Scripted("security", ok_step("security", {"signIns": {"value": []}}), windowed=True)
    registry = {"security": security}
    assert run_scripted(monkeypatch, tmp_path, registry, "security", run_name="resume") == 0
    run_dir = _run_dir(tmp_path)
    state_path = run_dir / "checkpoints" / "checkpoint-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["collectors"]["security"].pop("since")
    state["collectors"]["security"].pop("until")
    state_path.write_text(json.dumps(state), encoding="utf-8")

    assert run_scripted(monkeypatch, tmp_path, registry, "security", "--resume-from", str(run_dir), run_name="resume") == 0
    assert security.calls == 1, "no window asked for, none recorded: nothing to contradict"
    assert run_scripted(monkeypatch, tmp_path, registry, "security", "--resume-from", str(run_dir), "--since", "2026-10-01T00:00:00Z", run_name="resume") == 0
    assert security.calls == 2


def _blocked_auth_methods() -> Scripted:
    return Scripted("auth_methods", failed_step("auth_methods", "userRegistrationDetails", error_class="insufficient_permissions", error="403 Forbidden"))


def test_a_collector_the_preflight_skipped_as_blocked_is_a_blocked_collector_with_a_blocker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    registry = {"auth_methods": _blocked_auth_methods(), "licensing": Scripted("licensing", ok_step("licensing", {"subscribedSkus": {"value": [{"skuId": "s"}]}}))}

    rc = run_scripted(monkeypatch, tmp_path, registry, "auth_methods,licensing", "--probe-first", run_name="probe")

    run_dir = tmp_path / "acme-probe"
    assert rc == 1
    ledger = {row["collector"]: row for row in load(run_dir / "normalized" / "coverage_ledger.json")["records"]}
    assert ledger["auth_methods"]["coverage_status"] == "blocked_permission", "not not_applicable"
    assert ledger["licensing"]["coverage_status"].startswith("complete")
    blockers = load(run_dir / "blockers" / "blockers.json")
    assert [(item["collector"], item["error_class"]) for item in blockers] == [("auth_methods", "insufficient_permissions")]
    assert "403" in blockers[0]["error"]
    assert [row["name"] for row in load(run_dir / "summary.json")["collectors"] if row["status"] == "skipped"] == ["auth_methods"]
    refused = gate_findings(run_dir=str(run_dir), fail_on="critical")
    assert refused["status"] == "blocked" and refused["code"] == "incomplete_coverage"
    accepted = gate_findings(run_dir=str(run_dir), fail_on="critical", allow_partial=True)
    assert accepted["status"] == "pass"
    assert any("auth_methods=blocked_permission" in warning for warning in accepted["warnings"]), accepted["warnings"]


def test_a_resume_re_probes_a_collector_the_preflight_skipped(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    auth = Scripted(
        "auth_methods",
        failed_step("auth_methods", "userRegistrationDetails", error_class="insufficient_permissions", error="403 Forbidden"),
        ok_step("auth_methods", {"userRegistrationDetails": {"value": [{"id": "u", "isMfaRegistered": True}]}}),
    )
    registry: dict[str, Any] = {"auth_methods": auth}
    assert run_scripted(monkeypatch, tmp_path, registry, "auth_methods", "--probe-first", run_name="probe") == 1
    run_dir = tmp_path / "acme-probe"

    rc = run_scripted(monkeypatch, tmp_path, registry, "auth_methods", "--probe-first", "--resume-from", str(run_dir), run_name="probe")

    assert rc == 0
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir / "normalized" / "coverage_ledger.json")["records"]}
    assert ledger["auth_methods"].startswith("complete")
    assert not (run_dir / "blockers" / "blockers.json").exists()
