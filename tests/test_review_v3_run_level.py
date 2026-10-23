"""Section-scoped gaps reach the run: manifest, collection gaps, handoff and gate (review v3 defects 2, 3 and 15).

A read whose gap belongs to its own section (the Defender state of each device, the assignments of each Intune
policy, the beta update profile lists) keeps its collector ``ok``, so the rules that read it say ``not_assessed``
themselves. The run used to say nothing: exit code 0, ``coverage_gaps: []``, a passing gate and a clean handoff. These
tests run the whole live path against a scripted Graph client and read what the run, the gate and the handoff report.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from auditex.gate import gate_findings
from auditex.reporting import enterprise_handoff
from azure_tenant_audit.collection_gaps import list_truncations, section_gap_records
from azure_tenant_audit.graph import GraphError

from graph_fakes import COMPLIANCE_POLICY, RING, FakeGraph, devices, intune_lists, load, rule_statuses, run_collectors


def _section_gaps(run_dir: Path) -> dict[tuple[str, str], dict[str, Any]]:
    manifest = load(run_dir, "run-manifest.json")
    return {
        (item["collector"], item["section"]): item
        for gap in manifest["coverage_gaps"]
        for item in gap.get("section_gaps", [])
    }


def _assert_named_everywhere(run_dir: Path, section: tuple[str, str], *, collector_status: str = "ok") -> None:
    """The gap is a section gap in the manifest, collection_gaps.json, the handoff and the gate, and the run stays ok."""
    collector, name = section
    manifest = load(run_dir, "run-manifest.json")
    assert manifest["overall_status"] == "ok"
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir, "normalized/coverage_ledger.json")["records"]}
    assert ledger[collector].startswith("complete"), "a section-scoped gap must not make its collector partial"

    gaps = _section_gaps(run_dir)
    assert section in gaps, sorted(gaps)
    gap = next(item for item in manifest["coverage_gaps"] if section in {(g["collector"], g["section"]) for g in item["section_gaps"]})
    assert gap["status"] == "partial" and gap["scope"] == "section" and name in gap["message"]
    assert any(item["status"] == "partial" for item in manifest["surface_coverage"])

    records = {record["source"]: record for record in load(run_dir, "normalized/collection_gaps.json")["records"]}
    assert f"{collector}.{name}" in records and records[f"{collector}.{name}"]["section_scoped"] is True

    handoff = enterprise_handoff(run_dir)
    assert handoff["handoff_status"] == "ready_with_limitations"
    assert any(name in str(limitation.get("message")) for limitation in handoff["limitations"])

    result = gate_findings(run_dir=str(run_dir), fail_on="critical")
    assert result["status"] == "pass", result.get("reason")
    assert any(f"{collector}.{name}" in warning for warning in result["warnings"]), result["warnings"]
    assert {(item["collector"], item["section"]) for item in result["coverage"]["section_gaps"]} >= {section}
    assert load(run_dir, "validation.json")["valid"] is True


def test_a_defender_state_read_for_100_of_150_devices_is_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lists, objects = intune_lists(devices(150))

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "windowsProtectionStates"))
    gap = _section_gaps(run_dir)[("intune", "windowsProtectionStates")]
    assert gap["reason"] == "fanout_limit" and gap["rows_collected"] == 100 and gap["fanout_total"] == 150
    statuses = rule_statuses(run_dir)
    assert statuses["intune.defender_av_off"] == {("not_assessed", "defender_state_truncated")}


def test_refused_beta_update_profile_lists_are_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lists, objects = intune_lists(devices(5), configs=())
    fake = FakeGraph(
        lists=lists,
        objects=objects,
        errors={
            "beta:/deviceManagement/windowsQualityUpdateProfiles": (403, "Forbidden"),
            "beta:/deviceManagement/windowsFeatureUpdateProfiles": (403, "Forbidden"),
        },
    )

    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "intune,intune_depth")

    assert rc == 0
    for section in ("windowsQualityUpdateProfiles", "windowsFeatureUpdateProfiles"):
        _assert_named_everywhere(run_dir, ("intune_depth", section))
        gap = _section_gaps(run_dir)[("intune_depth", section)]
        assert gap["status"] == "failed" and gap["reason"] == "read_failed" and gap["error_classes"]
    assert rule_statuses(run_dir)["intune_depth.update_ring_not_assigned"] == {("not_assessed", "update_profiles_blocked")}


def test_a_refused_compliance_assignment_read_is_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    lists, objects = intune_lists(devices(5))
    fake = FakeGraph(
        lists=lists,
        objects=objects,
        batch_errors={"/deviceManagement/deviceCompliancePolicies/cp-1/assignments": (403, "Forbidden")},
    )

    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "deviceCompliancePolicyAssignments"))
    assert _section_gaps(run_dir)[("intune", "deviceCompliancePolicyAssignments")]["status"] == "failed"
    assert rule_statuses(run_dir)["intune.compliance_policy_missing_platform"] == {
        ("not_assessed", "policy_assignments_not_read_for_every_policy")
    }


def test_a_refused_windows_protection_state_on_every_device_is_named_by_the_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    lists, objects = intune_lists(devices(5))
    fake = FakeGraph(
        lists=lists,
        objects=objects,
        batch_errors={f"/deviceManagement/managedDevices/dev-Windows-{index}/windowsProtectionState": (403, "Forbidden") for index in range(5)},
    )

    rc, run_dir = run_collectors(monkeypatch, tmp_path, fake, "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "windowsProtectionStates"))
    assert _section_gaps(run_dir)[("intune", "windowsProtectionStates")]["status"] == "failed"
    assert {status for status, _reason in rule_statuses(run_dir)["intune.defender_av_off"]} == {"not_assessed"}


def test_111_compliance_policies_cut_at_100_are_named_by_the_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ios = [{**COMPLIANCE_POLICY, "id": f"cp-{index}", "@odata.type": "#microsoft.graph.iosCompliancePolicy"} for index in range(110)]
    windows = {**COMPLIANCE_POLICY, "id": "cp-win"}
    lists, objects = intune_lists(devices(5), compliance=(*ios, windows))
    for index in range(110):
        lists[f"/deviceManagement/deviceCompliancePolicies/cp-{index}/assignments"] = []

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    _assert_named_everywhere(run_dir, ("intune", "deviceCompliancePolicyAssignments"))
    gap = _section_gaps(run_dir)[("intune", "deviceCompliancePolicyAssignments")]
    assert gap["reason"] == "fanout_limit" and gap["fanout_total"] == 111


class _PageFails(FakeGraph):
    def iter_pages(self, path: str, params: Any = None):
        for number, page in enumerate(super().iter_pages(path, params), start=1):
            if number == 2 and "windowsQualityUpdateProfiles" in path:
                raise GraphError("Service unavailable", status=503, request=path)
            yield page


def test_a_failed_beta_page_leaves_a_valid_bundle_and_a_named_gap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    quality = [{"id": f"q{index}", "displayName": f"Q{index}"} for index in range(150)]
    lists, objects = intune_lists(devices(3), quality=tuple(quality), configs=())

    rc, run_dir = run_collectors(monkeypatch, tmp_path, _PageFails(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    validation = load(run_dir, "validation.json")
    assert validation["valid"] is True, [issue["code"] for issue in validation["issues"]]
    rows = {row["name"]: row for row in load(run_dir, "coverage.json")}
    assert rows["windowsQualityUpdateProfiles"]["section_scoped"] is True
    # The row still says how it was cut; it is a section gap, never a truncation of the collector.
    assert rows["windowsQualityUpdateProfiles"]["truncation_reason"] == "pagination_failed"
    assert ("intune_depth", "windowsQualityUpdateProfiles") in _section_gaps(run_dir)
    assert gate_findings(run_dir=str(run_dir), fail_on="critical")["status"] == "pass"


def test_top_cutting_a_beta_update_profile_list_leaves_a_valid_bundle_and_a_named_gap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    quality = tuple({"id": f"q{index}", "displayName": f"Q{index}"} for index in range(5))
    lists, objects = intune_lists(devices(2), quality=quality, configs=())

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune_depth", "--top", "2")

    assert rc == 0
    validation = load(run_dir, "validation.json")
    assert validation["valid"] is True, [issue["code"] for issue in validation["issues"]]
    gap = _section_gaps(run_dir)[("intune_depth", "windowsQualityUpdateProfiles")]
    assert gap["reason"] == "operator_limit" and gap["rows_collected"] == 2
    assert rule_statuses(run_dir)["intune_depth.update_ring_not_assigned"] == {("not_assessed", "update_profiles_truncated")}


def test_list_truncations_leave_out_a_section_scoped_row_and_section_gaps_name_it() -> None:
    rows = [
        {"collector": "c", "name": "whole", "status": "partial", "collection_truncated": True, "truncation_reason": "operator_limit", "result_limit": 5},
        {
            "collector": "c", "name": "scoped", "status": "partial", "collection_truncated": True,
            "truncation_reason": "operator_limit", "result_limit": 5, "section_scoped": True, "error_class": "collection_limit",
            "item_count": 5,
        },
        {"collector": "c", "name": "scopedFanout", "type": "derived", "status": "partial", "section_scoped": True, "fanout_total": 9, "rows_collected": 3},
        {"collector": "c", "name": "fine", "status": "ok", "section_scoped": True},
    ]

    assert [item["list"] for item in list_truncations(rows)] == ["whole"]
    records = section_gap_records(rows)
    assert [(item["collector"], item["section"], item["status"]) for item in records] == [("c", "scoped", "partial")]
    assert records[0]["reason"] == "operator_limit" and records[0]["fanout_total"] == 9 and records[0]["rows_collected"] == 5


def test_the_validator_warns_when_the_manifest_does_not_name_a_section_gap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import json

    from azure_tenant_audit.contracts import build_validation_report

    lists, objects = intune_lists(devices(150))
    _rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")
    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for gap in manifest["coverage_gaps"]:
        gap.pop("section_gaps", None)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir, read_only=True)

    warnings = [issue for issue in report["issues"] if issue["code"] == "section_gap_not_recorded"]
    assert warnings and warnings[0]["severity"] == "warning"
    assert warnings[0]["details"][0]["section"] == "windowsProtectionStates"


def test_a_tenant_with_more_than_ten_profiles_keeps_its_update_ring_rules(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The 10-profile assignment fan-out is a section gap: it must not make intune_depth, and the ring rules, not assessed."""
    profiles = tuple({"id": f"cfg-{index}", "displayName": f"Profile {index}", "@odata.type": "#microsoft.graph.windows10GeneralConfiguration"} for index in range(12))
    lists, objects = intune_lists(devices(5), configs=(RING, *profiles))

    rc, run_dir = run_collectors(monkeypatch, tmp_path, FakeGraph(lists=lists, objects=objects), "intune,intune_depth")

    assert rc == 0
    ledger = {row["collector"]: row["coverage_status"] for row in load(run_dir, "normalized/coverage_ledger.json")["records"]}
    assert ledger["intune_depth"].startswith("complete")
    statuses = rule_statuses(run_dir)
    for rule in ("intune_depth.update_ring_not_assigned", "intune_depth.update_ring_deferral_excessive"):
        assert statuses[rule] == {("pass", "")}, (rule, statuses[rule])
    # The unassigned-policy rule still reports that it saw a sample of the profiles.
    assert all(status == "not_assessed" for status, _reason in statuses["intune_depth.policies_without_assignments"])
    gap = _section_gaps(run_dir)[("intune_depth", "deviceConfigurationAssignments")]
    assert gap["reason"] == "fanout_limit"
