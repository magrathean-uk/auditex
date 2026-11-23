"""Review lane compare-bundle-mcp: verified same-tenant drift, row keys and compare classification (R054, R053, R132, R133, R135)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from auditex import compare as compare_module
from auditex.compare import compare_runs, render_compare_markdown
from auditex.mcp_server import diff_runs
from azure_tenant_audit.bundle_integrity import build_bundle_hash_manifest
from azure_tenant_audit.diffing import diff_run_directories

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"
FINDING = {
    "id": "identity:admin_set:unverified",
    "rule_id": "identity.example_check",
    "collector": "identity",
    "severity": "high",
    "status": "open",
    "title": "Administrator set unverified",
}


def _write(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _run(
    root: Path,
    name: str,
    *,
    created_utc: str | None,
    findings: list[dict[str, Any]],
    coverage: dict[str, str],
    tenant_name: str = "acme",
    tenant_id: str | None = TENANT_A,
    rule_parameters: dict[str, Any] | None = None,
) -> Path:
    run_dir = root / name
    manifest: dict[str, Any] = {"tenant_name": tenant_name, "run_id": name, "overall_status": "ok"}
    if rule_parameters is not None:
        manifest["rule_parameters"] = rule_parameters
    if created_utc is not None:
        manifest["created_utc"] = created_utc
    if tenant_id is not None:
        manifest["tenant_id"] = tenant_id
    _write(run_dir / "run-manifest.json", manifest)
    _write(
        run_dir / "normalized" / "coverage_ledger.json",
        {
            "kind": "coverage_ledger",
            "records": [{"collector": name_, "coverage_status": status} for name_, status in coverage.items()],
        },
    )
    _write(run_dir / "reports" / "report-pack.json", {"findings": findings})
    return run_dir


def _pair(tmp_path: Path, *, later_identity: str = "blocked_permission", **later: Any) -> tuple[Path, Path]:
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[FINDING], coverage={"identity": "complete"})
    run_b = _run(
        tmp_path,
        "run-b",
        created_utc="2026-10-02T00:00:00Z",
        findings=[],
        coverage={"identity": later_identity},
        **later,
    )
    return run_a, run_b


# R054 / R015 / R131: verified same-tenant drift


def test_raw_diff_is_not_same_tenant_when_known_tenant_ids_differ(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path, tenant_id=TENANT_B)

    result = diff_run_directories(run_a, run_b)

    assert result["compare_context"]["same_tenant"] is False


def test_raw_diff_does_not_call_a_finding_resolved_when_its_collector_was_blocked(tmp_path: Path) -> None:
    # The engine diff behind `auditex diff` has no compare gates; it still checks the later run's collector coverage.
    run_a, run_b = _pair(tmp_path)

    drift = diff_run_directories(run_a, run_b)["drift_summary"]

    assert drift["resolved_findings"] == []
    assert drift["resolved_count"] == 0
    assert drift["not_reassessed_findings"] == [FINDING["id"]]


def test_raw_diff_resolves_a_finding_its_completed_collector_no_longer_raises(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")

    drift = diff_run_directories(run_a, run_b)["drift_summary"]

    assert drift["resolved_findings"] == [FINDING["id"]]
    assert drift["not_reassessed_findings"] == []


def test_mcp_diff_runs_does_not_call_a_finding_resolved_when_its_collector_was_blocked(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path)

    result = diff_runs(str(run_a), str(run_b))

    drift = result["drift_summary"]
    assert drift["resolved_findings"] == []
    assert drift["not_reassessed_findings"] == [FINDING["id"]]
    assert drift["not_reassessed_count"] == 1


def test_mcp_diff_runs_still_resolves_a_finding_its_completed_collector_no_longer_raises(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")

    result = diff_runs(str(run_a), str(run_b))

    assert result["status"] == "ok"
    assert result["drift_summary"]["resolved_findings"] == [FINDING["id"]]


def test_mcp_diff_runs_blocks_two_tenants_that_share_a_tenant_name(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete", tenant_id=TENANT_B)

    result = diff_runs(str(run_a), str(run_b))

    assert result["status"] == "blocked"
    assert result["reason"] == "tenant_id_mismatch"
    assert "drift_summary" not in result


def test_diff_two_runs_blocks_a_bundle_whose_hash_check_fails(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")
    _write(run_b / "bundle-hashes.json", build_bundle_hash_manifest(run_b))
    _write(run_b / "reports" / "report-pack.json", {"findings": [], "edited": True})

    result = compare_module.diff_two_runs(run_a, run_b)

    assert result["status"] == "blocked"
    assert result["reason"].startswith("run_unverified:current:bundle_integrity_")


def test_compare_json_drift_summary_agrees_with_the_markdown_on_not_reassessed(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path)

    result = compare_runs([run_a, run_b])

    drift = result["baseline_diff"]["drift_summary"]
    assert drift["resolved_findings"] == []
    assert drift["resolved_count"] == 0
    assert drift["not_reassessed_findings"] == [FINDING["id"]]
    assert "Not reassessed findings: 1" in render_compare_markdown(result)


# R053 / R068: diff row keys


def test_diff_reports_a_coverage_ledger_row_that_changed_when_rows_are_keyed_by_collector(tmp_path: Path) -> None:
    coverage = {"identity": "complete", "exchange": "complete"}
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage=coverage)
    run_b = _run(
        tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[],
        coverage={**coverage, "identity": "blocked_permission"},
    )

    result = diff_run_directories(run_a, run_b)

    ledger = result["changes"]["coverage_ledger"]
    assert [row["key"] for row in ledger["changed"]] == ["coverage_ledger:identity"]
    assert ledger["added"] == [] and ledger["removed"] == []
    assert result["summary"]["changed"] == 1


def test_diff_reports_duplicate_row_keys_instead_of_overwriting_them(tmp_path: Path) -> None:
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[], coverage={})
    rows = [{"id": "p1", "state": "enabled"}, {"id": "p1", "state": "disabled"}]
    _write(run_a / "normalized" / "policies.json", {"kind": "policies", "records": rows})
    _write(run_b / "normalized" / "policies.json", {"kind": "policies", "records": [rows[0], {"id": "p1", "state": "enabled"}]})

    result = diff_run_directories(run_a, run_b)

    policies = result["changes"]["policies"]
    assert policies["duplicate_keys"] == ["policies:p1"]
    assert len(policies["changed"]) == 1


def test_diff_duplicate_suffix_never_overwrites_a_real_key(tmp_path: Path) -> None:
    # Repair round 1 (R053/R068): a real key equal to a generated duplicate suffix must not hide a row.
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[], coverage={})
    before = [{"key": "item", "v": 1}, {"key": "item", "v": 2}, {"key": "item#2", "v": 3}]
    after = [{"key": "item", "v": 1}, {"key": "item", "v": 20}, {"key": "item#2", "v": 3}]
    _write(run_a / "normalized" / "things.json", {"kind": "things", "records": before})
    _write(run_b / "normalized" / "things.json", {"kind": "things", "records": after})

    things = diff_run_directories(run_a, run_b)["changes"]["things"]

    assert things["duplicate_keys"] == ["item"]
    assert len(things["changed"]) == 1
    assert things["added"] == [] and things["removed"] == []


def test_diff_duplicate_suffix_never_takes_a_real_key_from_the_other_run(tmp_path: Path) -> None:
    # Review of repair round 1 (R053/R068): the real key item#2 exists only in the later run.
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[], coverage={})
    before = [{"key": "item", "v": 1}, {"key": "item", "v": 2}]
    after = [{"key": "item", "v": 1}, {"key": "item", "v": 2}, {"key": "item#2", "v": 3}]
    _write(run_a / "normalized" / "things.json", {"kind": "things", "records": before})
    _write(run_b / "normalized" / "things.json", {"kind": "things", "records": after})

    things = diff_run_directories(run_a, run_b)["changes"]["things"]

    assert things["changed"] == []
    assert things["removed"] == []
    assert things["added"] == [{"key": "item#2", "v": 3}]


# R132: missing or empty run directories


def test_compare_refuses_a_run_directory_that_does_not_exist(tmp_path: Path) -> None:
    run_a, _ = _pair(tmp_path)

    with pytest.raises(ValueError, match="run 2 .*not a run directory"):
        compare_runs([run_a, tmp_path / "missing"], allow_cross_tenant=True)


def test_compare_refuses_an_empty_run_directory(tmp_path: Path) -> None:
    run_a, _ = _pair(tmp_path)
    (tmp_path / "empty").mkdir()

    with pytest.raises(ValueError, match="run 2 .*run-manifest.json"):
        compare_runs([run_a, tmp_path / "empty"], allow_cross_tenant=True)


def test_compare_blocks_a_pair_when_a_run_has_no_creation_time(tmp_path: Path) -> None:
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[FINDING], coverage={"identity": "complete"})
    run_b = _run(tmp_path, "run-b", created_utc=None, findings=[], coverage={"identity": "complete"})

    result = compare_runs([run_a, run_b])

    assert result["baseline_diff"]["status"] == "blocked"
    assert result["baseline_diff"]["reason"] == "run_created_utc_missing"


def test_compare_blocks_two_undated_runs_whichever_order_they_are_given(tmp_path: Path) -> None:
    # Repair round 2 (R132): two undated runs cannot be placed in time, so neither argument order may decide which
    # one is the baseline. The pair is blocked both ways round instead of reporting resolved or new findings.
    baseline = _run(tmp_path, "z-before", created_utc=None, findings=[FINDING], coverage={"identity": "complete"})
    later = _run(tmp_path, "a-after", created_utc=None, findings=[], coverage={"identity": "complete"})

    for order in ([baseline, later], [later, baseline]):
        result = compare_runs(order)
        diff = result["baseline_diff"]
        assert diff["status"] == "blocked"
        assert diff["reason"] == "run_created_utc_missing"
        assert all(pair["status"] == "blocked" for pair in result["adjacent_diffs"])
        assert "drift_summary" not in diff or not diff["drift_summary"].get("resolved_findings")


# R133: findings the baseline never assessed


def test_compare_reports_a_finding_the_baseline_could_not_assess_as_newly_assessed(tmp_path: Path) -> None:
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={"identity": "blocked_permission"})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[FINDING], coverage={"identity": "complete"})

    result = compare_runs([run_a, run_b])
    markdown = render_compare_markdown(result)

    drift = result["baseline_diff"]["drift_summary"]
    assert drift["new_findings"] == []
    assert drift["newly_assessed_findings"] == [FINDING["id"]]
    assert "- New findings: 0" in markdown
    assert "- Newly assessed findings: 1 (high 1)" in markdown


def test_compare_treats_a_baseline_with_no_recorded_coverage_as_not_assessed(tmp_path: Path) -> None:
    # Repair round 1 (R133): a baseline that recorded no collector at all assessed nothing, as the resolved side
    # already treats a later run without coverage.
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[FINDING], coverage={"identity": "complete"})

    drift = compare_runs([run_a, run_b])["baseline_diff"]["drift_summary"]

    assert drift["new_findings"] == []
    assert drift["newly_assessed_findings"] == [FINDING["id"]]


def test_compare_still_reports_a_finding_the_baseline_assessed_as_new(tmp_path: Path) -> None:
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={"identity": "complete"})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[FINDING], coverage={"identity": "complete"})

    result = compare_runs([run_a, run_b])

    assert result["baseline_diff"]["drift_summary"]["new_findings"] == [FINDING["id"]]
    assert "- New findings: 1 (high 1)" in render_compare_markdown(result)


# R135: the not-reassessed heading and reasons


def test_not_reassessed_heading_is_neutral_and_reasons_are_plain_language(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path)

    markdown = render_compare_markdown(compare_runs([run_a, run_b]))

    assert "## Not reassessed findings (1)" in markdown
    assert "collector did not complete in the later run)" not in markdown.split("## Not reassessed findings")[0]
    assert "The finding's collector did not complete in the later run (blocked_permission)" in markdown


# Repair round 1: the `auditex diff` CLI goes through the same gates as compare (R054)


def _cli_diff(run_a: Path, run_b: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    from auditex import cli

    code = cli.main(["diff", str(run_a), str(run_b)])
    return code, json.loads(capsys.readouterr().out)


def test_cli_diff_blocks_two_tenants_that_share_a_tenant_name(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete", tenant_id=TENANT_B)

    code, result = _cli_diff(run_a, run_b, capsys)

    assert result["status"] == "blocked"
    assert result["reason"] == "tenant_id_mismatch"
    assert "drift_summary" not in result
    assert code == 1


def test_cli_diff_blocks_a_bundle_whose_hash_check_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")
    _write(run_b / "bundle-hashes.json", build_bundle_hash_manifest(run_b))
    _write(run_b / "reports" / "report-pack.json", {"findings": [], "edited": True})

    code, result = _cli_diff(run_a, run_b, capsys)

    assert result["status"] == "blocked"
    assert result["reason"].startswith("run_unverified:current:bundle_integrity_")
    assert "drift_summary" not in result
    assert code == 1


def test_cli_diff_of_a_verified_same_tenant_pair_resolves_and_exits_0(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")

    code, result = _cli_diff(run_a, run_b, capsys)

    assert code == 0
    assert result["status"] == "ok"
    assert result["drift_summary"]["resolved_findings"] == [FINDING["id"]]


def _keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


def test_mcp_drift_keeps_its_newly_assessed_keys_when_a_person_has_that_name(tmp_path: Path) -> None:
    # Repair round 2 (R133): a directory identity named "Newly Assessed" must not rename the result keys of the
    # public MCP diff and compare handlers. Every key the unredacted result carries stays a key.
    from auditex.mcp_server import compare_many_runs

    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={"identity": "blocked_permission"})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[FINDING], coverage={"identity": "complete"})
    person = {"kind": "user", "display_name": "Newly Assessed", "principal_name": "newly.assessed@contoso.example", "user_type": "Member"}
    for run_dir in (run_a, run_b):
        _write(run_dir / "normalized" / "users.json", {"kind": "users", "records": [person]})

    raw_compare = compare_runs([run_a, run_b])
    assert "newly_assessed" in _keys(raw_compare)
    mcp_diff = diff_runs(str(run_a), str(run_b))
    for raw, redacted in (
        (raw_compare, compare_many_runs([str(run_a), str(run_b)])),
        # The MCP diff is the gated diff, so it is checked against the gated, unredacted diff: the raw engine diff
        # carries no newly-assessed fields and could not notice them going missing.
        (compare_module.diff_two_runs(run_a, run_b), mcp_diff),
    ):
        lost = {key for key in _keys(raw) if "assessed" in key} - _keys(redacted)
        assert not lost, lost
    drift = mcp_diff["drift_summary"]
    assert {"newly_assessed", "newly_assessed_findings", "newly_assessed_count"} <= set(drift)
    assert drift["newly_assessed_count"] == 1
    assert len(drift["newly_assessed_findings"]) == 1
    assert len(drift["newly_assessed"]) == 1


# Wave-2 bot review fixes, group K: diff and compare correctness


def test_cli_diff_runs_the_engine_comparison_once(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    from azure_tenant_audit import diffing

    run_a, run_b = _pair(tmp_path, later_identity="complete")
    calls: list[Path] = []
    original = diffing._posture_drift_summary

    def counting(left: Path, right: Path) -> dict[str, Any]:
        calls.append(right)
        return original(left, right)

    monkeypatch.setattr(diffing, "_posture_drift_summary", counting)

    code, result = _cli_diff(run_a, run_b, capsys)

    assert code == 0
    assert result["status"] == "ok"
    assert len(calls) == 1


def _seal_with_policies(run_b: Path) -> Path:
    _write(run_b / "normalized" / "policies.json", {"kind": "policies", "records": [{"id": "p1", "state": "enabled"}]})
    _write(run_b / "bundle-hashes.json", build_bundle_hash_manifest(run_b))
    return run_b / "normalized" / "policies.json"


def test_cli_diff_blocks_a_sealed_bundle_whose_normalised_artifact_is_not_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")
    _seal_with_policies(run_b).write_text("{not json", encoding="utf-8")

    code, result = _cli_diff(run_a, run_b, capsys)

    assert result["status"] == "blocked"
    assert result["reason"] == "run_unverified:current:bundle_integrity_mismatch"
    assert code == 1


def test_cli_diff_blocks_an_unsealed_bundle_whose_normalised_artifact_is_not_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")
    (run_b / "normalized" / "policies.json").write_text("{not json", encoding="utf-8")

    code, result = _cli_diff(run_a, run_b, capsys)

    assert result["status"] == "blocked"
    assert result["reason"] == "run_evidence_malformed:current"
    assert "drift_summary" not in result
    assert code == 1


def test_cli_diff_still_refuses_a_symlinked_normalised_artifact_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from auditex import cli

    run_a, run_b = _pair(tmp_path, later_identity="complete")
    target = _seal_with_policies(run_b)
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"kind": "policies", "records": []}), encoding="utf-8")
    target.unlink()
    target.symlink_to(outside)

    code = cli.main(["diff", str(run_a), str(run_b)])

    captured = capsys.readouterr()
    assert code == 2
    assert "Refusing " in captured.err
    assert captured.out == ""


STALE_USER = {
    "id": "google:stale_user:alice",
    "rule_id": "google.stale_user",
    "collector": "google_directory",
    "severity": "medium",
    "status": "open",
    "title": "Stale user",
}


def _stale_user_pair(tmp_path: Path, *, before_days: int, after_days: int) -> tuple[Path, Path]:
    coverage = {"google_directory": "complete"}
    run_a = _run(
        tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage=coverage,
        rule_parameters={"stale_user_days": before_days, "stale_device_days": 90},
    )
    run_b = _run(
        tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[STALE_USER], coverage=coverage,
        rule_parameters={"stale_user_days": after_days, "stale_device_days": 90},
    )
    return run_a, run_b


def test_compare_reports_a_finding_raised_only_by_a_tighter_later_window_as_newly_assessed(tmp_path: Path) -> None:
    run_a, run_b = _stale_user_pair(tmp_path, before_days=90, after_days=30)

    drift = compare_runs([run_a, run_b])["baseline_diff"]["drift_summary"]

    assert drift["new_findings"] == []
    assert drift["newly_assessed_findings"] == [STALE_USER["id"]]
    assert drift["newly_assessed"][0]["reason"] == "rule_parameters_laxer:stale_user_days"


def test_compare_still_reports_a_finding_under_an_equal_window_as_new(tmp_path: Path) -> None:
    run_a, run_b = _stale_user_pair(tmp_path, before_days=90, after_days=90)

    drift = compare_runs([run_a, run_b])["baseline_diff"]["drift_summary"]

    assert drift["new_findings"] == [STALE_USER["id"]]
    assert drift["newly_assessed_findings"] == []


def test_compare_markdown_renders_the_stored_finding_delta_not_the_evidence_as_it_is_now(tmp_path: Path) -> None:
    run_a, run_b = _pair(tmp_path)
    result = compare_runs([run_a, run_b])
    _write(
        run_b / "normalized" / "coverage_ledger.json",
        {"kind": "coverage_ledger", "records": [{"collector": "identity", "coverage_status": "complete"}]},
    )

    markdown = render_compare_markdown(result)

    drift = result["baseline_diff"]["drift_summary"]
    assert drift["not_reassessed_count"] == 1 and drift["resolved_count"] == 0
    assert "- Not reassessed findings: 1" in markdown
    assert "- Resolved findings: 0" in markdown


def test_raw_diff_does_not_resolve_a_finding_when_the_later_run_recorded_no_coverage(tmp_path: Path) -> None:
    anonymous = {**FINDING, "id": "no-collector", "collector": None}
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[FINDING, anonymous], coverage={"identity": "complete"})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[], coverage={})

    drift = diff_run_directories(run_a, run_b)["drift_summary"]

    assert drift["not_reassessed_findings"] == [FINDING["id"]]
    assert drift["resolved_findings"] == ["no-collector"]


def test_raw_diff_builds_the_not_reassessed_set_a_bounded_number_of_times(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    from azure_tenant_audit import diffing

    findings = [{**FINDING, "id": f"f{index:03d}"} for index in range(200)]
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=findings, coverage={"identity": "complete"})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[], coverage={"identity": "blocked_permission"})
    built: list[int] = []

    def counting_set(*args: Any) -> set[Any]:
        built.append(1)
        return builtins.set(*args)

    monkeypatch.setattr(diffing, "set", counting_set, raising=False)

    drift = diffing._posture_drift_summary(run_a, run_b)

    assert drift["not_reassessed_count"] == 200
    assert len(built) < 20


def _things_pair(tmp_path: Path, before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    run_a = _run(tmp_path, "run-a", created_utc="2026-10-01T00:00:00Z", findings=[], coverage={})
    run_b = _run(tmp_path, "run-b", created_utc="2026-10-02T00:00:00Z", findings=[], coverage={})
    _write(run_a / "normalized" / "things.json", {"kind": "things", "records": before})
    _write(run_b / "normalized" / "things.json", {"kind": "things", "records": after})
    return diff_run_directories(run_a, run_b)


def test_diff_pairs_equal_duplicate_rows_whatever_their_order(tmp_path: Path) -> None:
    rows = [{"key": "item", "v": 1}, {"key": "item", "v": 2}]

    result = _things_pair(tmp_path, rows, list(reversed(rows)))

    things = result["changes"]["things"]
    assert things["duplicate_keys"] == ["item"]
    assert things["changed"] == [] and things["added"] == [] and things["removed"] == []
    assert result["summary"]["changed"] == 0


def test_diff_pairs_an_equal_duplicate_row_before_a_changed_one(tmp_path: Path) -> None:
    before = [{"key": "item", "v": 1}, {"key": "item", "v": 2}]
    after = [{"key": "item", "v": 3}, {"key": "item", "v": 1}]

    things = _things_pair(tmp_path, before, after)["changes"]["things"]

    assert [(row["before"]["v"], row["after"]["v"]) for row in things["changed"]] == [(2, 3)]
    assert things["added"] == [] and things["removed"] == []


def test_diff_never_pairs_an_anonymous_row_with_a_row_whose_id_matches_its_position(tmp_path: Path) -> None:
    result = _things_pair(tmp_path, [{"v": "anonymous"}], [{"id": 0, "v": "replacement"}])

    things = result["changes"]["things"]
    assert things["changed"] == []
    assert things["removed"] == [{"v": "anonymous"}]
    assert things["added"] == [{"id": 0, "v": "replacement"}]


def test_diff_pairs_reordered_duplicate_rows_that_differ_only_in_volatile_fields(tmp_path: Path) -> None:
    before = [{"key": "item", "v": 1, "updated_at": "2026-10-01"}, {"key": "item", "v": 2, "updated_at": "2026-10-01"}]
    after = [{"key": "item", "v": 2, "updated_at": "2026-10-02"}, {"key": "item", "v": 1, "updated_at": "2026-10-02"}]

    things = _things_pair(tmp_path, before, after)["changes"]["things"]

    assert things["changed"] == []
    assert sorted((row["before"]["v"], row["after"]["v"]) for row in things["suppressed"]) == [(1, 1), (2, 2)]


# Repair round 2: one finding classification, unique changed-row keys, malformed legacy evidence (items 37, 46, 48)


def _legacy_run(root: Path, name: str, created_utc: str, finding: dict[str, Any]) -> Path:
    run_dir = _run(root, name, created_utc=created_utc, findings=[], coverage={"identity": "complete"})
    _write(run_dir / "findings" / "findings.json", [finding])
    return run_dir


def test_compare_drift_summary_classifies_legacy_findings_as_the_finding_delta_does(tmp_path: Path) -> None:
    run_a = _legacy_run(tmp_path, "run-a", "2026-10-01T00:00:00Z", {**FINDING, "severity": "low", "status": "accepted"})
    run_b = _legacy_run(tmp_path, "run-b", "2026-10-02T00:00:00Z", {**FINDING, "severity": "high", "status": "open"})

    result = compare_runs([run_a, run_b])["baseline_diff"]

    assert [row["key"] for row in result["finding_delta"]["changed"]] == [FINDING["id"]]
    drift = result["drift_summary"]
    assert drift["worsened_findings"] == [FINDING["id"]]
    assert drift["state_transition_count"] == 1
    assert drift["reactivated_accepted_risk_count"] == 1
    assert drift["notification_recommended"] is True


def test_diff_gives_an_anonymous_row_and_a_row_whose_id_matches_its_position_different_keys(tmp_path: Path) -> None:
    before = [{"v": "anonymous"}, {"id": 0, "v": "explicit"}]
    after = [{"v": "anonymous changed"}, {"id": 0, "v": "explicit changed"}]

    things = _things_pair(tmp_path, before, after)["changes"]["things"]

    keys = [row["key"] for row in things["changed"]]
    assert len(keys) == 2 and len(set(keys)) == 2
    by_key = {row["key"]: row["after"]["v"] for row in things["changed"]}
    assert by_key["things:0"] == "explicit changed"
    assert things["duplicate_keys"] == ["things:0"]


def test_cli_diff_blocks_a_normalised_artifact_whose_records_are_not_a_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run_a, run_b = _pair(tmp_path, later_identity="complete")
    _write(run_a / "normalized" / "policies.json", {"kind": "policies", "records": [{"id": "p1"}]})
    _write(run_b / "normalized" / "policies.json", {"kind": "policies", "records": {"id": "p1"}})

    code, result = _cli_diff(run_a, run_b, capsys)

    assert result["status"] == "blocked"
    assert result["reason"] == "run_evidence_malformed:current"
    assert "changes" not in result or result["changes"] == {}
    assert code == 1


@pytest.mark.parametrize(
    ("relative", "content"),
    [
        ("reports/report-pack.json", "{not json"),
        ("reports/report-pack.json", json.dumps({"findings": {"id": FINDING["id"]}})),
        ("findings/findings.json", "{not json"),
    ],
)
def test_cli_diff_blocks_a_legacy_run_whose_findings_cannot_be_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], relative: str, content: str
) -> None:
    run_a = _legacy_run(tmp_path, "run-a", "2026-10-01T00:00:00Z", FINDING)
    run_b = _legacy_run(tmp_path, "run-b", "2026-10-02T00:00:00Z", FINDING)
    if relative == "findings/findings.json":
        (run_b / "reports" / "report-pack.json").unlink()
    (run_b / relative).write_text(content, encoding="utf-8")

    code, result = _cli_diff(run_a, run_b, capsys)

    assert result["status"] == "blocked"
    assert result["reason"] == "run_evidence_malformed:current"
    assert "drift_summary" not in result
    assert code == 1
