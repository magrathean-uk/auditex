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
) -> Path:
    run_dir = root / name
    manifest: dict[str, Any] = {"tenant_name": tenant_name, "run_id": name, "overall_status": "ok"}
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
