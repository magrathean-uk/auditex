from __future__ import annotations

from pathlib import Path

from auditex.run_bundle import RunBundle
from support import RunBundleBuilder


def test_run_bundle_view_uses_contract_report_pack_then_artifact_fallbacks(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(report_pack_path="custom/report-pack.json")
        .summary(tenant_name="legacy", assurance={"score": 75, "grade": "usable"})
        .report_pack(
            path="custom/report-pack.json",
            summary={"tenant_name": "acme", "overall_status": "partial", "finding_count": 1, "open_count": 1},
            findings=[{"id": "f1", "status": "open", "title": "Fix"}],
            action_plan=[{"id": "f1", "title": "Fix"}],
        )
        .blockers([{"collector": "identity"}])
        .evidence_db(path="custom/evidence.sqlite")
        .build()
    )

    bundle = RunBundle(run_dir)

    assert bundle.report_summary()["tenant_name"] == "acme"
    assert bundle.report_summary()["assurance"] == {"score": 75, "grade": "usable"}
    assert bundle.finding_rows() == [{"id": "f1", "status": "open", "title": "Fix"}]
    assert bundle.action_plan_rows() == [{"id": "f1", "title": "Fix"}]
    assert bundle.blocker_rows() == [{"collector": "identity"}]
    assert bundle.evidence_db_path() == run_dir / "custom" / "evidence.sqlite"
    assert bundle.metadata()["run_id"] == "run-1"


def test_run_bundle_view_keeps_legacy_shape_and_read_contract(tmp_path: Path) -> None:
    run_dir = (
        RunBundleBuilder(tmp_path)
        .manifest(tenant_name="legacy", run_id="run-old", overall_status="ok", findings_count=2)
        .summary(tenant_name="legacy", overall_status="ok")
        .findings({"findings": [{"id": "f1", "status": "open"}, {"id": "f2", "status": "accepted_risk"}]})
        .action_plan({"open_findings": [{"id": "f1", "title": "Fix"}], "waived_findings": [], "blocked": []})
        .build()
    )

    bundle = RunBundle(run_dir)
    payload = bundle.read()

    assert bundle.report_summary()["overall_status"] == "ok"
    assert bundle.finding_rows()[0]["id"] == "f1"
    assert bundle.action_plan_rows() == [{"id": "f1", "title": "Fix"}]
    assert payload["manifest"]["tenant_name"] == "legacy"
    assert payload["findings"]["findings"][1]["status"] == "accepted_risk"
    assert payload["action_plan"]["open_findings"][0]["id"] == "f1"
