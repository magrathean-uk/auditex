from __future__ import annotations

import json
from pathlib import Path

from auditex.reporting import analyze_report


def test_analyze_report_replays_saved_bundle_without_live_tenant(tmp_path: Path) -> None:
    run_dir = tmp_path / "acme-run"
    (run_dir / "reports").mkdir(parents=True)
    (run_dir / "normalized").mkdir()
    (run_dir / "run-manifest.json").write_text(
        json.dumps(
            {
                "tenant_name": "acme",
                "run_id": "run",
                "platform": "m365",
                "overall_status": "partial",
                "artifacts": ["reports/report-pack.json", "normalized/auth_methods.json"],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(
        json.dumps({"tenant_name": "acme", "run_id": "run", "overall_status": "partial", "collectors": []}),
        encoding="utf-8",
    )
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps(
            {
                "summary": {"tenant_name": "acme", "overall_status": "partial"},
                "findings": [
                    {
                        "id": "identity-1",
                        "rule_id": "identity.admin_mfa_missing",
                        "severity": "high",
                        "title": "Admin missing MFA",
                        "status": "open",
                        "category": "identity",
                        "evidence_refs": [
                            {
                                "artifact_path": "normalized/auth_methods.json",
                                "artifact_kind": "normalized",
                                "collector": "auth_methods",
                                "record_key": "admin@example.com",
                            }
                        ],
                    }
                ],
                "evidence_paths": ["normalized/auth_methods.json"],
            }
        ),
        encoding="utf-8",
    )

    result = analyze_report(run_dir)

    assert result["run_dir"] == str(run_dir)
    assert result["license_profile"]["minimum_live_access"] == "delegated_read_login"
    assert result["replay_context"]["requires_live_tenant"] is False
    assert result["auditor_score"]["score"] > 0
    assert result["report_qa"]["status"] == "pass"
