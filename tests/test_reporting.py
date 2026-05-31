from __future__ import annotations

import json
from pathlib import Path

from auditex.exporters import list_exporters, run_exporter
from auditex.reporting import load_section_registry, preview_report, render_report


def _write_run(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run-manifest.json").write_text(
        json.dumps(
            {
                "tenant_name": "acme",
                "run_id": "run-1",
                "overall_status": "partial",
                "live_readiness_path": "live-readiness.json",
                "api_inventory_path": "api-inventory.json",
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(
        json.dumps({"collectors": [], "assurance": {"grade": "usable", "score": 75}}),
        encoding="utf-8",
    )
    (run_dir / "reports").mkdir(exist_ok=True)
    (run_dir / "findings").mkdir(exist_ok=True)
    (run_dir / "normalized").mkdir(exist_ok=True)
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps(
            {
                "summary": {
                    "tenant_name": "acme",
                    "overall_status": "partial",
                    "finding_count": 2,
                    "blocker_count": 1,
                    "open_count": 1,
                    "accepted_count": 1,
                    "risk": {"grade": "high", "score": 40},
                },
                "executive_summary": {
                    "tenant_name": "acme",
                    "quality": "partial",
                    "top_findings": [{"id": "finding-1", "title": "Fix sharing", "severity": "high"}],
                },
                "technical_appendix": {
                    "evidence_path_count": 2,
                    "proof_table_count": 1,
                    "data_handling": "read_only_audit_default",
                },
                "reviewer_index": {
                    "start_here": [
                        {
                            "section": "executive_summary",
                            "artifact_path": "reports/report-pack.json",
                            "reason": "Start with posture and top findings.",
                        }
                    ],
                    "prove_this": [
                        {
                            "finding_id": "finding-1",
                            "severity": "high",
                            "proof_status": "supported",
                            "artifact_path": "normalized/users.json",
                            "record_key": "user:alice",
                        }
                    ],
                    "known_limits": [
                        {
                            "surface": "mail",
                            "status": "partial",
                            "message": "mail coverage is partial",
                        }
                    ],
                },
                "limitations": [
                    {
                        "surface": "mail",
                        "status": "partial",
                        "message": "mail coverage is partial",
                        "collectors": ["google_gmail_settings"],
                    }
                ],
                "findings": [
                    {
                        "id": "finding-1",
                        "rule_id": "google.gmail_external_forwarding",
                        "title": "Fix sharing",
                        "severity": "high",
                        "status": "open",
                        "impact": "Mail leaves the tenant boundary.",
                        "remediation": "Disable unapproved forwarding.",
                    },
                    {"id": "finding-2", "title": "Accepted", "severity": "medium", "status": "accepted_risk"},
                ],
                "action_plan": [{"id": "finding-1", "title": "Fix sharing", "severity": "high"}],
                "next_actions": [
                    {
                        "id": "finding-1",
                        "title": "Fix sharing",
                        "severity": "high",
                        "remediation": "Disable unapproved forwarding.",
                    }
                ],
                "license_profile": {"minimum_live_access": "delegated_read_login", "production_writes": False},
                "auditor_score": {"score": 82, "grade": "strong", "components": {"evidence_depth": 100}},
                "attack_paths": [
                    {
                        "id": "attack_path:primary",
                        "summary": "identity -> mail_exfiltration",
                        "severity": "high",
                        "stage_count": 2,
                    }
                ],
                "control_simulator": {"current_risk_score": 15, "simulated_best_score": 0, "actions": []},
                "report_qa": {"status": "pass", "unsupported_claims": [], "low_confidence_findings": []},
                "replay_context": {"requires_live_tenant": False, "input": "saved_bundle_or_synthetic_evidence"},
                "proof_table": [
                    {
                        "finding_id": "finding-1",
                        "id": "finding-1",
                        "rule_id": "google.gmail_external_forwarding",
                        "title": "Fix sharing",
                        "severity": "high",
                        "confidence": "high",
                        "proof_status": "supported",
                        "evidence_count": 1,
                        "collector": "google_gmail_settings",
                        "artifact_path": "normalized/users.json",
                        "artifact_kind": "normalized",
                        "record_key": "user:alice",
                        "json_pointer": "/records/0",
                    }
                ],
                "evidence_paths": ["findings/findings.json", "normalized/users.json"],
            }
        ),
        encoding="utf-8",
    )
    summary_payload = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    summary_payload["surface_coverage"] = [
        {"surface": "identity", "status": "complete"},
        {"surface": "mail", "status": "partial"},
    ]
    summary_payload["provider_scorecard"] = {
        "platform": "google_workspace",
        "score": 80,
        "grade": "usable",
        "surface_count": 2,
        "coverage_gap_count": 1,
        "surfaces": [
            {"surface": "identity", "status": "complete", "score": 100},
            {"surface": "mail", "status": "partial", "score": 60, "gap_severity": "medium"},
        ],
    }
    summary_payload["coverage_gaps"] = [
        {
            "surface": "mail",
            "status": "partial",
            "severity": "medium",
            "collectors": ["google_gmail_settings"],
            "error_classes": ["invalid_scope"],
            "message": "mail coverage is partial; affected collectors: google_gmail_settings",
        }
    ]
    (run_dir / "summary.json").write_text(json.dumps(summary_payload), encoding="utf-8")
    (run_dir / "live-readiness.json").write_text(
        json.dumps(
            {
                "trust_level": "partial",
                "trusted_collectors": ["identity"],
                "cannot_trust": ["google_gmail_settings"],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "api-inventory.json").write_text(
        json.dumps(
            {
                "schema_version": "2026-04-21",
                "platform": "google_workspace",
                "declared_collectors": [{"collector": "google_directory", "observed_call_count": 1}],
                "observed_calls": [
                    {
                        "collector": "google_directory",
                        "method": "GET",
                        "endpoint": "admin.directory.users.list",
                        "status": "ok",
                        "item_count": 2,
                        "data_class": "directory_identity",
                    }
                ],
                "counts": {"observed_calls": 1},
                "safety": {"read_only": True, "no_content_reads": True},
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "reports" / "action-plan.json").write_text(
        json.dumps([{"id": "finding-1", "title": "Fix sharing", "severity": "high"}]),
        encoding="utf-8",
    )
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps(
            [
                {"id": "finding-1", "title": "Fix sharing", "severity": "high", "status": "open"},
                {"id": "finding-2", "title": "Accepted", "severity": "medium", "status": "accepted_risk"},
            ]
        ),
        encoding="utf-8",
    )
    (run_dir / "normalized" / "users.json").write_text(
        json.dumps({"kind": "users", "records": [{"key": "user:1", "display_name": "Alice"}]}),
        encoding="utf-8",
    )


def test_load_section_registry_includes_core_sections() -> None:
    rows = load_section_registry()
    ids = {row["id"] for row in rows}
    assert {
        "summary",
        "executive_summary",
        "reviewer_index",
        "findings",
        "proof_table",
        "action_plan",
        "api_inventory",
        "normalized",
        "report_qa",
    }.issubset(ids)


def test_render_report_respects_section_filters(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    result = render_report(
        run_dir=str(run_dir),
        format_name="json",
        include_sections=["summary", "action_plan"],
    )

    payload = json.loads(Path(result["output_path"]).read_text(encoding="utf-8"))
    assert payload["sections"]["summary"]["tenant_name"] == "acme"
    assert "action_plan" in payload["sections"]
    assert "findings" not in payload["sections"]


def test_render_report_supports_md_csv_and_html(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    md_result = render_report(run_dir=str(run_dir), format_name="md")
    csv_result = render_report(run_dir=str(run_dir), format_name="csv")
    html_result = render_report(run_dir=str(run_dir), format_name="html")

    md_content = Path(md_result["output_path"]).read_text(encoding="utf-8")
    assert md_content.startswith("# Auditex Report")
    assert "Risk: high / 40" in md_content
    assert "Assurance: usable / 75" in md_content
    assert "Scorecard: usable / 80" in md_content
    assert "Live readiness: partial" in md_content
    assert "Cannot trust: google_gmail_settings" in md_content
    assert "## Executive Summary" in md_content
    assert "## Reviewer Index" in md_content
    assert "### Start Here" in md_content
    assert "### Prove This" in md_content
    assert "### Known Limits" in md_content
    assert "read_only_audit_default" in md_content
    assert "## Next Actions" in md_content
    assert "## Auditor Score" in md_content
    assert "identity -> mail_exfiltration" in md_content
    assert "## Report QA" in md_content
    assert "identity: complete" in md_content
    assert "mail: partial" in md_content
    assert "## Coverage Gaps" in md_content
    assert "mail coverage is partial; affected collectors: google_gmail_settings" in md_content
    assert "invalid_scope" in md_content
    assert "google.gmail_external_forwarding" in md_content
    assert "Mail leaves the tenant boundary." in md_content
    assert "Disable unapproved forwarding." in md_content
    assert "## Proof Table" in md_content
    assert "google_gmail_settings" in md_content
    assert "user:alice" in md_content
    assert "## API Calls" in md_content
    assert "admin.directory.users.list" in md_content
    assert "No content reads: True" in md_content
    csv_content = Path(csv_result["output_path"]).read_text(encoding="utf-8")
    assert "finding-1" in csv_content
    assert "google.gmail_external_forwarding" in csv_content
    assert "Disable unapproved forwarding." in csv_content
    html_content = Path(html_result["output_path"]).read_text(encoding="utf-8")
    assert "<html" in html_content.lower()
    assert "Mail leaves the tenant boundary." in html_content
    assert "Disable unapproved forwarding." in html_content
    assert "Proof Table" in html_content
    assert "user:alice" in html_content
    assert "Executive Summary" in html_content
    assert "Reviewer Index" in html_content
    assert "Report QA" in html_content
    assert "admin.directory.users.list" in html_content


def test_preview_report_returns_content_without_writing(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    result = preview_report(run_dir=str(run_dir), format_name="json", include_sections=["summary"])

    payload = json.loads(result["content"])
    assert result["format"] == "json"
    assert result["sections"] == ["summary"]
    assert result["citations"] == [
        {
            "artifact_path": "summary.json",
            "reason": "Top-level run summary for this preview.",
        }
    ]
    assert result["citation_summary"]["artifact_count"] == 1
    assert result["evidence_missing"] == []
    assert payload["sections"]["summary"]["tenant_name"] == "acme"
    assert payload["sections"]["summary"]["live_readiness"]["trust_level"] == "partial"


def test_list_exporters_includes_builtin_formats() -> None:
    rows = list_exporters()
    names = {row["name"] for row in rows}
    assert {"json", "md", "csv", "html"}.issubset(names)


def test_run_exporter_uses_builtin_renderer(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir)

    result = run_exporter(name="html", run_dir=str(run_dir))

    assert result["name"] == "html"
    assert result["artifacts"][0]["path"].endswith(".html")
