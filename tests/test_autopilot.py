from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.contracts import build_validation_report
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.finalize import finalize_bundle_contract
from azure_tenant_audit.findings import build_report_pack

from test_finalize_idempotent import _prepare_bundle_for_finalize


def test_autopilot_plan_marks_partial_with_exact_scope_blockers() -> None:
    from azure_tenant_audit.autopilot import build_audit_autopilot_plan

    plan = build_audit_autopilot_plan(
        platform="google_workspace",
        selected_collectors=["google_directory", "google_reports", "google_gmail_settings"],
        capability_rows=[
            {
                "collector": "google_directory",
                "status": "supported_exact_scope",
                "required_permissions": ["admin.directory.user.readonly"],
                "missing_permissions": [],
            },
            {
                "collector": "google_reports",
                "status": "blocked_by_scope",
                "required_permissions": ["admin.reports.audit.readonly"],
                "missing_permissions": ["admin.reports.audit.readonly"],
            },
            {
                "collector": "google_gmail_settings",
                "status": "partial",
                "required_permissions": ["gmail.settings.basic"],
                "missing_permissions": [],
            },
        ],
        coverage_gaps=[
            {
                "surface": "audit_logs",
                "status": "blocked",
                "message": "audit logs blocked",
                "collectors": ["google_reports"],
            }
        ],
        blockers=[],
        findings=[],
    )

    assert plan["schema_version"] == "2026-04-21"
    assert plan["platform"] == "google_workspace"
    assert plan["quality_gate"]["status"] == "partial"
    assert plan["quality_gate"]["human_reviewer_required"] is True
    assert plan["required_scopes"] == [
        "admin.directory.user.readonly",
        "admin.reports.audit.readonly",
        "gmail.settings.basic",
    ]
    gates = {row["collector"]: row for row in plan["evidence_gates"]}
    assert gates["google_reports"]["status"] == "blocked"
    assert gates["google_reports"]["blocker_kind"] == "auth_scope"
    assert gates["google_reports"]["next_step"]
    assert gates["google_reports"]["missing_permissions"] == ["admin.reports.audit.readonly"]
    assert "google_reports: missing admin.reports.audit.readonly" in plan["quality_gate"]["reasons"]


def test_autopilot_and_live_readiness_share_evidence_gate_rows() -> None:
    from azure_tenant_audit.assurance import build_live_readiness_summary
    from azure_tenant_audit.autopilot import build_audit_autopilot_plan

    capability_rows = [
        {"collector": "google_directory", "status": "supported_exact_scope"},
        {
            "collector": "google_reports",
            "status": "blocked_by_scope",
            "reason": "runtime_permission_block",
            "missing_permissions": ["admin.reports.audit.readonly"],
        },
        {"collector": "google_gmail_settings", "status": "partial", "reason": "runtime_endpoint_block"},
    ]
    selected = ["google_directory", "google_reports", "google_gmail_settings"]

    readiness = build_live_readiness_summary(
        selected_collectors=selected,
        capability_rows=capability_rows,
    )
    plan = build_audit_autopilot_plan(
        platform="google_workspace",
        selected_collectors=selected,
        capability_rows=capability_rows,
        coverage_gaps=[],
        blockers=[],
        findings=[],
    )

    assert readiness["evidence_gates"] == plan["evidence_gates"]


def test_autopilot_plan_marks_unusable_when_no_trusted_critical_evidence() -> None:
    from azure_tenant_audit.autopilot import build_audit_autopilot_plan

    plan = build_audit_autopilot_plan(
        platform="m365",
        selected_collectors=["identity", "security"],
        capability_rows=[
            {"collector": "identity", "status": "blocked_by_scope", "missing_permissions": ["Directory.Read.All"]},
            {"collector": "security", "status": "blocked_by_scope", "missing_permissions": ["SecurityEvents.Read.All"]},
        ],
        coverage_gaps=[],
        blockers=[{"collector": "identity", "error_class": "insufficient_permissions"}],
        findings=[],
    )

    assert plan["quality_gate"]["status"] == "unusable"
    assert plan["quality_gate"]["human_reviewer_required"] is True
    assert "No trusted evidence gates completed." in plan["quality_gate"]["reasons"]


def test_report_pack_adds_board_ready_sections_and_enriched_finding_proof() -> None:
    report = build_report_pack(
        tenant_name="acme",
        overall_status="partial",
        findings=[
            {
                "id": "finding-1",
                "rule_id": "identity.admin_mfa_missing",
                "severity": "high",
                "title": "Admin missing MFA",
                "status": "open",
                "category": "identity",
                "impact": "Admin compromise risk.",
                "remediation": "Require phishing-resistant MFA.",
                "affected_objects": ["admin@example.com"],
                "evidence_refs": [
                    {
                        "artifact_path": "normalized/auth_methods.json",
                        "artifact_kind": "normalized",
                        "collector": "auth_methods",
                        "record_key": "user:admin@example.com",
                    }
                ],
            }
        ],
        evidence_paths=["normalized/auth_methods.json"],
        blocker_count=1,
        coverage_gaps=[{"surface": "audit_logs", "message": "audit logs blocked", "status": "blocked"}],
    )

    assert report["executive_summary"]["tenant_name"] == "acme"
    assert report["executive_summary"]["quality"] == "partial"
    assert report["limitations"][0]["message"] == "audit logs blocked"
    assert report["next_actions"][0]["id"] == "finding-1"
    finding = report["findings"][0]
    assert finding["confidence"] == "high"
    assert finding["blast_radius"]["scope"] == "single_object"
    assert finding["business_impact"]
    assert finding["false_positive_notes"]
    assert report["proof_table"][0]["evidence_count"] == 1
    assert report["proof_table"][0]["proof_status"] == "supported"
    assert report["proof_table"][0]["artifact_path"] == "normalized/auth_methods.json"
    assert report["proof_table"][0]["record_key"] == "user:admin@example.com"
    assert report["technical_appendix"]["evidence_path_count"] == 1


def test_basic_license_intelligence_builds_score_paths_simulator_and_qa() -> None:
    from azure_tenant_audit.autopilot import build_basic_license_intelligence

    findings = [
        {
            "id": "identity-1",
            "rule_id": "identity.admin_mfa_missing",
            "severity": "high",
            "title": "Admin missing MFA",
            "status": "open",
            "category": "identity",
            "affected_objects": ["admin@example.com"],
            "evidence_refs": [
                {
                    "artifact_path": "normalized/auth_methods.json",
                    "artifact_kind": "normalized",
                    "collector": "auth_methods",
                    "record_key": "admin@example.com",
                }
            ],
        },
        {
            "id": "oauth-1",
            "rule_id": "google.oauth_token_risky_grant",
            "severity": "high",
            "title": "Risky OAuth grant",
            "status": "open",
            "category": "apps",
            "affected_objects": ["app-1"],
            "evidence_refs": [
                {
                    "artifact_path": "normalized/google_oauth_tokens.json",
                    "artifact_kind": "normalized",
                    "collector": "google_reports",
                    "record_key": "app-1",
                }
            ],
        },
        {
            "id": "mail-1",
            "rule_id": "google.gmail_filter_external_forwarding",
            "severity": "critical",
            "title": "External forwarding",
            "status": "open",
            "category": "mail",
            "affected_objects": ["user@example.com"],
            "evidence_refs": [
                {
                    "artifact_path": "normalized/google_gmail_settings.json",
                    "artifact_kind": "normalized",
                    "collector": "google_gmail_settings",
                    "record_key": "user@example.com",
                }
            ],
        },
        {
            "id": "weak-claim",
            "rule_id": "manual.weak_claim",
            "severity": "medium",
            "title": "Weak claim",
            "status": "open",
            "category": "general",
            "evidence_refs": [],
        },
    ]

    pack = build_basic_license_intelligence(
        tenant_name="acme",
        platform="google_workspace",
        overall_status="partial",
        findings=findings,
        evidence_paths=["normalized/auth_methods.json", "normalized/google_gmail_settings.json"],
        coverage_gaps=[{"surface": "audit_logs", "status": "partial"}],
    )

    assert pack["license_profile"] == {
        "minimum_live_access": "delegated_read_login",
        "requires_premium_license": False,
        "works_from_saved_bundle": True,
        "supports_synthetic_evidence": True,
        "production_writes": False,
    }
    assert pack["auditor_score"]["grade"] in {"usable", "strong"}
    assert pack["auditor_score"]["components"]["license_fit"] == 100
    assert pack["attack_paths"][0]["chain"] == ["identity", "app_access", "mail_exfiltration"]
    assert pack["control_simulator"]["actions"][0]["requires_write_access"] is False
    assert pack["control_simulator"]["actions"][0]["execution"] == "dry_run_only"
    assert pack["report_qa"]["status"] == "fail"
    assert pack["report_qa"]["unsupported_claims"] == ["weak-claim"]
    assert pack["replay_context"]["requires_live_tenant"] is False


def test_report_pack_includes_basic_license_intelligence() -> None:
    report = build_report_pack(
        tenant_name="acme",
        overall_status="ok",
        findings=[
            {
                "id": "finding-1",
                "rule_id": "exchange.external_forwarding",
                "severity": "high",
                "title": "External forwarding",
                "status": "open",
                "category": "mail",
                "evidence_refs": [
                    {
                        "artifact_path": "normalized/mailbox_forwarding.json",
                        "artifact_kind": "normalized",
                        "collector": "mailbox_forwarding",
                        "record_key": "rule-1",
                    }
                ],
            }
        ],
        evidence_paths=["normalized/mailbox_forwarding.json"],
    )

    assert report["auditor_score"]["components"]["license_fit"] == 100
    assert report["control_simulator"]["actions"][0]["id"] == "finding-1"
    assert report["report_qa"]["status"] == "pass"
    assert report["replay_context"]["requires_live_tenant"] is False


def test_contract_validates_optional_data_handling_when_manifest_references_it(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    run_dir = writer.run_dir
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    handling_path = run_dir / manifest["data_handling_path"]
    payload = json.loads(handling_path.read_text(encoding="utf-8"))
    payload["read_only"] = True
    payload["write_actions"] = True
    handling_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir)

    assert "invalid_data_handling_semantics" in [item["code"] for item in report["issues"]]
    assert report["valid"] is False


def test_contract_validates_google_no_content_assertions(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    kwargs["bundle_metadata"]["platform"] = "google_workspace"
    finalize_bundle_contract(**kwargs)
    run_dir = writer.run_dir
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    handling_path = run_dir / manifest["data_handling_path"]
    payload = json.loads(handling_path.read_text(encoding="utf-8"))
    payload["provider_assertions"]["gmail_body_reads"] = True
    handling_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir)

    assert "invalid_data_handling_no_content_assertion" in [item["code"] for item in report["issues"]]
    assert report["valid"] is False


def test_contract_validates_report_pack_proof_table_rows(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    run_dir = writer.run_dir
    report_path = run_dir / "reports" / "report-pack.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    finding_id = (payload.get("findings") or [{"id": "finding-1"}])[0]["id"]
    payload["proof_table"] = [
        {
            "finding_id": finding_id,
            "proof_status": "supported",
            "artifact_path": "normalized/missing.json",
            "artifact_kind": "normalized",
            "collector": "identity",
            "record_key": "record-1",
        }
    ]
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    report = build_validation_report(run_dir=run_dir)

    assert "broken_report_proof_table_ref" in [item["code"] for item in report["issues"]]
    assert report["valid"] is False


def test_contract_flags_missing_manifest_optional_artifact(tmp_path: Path) -> None:
    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    run_dir = writer.run_dir
    manifest_path = run_dir / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (run_dir / manifest["data_handling_path"]).unlink()

    report = build_validation_report(run_dir=run_dir)

    assert "missing_manifest_artifact" in [item["code"] for item in report["issues"]]
    assert report["valid"] is False


def _write_minimal_run(run_dir: Path, *, tenant: str, platform: str, findings: list[dict]) -> None:
    run_dir.mkdir(parents=True)
    (run_dir / "normalized").mkdir()
    (run_dir / "reports").mkdir()
    (run_dir / "run-manifest.json").write_text(
        json.dumps(
            {
                "tenant_name": tenant,
                "platform": platform,
                "run_id": run_dir.name,
                "created_utc": "2026-05-22T10:00:00Z",
                "overall_status": "ok",
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "normalized" / "snapshot.json").write_text(
        json.dumps({"kind": "snapshot", "records": []}),
        encoding="utf-8",
    )
    (run_dir / "reports" / "report-pack.json").write_text(
        json.dumps({"summary": {"tenant_name": tenant}, "findings": findings}),
        encoding="utf-8",
    )


def test_diff_reports_posture_drift_for_new_resolved_and_worse_findings(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write_minimal_run(
        before,
        tenant="acme",
        platform="google_workspace",
        findings=[
            {"id": "same-risk", "severity": "medium", "status": "open", "title": "Risk got worse"},
            {"id": "resolved-risk", "severity": "high", "status": "open", "title": "Resolved"},
        ],
    )
    _write_minimal_run(
        after,
        tenant="acme",
        platform="google_workspace",
        findings=[
            {"id": "same-risk", "severity": "critical", "status": "open", "title": "Risk got worse"},
            {"id": "new-risk", "severity": "medium", "status": "open", "title": "New"},
        ],
    )

    diff = diff_run_directories(before, after)

    assert diff["drift_summary"]["new_findings"] == ["new-risk"]
    assert diff["drift_summary"]["resolved_findings"] == ["resolved-risk"]
    assert diff["drift_summary"]["worsened_findings"] == ["same-risk"]
    assert diff["drift_summary"]["notification_recommended"] is True
