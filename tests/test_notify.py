from __future__ import annotations

import json
from pathlib import Path

from auditex.notify import send_notification


def _write_run_bundle(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run-manifest.json").write_text(
        json.dumps({"tenant_name": "acme", "live_readiness_path": "live-readiness.json"}),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "live-readiness.json").write_text(
        json.dumps(
            {
                "trust_level": "partial",
                "trusted_collectors": ["google_directory"],
                "cannot_trust": ["google_reports", "google_gmail_settings"],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "reports").mkdir(exist_ok=True)
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
                    "provider_scorecard": {
                        "platform": "google_workspace",
                        "score": 80,
                        "grade": "usable",
                        "surface_count": 2,
                        "coverage_gap_count": 1,
                    },
                    "coverage_gaps": [
                        {
                            "surface": "mail",
                            "status": "partial",
                            "severity": "medium",
                            "collectors": ["google_gmail_settings"],
                            "error_classes": ["invalid_scope"],
                            "message": "mail coverage is partial; affected collectors: google_gmail_settings",
                        }
                    ],
                },
                "findings": [],
                "action_plan": [{"id": "finding-1", "title": "Fix sharing"}],
                "evidence_paths": [],
            }
        ),
        encoding="utf-8",
    )


def test_send_notification_builds_dry_run_payload(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)

    result = send_notification(run_dir=str(run_dir), sink="teams", dry_run=True)

    assert result["sink"] == "teams"
    assert result["dry_run"] is True
    assert result["payload"]["tenant_name"] == "acme"
    assert result["payload"]["open_count"] == 1
    assert result["payload"]["live_readiness"]["trust_level"] == "partial"
    assert result["payload"]["live_readiness"]["cannot_trust"] == ["google_reports", "google_gmail_settings"]
    assert result["payload"]["provider_scorecard"]["score"] == 80
    assert result["payload"]["coverage_gap_count"] == 1
    assert result["payload"]["coverage_gaps"][0]["error_classes"] == ["invalid_scope"]
    assert result["payload"]["action_plan"][0]["id"] == "finding-1"


def test_send_notification_posts_to_webhook_when_execute_enabled(tmp_path: Path, monkeypatch) -> None:
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)
    seen: dict[str, object] = {}

    class _Response:
        status_code = 200
        text = "ok"

    def _fake_post(url, json=None, timeout=None):  # noqa: ANN001
        seen["url"] = url
        seen["json"] = json
        seen["timeout"] = timeout
        return _Response()

    monkeypatch.setenv("AUDITEX_TEAMS_WEBHOOK_URL", "https://hooks.example.test/teams")
    monkeypatch.setattr("auditex.notify.requests.post", _fake_post)

    result = send_notification(run_dir=str(run_dir), sink="teams", dry_run=False)

    assert result["status"] == "sent"
    assert seen["url"] == "https://hooks.example.test/teams"
    assert seen["json"]["text"]
    assert "Live readiness: partial" in seen["json"]["text"]
    assert "Cannot trust: google_reports, google_gmail_settings" in seen["json"]["text"]
    assert "Scorecard: usable / 80" in seen["json"]["text"]
    assert "Coverage gaps: 1" in seen["json"]["text"]
    assert "mail coverage is partial; affected collectors: google_gmail_settings" in seen["json"]["text"]


def test_send_notification_falls_back_to_manifest_and_findings(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run-manifest.json").write_text(
        json.dumps({"tenant_name": "acme", "overall_status": "partial", "findings_count": 2, "blocker_count": 1}),
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "summary.md").write_text("# Audit Summary", encoding="utf-8")
    (run_dir / "findings").mkdir(exist_ok=True)
    (run_dir / "findings" / "findings.json").write_text(
        json.dumps(
            {
                "findings": [
                    {"id": "f1", "status": "open"},
                    {"id": "f2", "status": "accepted_risk"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = send_notification(run_dir=str(run_dir), sink="teams", dry_run=True)

    assert result["payload"]["tenant_name"] == "acme"
    assert result["payload"]["overall_status"] == "partial"
    assert result["payload"]["finding_count"] == 2
    assert result["payload"]["blocker_count"] == 1
    assert result["payload"]["open_count"] == 1
    assert result["payload"]["accepted_count"] == 1
    assert result["payload"]["report_pack_path"] is None
