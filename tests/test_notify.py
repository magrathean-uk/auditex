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
    assert "run-manifest.json" in [row["artifact_path"] for row in result["citations"]]
    assert "reports/report-pack.json" in [row["artifact_path"] for row in result["citations"]]
    assert "live-readiness.json" in [row["artifact_path"] for row in result["citations"]]
    assert result["evidence_missing"] == []


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
    assert "reports/report-pack.json" in result["evidence_missing"]
    assert "live-readiness.json" in result["evidence_missing"]


def test_send_notification_webhook_transport_error_does_not_leak_webhook_url(tmp_path: Path, monkeypatch) -> None:
    """R065: a transport failure must not surface the webhook URL (a credential) in the result or a traceback."""
    import requests

    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)
    secret_url = "https://hooks.slack.example.test/services/T000/B000/SECRETPART"
    teams_url = "https://flow.example.test/workflows/abc/triggers/manual?api-version=1&sig=SIGSECRET"

    def _fake_post(url, json=None, timeout=None):  # noqa: ANN001
        raise requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='hooks.slack.example.test', port=443): Max retries exceeded with url: {url}"
        )

    monkeypatch.setattr("auditex.notify.requests.post", _fake_post)
    for sink, env_name, url in (
        ("slack", "AUDITEX_SLACK_WEBHOOK_URL", secret_url),
        ("teams", "AUDITEX_TEAMS_WEBHOOK_URL", teams_url),
    ):
        monkeypatch.setenv(env_name, url)
        result = send_notification(run_dir=str(run_dir), sink=sink, dry_run=False)
        dumped = json.dumps(result)
        assert result["status"] == "failed"
        assert result["error_class"] == "ConnectionError"
        assert "SECRETPART" not in dumped
        assert "SIGSECRET" not in dumped
        assert "/services/" not in dumped


def test_notify_cli_webhook_transport_error_prints_no_webhook_url(tmp_path: Path, monkeypatch, capsys) -> None:
    """R065: the CLI path prints a failed result, not a traceback carrying the webhook path."""
    import requests

    from auditex.cli import main

    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)
    secret_url = "https://hooks.slack.example.test/services/T000/B000/SECRETPART"

    def _fake_post(url, json=None, timeout=None):  # noqa: ANN001
        raise requests.exceptions.ConnectionError(f"Max retries exceeded with url: {url}")

    monkeypatch.setenv("AUDITEX_SLACK_WEBHOOK_URL", secret_url)
    monkeypatch.setattr("auditex.notify.requests.post", _fake_post)
    exit_code = main(["notify", "send", str(run_dir), "--sink", "slack", "--execute"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "SECRETPART" not in captured.out + captured.err
    assert json.loads(captured.out)["status"] == "failed"


def test_send_notification_smtp_transport_error_returns_failed(tmp_path: Path, monkeypatch) -> None:
    """R065: an SMTP connection failure becomes a failed result instead of an uncaught traceback."""
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)

    def _refuse(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setenv("AUDITEX_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("AUDITEX_SMTP_TO", "ops@example.test")
    monkeypatch.setattr("auditex.notify.smtplib.SMTP", _refuse)
    result = send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)
    assert result["status"] == "failed"
    assert result["error_class"] == "ConnectionRefusedError"


def test_send_notification_webhook_error_body_echoing_url_is_scrubbed(tmp_path: Path, monkeypatch) -> None:
    """R065 (review): a 4xx body that echoes the webhook path or query does not reach the result."""
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)
    secret_url = "https://hooks.slack.example.test/services/T000/B000/SECRETPART?sig=SIGSECRET"

    class _Response:
        status_code = 404
        text = "no_service: POST /services/T000/B000/SECRETPART?sig=SIGSECRET not found"

    monkeypatch.setenv("AUDITEX_SLACK_WEBHOOK_URL", secret_url)
    monkeypatch.setattr("auditex.notify.requests.post", lambda *_a, **_k: _Response())
    result = send_notification(run_dir=str(run_dir), sink="slack", dry_run=False)
    dumped = json.dumps(result)
    assert result["status"] == "failed" and result["http_status"] == 404
    assert "SECRETPART" not in dumped and "SIGSECRET" not in dumped
    assert result["response_text"] == "HTTP 404"


def test_send_notification_webhook_error_reply_keeps_only_a_short_code(tmp_path: Path, monkeypatch) -> None:
    """R065 (review round 2): a failing reply is kept only when it is a short service code; anything else (a
    JSON-escaped echo of the path) becomes a fixed diagnostic."""
    run_dir = tmp_path / "run"
    _write_run_bundle(run_dir)
    monkeypatch.setenv("AUDITEX_SLACK_WEBHOOK_URL", "https://hooks.slack.example.test/services/T000/B000/SECRETPART")
    replies = iter(['{"path": "\\/services\\/T000\\/B000\\/SECRETPART"}', "invalid_token"])

    class _Response:
        status_code = 403

        @property
        def text(self) -> str:
            return next(replies)

    monkeypatch.setattr("auditex.notify.requests.post", lambda *_a, **_k: _Response())
    first = send_notification(run_dir=str(run_dir), sink="slack", dry_run=False)
    assert "SECRETPART" not in json.dumps(first) and first["response_text"] == "HTTP 403"
    second = send_notification(run_dir=str(run_dir), sink="slack", dry_run=False)
    assert second["response_text"] == "invalid_token"


# Dedup search replies (bot review, PR 168) ----------------------------------------------------------------------------

class _SearchReply:
    def __init__(self, body: object) -> None:
        self.status_code = 200
        self._body = body

    def json(self) -> object:
        return self._body


def _search_with(monkeypatch, body: object) -> None:
    import auditex.notify as notify

    monkeypatch.setattr(notify.requests, "get", lambda *args, **kwargs: _SearchReply(body))


def test_jira_dedup_search_reports_a_malformed_first_hit_as_failed(monkeypatch) -> None:
    """A 200 reply whose first hit is not a usable issue is not a clean miss: dedup must show as skipped."""
    from auditex.notify import _SEARCH_FAILED, _jira_search_existing

    for issues in ([None], [{}], [{"key": ""}], [{"key": 7}], [{"key": "not a key"}], [{"key": "SEC-0"}], [{"key": "SEC"}]):
        _search_with(monkeypatch, {"issues": issues})
        assert _jira_search_existing("https://jira.example", "SEC", "label", ("u", "t")) == (None, _SEARCH_FAILED)


def test_jira_dedup_search_keeps_an_empty_result_and_a_real_hit(monkeypatch) -> None:
    from auditex.notify import _jira_search_existing

    for body in ({"issues": []}, {}):
        _search_with(monkeypatch, body)
        assert _jira_search_existing("https://jira.example", "SEC", "label", ("u", "t")) == (None, None)
    _search_with(monkeypatch, {"issues": [{"key": "SEC-12"}]})
    assert _jira_search_existing("https://jira.example", "SEC", "label", ("u", "t")) == ("SEC-12", None)


def test_github_dedup_search_reports_a_malformed_first_hit_as_failed(monkeypatch) -> None:
    from auditex.notify import _SEARCH_FAILED, _github_search_existing_issue

    for items in ([None], ["x"], [{}], [{"number": 0}], [{"number": -1}], [{"number": True}]):
        _search_with(monkeypatch, {"items": items})
        assert _github_search_existing_issue("https://api.github.example", "o/r", "fp", "t") == (None, None, _SEARCH_FAILED)


def test_github_dedup_search_keeps_an_empty_result_and_a_real_hit(monkeypatch) -> None:
    from auditex.notify import _github_search_existing_issue

    for body in ({"items": []}, {}):
        _search_with(monkeypatch, body)
        assert _github_search_existing_issue("https://api.github.example", "o/r", "fp", "t") == (None, None, None)
    _search_with(monkeypatch, {"items": [{"number": 4, "html_url": "https://github.example/o/r/issues/4"}]})
    assert _github_search_existing_issue("https://api.github.example", "o/r", "fp", "t") == (
        4, "https://github.example/o/r/issues/4", None
    )
