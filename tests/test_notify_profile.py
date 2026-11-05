"""Notifications leave the machine for third-party services, so they use the customer-pack redaction profile.

Free text a waiver or finding carries (owner, justification, comment, comments, notes) must never reach a webhook
body, an SMTP message, a Jira payload or a GitHub payload; and no redaction call in ``notify.py`` may use a profile
weaker than ``customer_pack`` (decided by product, 5 Nov 2026).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_POLICY,
    PROFILE_SHAREABLE,
    PROFILES,
)
from auditex.output_writers import WRITER_INVENTORY

REPO_ROOT = Path(__file__).resolve().parents[1]
NOTIFY_SOURCE = REPO_ROOT / "src" / "auditex" / "notify.py"

# Planted text: each marker is unique so a leak is traceable to its key and depth.
MARKERS = {
    "owner": "PLANTED-OWNER-zq1 Priya Nairplanted",
    "justification": "PLANTED-JUSTIFICATION-zq2 legacy printer needs it",
    "comment": "PLANTED-COMMENT-zq3 approved by the CFO",
    "comments": "PLANTED-COMMENTS-zq4 see ticket",
    "notes": "PLANTED-NOTES-zq5 revisit in March",
    "deep": "PLANTED-DEEP-zq6 buried waiver text",
    "list_item": "PLANTED-LIST-zq7 first",
    "list_item2": "PLANTED-LIST-zq8 second",
    "nested_value": "PLANTED-NESTED-zq9 inside a container",
    "gap_owner": "PLANTED-GAPOWNER-zqa gap owner",
    "readiness_notes": "PLANTED-READINESS-zqb readiness note",
}


def _write_run_bundle(run_dir: Path) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run-manifest.json").write_text(
        json.dumps({"tenant_name": "acme", "live_readiness_path": "live-readiness.json"}), encoding="utf-8"
    )
    (run_dir / "summary.json").write_text(json.dumps({"collectors": []}), encoding="utf-8")
    (run_dir / "live-readiness.json").write_text(
        json.dumps(
            {
                "trust_level": "partial",
                "trusted_collectors": ["google_directory"],
                "cannot_trust": ["google_reports"],
                "notes": MARKERS["readiness_notes"],
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
                    "provider_scorecard": {"grade": "usable", "score": 80, "owner": MARKERS["owner"]},
                    "coverage_gaps": [
                        {
                            "surface": "mail",
                            "message": "mail coverage is partial",
                            "owner": MARKERS["gap_owner"],
                            "waiver": {"justification": MARKERS["justification"]},
                        }
                    ],
                },
                "findings": [],
                "action_plan": [
                    {
                        "id": "finding-1",
                        "title": "Fix sharing",
                        "owner": MARKERS["owner"],
                        "justification": MARKERS["justification"],
                        "comment": MARKERS["comment"],
                        "comments": [MARKERS["comments"], {"text": MARKERS["nested_value"]}],
                        "notes": {"a": [MARKERS["notes"], MARKERS["list_item"]], "b": (MARKERS["list_item2"],)},
                        "waiver": {"detail": {"deeper": {"Owner": MARKERS["deep"], "NOTES": [MARKERS["deep"] + "-2"]}}},
                    },
                    {"id": "finding-2", "title": "Second", "Justification": MARKERS["justification"] + "-b"},
                ],
                "evidence_paths": [],
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    path = tmp_path / "run"
    _write_run_bundle(path)
    return path


def _assert_no_planted_text(text: str) -> None:
    leaked = sorted(name for name, marker in MARKERS.items() if marker in text or marker.split()[0] in text)
    assert not leaked, f"free text reached a notification: {leaked}"


class _Response:
    def __init__(self, status_code: int = 201, body: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._body = body or {}
        self.text = json.dumps(self._body)

    def json(self) -> dict[str, Any]:
        return self._body


class _FakeSMTP:
    messages: list[Any] = []

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        pass

    def __enter__(self) -> "_FakeSMTP":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def has_extn(self, name: str) -> bool:
        return True

    def starttls(self, context: Any = None) -> None:
        return None

    def login(self, user: str, password: str) -> None:
        return None

    def send_message(self, message: Any) -> None:
        type(self).messages.append(message)


def _capture_http(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    import auditex.notify as notify_module

    sent: list[dict[str, Any]] = []

    def fake_post(url: str, json: Any = None, **kwargs: Any) -> _Response:  # noqa: A002
        sent.append({"url": url, "json": json, **{k: v for k, v in kwargs.items() if k != "auth"}})
        return _Response(201, {"key": "AUDIT-1", "number": 7, "html_url": "https://github.com/x/y/issues/7"})

    def fake_get(url: str, **kwargs: Any) -> _Response:
        return _Response(200, {"issues": [], "items": []})

    monkeypatch.setattr(notify_module.requests, "post", fake_post)
    monkeypatch.setattr(notify_module.requests, "get", fake_get)
    return sent


def test_the_planted_free_text_is_present_in_the_run_bundle(run_dir: Path) -> None:
    """Guard the fixture: the planted text really is read into the unredacted payload."""
    from auditex.notify import _build_payload

    built = json.dumps(_build_payload(run_dir), default=str)
    assert MARKERS["owner"] in built and MARKERS["comment"] in built and MARKERS["deep"] in built
    assert MARKERS["nested_value"] in built and MARKERS["notes"] in built and MARKERS["gap_owner"] in built


def test_free_text_is_redacted_from_the_dry_run_preview(run_dir: Path) -> None:
    from auditex.notify import send_notification

    for sink in ("teams", "slack", "smtp", "jira", "github"):
        result = send_notification(run_dir=str(run_dir), sink=sink, dry_run=True)
        _assert_no_planted_text(json.dumps(result, default=str))
        assert "<redacted-text>" in json.dumps(result)


@pytest.mark.parametrize("sink", ["teams", "slack"])
def test_free_text_never_reaches_a_webhook_body(run_dir: Path, monkeypatch: pytest.MonkeyPatch, sink: str) -> None:
    from auditex.notify import WEBHOOK_ENV, send_notification

    monkeypatch.setenv(WEBHOOK_ENV[sink], "https://hooks.example.invalid/x")
    sent = _capture_http(monkeypatch)
    result = send_notification(run_dir=str(run_dir), sink=sink, dry_run=False)
    assert result["status"] == "sent" and len(sent) == 1
    _assert_no_planted_text(json.dumps(sent[0]["json"]))
    _assert_no_planted_text(json.dumps(result, default=str))


def test_free_text_never_reaches_an_smtp_message(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_SMTP_HOST", "smtp.example.invalid")
    monkeypatch.setenv("AUDITEX_SMTP_TO", "auditor@example.invalid")
    _FakeSMTP.messages = []
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _FakeSMTP)
    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)
    assert result["status"] == "sent" and len(_FakeSMTP.messages) == 1
    message = _FakeSMTP.messages[0]
    _assert_no_planted_text(message.as_string() + str(message.get_content()))
    _assert_no_planted_text(json.dumps(result, default=str))


def test_free_text_never_reaches_a_jira_payload(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_JIRA_BASE_URL", "https://example.atlassian.invalid")
    monkeypatch.setenv("AUDITEX_JIRA_PROJECT_KEY", "AUDIT")
    monkeypatch.setenv("AUDITEX_JIRA_EMAIL", "bot@example.invalid")
    monkeypatch.setenv("AUDITEX_JIRA_API_TOKEN", "token-123")
    sent = _capture_http(monkeypatch)
    result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)
    assert result["status"] == "sent" and len(sent) == 1
    _assert_no_planted_text(json.dumps(sent[0]["json"]))
    _assert_no_planted_text(json.dumps(result, default=str))


def test_free_text_never_reaches_a_github_payload(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    monkeypatch.setenv("AUDITEX_GITHUB_TOKEN", "ghp_token")
    monkeypatch.setenv("AUDITEX_GITHUB_REPO", "example/example")
    sent = _capture_http(monkeypatch)
    result = notify_module.send_notification(run_dir=str(run_dir), sink="github", dry_run=False)
    assert result["status"] == "sent" and len(sent) == 1
    _assert_no_planted_text(json.dumps(sent[0]["json"]))
    _assert_no_planted_text(json.dumps(result, default=str))


def test_secrets_and_guids_stay_redacted_in_a_notification(run_dir: Path) -> None:
    from auditex.notify import send_notification

    guid = "3f2b8c1e-5a6d-4e7f-9a1b-2c3d4e5f6a7b"
    pack = run_dir / "reports" / "report-pack.json"
    data = json.loads(pack.read_text(encoding="utf-8"))
    query_value = "abcd" + "1234efgh"  # built at run time so no credential-shaped literal sits in the source
    query_key = "access" + "_token"
    data["action_plan"][0]["title"] = f"Fix {guid} via https://user:hunter2pw@host.example.invalid/x?{query_key}={query_value}"
    pack.write_text(json.dumps(data), encoding="utf-8")
    text = json.dumps(send_notification(run_dir=str(run_dir), sink="teams", dry_run=True), default=str)
    assert guid not in text and "hunter2pw" not in text and query_value not in text


# --- the profile of every redaction call in notify.py ---------------------------------------------------------

_REDACTION_FUNCTIONS = {"redact_output", "redact_for_run", "redact_payload"}


def _profile_name(node: ast.AST | None, constants: dict[str, str]) -> str | None:
    """The profile a ``profile=`` argument names, or ``None`` when it cannot be resolved statically."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _module_constants(tree: ast.Module) -> dict[str, str]:
    """Names bound to a profile: the imported ``PROFILE_*`` constants and module-level aliases of them."""
    import azure_tenant_audit.output_redaction as module

    constants = {name: getattr(module, name) for name in dir(module) if name.startswith("PROFILE_") and isinstance(getattr(module, name), str)}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            resolved = _profile_name(node.value, constants)
            if resolved is not None:
                constants[node.targets[0].id] = resolved
    return constants


def _at_least_customer_pack(name: str | None) -> bool:
    if name not in PROFILES:
        return False
    required = PROFILE_POLICY[PROFILE_CUSTOMER_PACK]
    policy, profile, base = PROFILE_POLICY[name], PROFILES[name], PROFILES[PROFILE_CUSTOMER_PACK]
    return (
        (policy.redact_free_text_keys or not required.redact_free_text_keys)
        and (policy.redact_guids or not required.redact_guids)
        and (policy.redact_domains or not required.redact_domains)
        and (policy.redact_group_names or not required.redact_group_names)
        and all(not getattr(base, field) or getattr(profile, field) for field in ("guids", "run_paths", "emails", "identities") if hasattr(base, field))
    )


def _weak_redaction_calls(source: str) -> list[str]:
    tree = ast.parse(source)
    constants = _module_constants(tree)
    problems: list[str] = []
    found = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        name = target.id if isinstance(target, ast.Name) else target.attr if isinstance(target, ast.Attribute) else ""
        if name not in _REDACTION_FUNCTIONS:
            continue
        found += 1
        profile = next((kw.value for kw in node.keywords if kw.arg == "profile"), None)
        if profile is None:
            problems.append(f"line {node.lineno}: {name} without profile= (the default is shareable)")
        elif not _at_least_customer_pack(_profile_name(profile, constants)):
            problems.append(f"line {node.lineno}: {name} with a profile weaker than customer_pack or not statically known")
    if not found:
        problems.append("no redaction call found")
    return problems


def test_no_notify_redaction_call_uses_a_profile_weaker_than_customer_pack() -> None:
    assert _weak_redaction_calls(NOTIFY_SOURCE.read_text(encoding="utf-8")) == []


def test_the_profile_guard_catches_weaker_or_missing_profiles() -> None:
    header = "from azure_tenant_audit.output_redaction import PROFILE_SHAREABLE, PROFILE_REPORT_PACK, PROFILE_CUSTOMER_PACK, redact_output\n"
    assert _weak_redaction_calls(header + "redact_output(x, profile=PROFILE_SHAREABLE)\n")
    assert _weak_redaction_calls(header + "redact_output(x, profile='shareable')\n")
    assert _weak_redaction_calls(header + "redact_output(x, profile=PROFILE_REPORT_PACK)\n")
    assert _weak_redaction_calls(header + "redact_output(x)\n")
    assert _weak_redaction_calls(header + "redact_output(x, profile=some_variable)\n")
    assert _weak_redaction_calls(header + "P = PROFILE_SHAREABLE\nredact_output(x, profile=P)\n")
    assert _weak_redaction_calls(header + "redact_output(x, profile=PROFILE_CUSTOMER_PACK)\n") == []
    assert _weak_redaction_calls(header + "P = PROFILE_CUSTOMER_PACK\nredact_output(x, profile=P)\n") == []


def test_the_guard_knows_customer_pack_is_stricter_than_shareable() -> None:
    assert _at_least_customer_pack(PROFILE_CUSTOMER_PACK)
    assert not _at_least_customer_pack(PROFILE_SHAREABLE)
    assert not _at_least_customer_pack("report_pack")
    assert not _at_least_customer_pack("unknown")


def test_the_writer_inventory_records_notifications_as_customer_pack() -> None:
    entry = next(item for item in WRITER_INVENTORY if item.module == "auditex.notify" and item.qualname == "send_notification")
    assert entry.profile == PROFILE_CUSTOMER_PACK


def test_notify_uses_the_one_shared_profile_constant() -> None:
    import auditex.notify as notify_module

    assert notify_module.NOTIFY_PROFILE == PROFILE_CUSTOMER_PACK
