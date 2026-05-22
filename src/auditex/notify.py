from __future__ import annotations

import hashlib
import json
import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import requests

from .run_bundle import RunBundle


# E4 redaction: any token-shaped string in an outbound webhook body gets
# replaced before the body leaves the process. Webhook channels (Teams,
# Slack) frequently get archived to long-lived stores (chat history,
# email digests, third-party loggers) — once a credential lands there it
# might never be rotated. Defence-in-depth: assume any long base64 blob
# or JWT-shaped string in a finding's evidence is sensitive and redact
# regardless of whether the key name was on the existing sensitive-key
# allowlist.
_REDACTION_PLACEHOLDER = "[REDACTED]"
_TOKEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # OAuth Authorization headers: ``Authorization: Bearer <token>`` and
    # bare ``Bearer <token>``.
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-+=/]{8,}", re.IGNORECASE), "Bearer [REDACTED]"),
    # JWTs (header.payload.signature, base64url everywhere). The header
    # almost always starts with ``eyJ`` (decoded ``{"``).
    (re.compile(r"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]+"), "[REDACTED-JWT]"),
    # Long base64 blobs — DSC export payloads, encrypted credential blobs,
    # PFX-encoded certificates. 200 chars is well above any legitimate
    # short ID / display name and short of a full RSA key dump.
    (re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), "[REDACTED-BLOB]"),
]
# Sensitive key names whose VALUES (regardless of shape) get fully
# replaced. Mirrors the contracts.py sensitive-keys regex but scoped
# tightly to credentials that should never leave the auditex host.
_SENSITIVE_VALUE_KEY_RE = re.compile(
    r"^(?:client[_-]?secret|secret[_-]?text|app[_-]?secret|password|"
    r"access[_-]?token|refresh[_-]?token|api[_-]?token|api[_-]?key|"
    r"dsc[_-]?export|key[_-]?material)$",
    re.IGNORECASE,
)


def _redact_string(value: str) -> str:
    out = value
    for pattern, replacement in _TOKEN_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _redact_value(value: Any, current_key: str = "") -> Any:
    """Walk ``value`` and redact token-shaped strings.

    For dict keys that match a sensitive-key name, the entire value is
    replaced with the placeholder regardless of shape (catches values
    that are short / ID-like / not yet token-formatted).
    """
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key_text = str(k)
            if _SENSITIVE_VALUE_KEY_RE.match(key_text) and v not in (None, ""):
                out[key_text] = _REDACTION_PLACEHOLDER
            else:
                out[key_text] = _redact_value(v, key_text)
        return out
    if isinstance(value, list):
        return [_redact_value(item, current_key) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, current_key) for item in value)
    return value


def _run_fingerprint(payload: dict[str, Any]) -> str:
    """Stable per-run fingerprint used to dedup notify-sink tickets.

    Hash includes tenant_name + run_dir basename so re-running ``auditex
    notify send`` against the same bundle hits the deduplication path
    instead of creating a fresh ticket on each invocation.

    The 16-char hex prefix is short enough to embed in a Jira label
    (50-char max per label) and long enough that collisions across an
    operator's portfolio are vanishingly unlikely.
    """
    tenant = str(payload.get("tenant_name") or "")
    run_dir = str(payload.get("run_dir") or "")
    digest = hashlib.sha256(f"{tenant}|{run_dir}".encode("utf-8")).hexdigest()
    return digest[:16]


def _audit_fingerprint_label(payload: dict[str, Any]) -> str:
    return f"auditex-fp-{_run_fingerprint(payload)}"


def _jira_search_existing(
    base_url: str, project_key: str, label: str, auth: tuple[str, str]
) -> str | None:
    """Look up an existing Auditex issue with the dedup label.

    Any error (network, auth failure, malformed response) → ``None``,
    causing the caller to fall through to create the issue. Failing
    closed would silently drop notifications during a transient Jira
    outage; failing open creates one ticket per run, which is the
    pre-E1 behaviour.
    """
    jql = f'project = "{project_key}" AND labels = "{label}"'
    url = f"{base_url.rstrip('/')}/rest/api/3/search"
    try:
        response = requests.get(
            url,
            params={"jql": jql, "fields": "summary", "maxResults": 1},
            headers={"accept": "application/json"},
            auth=auth,
            timeout=15,
        )
    except Exception:  # noqa: BLE001
        return None
    if response.status_code >= 400:
        return None
    try:
        issues = response.json().get("issues") or []
    except (ValueError, AttributeError, TypeError):
        return None
    if not isinstance(issues, list) or not issues:
        return None
    first = issues[0]
    if not isinstance(first, dict):
        return None
    key = first.get("key")
    return str(key) if key else None


WEBHOOK_ENV = {
    "teams": "AUDITEX_TEAMS_WEBHOOK_URL",
    "slack": "AUDITEX_SLACK_WEBHOOK_URL",
}


def _build_payload(run_dir: str | Path) -> dict[str, Any]:
    bundle = RunBundle(run_dir)
    report_summary = bundle.report_summary()
    action_plan = bundle.action_plan_rows()
    manifest = bundle.manifest()
    findings_rows = bundle.finding_rows()
    report_pack_path, _ = bundle.report_pack()
    action_plan_path, _ = bundle.action_plan()
    _, live_readiness_raw = bundle.live_readiness()
    live_readiness = dict(live_readiness_raw) if isinstance(live_readiness_raw, dict) else {}
    open_count = sum(1 for item in findings_rows if isinstance(item, dict) and item.get("status") == "open")
    accepted_count = sum(1 for item in findings_rows if isinstance(item, dict) and item.get("status") == "accepted_risk")
    coverage_gaps = [
        dict(item)
        for item in (report_summary.get("coverage_gaps") or manifest.get("coverage_gaps") or [])
        if isinstance(item, dict)
    ]
    provider_scorecard = (
        dict(report_summary.get("provider_scorecard"))
        if isinstance(report_summary.get("provider_scorecard"), dict)
        else dict(manifest.get("provider_scorecard"))
        if isinstance(manifest.get("provider_scorecard"), dict)
        else {}
    )
    return {
        "run_dir": str(run_dir),
        "tenant_name": report_summary.get("tenant_name") or manifest.get("tenant_name"),
        "overall_status": report_summary.get("overall_status") or manifest.get("overall_status"),
        "finding_count": report_summary.get("finding_count", manifest.get("findings_count", len(findings_rows))),
        "blocker_count": report_summary.get("blocker_count", manifest.get("blocker_count", 0)),
        "open_count": report_summary.get("open_count", open_count),
        "accepted_count": report_summary.get("accepted_count", accepted_count),
        "provider_scorecard": provider_scorecard,
        "live_readiness": live_readiness,
        "coverage_gap_count": len(coverage_gaps),
        "coverage_gaps": coverage_gaps,
        "action_plan": action_plan,
        "report_pack_path": str(report_pack_path) if report_pack_path is not None else None,
        "action_plan_path": str(action_plan_path) if action_plan_path is not None else None,
    }


def _payload_text(payload: dict[str, Any], sink: str) -> str:
    lines = [
        f"Auditex {sink} notification",
        f"Tenant: {payload.get('tenant_name') or 'unknown'}",
        f"Status: {payload.get('overall_status') or 'unknown'}",
        f"Findings: {payload.get('finding_count', 0)}",
        f"Open: {payload.get('open_count', 0)}",
        f"Blockers: {payload.get('blocker_count', 0)}",
    ]
    provider_scorecard = payload.get("provider_scorecard") if isinstance(payload.get("provider_scorecard"), dict) else {}
    if provider_scorecard:
        lines.append(f"Scorecard: {provider_scorecard.get('grade') or 'unknown'} / {provider_scorecard.get('score', 0)}")
    live_readiness = payload.get("live_readiness") if isinstance(payload.get("live_readiness"), dict) else {}
    if live_readiness:
        lines.append(f"Live readiness: {live_readiness.get('trust_level') or 'unknown'}")
        cannot_trust = live_readiness.get("cannot_trust") or []
        if cannot_trust:
            lines.append("Cannot trust: " + ", ".join(str(item) for item in cannot_trust[:5]))
    coverage_gaps = payload.get("coverage_gaps") or []
    if coverage_gaps:
        lines.append(f"Coverage gaps: {payload.get('coverage_gap_count', len(coverage_gaps))}")
        for gap in coverage_gaps[:3]:
            if isinstance(gap, dict):
                lines.append(f"- {gap.get('message') or gap.get('surface') or 'coverage gap'}")
    action_plan = payload.get("action_plan") or []
    if action_plan:
        lines.append(f"Top action: {action_plan[0].get('title') or action_plan[0].get('id')}")
    return "\n".join(lines)


def _send_webhook(sink: str, payload: dict[str, Any]) -> dict[str, Any]:
    env_name = WEBHOOK_ENV[sink]
    url = os.environ.get(env_name)
    if not url:
        return {"status": "blocked", "reason": f"{env_name} is not set", "payload": payload}
    # E4: redact every token-shaped string and every sensitive-key value
    # before the body crosses the process boundary. Both the rendered
    # text and the embedded JSON payload pass through the same walker
    # so adversarial values in finding evidence never reach Teams/Slack.
    redacted_payload = _redact_value(payload)
    body = {
        "text": _redact_string(_payload_text(redacted_payload, sink)),
        "auditex": redacted_payload,
    }
    response = requests.post(url, json=body, timeout=15)
    return {
        "status": "sent" if response.status_code < 400 else "failed",
        "sink": sink,
        "payload": payload,
        "http_status": response.status_code,
        "response_text": response.text,
    }


def _smtp_ssl_context(allow_self_signed: bool) -> ssl.SSLContext:
    """Build the TLS context the SMTP sink uses for STARTTLS.

    Default: ``ssl.create_default_context()`` — strict verification,
    hostname check enabled, system CA bundle. Suitable for any
    properly-configured outbound relay.

    Opt-in: ``AUDITEX_SMTP_ALLOW_SELF_SIGNED=1`` relaxes both checks.
    Used only for lab / pre-prod relays with non-public CA chains.
    The relaxation surfaces in the response payload so audit trails
    capture the elevated risk.
    """
    context = ssl.create_default_context()
    if allow_self_signed:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _send_smtp(payload: dict[str, Any]) -> dict[str, Any]:
    host = os.environ.get("AUDITEX_SMTP_HOST")
    to_addr = os.environ.get("AUDITEX_SMTP_TO")
    from_addr = os.environ.get("AUDITEX_SMTP_FROM", "auditex@localhost")
    if not host or not to_addr:
        return {
            "status": "blocked",
            "reason": "AUDITEX_SMTP_HOST and AUDITEX_SMTP_TO are required",
            "payload": payload,
        }
    port = int(os.environ.get("AUDITEX_SMTP_PORT", "25"))
    allow_self_signed = os.environ.get("AUDITEX_SMTP_ALLOW_SELF_SIGNED", "") == "1"
    smtp_user = os.environ.get("AUDITEX_SMTP_USER")
    smtp_password = os.environ.get("AUDITEX_SMTP_PASSWORD")

    message = EmailMessage()
    message["Subject"] = f"Auditex report for {payload.get('tenant_name') or 'tenant'}"
    message["From"] = from_addr
    message["To"] = to_addr
    message.set_content(_payload_text(payload, "smtp") + "\n\n" + json.dumps(payload, indent=2))

    context = _smtp_ssl_context(allow_self_signed)
    starttls_used = False
    try:
        with smtplib.SMTP(host, port, timeout=15) as client:
            client.ehlo()
            if not client.has_extn("STARTTLS"):
                # E3 contract: refuse to send credentials/findings over a
                # plaintext channel. Operators who genuinely need plaintext
                # delivery should run an internal relay that wraps STARTTLS.
                return {
                    "status": "failed",
                    "sink": "smtp",
                    "payload": payload,
                    "reason": (
                        f"SMTP server {host}:{port} does not advertise STARTTLS; "
                        "auditex refuses to send findings in plaintext"
                    ),
                }
            client.starttls(context=context)
            client.ehlo()
            starttls_used = True
            if smtp_user and smtp_password:
                client.login(smtp_user, smtp_password)
            client.send_message(message)
    except ssl.SSLError as exc:
        return {
            "status": "failed",
            "sink": "smtp",
            "payload": payload,
            "reason": (
                f"SMTP TLS handshake failed: {exc}. Set "
                "AUDITEX_SMTP_ALLOW_SELF_SIGNED=1 if you understand the risk."
            ),
        }
    return {
        "status": "sent",
        "sink": "smtp",
        "payload": payload,
        "starttls_used": starttls_used,
        "tls_verification_relaxed": allow_self_signed,
    }


def _ticket_summary_text(payload: dict[str, Any]) -> str:
    finding_count = payload.get("finding_count", 0)
    open_count = payload.get("open_count", 0)
    return (
        f"Auditex audit for **{payload.get('tenant_name') or 'tenant'}** finished with "
        f"status `{payload.get('overall_status') or 'unknown'}`. "
        f"Findings: {finding_count} (open: {open_count}). "
        f"Top action: {(payload.get('action_plan') or [{}])[0].get('title') or 'n/a'}."
    )


def _send_jira(payload: dict[str, Any]) -> dict[str, Any]:
    base_url = os.environ.get("AUDITEX_JIRA_BASE_URL")
    project_key = os.environ.get("AUDITEX_JIRA_PROJECT_KEY")
    email = os.environ.get("AUDITEX_JIRA_EMAIL")
    token = os.environ.get("AUDITEX_JIRA_API_TOKEN")
    issue_type = os.environ.get("AUDITEX_JIRA_ISSUE_TYPE", "Task")
    missing = [
        var
        for var, value in (
            ("AUDITEX_JIRA_BASE_URL", base_url),
            ("AUDITEX_JIRA_PROJECT_KEY", project_key),
            ("AUDITEX_JIRA_EMAIL", email),
            ("AUDITEX_JIRA_API_TOKEN", token),
        )
        if not value
    ]
    if missing:
        return {
            "status": "blocked",
            "sink": "jira",
            "reason": f"missing env: {', '.join(missing)}",
            "payload": payload,
        }
    summary = f"[Auditex] {payload.get('tenant_name') or 'tenant'} run – {payload.get('finding_count', 0)} findings"
    fingerprint = _run_fingerprint(payload)
    dedup_label = _audit_fingerprint_label(payload)
    auth = (email, token)

    # E1 dedup: re-running notify against the same bundle must not create a
    # second Jira issue. Search by stable fingerprint label; skip create when
    # found. Search failures fall through to create (fail-open) so a transient
    # Jira outage never silently drops a notification.
    existing_key = _jira_search_existing(base_url, project_key, dedup_label, auth)
    if existing_key:
        return {
            "status": "deduped",
            "sink": "jira",
            "payload": payload,
            "issue_key": existing_key,
            "fingerprint": fingerprint,
        }

    body = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:250],
            "issuetype": {"name": issue_type},
            "labels": ["auditex", dedup_label],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": _ticket_summary_text(payload)}],
                    },
                    {
                        "type": "codeBlock",
                        "attrs": {"language": "json"},
                        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    },
                ],
            },
        }
    }
    url = f"{base_url.rstrip('/')}/rest/api/3/issue"
    response = requests.post(
        url,
        json=body,
        headers={"accept": "application/json", "content-type": "application/json"},
        auth=auth,
        timeout=15,
    )
    issue_key: str | None = None
    if response.status_code < 400:
        try:
            issue_key = response.json().get("key")
        except (ValueError, AttributeError):
            issue_key = None
    return {
        "status": "sent" if response.status_code < 400 else "failed",
        "sink": "jira",
        "payload": payload,
        "http_status": response.status_code,
        "response_text": response.text,
        "issue_key": issue_key,
        "fingerprint": fingerprint,
    }


def _github_search_existing_issue(
    api_root: str, repo: str, fingerprint_token: str, token: str
) -> tuple[int | None, str | None]:
    """Search GitHub for an open issue whose title contains the dedup
    token. Returns ``(issue_number, html_url)`` when found, ``(None, None)``
    on miss or error (fail-open).
    """
    query = f'repo:{repo} is:issue in:title "{fingerprint_token}"'
    url = f"{api_root.rstrip('/')}/search/issues"
    try:
        response = requests.get(
            url,
            params={"q": query, "per_page": 1},
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15,
        )
    except Exception:  # noqa: BLE001
        return None, None
    if response.status_code >= 400:
        return None, None
    try:
        items = response.json().get("items") or []
    except (ValueError, AttributeError, TypeError):
        return None, None
    if not isinstance(items, list) or not items:
        return None, None
    first = items[0]
    if not isinstance(first, dict):
        return None, None
    number = first.get("number")
    html_url = first.get("html_url")
    return (int(number) if number is not None else None, str(html_url) if html_url else None)


def _send_github(payload: dict[str, Any]) -> dict[str, Any]:
    token = os.environ.get("AUDITEX_GITHUB_TOKEN")
    repo = os.environ.get("AUDITEX_GITHUB_REPO")
    api_root = os.environ.get("AUDITEX_GITHUB_API_ROOT", "https://api.github.com")
    labels_env = os.environ.get("AUDITEX_GITHUB_LABELS", "auditex")
    missing = [
        var
        for var, value in (
            ("AUDITEX_GITHUB_TOKEN", token),
            ("AUDITEX_GITHUB_REPO", repo),
        )
        if not value
    ]
    if missing:
        return {
            "status": "blocked",
            "sink": "github",
            "reason": f"missing env: {', '.join(missing)}",
            "payload": payload,
        }
    fingerprint = _run_fingerprint(payload)
    fingerprint_token = f"fp:{fingerprint}"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    title = (
        f"[Auditex] {payload.get('tenant_name') or 'tenant'} run – "
        f"{payload.get('finding_count', 0)} findings ({fingerprint_token})"
    )
    body_lines = [_ticket_summary_text(payload), "", "```json", json.dumps(payload, indent=2), "```"]
    issue_body_text = "\n".join(body_lines)

    # E2 dedup: search for an existing issue whose title contains the
    # fingerprint token. If found, append a comment instead of creating
    # a duplicate. Search failures fall through to create (fail-open).
    existing_number, existing_url = _github_search_existing_issue(
        api_root, repo, fingerprint_token, token
    )
    if existing_number is not None:
        comment_url = (
            f"{api_root.rstrip('/')}/repos/{repo}/issues/{existing_number}/comments"
        )
        comment_response = requests.post(
            comment_url,
            json={"body": issue_body_text},
            headers=headers,
            timeout=15,
        )
        if comment_response.status_code < 400:
            return {
                "status": "commented",
                "sink": "github",
                "payload": payload,
                "http_status": comment_response.status_code,
                "response_text": comment_response.text,
                "issue_number": existing_number,
                "issue_url": existing_url,
                "fingerprint": fingerprint,
            }
        # Comment failed — return a structured failure rather than fall
        # through and create a duplicate issue.
        return {
            "status": "failed",
            "sink": "github",
            "payload": payload,
            "http_status": comment_response.status_code,
            "response_text": comment_response.text,
            "issue_number": existing_number,
            "issue_url": existing_url,
            "fingerprint": fingerprint,
        }

    body = {
        "title": title[:250],
        "body": issue_body_text,
        "labels": [label.strip() for label in labels_env.split(",") if label.strip()],
    }
    url = f"{api_root.rstrip('/')}/repos/{repo}/issues"
    response = requests.post(
        url,
        json=body,
        headers=headers,
        timeout=15,
    )
    issue_number: int | None = None
    issue_url: str | None = None
    if response.status_code < 400:
        try:
            data = response.json()
            issue_number = data.get("number")
            issue_url = data.get("html_url")
        except (ValueError, AttributeError):
            issue_number = None
    return {
        "status": "sent" if response.status_code < 400 else "failed",
        "sink": "github",
        "payload": payload,
        "http_status": response.status_code,
        "response_text": response.text,
        "issue_number": issue_number,
        "issue_url": issue_url,
        "fingerprint": fingerprint,
    }


def send_notification(*, run_dir: str, sink: str, dry_run: bool = True) -> dict[str, Any]:
    payload = _build_payload(run_dir)
    if dry_run:
        return {"status": "planned", "sink": sink, "dry_run": True, "payload": payload}
    if sink in WEBHOOK_ENV:
        result = _send_webhook(sink, payload)
        result["dry_run"] = False
        return result
    if sink == "smtp":
        result = _send_smtp(payload)
        result["dry_run"] = False
        return result
    if sink == "jira":
        result = _send_jira(payload)
        result["dry_run"] = False
        return result
    if sink == "github":
        result = _send_github(payload)
        result["dry_run"] = False
        return result
    return {"status": "blocked", "sink": sink, "dry_run": False, "reason": "unsupported sink", "payload": payload}
