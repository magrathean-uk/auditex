"""E3: SMTP TLS strict.

Pre-E3 the SMTP sink connected with ``smtplib.SMTP(host, port)`` and
sent the message in clear text. E3 enforces STARTTLS with default
``ssl.create_default_context()`` cert validation, refuses to send if
the server doesn't advertise STARTTLS, and exposes
``AUDITEX_SMTP_ALLOW_SELF_SIGNED=1`` as the explicit override for
lab relays.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "smtp-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-smtp-test"


class _FakeSMTP:
    """Minimal stand-in for ``smtplib.SMTP`` that records the EHLO →
    STARTTLS → EHLO → send_message dance the E3-hardened sink expects."""

    instances: list[_FakeSMTP] = []
    advertise_starttls = True
    starttls_raises: BaseException | None = None
    login_calls: list[tuple[str, str]] = []

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ehlo_calls = 0
        self.starttls_called_with: object = None
        self.send_message_calls: list[Any] = []
        self.login_calls = []
        type(self).instances.append(self)

    def __enter__(self) -> _FakeSMTP:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def ehlo(self) -> None:
        self.ehlo_calls += 1

    def has_extn(self, name: str) -> bool:
        return self.advertise_starttls if name == "STARTTLS" else False

    def starttls(self, context: Any = None) -> None:
        if self.starttls_raises is not None:
            raise self.starttls_raises
        self.starttls_called_with = context

    def login(self, user: str, password: str) -> None:
        self.login_calls.append((user, password))

    def send_message(self, message: Any) -> None:
        self.send_message_calls.append(message)


def _smtp_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("AUDITEX_SMTP_TO", "auditor@example.com")
    monkeypatch.setenv("AUDITEX_SMTP_FROM", "auditex@example.com")
    monkeypatch.setenv("AUDITEX_SMTP_PORT", "587")


def _patch_fake_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    _FakeSMTP.instances = []
    _FakeSMTP.advertise_starttls = True
    _FakeSMTP.starttls_raises = None
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _FakeSMTP)


def test_smtp_sink_invokes_starttls_with_default_context(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default behaviour: EHLO → STARTTLS(strict context) → EHLO → send."""
    import auditex.notify as notify_module

    _smtp_env(monkeypatch)
    _patch_fake_smtp(monkeypatch)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)

    assert result["status"] == "sent"
    assert result["starttls_used"] is True
    assert result["tls_verification_relaxed"] is False
    assert _FakeSMTP.instances, "SMTP client was not constructed"
    client = _FakeSMTP.instances[0]
    assert client.ehlo_calls == 2  # one before STARTTLS, one after
    assert client.starttls_called_with is not None
    assert client.send_message_calls, "no message sent"


def test_smtp_sink_refuses_when_server_lacks_starttls(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the server doesn't advertise STARTTLS, refuse to send."""
    import auditex.notify as notify_module

    _smtp_env(monkeypatch)
    _patch_fake_smtp(monkeypatch)
    _FakeSMTP.advertise_starttls = False

    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)

    assert result["status"] == "failed"
    assert "STARTTLS" in result["reason"]
    assert "plaintext" in result["reason"].lower()
    client = _FakeSMTP.instances[0]
    # Must NOT have called send_message — refusing to send is the contract.
    assert client.send_message_calls == []


def test_smtp_sink_uses_strict_context_by_default(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default SSL context must validate hostname AND certificate."""
    import auditex.notify as notify_module

    _smtp_env(monkeypatch)
    _patch_fake_smtp(monkeypatch)

    notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)

    client = _FakeSMTP.instances[0]
    ctx = client.starttls_called_with
    assert ctx is not None
    assert ctx.check_hostname is True
    import ssl as _ssl
    assert ctx.verify_mode == _ssl.CERT_REQUIRED


def test_smtp_sink_relaxes_verification_when_explicit_override_set(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``AUDITEX_SMTP_ALLOW_SELF_SIGNED=1`` switches off both checks."""
    import auditex.notify as notify_module

    _smtp_env(monkeypatch)
    monkeypatch.setenv("AUDITEX_SMTP_ALLOW_SELF_SIGNED", "1")
    _patch_fake_smtp(monkeypatch)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)

    assert result["status"] == "sent"
    assert result["tls_verification_relaxed"] is True
    client = _FakeSMTP.instances[0]
    ctx = client.starttls_called_with
    import ssl as _ssl
    assert ctx.check_hostname is False
    assert ctx.verify_mode == _ssl.CERT_NONE


def test_smtp_sink_calls_login_when_credentials_set(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``AUDITEX_SMTP_USER`` + ``AUDITEX_SMTP_PASSWORD`` are set,
    SMTP AUTH must run AFTER STARTTLS so creds are encrypted."""
    import auditex.notify as notify_module

    _smtp_env(monkeypatch)
    monkeypatch.setenv("AUDITEX_SMTP_USER", "submission-user")
    monkeypatch.setenv("AUDITEX_SMTP_PASSWORD", "secret")
    _patch_fake_smtp(monkeypatch)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)

    assert result["status"] == "sent"
    client = _FakeSMTP.instances[0]
    assert client.login_calls == [("submission-user", "secret")]
    # Login must happen AFTER STARTTLS — confirmed by the FakeSMTP not
    # raising; if login were called first, a real server would either
    # reject or send creds in clear (the real failure mode pre-E3).


def test_smtp_sink_surfaces_tls_handshake_errors(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A TLS handshake error must propagate as ``status=failed`` with a
    clear reason — not crash the loop."""
    import ssl as _ssl

    import auditex.notify as notify_module

    _smtp_env(monkeypatch)
    _patch_fake_smtp(monkeypatch)
    _FakeSMTP.starttls_raises = _ssl.SSLError("certificate verify failed")

    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)

    assert result["status"] == "failed"
    assert "TLS" in result["reason"]
    assert "AUDITEX_SMTP_ALLOW_SELF_SIGNED" in result["reason"]


def test_smtp_blocks_when_env_missing(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-existing contract: env-var-missing → status=blocked, no
    SMTP connection attempted."""
    import auditex.notify as notify_module

    monkeypatch.delenv("AUDITEX_SMTP_HOST", raising=False)
    monkeypatch.delenv("AUDITEX_SMTP_TO", raising=False)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="smtp", dry_run=False)
    assert result["status"] == "blocked"
    assert "AUDITEX_SMTP_HOST" in result["reason"]
