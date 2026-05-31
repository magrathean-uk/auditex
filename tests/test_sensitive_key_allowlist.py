"""Regression: sensitive-key regex allowlist for legitimate compound names.

Live audit on 2026-05-09 surfaced ``authorization_policy`` (a Microsoft Entra
resource) as a false positive in the AI-safe / contract-artifact validators.
The fix is an allowlist of ``authorization_*`` and ``credential_*`` compound
names that contain a sensitive-key token but are not credentials themselves.
"""
from __future__ import annotations

import json
from pathlib import Path

from azure_tenant_audit.contracts import build_validation_report


def _bundle(tmp_path: Path) -> Path:
    from auditex.notify import _build_payload  # noqa: F401  (just to ensure import path works)

    from test_finalize_idempotent import _prepare_bundle_for_finalize
    from azure_tenant_audit.finalize import finalize_bundle_contract

    writer, kwargs = _prepare_bundle_for_finalize(tmp_path)
    finalize_bundle_contract(**kwargs)
    return writer.run_dir


def _write_ai_safe_with_field(run_dir: Path, key: str, value: object) -> None:
    """Inject a key into ai_safe/run_summary.json so the validator walks it."""
    path = run_dir / "ai_safe" / "run_summary.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[key] = value
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_authorization_policy_key_is_not_flagged_as_sensitive(tmp_path: Path) -> None:
    """``authorization_policy`` is a Microsoft Entra resource, not a credential.
    Live audit fixture surfaced this false positive."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(run_dir, "authorization_policy", {"some": "config"})

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" not in codes, report["issues"]


def test_credential_method_key_is_not_flagged_as_sensitive(tmp_path: Path) -> None:
    """``credential_methods`` describes auth method types — not the credentials
    themselves. Should pass the allowlist."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(run_dir, "credential_methods", ["password", "fido2"])

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" not in codes


def test_actual_authorization_header_value_still_flagged(tmp_path: Path) -> None:
    """The value-pattern regex must still catch real Bearer tokens —
    the allowlist is for keys, not values."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(
        run_dir, "leak", "Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.signature"
    )

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" in codes, "real bearer token must still be flagged"


def test_actual_credential_token_key_still_flagged(tmp_path: Path) -> None:
    """``access_token`` as a key is still credential-ish — must be flagged."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(run_dir, "access_token", "redacted")

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" in codes


def test_credential_provider_key_is_allowlisted(tmp_path: Path) -> None:
    """``credential_provider`` describes which provider is in use, not the
    credential value itself."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(run_dir, "credential_provider", "azure-cli")

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" not in codes


def test_password_credentials_key_is_allowlisted(tmp_path: Path) -> None:
    """Credential inventory metadata can use ``*_credentials`` keys without
    carrying any secret values."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(
        run_dir,
        "password_credentials",
        [{"key_id": "k1", "end_date_time": "2099-01-01T00:00:00Z"}],
    )

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" not in codes, report["issues"]


def test_application_credential_objects_key_is_allowlisted(tmp_path: Path) -> None:
    """Normalized section names for app inventory are metadata, not secrets."""
    run_dir = _bundle(tmp_path)
    _write_ai_safe_with_field(run_dir, "application_credential_objects", 1)

    report = build_validation_report(run_dir=run_dir)
    codes = [issue["code"] for issue in report["issues"]]
    assert "unsafe_ai_safe_artifact" not in codes, report["issues"]
