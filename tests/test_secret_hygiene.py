from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from azure_tenant_audit.auth_runtime import SENSITIVE_CLI_ARGS, scrub_command_line
from azure_tenant_audit.secret_hygiene import (
    SENSITIVE_ARG_FLAGS,
    collect_sensitive_argv_values,
    deep_sanitize,
    file_mode,
    redact_argv,
    redact_command_string,
    redact_text,
    sanitize_token_claims,
    secure_write_json,
    token_freshness,
    validate_token_claims,
)


@pytest.mark.parametrize("flag", sorted(SENSITIVE_ARG_FLAGS))
@pytest.mark.parametrize("inline", [False, True])
def test_unique_sensitive_prefixes_are_redacted(flag: str, inline: bool) -> None:
    option = {"--client-secret": "--client-sec", "--access-token": "--access-tok"}.get(flag, flag[:-1])
    canary = "constructed-canary-argv-zz9"
    value_args = [f"{option}={canary}"] if inline else [option, canary]
    argv = ["auditex", *value_args, "--tenant-name", "constructed-tenant"]
    expected = [f"{option}=***redacted***"] if inline else [option, "***redacted***"]
    assert redact_argv(argv) == ["auditex", *expected, "--tenant-name", "constructed-tenant"]
    assert collect_sensitive_argv_values(argv) == {canary}
    assert canary not in redact_command_string(" ".join(argv))
    if flag in SENSITIVE_CLI_ARGS:
        assert scrub_command_line(argv) == redact_argv(argv)


def test_prefix_matching_preserves_exact_flags_and_unrelated_options() -> None:
    flags = {"--token", "--token-cache"}
    argv = ["--token", "constructed-token", "--token-c", "constructed-cache", "--tok", "ambiguous", "--", "positional"]
    assert redact_argv(argv, sensitive_flags=flags) == [
        "--token", "***redacted***", "--token-c", "***redacted***", "--tok", "ambiguous", "--", "positional",
    ]
    assert collect_sensitive_argv_values(argv, sensitive_flags=flags) == {"constructed-token", "constructed-cache"}
    assert redact_argv(["--client-sec"]) == ["--client-sec", "***redacted***"]
    assert redact_argv(["--unrelated=constructed", "ordinary"]) == ["--unrelated=constructed", "ordinary"]


def test_argv_redaction_covers_token_and_inline_forms() -> None:
    argv = ["auditex", "auth", "import-token", "--token", "eyJ.abc.def", "--client-secret=s3cr3t", "--tenant-id", "t1"]
    assert collect_sensitive_argv_values(argv) == {"eyJ.abc.def", "s3cr3t"}
    assert redact_argv(argv) == [
        "auditex",
        "auth",
        "import-token",
        "--token",
        "***redacted***",
        "--client-secret=***redacted***",
        "--tenant-id",
        "t1",
    ]
    assert "eyJ" not in redact_text("Authorization: Bearer eyJabc.def.ghi")


def test_command_string_redaction_handles_shell_strings() -> None:
    rendered = redact_command_string('m365 login --authType secret --secret "abc 123" --tenant t')
    assert "abc 123" not in rendered
    assert "--secret" in rendered
    assert "***redacted***" in rendered


def test_token_claim_sanitization_removes_raw_claims() -> None:
    claims = {
        "tenant_id": "tenant-1",
        "audience": "https://graph.microsoft.com",
        "delegated_scopes": ["User.Read", "Directory.Read.All"],
        "raw_claims": {"scp": "User.Read Directory.Read.All", "secret": "bad"},
    }
    sanitized = sanitize_token_claims(claims)
    assert sanitized["tenant_id"] == "tenant-1"
    assert "raw_claims" not in sanitized
    assert "secret" not in str(sanitized)


def test_token_freshness_and_validation_blocks_expired_token() -> None:
    now = datetime(2026, 5, 6, tzinfo=timezone.utc)
    claims = {
        "tenant_id": "tenant-1",
        "audience": "https://graph.microsoft.com",
        "delegated_scopes": ["User.Read"],
        "expires_at_utc": (now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    assert token_freshness(claims, now=now)["status"] == "expired"
    validation = validate_token_claims(claims, tenant_id="tenant-1")
    assert validation["status"] == "blocked"
    assert "token_expired" in validation["blockers"]


def test_deep_sanitize_redacts_sensitive_keys_and_values() -> None:
    payload = {
        "token": "eyJabc.def.ghi",
        "nested": {"client_secret": "abc", "safe": "ok"},
        "token_claims": {"tenant_id": "t", "raw_claims": {"password": "bad"}},
    }
    sanitized = deep_sanitize(payload)
    assert sanitized["token"] == "***redacted***"
    assert sanitized["nested"]["client_secret"] == "***redacted***"
    assert sanitized["nested"]["safe"] == "ok"
    assert "raw_claims" not in str(sanitized["token_claims"])


def test_secure_write_json_sets_posix_private_file_mode(tmp_path) -> None:
    target = secure_write_json(tmp_path / ".secrets" / "ctx.json", {"a": 1})
    mode = file_mode(target)
    # Windows and some mounted filesystems can ignore chmod; POSIX CI should be strict.
    if mode is not None:
        assert mode & 0o077 == 0
