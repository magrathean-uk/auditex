from __future__ import annotations

import os
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta

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
    secure_write_text,
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
        "--token", "***redacted***", "--token-c", "***redacted***", "--tok", "***redacted***", "--", "positional",
    ]
    assert collect_sensitive_argv_values(argv, sensitive_flags=flags) == {"constructed-token", "constructed-cache", "ambiguous"}
    assert redact_argv(["--client-sec"]) == ["--client-sec", "***redacted***"]
    assert redact_argv(["--unrelated=constructed", "ordinary"]) == ["--unrelated=constructed", "ordinary"]


@pytest.mark.parametrize("option", ["--c", "--a", "--s"])
@pytest.mark.parametrize("inline", [False, True])
def test_ambiguous_sensitive_prefixes_are_redacted(option: str, inline: bool) -> None:
    canary = "constructed-canary-ambiguous-zz9"
    argv = [f"{option}={canary}"] if inline else [option, canary]
    expected = [f"{option}=***redacted***"] if inline else [option, "***redacted***"]
    assert redact_argv(argv) == expected
    assert collect_sensitive_argv_values(argv) == {canary}
    assert canary not in redact_command_string(" ".join(argv))


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
    now = datetime(2026, 5, 6, tzinfo=UTC)
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


def test_redact_text_masks_quoted_secret_with_escaped_quote() -> None:
    """R093: a quoted secret holding an escaped quote is masked whole, not up to the escape."""
    from azure_tenant_audit.secret_hygiene import redact_text

    double = redact_text('{"password": "Pa\\"ss-Secret99", "x": 1}')
    single = redact_text("password='Pa\\'ss-Secret99'")
    assert "Secret99" not in double
    assert double.endswith(', "x": 1}')
    assert "Secret99" not in single


def test_redact_argv_masks_single_token_flag_and_value() -> None:
    """R093: a malformed single argv token '--client-secret value' is masked like parse_guarded treats it."""
    from azure_tenant_audit.secret_hygiene import redact_argv

    assert redact_argv(["tool", "--client-secret abc123"]) == ["tool", "--client-secret ***redacted***"]
    assert redact_argv(["tool", "--tenant-id contoso"]) == ["tool", "--tenant-id contoso"]


def test_collect_sensitive_argv_values_reads_single_token_flag_and_value() -> None:
    """R093 (review): child-output scrubbing collects the value of a malformed single token too."""
    from azure_tenant_audit.secret_hygiene import collect_sensitive_argv_values

    assert collect_sensitive_argv_values(["tool", "--client-secret abc123"]) == {"abc123"}


def test_redact_text_masks_unterminated_quoted_secret_to_the_end() -> None:
    """R093 (review): an opening quote with no closing quote (a cut-off diagnostic) is masked to the end."""
    from azure_tenant_audit.secret_hygiene import redact_text

    out = redact_text('error: {"password": "Pa\\"ss word Secret99')
    assert out == 'error: {"password": ***redacted***'


def test_redact_text_round2_cut_off_after_backslash_and_marker_prefix() -> None:
    """R093 (review round 2): a quoted value cut off after a backslash is masked to the end; only an exact redaction
    marker is left as it is, not a credential that merely starts with one."""
    from azure_tenant_audit.secret_hygiene import redact_text

    assert redact_text('password="abc def\\') == "password=***redacted***"
    assert "TAILSECRET" not in redact_text("password=***redacted***TAILSECRET")
    assert redact_text("token: ***redacted-jwt***") == "token: ***redacted-jwt***"


# ---- bot review wave 2 (items 22, 23): the secret write is anchored in a verified folder ---------------------------

_posix_owner = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="POSIX modes, not as root")


def _write_mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@_posix_owner
def test_folder_that_blocks_the_atomic_write_gives_a_fixed_actionable_error(tmp_path) -> None:
    folder = tmp_path / "private-marker"
    folder.mkdir()
    target = folder / "token.json"
    target.write_text("old", encoding="utf-8")
    os.chmod(target, 0o600)
    os.chmod(folder, 0o500)  # the file could be rewritten in place, but nothing can be created beside it
    try:
        with pytest.raises(PermissionError) as caught:
            secure_write_text(target, "new")
    finally:
        os.chmod(folder, 0o700)
    assert "secret_folder_refused" in str(caught.value) and "writable folder" in str(caught.value)
    assert "private-marker" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert target.read_text(encoding="utf-8") == "old"
    assert sorted(path.name for path in folder.iterdir()) == ["token.json"]


@_posix_owner
def test_folder_other_accounts_can_change_is_refused(tmp_path) -> None:
    folder = tmp_path / "shared"
    folder.mkdir()
    os.chmod(folder, 0o777)
    with pytest.raises(PermissionError, match="secret_folder_refused"):
        secure_write_text(folder / "token.json", "secret")
    assert list(folder.iterdir()) == []


@_posix_owner
def test_sticky_shared_folder_is_accepted(tmp_path) -> None:
    folder = tmp_path / "sticky"
    folder.mkdir()
    os.chmod(folder, 0o1777)
    target = secure_write_text(folder / "token.json", "secret")
    assert target.read_text(encoding="utf-8") == "secret" and _write_mode(target) == 0o600


@_posix_owner
def test_entry_swapped_after_the_write_is_neither_chmodded_nor_installed(tmp_path, monkeypatch) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    os.chmod(victim, 0o644)
    real_fdopen = os.fdopen

    class _SwapOnFlush:
        """After the write is flushed, puts a link where the temporary file was (another principal's move)."""

        def __init__(self, handle) -> None:
            self.handle = handle

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            self.handle.close()

        def flush(self) -> None:
            self.handle.flush()
            (temporary,) = [path for path in folder.iterdir() if path.name.endswith(".tmp")]
            temporary.unlink()
            temporary.symlink_to(victim)

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: _SwapOnFlush(real_fdopen(*a, **k)))
    with pytest.raises(PermissionError, match="secret_folder_refused"):
        secure_write_text(folder / "token.json", "secret")
    assert _write_mode(victim) == 0o644 and victim.read_text(encoding="utf-8") == "keep"
    assert not (folder / "token.json").exists() and not (folder / "token.json").is_symlink()


# ---- repair round 1 for group H (items 22, 23, 26): every refusal is the fixed message, ACLs count, reads are checked ----


@_posix_owner
def test_item22_blocked_creation_of_a_missing_cache_folder_gives_the_fixed_refusal(tmp_path) -> None:
    locked = tmp_path / "locked-marker"
    locked.mkdir()
    os.chmod(locked, 0o500)  # owner can enter, but nothing can be created inside
    try:
        with pytest.raises(PermissionError) as caught:
            secure_write_text(locked / "sub-marker" / "token.json", "secret")
    finally:
        os.chmod(locked, 0o700)
    assert "secret_folder_refused" in str(caught.value)
    assert "locked-marker" not in str(caught.value) and "sub-marker" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert list(locked.iterdir()) == []


_macos_owner = pytest.mark.skipif(sys.platform != "darwin" or os.geteuid() == 0, reason="macOS ACLs, not as root")


def _add_acl(path, entry: str) -> None:
    subprocess.run(["chmod", "+a", entry, str(path)], check=True)


def _clear_acl(path) -> None:
    subprocess.run(["chmod", "-N", str(path)], check=False)


@_macos_owner
@pytest.mark.parametrize(
    "entry",
    [
        "everyone allow add_file,delete_child",  # another account can replace the cache in an 0700 folder
        "everyone allow read,file_inherit",  # a new 0600 cache would inherit read access for another account
    ],
)
def test_item23_folder_whose_acl_grants_other_accounts_is_refused(tmp_path, entry: str) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    _add_acl(folder, entry)
    try:
        with pytest.raises(PermissionError, match="secret_folder_refused") as caught:
            secure_write_text(folder / "token.json", "secret")
        assert list(folder.iterdir()) == []
    finally:
        _clear_acl(folder)
    assert "cache" not in str(caught.value).split("secret_folder_refused", 1)[0]


@_macos_owner
def test_item23_deny_only_acl_like_the_desktop_folder_is_accepted(tmp_path) -> None:
    folder = tmp_path / "desktop-like"
    folder.mkdir(mode=0o700)
    _add_acl(folder, "everyone deny delete")
    try:
        target = secure_write_text(folder / "token.json", "secret")
        assert target.read_text(encoding="utf-8") == "secret" and _write_mode(target) == 0o600
    finally:
        _clear_acl(folder)


@_posix_owner
def test_item26_secure_read_returns_an_owner_written_secret_and_none_when_missing(tmp_path) -> None:
    from azure_tenant_audit import secret_hygiene

    target = secure_write_text(tmp_path / "cache" / "token.json", "secret")
    assert secret_hygiene.secure_read_text(target) == "secret"
    assert secret_hygiene.secure_read_text(tmp_path / "cache" / "absent.json") is None
    assert secret_hygiene.secure_read_text(tmp_path / "missing-folder" / "token.json") is None


@_posix_owner
def test_item26_secure_read_refuses_a_folder_other_accounts_can_change(tmp_path) -> None:
    from azure_tenant_audit import secret_hygiene

    folder = tmp_path / "shared-marker"
    folder.mkdir()
    (folder / "token.json").write_text("planted", encoding="utf-8")
    os.chmod(folder, 0o777)
    with pytest.raises(PermissionError, match="secret_folder_refused") as caught:
        secret_hygiene.secure_read_text(folder / "token.json")
    assert "shared-marker" not in str(caught.value) and caught.value.__cause__ is None


@_posix_owner
def test_item26_secure_read_refuses_a_link_or_a_file_others_can_write(tmp_path) -> None:
    from azure_tenant_audit import secret_hygiene

    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("planted", encoding="utf-8")
    (folder / "linked.json").symlink_to(elsewhere)
    with pytest.raises(PermissionError, match="secret_file_refused"):
        secret_hygiene.secure_read_text(folder / "linked.json")
    writable = folder / "writable.json"
    writable.write_text("planted", encoding="utf-8")
    os.chmod(writable, 0o666)
    with pytest.raises(PermissionError, match="secret_file_refused"):
        secret_hygiene.secure_read_text(writable)


def _mount_options(path) -> set[str] | None:
    """The options ``mount`` lists for the volume holding ``path`` (macOS), to check the detector independently."""
    output = subprocess.run(["/sbin/mount"], capture_output=True, text=True, check=True).stdout
    best: tuple[int, set[str]] | None = None
    resolved = os.path.realpath(path)
    for line in output.splitlines():
        head, _, rest = line.partition(" on ")
        point, _, options = rest.rpartition(" (")
        if not point or not (resolved == point or resolved.startswith(point.rstrip("/") + "/")):
            continue
        if best is None or len(point) > best[0]:
            best = (len(point), {option.strip() for option in options.rstrip(")").split(",")})
    return best[1] if best else None


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS mount policy")
def test_item26_ownership_enforced_matches_the_volume_mount_policy(tmp_path) -> None:
    # The test volume decides the expected answer: on a volume mounted with "Ignore ownership" (noowners) every account
    # is treated as the owner, so the owner and mode checks prove nothing there.
    from azure_tenant_audit import secret_hygiene

    options = _mount_options(tmp_path)
    assert options is not None
    assert secret_hygiene.ownership_enforced(tmp_path / "cache" / "token.json") is ("noowners" not in options)
    assert secret_hygiene.ownership_enforced("/") is True  # the system volume always enforces ownership


def test_item26_ownership_is_not_trusted_when_the_volume_flags_cannot_be_read(monkeypatch, tmp_path) -> None:
    from azure_tenant_audit import secret_hygiene

    monkeypatch.setattr(secret_hygiene.sys, "platform", "darwin")
    monkeypatch.setattr(secret_hygiene, "_darwin_mount_flags", lambda _path: None)
    assert secret_hygiene.ownership_enforced(tmp_path / "token.json") is False
    monkeypatch.setattr(secret_hygiene, "_darwin_mount_flags", lambda _path: secret_hygiene._MNT_IGNORE_OWNERSHIP)
    assert secret_hygiene.ownership_enforced(tmp_path / "token.json") is False
    monkeypatch.setattr(secret_hygiene, "_darwin_mount_flags", lambda _path: 0)
    assert secret_hygiene.ownership_enforced(tmp_path / "token.json") is True


@pytest.mark.skipif(sys.platform != "darwin", reason="reads macOS mount flags")
def test_item26_a_vanished_cache_folder_is_not_judged_by_the_volume_above_it() -> None:
    from pathlib import Path

    from azure_tenant_audit import secret_hygiene

    # A folder that does not exist under a system-volume folder: the volume that held it (say an unmounted noowners
    # disk) is gone, so the system volume's ownership policy above it says nothing about the cache.
    gone = Path("/private/var/auditex-missing-volume-check") / "auditex"
    assert not gone.parent.exists()
    assert secret_hygiene.ownership_enforced(gone / "token.json") is False


@_posix_owner
def test_regular_file_swapped_in_after_the_write_is_not_installed(tmp_path, monkeypatch) -> None:
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    real_fdopen = os.fdopen

    class _ReplaceOnFlush:
        """After the flush, replaces the temporary entry with another regular file holding other content."""

        def __init__(self, handle) -> None:
            self.handle = handle

        def __getattr__(self, name):
            return getattr(self.handle, name)

        def flush(self) -> None:
            self.handle.flush()
            (temporary,) = [path for path in folder.iterdir() if path.name.endswith(".tmp")]
            temporary.unlink()
            temporary.write_text("planted", encoding="utf-8")

        def close(self) -> None:
            self.handle.close()

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            self.handle.close()

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: _ReplaceOnFlush(real_fdopen(*a, **k)))
    with pytest.raises(PermissionError, match="secret_folder_refused"):
        secure_write_text(folder / "token.json", "secret")
    assert not (folder / "token.json").exists()


@_posix_owner
def test_written_file_stays_open_through_the_identity_check_and_the_rename(tmp_path, monkeypatch) -> None:
    # While the descriptor is open the written inode cannot be freed, so its number cannot be reused by anything put
    # where the temporary file was (Linux reuses a freed inode number at once).
    folder = tmp_path / "cache"
    folder.mkdir(mode=0o700)
    handles: list = []
    seen: list[tuple[str, bool]] = []
    real_fdopen, real_stat, real_rename = os.fdopen, os.stat, os.rename

    def fdopen(*args, **kwargs):
        handles.append(real_fdopen(*args, **kwargs))
        return handles[-1]

    def stat_(path, *args, **kwargs):
        if kwargs.get("dir_fd") is not None and handles:
            seen.append(("stat", handles[-1].closed))
        return real_stat(path, *args, **kwargs)

    def rename(src, dst, *args, **kwargs):
        if kwargs.get("src_dir_fd") is not None and handles:
            seen.append(("rename", handles[-1].closed))
        return real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", fdopen)
    monkeypatch.setattr(os, "stat", stat_)
    monkeypatch.setattr(os, "rename", rename)
    secure_write_text(folder / "token.json", "secret")
    assert ("stat", False) in seen and ("rename", False) in seen
    assert all(closed is False for _, closed in seen)
    assert handles[-1].closed and (folder / "token.json").read_text(encoding="utf-8") == "secret"
