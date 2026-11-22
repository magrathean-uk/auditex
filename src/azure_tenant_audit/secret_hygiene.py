from __future__ import annotations

import errno
import functools
import json
import os
import re
import secrets
import shlex
import stat
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .argument_parser import DiagnosticRedactingArgumentParser, build_argument_parser  # noqa: F401 - re-exported for callers of this module

# Flags that name certificate key material or its location (the key file, its password source and the
# certificate's thumbprint). Every argv redactor treats them as sensitive whatever flag set its caller
# passes, so no redactor (product, response, Google, bootstrap) can leak a key path or password source.
CERTIFICATE_ARG_FLAGS = frozenset(
    {
        "--certificate-path",
        "--certificate-thumbprint",
        "--certificate-password-env",
        "--certificate-password-file",
    }
)

SENSITIVE_ARG_FLAGS = frozenset(
    {
        "--access-token",
        "--token",
        "--client-secret",
        *CERTIFICATE_ARG_FLAGS,
        "--secret",
        "--password",
        "--command-override",
        "--adapter-override",
        "--sensitive-users",
        "--partner-domains",
        "--oauth-client",
        "--service-account-key",
        "--token-cache",
        "--token-file",
        "--env",
        "--break-glass-accounts",
        "--doh-endpoint",
    }
)

SENSITIVE_KEY_RE = re.compile(
    r"(^|[_-])(access[_-]?token|refresh[_-]?token|token|secret|password|passphrase|credential|authorization|raw[_-]?claims"
    r"|private[_-]?key|client[_-]?assertion)([_-]|$)",
    re.IGNORECASE,
)

BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
# A PEM private key block (RSA, EC, ENCRYPTED or PKCS#8), including one cut off before its END line.
PRIVATE_KEY_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]++\.[A-Za-z0-9_-]++\.[A-Za-z0-9_-]+")
# Include guest UPNs (#EXT#), Unicode local parts and single-label UPN suffixes.
_OUTPUT_EMAIL_RE = re.compile(
    # Keep familiar diagnostic field labels; otherwise mask an ambiguous '=' with
    # the local part, which may legitimately contain it.
    # Apostrophes inside a name are allowed, but surrounding single quotes stay intact.
    # Query/filter separators (? & | + ' and %20/%27) can start another address.
    # Keep these fixed-width starts and the bounded local/domain scans: even a
    # delimiter at every position must take only constant work per input byte.
    # Slash is a URL path separator, not part of a diagnostic local part.
    r"(?:(?<![\w.!#$%*=^`{}~\\-])|(?<=\\[nrtbf])|(?<=%2[07]))"
    r"(?P<field>(?i:SentTo|UserPrincipalName|UPN|EmailAddress|Email|Recipient|From|To)='?)?"
    r"(?P<quote>'?)"
    r'(?P<local>\\?"(?:\\u[0-9a-fA-F]{4}|[^"\\\r\n]){1,64}\\?"|'
    r"(?:\\u[0-9a-fA-F]{4}|[\w.!#$%&*+=?^`{|}~-])"
    r"(?:\\u[0-9a-fA-F]{4}|[\w.!#$%&'*+=?^`{|}~-]){0,63})"
    r"@(?P<domain>[\w](?:[\w.-]{0,251}[\w])?)"
)
_OUTPUT_GUID_RE = re.compile(
    r"(?P<label>(?:Trace ID|Correlation ID):[ \t]*)?"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])",
    re.IGNORECASE,
)
# Decode only representations needed for identifier matching; never execute a
# general escape decoder on arbitrary command output. One pass, no recursion.
_OUTPUT_ENCODING_RE = re.compile(r"%40|%7b|%7d|%2d|\\u0040|&#64;|＠", re.IGNORECASE)
_OUTPUT_ENCODINGS = {
    "%40": "@", "%7b": "{", "%7d": "}", "%2d": "-",
    r"\u0040": "@", "&#64;": "@", "＠": "@",
}
# 320 covers a plain 64-character local part plus a 253-character domain.
# JSON can spell each local character as six bytes (\uXXXX); 2048 also covers
# that and percent-encoded GUIDs at the cut, without scanning a whole dump.
_OUTPUT_SAMPLE_MARGIN = 2048
# ``key=value``, ``key: value`` and the JSON forms ``"key": "value"`` / ``'key':'value'``: the closing quote of the
# key and a quoted value (which may hold spaces) are part of the match, so a JSON-keyed secret is not left behind.
# The credential words both redactors (this diagnostic one and the shareable ``output_redaction`` one) mask as
# ``word=value``; a quoted value may hold backslash-escaped quotes.
INLINE_SECRET_WORDS = (
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|passwd|pwd|authorization"
    r"|api[_-]?key|client[_-]?assertion|private[_-]?key|passphrase|token"
    r"|certificate[_-]?(?:path|thumbprint|password(?:[_-]?(?:env|file))?)"
)
# A quoted value runs to its closing quote, or to the end of the text when it was cut off before one. A value that is
# exactly a redaction marker (``***redacted-jwt***``), ending at a value boundary, is left as it is.
INLINE_SECRET_VALUE = r"(?!\*\*\*redacted(?:-[a-z-]+)?\*\*\*(?![^\s,;]))(?:\"(?:[^\"\\]|\\.)*(?:\"|\\?\Z)|'(?:[^'\\]|\\.)*(?:'|\\?\Z)|[^\s,;]+)"
INLINE_SECRET_RE = re.compile(
    rf"(?P<prefix>[\"']?(?:{INLINE_SECRET_WORDS})[\"']?\s*[=:]\s*)(?P<value>{INLINE_SECRET_VALUE})",
    re.IGNORECASE,
)

_ALLOWED_TOKEN_CLAIMS = (
    "tenant_id",
    "audience",
    "app_id",
    "subject",
    "user_principal_name",
    "delegated_scopes",
    "app_roles",
    "issued_at_utc",
    "not_before_utc",
    "expires_at_utc",
)


def ensure_private_dir(path: str | Path, *, mode: int = 0o700) -> Path:
    """Create a local secret directory and restrict it on POSIX platforms.

    This intentionally degrades gracefully on filesystems or platforms where chmod is not
    meaningful. The caller still gets a usable directory, but POSIX systems get 0700.
    """

    directory = Path(path).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(directory, mode)
        except OSError:
            pass
    return directory


def _create_private_parents(directory: Path, *, mode: int = 0o700) -> None:
    """Create the missing folders above a secret file owner-only; a folder that already exists is left as it is.

    The secret file itself is what is kept private, so an operator's working or shared folder never has its mode changed.
    """
    missing: list[Path] = []
    current = directory
    while not current.exists() and current != current.parent:
        missing.append(current)
        current = current.parent
    for folder in reversed(missing):
        try:
            folder.mkdir(mode=mode)
        except FileExistsError:
            continue
        if os.name == "posix":
            try:
                os.chmod(folder, mode)  # mkdir's mode is reduced by the umask
            except OSError:
                pass


SECRET_FOLDER_REFUSED = (
    "secret_folder_refused: a secret file is written to a new file beside it that then replaces it, so its folder "
    "must be owned by you (or root), let you create and replace files, and not let other accounts replace them "
    "(no group or world write unless the sticky bit is set). Choose an owner-controlled writable folder "
    "(for example one created with chmod 700) and run again."
)


def _secret_folder_refused() -> PermissionError:
    # A fixed message: never the folder or file path, which may be a sensitive argument such as --token-cache.
    return PermissionError(errno.EACCES, SECRET_FOLDER_REFUSED)


SECRET_FILE_REFUSED = (
    "secret_file_refused: a secret file is read only when it is a regular file (not a link) owned by you that other "
    "accounts cannot change. Remove it so it is written again, and run again."
)


def _secret_file_refused() -> PermissionError:
    return PermissionError(errno.EACCES, SECRET_FILE_REFUSED)


# macOS extended ACLs (sys/acl.h): an entry can let another account add, remove or read entries whatever the mode
# bits say, and a folder entry marked to inherit reaches every file created in it. Linux POSIX ACLs need no check of
# their own: a named entry sets the group bits of the mode to its mask, so the mode check below already sees it.
_ACL_TYPE_EXTENDED = 0x00000100
_ACL_FIRST_ENTRY = 0
_ACL_NEXT_ENTRY = -1
_ACL_EXTENDED_ALLOW = 1


@functools.cache
def _darwin_acl_api() -> Any:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_fd_np.restype = ctypes.c_void_p
    libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_tag_type.restype = ctypes.c_int
    libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    libc.acl_free.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    return ctypes, libc


def _acl_grants_access(descriptor: int) -> bool:
    """Whether an extended ACL on this open file or folder allows anything (macOS); deny-only entries grant nothing.

    Read with the C library's ACL calls through ``ctypes`` (standard library, no command). A failure to read the ACL
    counts as a grant, so an unknown ACL is refused rather than trusted.
    """
    if sys.platform != "darwin":
        return False
    try:
        ctypes, libc = _darwin_acl_api()
    except (OSError, AttributeError, ImportError):
        return True
    acl = libc.acl_get_fd_np(descriptor, _ACL_TYPE_EXTENDED)
    if not acl:
        # No ACL at all, or a file system without ACLs.
        return ctypes.get_errno() not in {errno.ENOENT, errno.ENOTSUP, errno.EOPNOTSUPP}
    try:
        entry = ctypes.c_void_p()
        tag = ctypes.c_int()
        entry_id = _ACL_FIRST_ENTRY
        while libc.acl_get_entry(acl, entry_id, ctypes.byref(entry)) == 0:
            if libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or tag.value == _ACL_EXTENDED_ALLOW:
                return True
            entry_id = _ACL_NEXT_ENTRY
        return False
    finally:
        libc.acl_free(acl)


# sys/mount.h: a macOS volume with "Ignore ownership on this volume" set (mounted noowners) treats every account as the
# owner of every file, so the owner and mode checks above pass for files another local account wrote.
_MNT_IGNORE_OWNERSHIP = 0x00200000
# struct statfs (64-bit inode layout, the only one on Apple silicon): f_flags follows four bytes of block size, four of
# I/O size, five 64-bit counts, the 8-byte fsid, f_owner and f_type. The buffer is larger than the 2168-byte struct.
_STATFS_FLAGS_OFFSET = 64
_STATFS_BUFFER = 4096


def _darwin_mount_flags(path: Path) -> int | None:
    """The mount flags of the volume holding the folder ``path``; ``None`` when it is missing or they cannot be read.

    A missing folder is not judged by the volume above it: the volume that held it may have been unmounted since the
    secret was read, and the folder above it is then on another volume with another ownership policy.
    """
    import ctypes

    current = path
    if not os.path.isdir(current):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            statfs = libc["statfs$INODE64"]  # Intel: the 64-bit inode layout under its own symbol
        except AttributeError:
            statfs = libc.statfs
        statfs.restype = ctypes.c_int
        statfs.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        buffer = ctypes.create_string_buffer(_STATFS_BUFFER)
        if statfs(os.fsencode(current), buffer) != 0:
            return None
        return int.from_bytes(buffer.raw[_STATFS_FLAGS_OFFSET:_STATFS_FLAGS_OFFSET + 4], sys.byteorder)
    except (OSError, AttributeError, ValueError):
        return None


def ownership_enforced(path: str | Path) -> bool:
    """Whether the owner checks of :func:`secure_read_text` prove that this account wrote the secret file at ``path``.

    False on a macOS volume that ignores ownership (noowners), when its mount flags cannot be read, and off POSIX (no
    owner check is made there). A secret read from such a place is still the caller's to use, but nothing it records
    about itself (a token cache's granted scopes, say) can be trusted on its own word.
    """
    if os.name != "posix":
        return False
    if sys.platform != "darwin":
        return True
    flags = _darwin_mount_flags(Path(path).expanduser().parent)
    return flags is not None and not flags & _MNT_IGNORE_OWNERSHIP


def _trusted_folder(folder: int) -> bool:
    """Whether only the caller (or root) can create, rename or remove entries in this open folder.

    The folder's extended ACL must allow nothing either: an allow entry can let another account replace entries in an
    owner-only folder, or pass read access on to the secret file written into it.
    """
    info = os.fstat(folder)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {os.geteuid(), 0}:
        return False
    # A sticky folder (/tmp) lets an account remove or rename only the entries it owns.
    if not (info.st_mode & stat.S_ISVTX) and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return not _acl_grants_access(folder)


def _open_secret_folder(directory: Path) -> int:
    """The folder opened once and checked; a fixed refusal (no path) when it cannot be opened or is not trusted."""
    try:
        folder = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        raise _secret_folder_refused() from None
    try:
        trusted = _trusted_folder(folder)
    except BaseException:
        os.close(folder)
        raise
    if not trusted:
        os.close(folder)
        raise _secret_folder_refused()
    return folder


# A token cache or key file is a few KB; anything this large is not one.
_SECRET_READ_LIMIT = 1024 * 1024


def secure_read_text(path: str | Path, *, limit: int = _SECRET_READ_LIMIT) -> str | None:
    """Read a secret file only from a folder and file no other account can change; ``None`` when there is none.

    The same folder check as :func:`secure_write_text`, so what is read is what this account wrote: the folder is opened
    once and checked, and the file is opened in it without following a link and checked on its descriptor (a regular
    file you own, no group or world write, no ACL that allows anything). Refusals carry a fixed message, never the path.
    """
    target = Path(path).expanduser()
    if os.name != "posix":
        try:
            return target.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
    if not os.path.isdir(target.parent):
        return None
    folder = _open_secret_folder(target.parent)
    try:
        try:
            descriptor = os.open(
                target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=folder
            )
        except FileNotFoundError:
            return None
        except OSError:  # a link (ELOOP) or a file this account cannot open
            raise _secret_file_refused() from None
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or info.st_size > limit
                or _acl_grants_access(descriptor)
            ):
                raise _secret_file_refused()
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(limit + 1)
        finally:
            os.close(descriptor)
    finally:
        os.close(folder)
    if len(data) > limit:
        raise _secret_file_refused()
    return data.decode("utf-8")


def secure_write_text(path: str | Path, content: str, *, mode: int = 0o600) -> Path:
    """Write text without briefly creating world-readable secret files.

    The text goes to a new owner-only file beside the target (created exclusively, never through a link), which then
    replaces the target in one step: an old copy at a looser mode is never rewritten in place, and a link at the path
    is replaced rather than followed. On POSIX every step is anchored in the folder opened once and checked to be one
    no other account can change; the mode is set on the open descriptor, and the entry is renamed only while it is
    still the file just written. A folder that fails the check or blocks the write is refused with a fixed message.
    """

    target = Path(path).expanduser()
    try:
        _create_private_parents(target.parent)
    except OSError:  # the OS message names the folder, which may be a sensitive argument such as --token-cache
        raise _secret_folder_refused() from None
    if os.name != "posix":  # no POSIX modes or folder descriptors (Windows): the same replace in one step
        fd, path_name = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.replace(path_name, target)
        except BaseException:
            try:
                os.unlink(path_name)
            except OSError:
                pass
            raise
        return target
    folder = _open_secret_folder(target.parent)
    try:
        temporary = f".{target.name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(temporary, flags, 0o600, dir_fd=folder)
        except PermissionError:
            raise _secret_folder_refused() from None
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), mode)
                handle.write(content)
                handle.flush()
                written = os.fstat(handle.fileno())
            current = os.stat(temporary, dir_fd=folder, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (written.st_dev, written.st_ino):
                raise _secret_folder_refused()
            try:
                os.rename(temporary, target.name, src_dir_fd=folder, dst_dir_fd=folder)
            except PermissionError:
                raise _secret_folder_refused() from None
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=folder)
            except OSError:
                pass
            raise
    finally:
        os.close(folder)
    return target


def secure_write_json(path: str | Path, payload: Any, *, mode: int = 0o600) -> Path:
    return secure_write_text(path, json.dumps(payload, indent=2), mode=mode)


def file_mode(path: str | Path) -> int | None:
    try:
        return stat.S_IMODE(Path(path).stat().st_mode)
    except OSError:
        return None


def collect_sensitive_argv_values(
    argv: Sequence[str],
    *,
    sensitive_flags: Iterable[str] = SENSITIVE_ARG_FLAGS,
) -> set[str]:
    flags = set(sensitive_flags) | CERTIFICATE_ARG_FLAGS
    values: set[str] = set()
    skip_next = False
    for item in argv:
        if skip_next:
            if item:
                values.add(str(item))
            skip_next = False
            continue
        option, separator, value = item.partition("=")
        words = str(item).split(maxsplit=1)
        if len(words) == 2 and "=" not in words[0] and _sensitive_option(words[0], flags):
            values.add(words[1])  # a single malformed token '--client-secret value', as redact_argv reads it
            continue
        if _sensitive_option(option, flags):
            if separator:
                if value:
                    values.add(value)
            else:
                skip_next = True
    return values


def _sensitive_option(option: str, flags: set[str]) -> bool:
    """Recognise exact flags and any sensitive long-option prefix, defensively.

    Public parsers reject abbreviations. Retain this protection for synthetic
    command lines and any future parser that accidentally enables them again.
    """
    return option in flags or (
        option.startswith("--")
        and len(option) > 2
        and sum(flag.startswith(option) for flag in flags) >= 1
    )


def redact_text(value: str, sensitive_values: Iterable[str] | None = None) -> str:
    redacted = value or ""
    for sensitive in sorted({str(item) for item in sensitive_values or [] if item}, key=len, reverse=True):
        redacted = redacted.replace(sensitive, "***redacted***")
    redacted = BEARER_RE.sub("Bearer ***redacted***", redacted)
    redacted = PRIVATE_KEY_PEM_RE.sub("***redacted-private-key***", redacted)
    redacted = JWT_RE.sub("***redacted-jwt***", redacted)
    redacted = INLINE_SECRET_RE.sub(lambda match: f"{match.group('prefix')}***redacted***", redacted)
    return redacted


def redact_output(
    value: Any,
    sensitive_values: Iterable[str] | None = None,
    *,
    limit: int | None = 500,
) -> str:
    """Mask diagnostic output, then bound it; never use on collected evidence rows.

    Domains, punctuation and error wording remain useful. ``limit=None`` is for full
    MCP command responses, which are not log samples and must not be clipped.
    """
    text = "" if value is None else value if isinstance(value, (str, bytes)) else str(value)
    clipped = limit is not None and len(text) > max(0, limit) + _OUTPUT_SAMPLE_MARGIN
    if limit is not None:
        text = text[:max(0, limit) + _OUTPUT_SAMPLE_MARGIN]
    text = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text
    # Credentials take precedence over decoding, which can change a literal
    # sensitive value. Reuse iterators for the post-decoding pass as well.
    sensitive_values = tuple(sensitive_values) if sensitive_values is not None else None
    text = redact_text(text, sensitive_values)
    text = _OUTPUT_ENCODING_RE.sub(lambda match: _OUTPUT_ENCODINGS[match[0].lower()], text)
    redacted = redact_text(text, sensitive_values)

    def mask_email(match: re.Match[str]) -> str:
        # Package versions and the conventional Git SSH user are diagnostics.
        version = match["domain"].replace(".", "").isdigit()
        git_ssh = match["local"] == "git" and match["domain"].lower().startswith(("git", "ssh."))
        if version or git_ssh:
            return match[0]
        return f"{match['field'] or ''}{match['quote']}***@{match['domain']}"

    redacted = _OUTPUT_EMAIL_RE.sub(mask_email, redacted)
    redacted = _OUTPUT_GUID_RE.sub(lambda match: match[0] if match['label'] else "<redacted-guid>", redacted)
    if clipped:
        # Masking can shrink the window below the requested limit. Discard its
        # last token: the scan boundary may have cut an address before its '@'.
        trailing = re.split(r"[\s,;:\"'<>()\[\]{}]", redacted)[-1]
        if trailing:
            redacted = redacted[:-len(trailing)]
    return redacted if limit is None else redacted[:max(0, limit)]


def redact_argv(
    argv: Sequence[str],
    *,
    sensitive_flags: Iterable[str] = SENSITIVE_ARG_FLAGS,
) -> list[str]:
    flags = set(sensitive_flags) | CERTIFICATE_ARG_FLAGS
    redacted: list[str] = []
    skip_next = False
    for item in argv:
        if skip_next:
            redacted.append("***redacted***")
            skip_next = False
            continue
        option, separator, _value = item.partition("=")
        words = str(item).split(maxsplit=1)
        if len(words) == 2 and "=" not in words[0] and _sensitive_option(words[0], flags):
            # A single malformed token '--client-secret value' (as parse_guarded also splits it).
            redacted.append(f"{words[0]} ***redacted***")
            continue
        if _sensitive_option(option, flags):
            if separator:
                redacted.append(f"{option}=***redacted***")
                continue
            redacted.append(str(item))
            skip_next = True
            continue
        redacted.append(redact_text(str(item)))
    if skip_next:
        redacted.append("***redacted***")
    return redacted


def redact_command_string(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        return redact_text(command)
    return " ".join(shlex.quote(part) for part in redact_argv(parts))


def _iso_to_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def token_freshness(token_claims: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    expires_at = _iso_to_datetime(token_claims.get("expires_at_utc"))
    if expires_at is None:
        return {"status": "unknown", "expires_at_utc": token_claims.get("expires_at_utc"), "seconds_remaining": None}
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    seconds = int((expires_at - current.astimezone(UTC)).total_seconds())
    if seconds <= 0:
        status = "expired"
    elif seconds <= 3600:
        status = "stale"
    else:
        status = "fresh"
    return {"status": status, "expires_at_utc": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"), "seconds_remaining": seconds}


def sanitize_token_claims(token_claims: Mapping[str, Any] | None) -> dict[str, Any]:
    claims = dict(token_claims or {})
    sanitized: dict[str, Any] = {}
    raw_claims = claims.get("raw_claims") if isinstance(claims.get("raw_claims"), Mapping) else {}

    field_map = {
        "tenant_id": ("tenant_id", "tid"),
        "audience": ("audience", "aud"),
        "app_id": ("app_id", "appid", "azp"),
        "subject": ("subject", "sub"),
        "user_principal_name": ("user_principal_name", "upn", "preferred_username"),
        "delegated_scopes": ("delegated_scopes",),
        "app_roles": ("app_roles", "roles"),
        "issued_at_utc": ("issued_at_utc",),
        "not_before_utc": ("not_before_utc",),
        "expires_at_utc": ("expires_at_utc",),
    }
    for output_key, candidate_keys in field_map.items():
        for key in candidate_keys:
            value = claims.get(key)
            if value is None and isinstance(raw_claims, Mapping):
                value = raw_claims.get(key)
            if value is not None:
                if output_key in {"delegated_scopes", "app_roles"}:
                    if isinstance(value, str):
                        sanitized[output_key] = sorted({item for item in re.split(r"[\s,]+", value) if item})
                    elif isinstance(value, list):
                        sanitized[output_key] = sorted({str(item) for item in value if item})
                    else:
                        sanitized[output_key] = []
                else:
                    sanitized[output_key] = value
                break
    for list_key in ("delegated_scopes", "app_roles"):
        sanitized.setdefault(list_key, [])
    freshness = token_freshness(sanitized)
    sanitized["freshness"] = freshness
    return {key: sanitized[key] for key in (*_ALLOWED_TOKEN_CLAIMS, "freshness") if key in sanitized}


def validate_token_claims(
    token_claims: Mapping[str, Any] | None,
    *,
    expected_audience: str = "https://graph.microsoft.com",
    tenant_id: str | None = None,
) -> dict[str, Any]:
    claims = sanitize_token_claims(token_claims)
    blockers: list[str] = []
    warnings: list[str] = []
    freshness = claims.get("freshness") or {}
    if freshness.get("status") == "expired":
        blockers.append("token_expired")
    elif freshness.get("status") in {"stale", "unknown"}:
        warnings.append(f"token_{freshness.get('status')}")
    audience = claims.get("audience")
    if audience and expected_audience and audience != expected_audience:
        warnings.append("unexpected_audience")
    if tenant_id and claims.get("tenant_id") and str(claims.get("tenant_id")) != str(tenant_id):
        blockers.append("tenant_mismatch")
    if not claims.get("tenant_id"):
        warnings.append("missing_tenant_id")
    if not claims.get("delegated_scopes") and not claims.get("app_roles"):
        warnings.append("missing_scopes_or_roles")
    return {
        "status": "blocked" if blockers else "warning" if warnings else "ok",
        "blockers": blockers,
        "warnings": warnings,
        "token_claims": claims,
    }


def deep_sanitize(value: Any, *, preserve_allowed_token_claims: bool = True) -> Any:
    if isinstance(value, Mapping):
        if preserve_allowed_token_claims and set(value.keys()).issubset(set(_ALLOWED_TOKEN_CLAIMS) | {"freshness"}):
            return {str(key): deep_sanitize(item, preserve_allowed_token_claims=False) for key, item in value.items()}
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text == "token_claims" and isinstance(item, Mapping):
                output[key_text] = sanitize_token_claims(item)
            elif SENSITIVE_KEY_RE.search(key_text):
                output[key_text] = "***redacted***"
            else:
                output[key_text] = deep_sanitize(item)
        return output
    if isinstance(value, list):
        return [deep_sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
