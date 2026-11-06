"""Structured redaction and bounded identity discovery for shareable output."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .citations import build_citation_summary, dedupe_citations
from .secret_hygiene import BEARER_RE, JWT_RE, _OUTPUT_EMAIL_RE as OUTPUT_EMAIL_RE, _OUTPUT_GUID_RE as OUTPUT_GUID_RE

# Keep the output-specific form local: diagnostic argv redaction is a separate boundary.
INLINE_SECRET_RE = re.compile(
    r"(?P<prefix>[\"']?(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|authorization|api[_-]?key)"
    r"[\"']?\s*[=:]\s*)(?P<value>\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s,;]+)",
    re.IGNORECASE,
)

PROFILE_LOCAL = "local"
PROFILE_SHAREABLE = "shareable"
PROFILE_CUSTOMER_PACK = "customer_pack"
PROFILE_EXPLAINER = "explainer"

SECRET_PLACEHOLDER = "***redacted***"
RUN_DIR_PLACEHOLDER = "<run-dir>"
TEXT_PLACEHOLDER = "<redacted-text>"

# Values nested deeper than this (mappings, lists and JSON embedded in strings together) are refused.
MAX_DEPTH = 100


class RedactionError(ValueError):
    """The value cannot be redacted safely; nothing was returned."""


class RedactionDepthError(RedactionError):
    """The value is nested more than ``MAX_DEPTH`` levels (or refers to itself): fail closed."""


class ContextIncompleteError(RedactionError):
    """The run's identities could not all be discovered (see ``RedactionContext.incomplete``): fail closed.

    The attributes, and most messages, name each unusable file by a *safe label* (its run-relative path with every
    segment that is not a recognised public section label, ``_PUBLIC_SECTION_LABELS``, replaced by ``<redacted-segment-N>``) and a reason class
    (``unreadable``, ``malformed JSON``, ``oversize``, ``scan bytes limit``, ``non-regular``, ``dangling link``,
    ``limit``, ``outside run``, ``changed during scan``). Never file content, an operating-system message or the
    absolute run path. Size-budget refusals use one message without file labels, even if other problems were found.

    ``files`` is a sorted list of at most ``_MAX_LISTED_FILES`` ``(label, reason class)`` pairs; ``omitted`` counts
    the unusable files beyond it. ``size_limit`` records a byte-budget refusal even when its reason was omitted.
    """

    def __init__(self, files: Iterable[tuple[str, str]] = (), omitted: int = 0, *, size_limit: bool = False) -> None:
        listed = tuple((str(label), str(reason)) for label, reason in files)
        shown, rest = listed[:_MAX_LISTED_FILES], max(0, int(omitted)) + max(0, len(listed) - _MAX_LISTED_FILES)
        self.files: tuple[tuple[str, str], ...] = shown
        self.omitted: int = rest
        self.size_limit = size_limit or _size_budget_exceeded(listed)
        if self.size_limit:
            super().__init__(
                "Shareable output refused: identity discovery is incomplete. Supported normalised evidence is up to "
                f"{_format_byte_limit(_MAX_FILE_BYTES)} per file and {_format_byte_limit(_MAX_SCAN_BYTES)} total per run."
            )
            return
        total = len(shown) + rest
        names = "; ".join(f"{label} ({reason})" for label, reason in shown) or "no file could be named"
        more = f"; and {rest} more" if rest else ""
        super().__init__(
            f"identity discovery was incomplete for {total} file(s): {names}{more}. Nothing was redacted or returned. "
            "Repair or remove the listed files and retry"
        )


# Local output is the operator's unchanged working report. The three shareable
# profiles intentionally have the same D3 rules.
PROFILES = frozenset({PROFILE_LOCAL, PROFILE_SHAREABLE, PROFILE_CUSTOMER_PACK, PROFILE_EXPLAINER})


TENANT_TEXT_KEYS = frozenset({"owner", "justification", "comment", "comments", "notes"})

# Exact public addresses from the public baselines and their examples; compared case-insensitively.
PUBLIC_ADDRESSES = frozenset(
    {
        "reports@dmarc.cyber.dhs.gov",
        "cyberliaison@cisa.dhs.gov",
        "reports@example.com",
        "username@somedomain.com",
    }
)

# Values of these keys (compared as ``_norm``, so ``client_secret``, ``Client-Secret`` and ``clientSecret`` are
# one key) are credentials whatever their shape: a non-empty value of any type is replaced whole.
_SECRET_KEYS = frozenset(
    {
        "client_secret", "secret_text", "app_secret", "password", "access_token", "refresh_token",
        "id_token", "api_token", "api_key", "key_material", "dsc_export", "private_key",
    }
)

# Keys whose values are controlled vocabulary or structure (ids of findings and policies, setting names, reason codes,
# statuses, verdicts, sections, kinds, cells, roles): a user's name is never substituted into them, whatever the
# user is called. Compared as ``_norm``. Identifiers (GUIDs, e-mail addresses, immutable ids) in them are still masked.
_CONTROLLED_KEYS = frozenset(
    {
        "id", "ids", "findingid", "findingids", "policyid", "policyids", "ruleid", "ruleids", "checkid", "controlid",
        "setting", "settings", "settingname", "settingnames", "reason", "reasons", "reasoncode", "reasoncodes", "code",
        "errorcode", "errorclass", "status", "severity", "verdict", "section", "sections", "kind", "cell", "cellid",
        "collector", "priority", "type", "format", "principaltype", "state", "outcome", "result", "category", "level",
        "role", "roles", "rolename", "rolenames", "roledisplayname", "roledefinitionname",
        "group", "groups", "groupname", "groupnames", "groupdisplayname",
    }
)
_ROLE_KEYS = frozenset({"role", "rolename", "rolenames", "roledisplayname", "roledefinitionname", "roles"})
# Words that read as report vocabulary: a privileged user who happens to be called one of them keeps the word in
# free text (their structured ``display_name`` is still pseudonymised).
_STATIC_VOCABULARY = frozenset(
    {
        "open", "closed", "pass", "fail", "warning", "critical", "high", "medium", "info", "error", "true", "false",
        "none", "null", "unknown", "enabled", "disabled", "status", "severity", "verdict", "owner", "accepted",
        "resolved", "blocked", "partial", "complete", "manual", "ok", "warn", "skipped", "low", "unavailable",
    }
)
# By shape: policy ids (``MS.EXO.4.1v1``), snake_case and UPPER_SNAKE codes (``not_collected``) are structure
# wherever they appear; a user called one of them keeps it readable in free text (the structured name field is
# still pseudonymised).
_STRUCTURAL_SHAPES = (
    re.compile(r"^[A-Za-z]{2,}(?:\.[A-Za-z0-9]+)+\.\d+v\d+$"),
    re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$"),
    re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"),
)


def _structural(text: str) -> bool:
    return any(shape.match(text) for shape in _STRUCTURAL_SHAPES)


# Finding ids are ``<namespace>:<snake_case_words>[:<guid-or-digest>]`` (``identity:global_admin_stale_password:<guid>``).
# A credential word inside such an id (``..._password:<guid>``) is part of the name, not an assignment, so the inline
# secret pattern must not read it as ``password: <value>``. The exemption is exact and closed:
#
# * the ``namespace:name`` pair is one of ``_ID_DEFINITIONS``, the finding definitions the producers under ``src/``
#   emit whose name carries a credential word (a test scans the producers and fails when one is missing); an arbitrary
#   snake_case name under a known namespace (``identity:db_password:654321``) is NOT exempt, because a numeric or hex
#   password has the same shape as a finding suffix;
# * the optional suffix is a dashed GUID, a lower-case hex digest of 16 to 64 digits or a decimal id of 16 to 24 digits;
# * the token is not preceded by a word, ``:``, ``.`` or ``-`` and is not followed by a word character, ``:`` or ``=``,
#   so ``identity:global_admin_stale_password:<guid>:hunter`` and ``config:identity:global_admin_stale_password:x`` are
#   still read as credentials and redacted.
#
# Everything is one regular expression run in one left-to-right pass (the id alternative is tried first at every
# position, the inline secret pattern second): linear in the text, no recursion, no second scan.
_ID_DEFINITIONS = frozenset({"identity:global_admin_stale_password"})
_ID_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ID_TOKEN = (
    r"(?-i:(?<![\w:.-])(?:" + "|".join(re.escape(d) for d in sorted(_ID_DEFINITIONS, key=len, reverse=True)) + r")"
    rf"(?::(?:{_ID_GUID}|[0-9a-f]{{16,64}}|[0-9]{{16,24}}))?(?![\w:=]))"
)
_INLINE_OR_ID_RE = re.compile(rf"(?P<idtoken>{_ID_TOKEN})|{INLINE_SECRET_RE.pattern}", INLINE_SECRET_RE.flags)


def _redact_inline_secrets(value: str) -> str:
    """``INLINE_SECRET_RE`` over ``value``, except that a credential word inside a finding id is left alone."""

    def inline(match: re.Match[str]) -> str:
        if match["idtoken"] is not None:
            return match[0]
        raw = match["value"]
        quote = raw[0] if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0] else ""
        return f"{match['prefix']}{quote}{SECRET_PLACEHOLDER}{quote}"

    return _INLINE_OR_ID_RE.sub(inline, value)


# Credentials carried by a URL: the password of ``scheme://user:password@host`` and the value of a credential-looking
# query or fragment parameter (OAuth tokens and codes, shared-access-signature fields, API keys). The URL syntax stays.
# The scheme is one to 32 characters (``x://u:pw@host`` is a URL); a scheme-relative ``//user:pw@host`` is one too.
_URL_USERINFO_RE = re.compile(
    r"(?P<head>(?:(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}:|(?<![\w:/.+-]))//[^\s/@:?#\"'<>]*:)"
    r"(?P<password>[^\s/@?#\"'<>]+)(?=@)"
)
_URL_PARAMETERS = (
    "access_token", "refresh_token", "id_token", "token", "sig", "signature", "code", "password", "passwd", "pwd",
    "secret", "client_secret", "key", "api_key", "apikey", "sv", "se", "sp", "sr", "spr", "st", "skoid", "sktid",
    "sas", "sastoken", "auth", "authorization", "assertion", "jwt", "bearer",
)
_URL_PARAMETER_RE = re.compile(
    r"(?P<lead>[?&;#])(?P<name>" + "|".join(_URL_PARAMETERS) + r")(?P<eq>=)(?P<value>[^&;\s#\"'<>]*)", re.IGNORECASE
)


def _redact_url_credentials(value: str) -> str:
    """URL userinfo passwords and credential parameters of ``value`` replaced by ``SECRET_PLACEHOLDER``."""
    if "=" not in value and "//" not in value:
        return value
    value = _URL_USERINFO_RE.sub(lambda m: m["head"] + SECRET_PLACEHOLDER, value)
    return _URL_PARAMETER_RE.sub(lambda m: m["lead"] + m["name"] + m["eq"] + SECRET_PLACEHOLDER, value)


# An immutable id shorter than this is pseudonymised under its own key but not searched for in free text.
_MIN_NARRATIVE_ID = 4
_IMMUTABLE_PREFIX = "Id "
_USER_PREFIX = "User "
_HEX16 = r"[0-9a-f]{16}"
_PSEUDONYM_RE = re.compile(rf"^(?:User|Id|Group|Guid) {_HEX16}$")
_PSEUDONYM_KEEP = rf"(?P<keep>(?<!\w)(?:User|Id|Group|Guid) {_HEX16}(?!\w))"
_GUID_RE = OUTPUT_GUID_RE
# The e-mail forms the plain pattern cannot see: the at sign spelled ``%40``, ``@``, ``&#64;`` or full-width.
# Same start rules and bounds as ``OUTPUT_EMAIL_RE``; the local part may carry percent- and ``\u`` escapes.
_ENCODED_EMAIL_RE = re.compile(
    r"(?:(?<![\w.!#$%*=^`{}~\\-])|(?<=\\[nrtbf])|(?<=%2[07]))"
    r"(?P<local>(?:\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}|[\w.!#$&'*+=?^`{|}~-]){1,64}?)"
    r"(?P<sep>%40|\\u0040|&#64;|＠)"
    r"(?P<domain>[\w](?:[\w.-]{0,251}[\w])?)",
    re.IGNORECASE,
)
_IDENTITY_KEYS = ("onpremisesimmutableid", "immutableid")
_ADMIN_FLAGS = ("isadmin", "isdelegatedadmin", "issuperadmin", "isprivileged")
_NOT_USER_TYPES = frozenset({"group", "serviceprincipal", "application", "app", "device"})


def _norm(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


_SECRET_NORMS = frozenset(_norm(key) for key in _SECRET_KEYS)


@dataclass(frozen=True)
class RedactionContext:
    """Per-output inputs: everything that is not in the value itself.

    ``salt`` is the run salt (see ``run_salt``); with an empty salt the pseudonyms are still deterministic but
    carry no run separation. ``run_paths`` are the spellings of the operator's run directory to remove.
    ``protected_names`` and ``protected_ids`` are privileged-user display names and immutable ids the caller
    already knows (``context_for_run`` reads them from the run's ``normalized/`` records, so they hold whichever
    sections the output selects; any found inside the value are added automatically). ``vocabulary`` is
    controlled vocabulary (role and group names) that a user's name must never rewrite.
    """

    salt: str = ""
    run_paths: tuple[str, ...] = ()
    protected_names: frozenset[str] = frozenset()
    protected_ids: frozenset[str] = frozenset()
    vocabulary: frozenset[str] = frozenset()
    incomplete: bool = False
    # What made the context incomplete, as safe ``(label, reason class)`` pairs (see ``ContextIncompleteError``) and
    # the same as ``"<label>: <reason class>"`` strings; ``incomplete_omitted`` counts problems beyond the kept ones.
    incomplete_reasons: tuple[str, ...] = ()
    incomplete_files: tuple[tuple[str, str], ...] = ()
    incomplete_omitted: int = 0
    # Retained separately because the associated reason can fall beyond the displayed-reasons limit.
    scan_size_exceeded: bool = False
    # The state of the run's ``normalized/`` files as discovery read them (see ``snapshot_run``); empty for a context
    # that was not built from one run directory.
    snapshot: tuple[tuple[str, tuple[int, int, int, int, int]], ...] = ()


def pseudonym(salt: str, text: str) -> str:
    """The projection's pseudonym: the first 16 hex digits of ``sha256(salt NUL text)``."""
    return hashlib.sha256((salt + "\0" + text).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def run_salt(run_dir: str | Path) -> str:
    """Derive a stable per-run salt without opening another run artifact."""
    return hashlib.sha256(os.path.realpath(run_dir).encode("utf-8", "surrogatepass")).hexdigest()


def run_path_roots(run_dir: str | Path) -> tuple[str, ...]:
    """Every spelling of the run directory a payload may carry, longest first."""
    run_path = Path(run_dir)
    roots = {str(run_path), os.path.abspath(run_path), os.path.realpath(run_path)}
    return tuple(sorted((r.rstrip(os.sep) for r in roots if r and r != os.sep), key=len, reverse=True))


_ROOT_PATTERNS: dict[tuple[str, ...], re.Pattern[str]] = {}


def _root_pattern(roots: tuple[str, ...]) -> re.Pattern[str]:
    pattern = _ROOT_PATTERNS.get(roots)
    if pattern is None:
        # A root is a whole path prefix: not the tail of a longer word or path, and not the start of a longer name
        # (``/tmp/run2``, ``/tmp/run.bak``); a sentence's closing full stop still ends it.
        pattern = re.compile(r"(?<![\w.~-])(?:" + "|".join(re.escape(r) for r in roots) + r")(?![\w-]|\.\w)")
        if len(_ROOT_PATTERNS) > 64:
            _ROOT_PATTERNS.clear()
        _ROOT_PATTERNS[roots] = pattern
    return pattern


def scrub_run_paths(text: str, roots: Iterable[str]) -> str:
    """Paths below the run become run-relative (when the text starts with one), the run itself ``<run-dir>``;
    every other occurrence of the run path becomes ``<run-dir>``. The result holds no root and is stable."""
    unique = tuple(sorted({r for r in roots if r}, key=lambda r: (-len(r), r)))
    if not unique or not text:
        return text
    for root in unique:
        if text == root:
            return RUN_DIR_PLACEHOLDER
        if text.startswith(root + os.sep):
            text = text[len(root) + 1:]
            break
    return _root_pattern(unique).sub(RUN_DIR_PLACEHOLDER, text)


# -- identities found in the data ---------------------------------------------------------------------------------


def _is_privileged_user(record: Mapping[Any, Any]) -> bool:
    keys = {_norm(k): v for k, v in record.items()}
    if str(keys.get("principaltype", "")).lower() in _NOT_USER_TYPES:
        return False
    if "onpremisesimmutableid" in keys or "immutableid" in keys:
        return True
    if any(keys.get(flag) is True for flag in _ADMIN_FLAGS):
        return True  # Google Workspace super and delegated administrators, and records flagged privileged
    if str(keys.get("principaltype", "")).lower() == "user" and ("roles" in keys or "rolenames" in keys or "counted" in keys):
        return True
    return keys.get("isuser") is True and ("roles" in keys or "rolenames" in keys)


def _is_group(record: Mapping[Any, Any]) -> bool:
    return str({_norm(k): v for k, v in record.items()}.get("principaltype", "")).lower() == "group"


@dataclass
class _Found:
    names: set[str] = field(default_factory=set)
    ids: set[str] = field(default_factory=set)
    vocabulary: set[str] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)
    limit_hits: int = 0  # JSON-looking strings above ``_MAX_EMBEDDED_JSON_CHARS`` that were not parsed

    def merge(self, other: "_Found") -> None:
        self.names |= other.names
        self.ids |= other.ids
        self.vocabulary |= other.vocabulary
        self.keys |= other.keys
        self.limit_hits += other.limit_hits


class _Num:
    """A JSON number kept as the literal it was written as: never re-parsed, so it cannot round, overflow to
    ``Infinity`` or lose its sign."""

    __slots__ = ("raw",)

    def __init__(self, raw: str) -> None:
        self.raw = raw

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Num({self.raw!r})"


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


# JSON embedded in a string is parsed (to find identities in it and to redact it as structure) up to this many
# characters. A longer string that looks like JSON is not parsed and is never passed on as if it had been: discovery
# and redaction both treat it as an incomplete context and fail closed (``_EmbeddedLimitError``).
_MAX_EMBEDDED_JSON_CHARS = 16 * 1024 * 1024
_JSON_START_RE = re.compile(r"\s*[\[{]")


def _maybe_json(text: str) -> Any:
    """The parsed value of a string that is a JSON object or array, else ``None``. Numbers are ``_Num``; the
    non-standard ``NaN`` and ``Infinity`` make the text not JSON. Raises ``_EmbeddedLimitError`` for a string longer
    than ``_MAX_EMBEDDED_JSON_CHARS`` that starts like JSON."""
    if not _JSON_START_RE.match(text):
        return None  # not JSON-looking: the one test discovery and redaction share (``str.strip`` and ``\\s`` agree)
    if len(text) > _MAX_EMBEDDED_JSON_CHARS:
        raise _EmbeddedLimitError
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] not in "{[" or stripped[-1] not in "}]":
        return None
    try:
        parsed = json.loads(stripped, parse_float=_Num, parse_int=_Num, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise RedactionDepthError("embedded JSON is nested too deeply to redact") from exc
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _collect(value: Any, found: _Found, *, names: bool) -> None:
    """Privileged-user display names, immutable ids, role vocabulary and key names found anywhere in ``value``
    (JSON embedded in a string included), so the same strings are replaced inside free text of the same output."""
    stack = [value]
    # Visited containers are kept alive here, not only their ids: a parsed embedded record that is freed would
    # hand its id to the next one parsed, which would then be skipped as "seen" and its identities lost.
    seen: dict[int, Any] = {}
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if names:  # ``_maybe_json`` is the one recogniser, the same one redaction uses
                try:
                    parsed = _maybe_json(item)
                except _EmbeddedLimitError:
                    found.limit_hits += 1
                    continue
                if parsed is not None:
                    stack.append(parsed)
        elif isinstance(item, Mapping):
            if id(item) in seen:
                continue
            seen[id(item)] = item
            if names:
                privileged = _is_privileged_user(item)
                for key, member in item.items():
                    norm = _norm(key)
                    if isinstance(key, str) and len(key) <= 64 and "@" not in key:
                        found.keys.add(key.lower())
                    if privileged and norm == "displayname" and isinstance(member, str) and member and not _PSEUDONYM_RE.match(member):
                        found.names.add(member)
                    if norm in _IDENTITY_KEYS and isinstance(member, str) and member and not _PSEUDONYM_RE.match(member):
                        found.ids.add(member)
                    if norm in _ROLE_KEYS or (_is_group(item) and norm == "displayname"):
                        if isinstance(member, str) and member:
                            found.vocabulary.add(member.lower())
                        elif isinstance(member, (list, tuple)):
                            found.vocabulary.update(m.lower() for m in member if isinstance(m, str) and m)
            stack.extend(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            if id(item) in seen:
                continue
            seen[id(item)] = item
            stack.extend(item)


# -- contexts ---------------------------------------------------------------------------------------------------------

# Discovery limits. Hitting one is never silent: the context is flagged ``incomplete`` (see ``RedactionContext``).
# A synthetic 90k-user run measured 44.1 MiB for its largest file and 84.1 MiB total. These limit scan bytes, not RSS.
_MAX_SCAN_FILES = 5_000            # ``normalized/**/*.json`` files per run
_MAX_FILE_BYTES = 64 * 1024 * 1024  # one file; a larger one is not read
_MAX_SCAN_BYTES = 256 * 1024 * 1024  # all files of one run together
_MAX_SCAN_DEPTH = 32               # directory levels below ``normalized/``
_MAX_REASONS = 20                  # problems a context keeps (the rest is only counted)
_MAX_LISTED_FILES = 10             # problems a refusal names (the rest is only counted)

# Why a file could not be used. A label and one of these classes are all a refusal ever says about a file.
REASON_UNREADABLE = "unreadable"
REASON_MALFORMED = "malformed JSON"
REASON_OVERSIZE = "oversize"
REASON_SCAN_BYTES = "scan bytes limit"
REASON_NON_REGULAR = "non-regular"
REASON_DANGLING = "dangling link"
REASON_LIMIT = "limit"
REASON_OUTSIDE = "outside run"
REASON_CHANGED = "changed during scan"


def _size_budget_exceeded(problems: Iterable[tuple[str, str]]) -> bool:
    return any(reason in (REASON_OVERSIZE, REASON_SCAN_BYTES) for _, reason in problems)


def _format_byte_limit(value: int) -> str:
    mib = 1024 * 1024
    return f"{value // mib} MiB" if value and value % mib == 0 else f"{value} bytes"


# The only path segments a refusal ever shows: the run's ``normalized`` directory and the ``normalized/<section>.json``
# names the product itself writes. A file name is untrusted text (``alice_smith.json``, ``acme_corp.json``), so spelling
# is never the test: a segment that is not on this list is opaque. A test scans ``src/`` and fails when a section
# literal the producers write is missing; a section the list does not know shows as ``<redacted-segment-N>``.
_PUBLIC_SECTION_LABELS = frozenset(
    {
        "normalized", "app_owner_edges", "application_consents", "application_credential_objects", "auth_context",
        "auth_methods", "bounded_samples", "break_glass_assessment", "capabilities", "capability_matrix",
        "collection_gaps", "compliance_policy_objects", "conditional_access_graph", "consent_policy_objects",
        "coverage_ledger", "cross_tenant_access_objects", "defender_av_objects", "detection_signal_objects",
        "device_posture", "devices", "directory_relationship_objects", "domain_hybrid_objects", "effective_admin_set",
        "exchange_policy_objects", "google_alias_errors", "google_calendar_acl_errors", "google_domains",
        "google_drive_files", "google_gmail_settings", "google_group_member_errors", "google_group_setting_errors",
        "google_group_settings", "google_mailbox_settings", "google_oauth_grant_errors", "google_oauth_tokens",
        "google_two_step_policies", "governance_objects", "identity_control_verdicts", "identity_users",
        "intune_policy_assignment_objects", "mailbox_forwarding", "normalization_coverage", "onedrive_posture_objects",
        "privileged_roles", "public_footprint_objects", "response", "role_assignments", "security_score_control_profiles",
        "security_scores", "sharepoint_tenant_settings", "snapshot", "teams_policy_objects", "update_management_objects",
        "users",
    }
)


def _safe_label(parts: Iterable[str]) -> str:
    """A run-relative path that is safe to show: a segment is kept only when it is a recognised public label
    (``_PUBLIC_SECTION_LABELS``: ``normalized`` or the name of a section the product writes, with the ``.json`` suffix);
    every other segment (a name, an address, a GUID, a credential or anything else a file can be called, however
    harmless it looks) becomes ``<redacted-segment-N>``, N being its 1-based position in the path. The run directory
    is never part of it."""
    shown = []
    for index, part in enumerate(parts, start=1):
        stem = part[: -len(".json")] if part.endswith(".json") else part
        keep = stem in _PUBLIC_SECTION_LABELS and (stem != "normalized" or part == stem)
        shown.append(part if keep else f"<redacted-segment-{index}>")
    return "/".join(shown) or "<run>"


class _EmbeddedLimitError(Exception):
    """A JSON-looking string is longer than ``_MAX_EMBEDDED_JSON_CHARS`` (internal; becomes a ``limit`` reason)."""


class _Unsafe(Exception):
    """A file or directory cannot be used; ``reason`` is one of the ``REASON_*`` classes."""

    def __init__(self, reason: str, bytes_read: int = 0) -> None:
        super().__init__(reason)
        self.reason = reason
        self.bytes_read = bytes_read


_DIR_MODE = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_FILE_MODE = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


def _open_dir_at(parent_fd: int, name: str, expected: os.stat_result | None = None) -> int:
    """A directory descriptor for ``name`` below ``parent_fd``, opened without following a link and checked on the
    descriptor (type, and identity when ``expected`` is the earlier ``lstat``)."""
    try:
        descriptor = os.open(name, _DIR_MODE, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise _Unsafe(REASON_CHANGED) from exc
    except PermissionError as exc:
        raise _Unsafe(REASON_UNREADABLE) from exc
    except OSError as exc:  # a symlink or a non-directory in the way: the tree changed under us
        raise _Unsafe(REASON_CHANGED) from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or (expected is not None and (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino)):
            raise _Unsafe(REASON_CHANGED)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """What identifies the state of one file: device, inode, size and the two change times (a write moves ``ctime``
    even when it restores ``mtime``)."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file_at(parent_fd: int, name: str, expected: os.stat_result, cap: int = _MAX_FILE_BYTES) -> bytes:
    """The bytes of regular file ``name`` below ``parent_fd``: never following a link, never blocking, identity, type
    and state re-checked on the descriptor, at most ``cap`` bytes (never more than ``_MAX_FILE_BYTES``).

    The state of the file (``_fingerprint``) must equal the listed one (``expected``) when it is opened and again after
    the last byte is read, and the bytes read must equal the size: a file that grew, shrank or was rewritten while
    it was read is ``changed during scan``, never partial content. ``cap`` is what the caller can still afford of
    the aggregate budget (reading past it is a ``limit``), charged against what was really read, not what was listed.
    """
    try:
        descriptor = os.open(name, _FILE_MODE, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise _Unsafe(REASON_CHANGED) from exc
    except PermissionError as exc:
        raise _Unsafe(REASON_UNREADABLE) from exc
    except OSError as exc:
        raise _Unsafe(REASON_CHANGED) from exc
    total = 0
    read_failed = False
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise _Unsafe(REASON_NON_REGULAR)
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise _Unsafe(REASON_CHANGED)
        if info.st_size > _MAX_FILE_BYTES:
            raise _Unsafe(REASON_OVERSIZE)
        if _fingerprint(info) != _fingerprint(expected):
            raise _Unsafe(REASON_CHANGED)  # grown, shrunk or rewritten between the listing and the open
        limit = min(cap, _MAX_FILE_BYTES)
        if info.st_size > limit:
            raise _Unsafe(REASON_OVERSIZE if limit >= _MAX_FILE_BYTES else REASON_SCAN_BYTES)
        chunks: list[bytes] = []
        while total < info.st_size:
            chunk = os.read(descriptor, min(1 << 20, info.st_size - total))
            if not chunk:
                break
            total += len(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if after.st_nlink != 1 or total != info.st_size or _fingerprint(after) != _fingerprint(info):
            raise _Unsafe(REASON_CHANGED)
        return b"".join(chunks)
    except _Unsafe as exc:
        read_failed = True
        exc.bytes_read += total
        raise
    except OSError as exc:
        read_failed = True
        raise _Unsafe(REASON_UNREADABLE, total) from exc
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            # Preserve an earlier refusal; otherwise closing can fail after consuming budget too.
            if not read_failed:
                raise _Unsafe(REASON_UNREADABLE, total) from exc


class _Scan:
    def __init__(self, *, read: bool = True) -> None:
        self.read = read  # False: only list and fingerprint (``snapshot_run``)
        self.found = _Found()
        self.problems: list[tuple[tuple[str, ...], str]] = []
        self.fingerprints: list[tuple[str, tuple[int, int, int, int, int]]] = []
        self.files = 0
        self.budget = _MAX_SCAN_BYTES

    def problem(self, parts: tuple[str, ...], reason: str) -> None:
        self.problems.append((parts, reason))

    def collect(self, parts: tuple[str, ...], data: bytes) -> None:
        try:
            payload = json.loads(data.decode("utf-8"))
            local = _Found()
            _collect(payload, local, names=True)
        except (ValueError, RecursionError):  # malformed JSON, bad encoding, too deeply nested
            self.problem(parts, REASON_MALFORMED)
            return
        self.found.merge(local)
        if local.limit_hits:
            self.problem(parts, REASON_LIMIT)

    def take(self, parts: tuple[str, ...], reader: Callable[[int], bytes], info: os.stat_result) -> None:
        if self.files >= _MAX_SCAN_FILES:
            self.problem(parts, REASON_LIMIT)
            return
        self.files += 1
        if info.st_nlink != 1:
            self.problem(parts, REASON_NON_REGULAR)
            return
        size = info.st_size
        self.fingerprints.append(("/".join(parts), _fingerprint(info)))
        if size > _MAX_FILE_BYTES:
            self.problem(parts, REASON_OVERSIZE)
            return
        if size > self.budget:
            self.problem(parts, REASON_SCAN_BYTES)
            return
        if not self.read:
            self.budget -= size  # snapshots also enforce the aggregate size limit
            return
        try:
            data = reader(self.budget)
        except _Unsafe as exc:
            self.budget -= exc.bytes_read
            self.problem(parts, exc.reason)
            return
        except OSError:
            self.problem(parts, REASON_UNREADABLE)
            return
        self.budget -= len(data)  # what was really read, not what was listed
        self.collect(parts, data)

    def _enter(self, frames: list["_Frame"], descriptor: int, parts: tuple[str, ...], depth: int) -> None:
        """Push the directory ``descriptor`` (owned from here on) unless it is too deep or cannot be listed."""
        try:
            if depth > _MAX_SCAN_DEPTH:
                self.problem(parts, REASON_LIMIT)
            else:
                frames.append(_Frame(descriptor, parts, sorted(os.listdir(descriptor))))
                return
        except OSError:
            self.problem(parts, REASON_UNREADABLE)
        os.close(descriptor)

    def walk(self, root_fd: int, root_parts: tuple[str, ...]) -> None:
        """Every ``*.json`` below the descriptor (which is closed here), depth first, names sorted; nothing but a
        regular file is opened, and at most ``_MAX_SCAN_DEPTH`` + 1 descriptors are open at once."""
        frames: list[_Frame] = []
        try:
            self._enter(frames, root_fd, root_parts, 0)
            while frames:
                frame = frames[-1]
                if frame.position >= len(frame.names):
                    os.close(frame.descriptor)
                    frames.pop()
                    continue
                name = frame.names[frame.position]
                frame.position += 1
                here = (*frame.parts, name)
                try:
                    info = os.stat(name, dir_fd=frame.descriptor, follow_symlinks=False)
                except OSError:
                    self.problem(here, REASON_CHANGED)
                    continue
                mode = info.st_mode
                if stat.S_ISDIR(mode):
                    try:
                        child = _open_dir_at(frame.descriptor, name, info)
                    except _Unsafe as exc:
                        self.problem(here, exc.reason)
                    else:
                        self._enter(frames, child, here, len(frames))
                elif stat.S_ISLNK(mode):
                    self.problem(here, REASON_NON_REGULAR)
                elif not name.lower().endswith(".json"):
                    continue
                elif not stat.S_ISREG(mode):
                    self.problem(here, REASON_NON_REGULAR)  # FIFO, socket, device: never opened
                else:
                    self.take(here, lambda cap, d=frame.descriptor, n=name, i=info: _read_file_at(d, n, i, cap), info)
        finally:
            for frame in frames:
                os.close(frame.descriptor)


class _Frame:
    __slots__ = ("descriptor", "parts", "names", "position")

    def __init__(self, descriptor: int, parts: tuple[str, ...], names: list[str]) -> None:
        self.descriptor = descriptor
        self.parts = parts
        self.names = names
        self.position = 0


def read_normalized_sections(run_dir: str | Path) -> dict[str, Any]:
    """Read shareable report sections; refuse a failed read even if it later recovers."""
    sections: dict[str, Any] = {}
    run_real = os.path.realpath(run_dir)
    try:
        run_fd = os.open(run_real, _DIR_MODE)
    except OSError:
        raise ContextIncompleteError((("<run>", REASON_UNREADABLE),)) from None
    try:
        try:
            info = os.stat("normalized", dir_fd=run_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise _Unsafe(REASON_NON_REGULAR)
            root_fd = _open_dir_at(run_fd, "normalized", info)
        except FileNotFoundError:
            return sections
        except _Unsafe as exc:
            raise ContextIncompleteError((("normalized", exc.reason),)) from None
        except OSError:
            raise ContextIncompleteError((("normalized", REASON_UNREADABLE),)) from None
        try:
            budget = _MAX_SCAN_BYTES
            try:
                names = sorted(os.listdir(root_fd))
            except OSError:
                raise ContextIncompleteError((("normalized", REASON_UNREADABLE),)) from None
            for name in names:
                if not name.lower().endswith(".json"):
                    continue
                try:
                    entry = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                    if stat.S_ISDIR(entry.st_mode):
                        continue
                    if stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1:
                        reader = lambda cap, d=root_fd, n=name, i=entry: _read_file_at(d, n, i, cap)  # noqa: E731
                    else:
                        raise _Unsafe(REASON_NON_REGULAR)
                    if entry.st_size > _MAX_FILE_BYTES:
                        raise _Unsafe(REASON_OVERSIZE)
                    if entry.st_size > budget:
                        raise _Unsafe(REASON_SCAN_BYTES)
                    data = reader(budget)
                    budget -= len(data)  # charged for the bytes really read
                    payload = json.loads(data.decode("utf-8"))
                except _Unsafe as exc:
                    budget -= exc.bytes_read
                    raise ContextIncompleteError(((_safe_label(("normalized", name)), exc.reason),)) from None
                except (ValueError, RecursionError):
                    raise ContextIncompleteError(((_safe_label(("normalized", name)), REASON_MALFORMED),)) from None
                except OSError:
                    raise ContextIncompleteError(((_safe_label(("normalized", name)), REASON_UNREADABLE),)) from None
                if payload not in ({}, [], None):
                    sections[name[: -len(".json")]] = payload
        finally:
            os.close(root_fd)
    finally:
        os.close(run_fd)
    return sections


Snapshot = tuple[tuple[str, tuple[int, int, int, int, int]], ...]


@dataclass(frozen=True)
class _Discovery:
    names: frozenset[str] = frozenset()
    ids: frozenset[str] = frozenset()
    vocabulary: frozenset[str] = frozenset()
    problems: tuple[tuple[str, str], ...] = ()
    snapshot: Snapshot = ()


def _scan_run_identities(run_path: Path, *, read: bool = True) -> _Discovery:
    """Privileged-user names, immutable ids, role vocabulary and the files discovery could not use.

    Every ``normalized/**/*.json`` is read (bounded), not just the sections a report selects, so an output that
    shows only findings still knows who the administrators are. Discovery never gives up silently: a file that
    cannot be read, or a limit that is hit, is a problem (a safe label and a reason class), the identities found
    elsewhere are kept, and the caller gets the problems (``RedactionContext.incomplete``).

    Every directory is opened below a descriptor of the run directory without following links, every file is
    checked on its descriptor (regular, same identity as listed, size) and nothing is cached: a file replaced,
    swapped, made unreadable or edited between two calls is seen by the next one. A file that changes while it is
    read is a ``changed during scan`` problem, and the fingerprints of every file listed are returned as the
    ``snapshot`` the caller can compare later (``read=False`` lists and fingerprints without reading).
    """
    run_real = os.path.realpath(run_path)
    try:
        run_fd = os.open(run_real, _DIR_MODE)
    except OSError:
        return _Discovery(problems=(("<run>", REASON_UNREADABLE),))
    scan = _Scan(read=read)
    try:
        try:
            info = os.stat("normalized", dir_fd=run_fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None  # no normalized directory: nothing to discover
        except OSError:
            scan.problem(("normalized",), REASON_UNREADABLE)
            info = None
        if info is not None:
            if stat.S_ISLNK(info.st_mode):
                try:
                    os.stat("normalized", dir_fd=run_fd)
                    scan.problem(("normalized",), REASON_NON_REGULAR)  # a symlinked root is a symlinked ancestor
                except FileNotFoundError:
                    scan.problem(("normalized",), REASON_DANGLING)
                except OSError:
                    scan.problem(("normalized",), REASON_UNREADABLE)
            elif not stat.S_ISDIR(info.st_mode):
                scan.problem(("normalized",), REASON_NON_REGULAR)
            else:
                try:
                    root_fd = _open_dir_at(run_fd, "normalized", info)
                except _Unsafe as exc:
                    scan.problem(("normalized",), exc.reason)
                else:
                    scan.walk(root_fd, ("normalized",))  # closes the descriptor
    finally:
        os.close(run_fd)
    labelled = []
    for index, (parts, reason) in enumerate(sorted(set(scan.problems)), start=1):
        label = _safe_label(parts)
        labelled.append((f"{label}#{index}" if "<redacted-segment-" in label else label, reason))
    found = scan.found
    return _Discovery(
        frozenset(found.names), frozenset(found.ids), frozenset(found.vocabulary), tuple(labelled), tuple(sorted(scan.fingerprints))
    )


def snapshot_run(run_dir: str | Path) -> Snapshot:
    """The state of every ``normalized/**/*.json`` file of a run (relative path, device, inode, size, ``mtime`` and
    ``ctime``), listed without reading any file. Two equal snapshots taken around a read mean the files read were not
    touched in between; compare with ``RedactionContext.snapshot`` (``assert_snapshot_stable``)."""
    discovery = _scan_run_identities(Path(run_dir), read=False)
    if discovery.problems:
        files, omitted = _problem_fields(list(discovery.problems))
        raise ContextIncompleteError(files, omitted, size_limit=_size_budget_exceeded(discovery.problems))
    return discovery.snapshot


def assert_snapshot_stable(run_dir: str | Path, expected: Snapshot, *, label: str = "<run>") -> None:
    """Raise ``ContextIncompleteError`` unless the run's ``normalized/`` files are exactly as ``expected`` (an earlier
    ``snapshot_run`` or ``RedactionContext.snapshot``): a file added, removed, replaced, grown or rewritten since then
    means what was read and what was discovered may not be the same bytes, so nothing is published."""
    if snapshot_run(run_dir) != expected:
        raise ContextIncompleteError(((label, REASON_CHANGED),))


def _problem_fields(problems: list[tuple[str, str]], prefix: str = "") -> tuple[tuple[tuple[str, str], ...], int]:
    kept = tuple((f"{prefix}{label}", reason) for label, reason in problems[:_MAX_REASONS])
    return kept, max(0, len(problems) - _MAX_REASONS)


def _reason_strings(files: tuple[tuple[str, str], ...], omitted: int) -> tuple[str, ...]:
    return (*(f"{label}: {reason}" for label, reason in files), *((f"and {omitted} more",) if omitted else ()))


def context_for_run(run_dir: str | Path) -> RedactionContext:
    """The context for outputs derived from one run: its salt, its path spellings, its administrators' names and
    immutable ids (from every ``normalized/`` record, whichever sections the output selects) and role vocabulary."""
    run_path = Path(run_dir)
    discovery = _scan_run_identities(run_path)
    names, ids, vocabulary = discovery.names, discovery.ids, discovery.vocabulary
    files, omitted = _problem_fields(list(discovery.problems))
    values: dict[str, Any] = {
        "incomplete": bool(discovery.problems),
        "snapshot": discovery.snapshot,
        "incomplete_reasons": _reason_strings(files, omitted),
        "incomplete_files": files,
        "incomplete_omitted": omitted,
        "scan_size_exceeded": _size_budget_exceeded(discovery.problems),
        "salt": run_salt(run_path),
        "run_paths": run_path_roots(run_path),
        "protected_names": names,
        "protected_ids": ids,
        "vocabulary": vocabulary,
    }
    return RedactionContext(**values)


def context_for_runs(run_dirs: Iterable[str | Path], paths: Iterable[str | Path] = ()) -> RedactionContext:
    """One context for an output built from several runs (a diff, a comparison) or from other local paths.

    The first run supplies the salt (a comparison has one); names, ids, vocabulary and path spellings of every
    run are protected, and ``paths`` are further directories whose spellings are scrubbed (a customer pack).
    """
    roots: set[str] = set()
    names: set[str] = set()
    ids: set[str] = set()
    vocabulary: set[str] = set()
    files: list[tuple[str, str]] = []
    omitted = 0
    incomplete = False
    size_limit = False
    salt = ""
    snapshot: list[tuple[str, tuple[int, int, int, int, int]]] = []
    for index, run_dir in enumerate(run_dirs):
        context = context_for_run(run_dir)
        snapshot.extend((f"{index}/{path}", state) for path, state in context.snapshot)
        incomplete = incomplete or context.incomplete
        size_limit = size_limit or context.scan_size_exceeded
        files.extend((f"run {index + 1}: {label}", reason) for label, reason in context.incomplete_files)
        omitted += context.incomplete_omitted
        salt = salt if index else context.salt
        roots.update(context.run_paths)
        names.update(context.protected_names)
        ids.update(context.protected_ids)
        vocabulary.update(context.vocabulary)
    for path in paths:
        roots.update(run_path_roots(path))
    kept = tuple(files[:_MAX_REASONS])
    omitted += max(0, len(files) - _MAX_REASONS)
    return RedactionContext(
        salt=salt,
        run_paths=tuple(sorted(roots, key=lambda r: (-len(r), r))),
        protected_names=frozenset(names),
        protected_ids=frozenset(ids),
        vocabulary=frozenset(vocabulary),
        incomplete=incomplete,
        incomplete_reasons=_reason_strings(kept, omitted),
        incomplete_files=kept,
        incomplete_omitted=omitted,
        scan_size_exceeded=size_limit,
        snapshot=tuple(snapshot),
    )


def assert_runs_stable(run_dirs: Iterable[str | Path], context: RedactionContext) -> None:
    """``assert_snapshot_stable`` for the runs of a ``context_for_runs`` context (or the one run of ``context_for_run``)."""
    dirs = list(run_dirs)
    if len(dirs) == 1 and not any(path[:2] == "0/" for path, _ in context.snapshot):
        assert_snapshot_stable(dirs[0], context.snapshot)
        return
    now: list[tuple[str, tuple[int, int, int, int, int]]] = []
    for index, run_dir in enumerate(dirs):
        now.extend((f"{index}/{path}", state) for path, state in snapshot_run(run_dir))
    if tuple(now) != context.snapshot:
        raise ContextIncompleteError((("<run>", REASON_CHANGED),))


# -- redaction --------------------------------------------------------------------------------------------------------

_JSON_SHAPES: tuple[tuple[int | None, tuple[str, str]], ...] = (
    (None, (", ", ": ")), (None, (",", ":")), (2, (",", ": ")), (4, (",", ": ")), (1, (",", ": ")),
)


def _non_empty(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (str, bytes, list, tuple, set, frozenset, Mapping)):
        return len(value) > 0
    return True


def _dump(value: Any, ensure_ascii: bool, indent: int | None, separators: tuple[str, str], level: int = 0) -> str:
    """``json.dumps`` for parsed embedded JSON, writing ``_Num`` literals back exactly as they were written."""
    item_sep, key_sep = separators
    if isinstance(value, _Num):
        return value.raw
    if isinstance(value, (Mapping, list, tuple)):
        mapping = isinstance(value, Mapping)
        if not value:
            return "{}" if mapping else "[]"
        opener, closer = ("{", "}") if mapping else ("[", "]")
        if indent is None:
            glue, lead, tail = item_sep, "", ""
        else:
            pad = "\n" + " " * (indent * (level + 1))
            glue, lead, tail = item_sep + pad, pad, "\n" + " " * (indent * level)
        if mapping:
            parts = [
                json.dumps(str(key), ensure_ascii=ensure_ascii) + key_sep + _dump(member, ensure_ascii, indent, separators, level + 1)
                for key, member in value.items()
            ]
        else:
            parts = [_dump(member, ensure_ascii, indent, separators, level + 1) for member in value]
        return opener + lead + glue.join(parts) + tail + closer
    return json.dumps(value, ensure_ascii=ensure_ascii, allow_nan=False)


def _dump_like(original: str, parsed: Any, redacted: Any) -> str:
    """``redacted`` serialised the way ``original`` was, when one of the usual layouts reproduces it exactly."""
    for ensure_ascii in (True, False):
        for indent, separators in _JSON_SHAPES:
            try:
                if _dump(parsed, ensure_ascii, indent, separators) == original:
                    return _dump(redacted, ensure_ascii, indent, separators)
            except (ValueError, TypeError):
                continue
    return _dump(redacted, original.isascii(), None, (", ", ": "))


class _Redactor:
    def __init__(self, context: RedactionContext, value: Any, markup: bool) -> None:
        self.markup = markup
        self.salt = context.salt
        self.roots = context.run_paths
        self.depth = 0
        self.blank = 0  # > 0 while walking the value of a free-text key whose strings are replaced
        if context.incomplete:
            # Fail closed: the names and ids of this run were not all discovered, so free text may carry ones this
            # redactor was never told about. The shareable profiles refuse rather than return a partial result.
            raise ContextIncompleteError(
                context.incomplete_files or (("<context>", "incomplete"),), context.incomplete_omitted,
                size_limit=context.scan_size_exceeded,
            )
        found = _Found()
        names = set(context.protected_names)
        ids = set(context.protected_ids)
        _collect(value, found, names=True)
        if found.limit_hits:
            raise ContextIncompleteError((("<output value>", REASON_LIMIT),))
        names |= found.names
        ids |= found.ids
        # A name that is also report vocabulary (a role, a status word, a key of the structure) stays readable in
        # free text; the user's own structured ``display_name`` is still pseudonymised.
        vocabulary = {v.lower() for v in context.vocabulary} | found.vocabulary | _STATIC_VOCABULARY | found.keys
        vocabulary_norms = {_norm(v) for v in vocabulary}
        self.names = sorted(
            (
                n for n in names
                if len(n) >= 4 and not _PSEUDONYM_RE.match(n) and n.lower() not in vocabulary and _norm(n) not in vocabulary_norms and not _structural(n)
            ),
            key=len, reverse=True,
        )
        # The alternation puts a generated pseudonym first, so ``User 0123...`` is never re-read as the name ``User``.
        self.name_re = (
            re.compile(_PSEUDONYM_KEEP + r"|(?<!\w)(?P<hit>" + "|".join(re.escape(n) for n in self.names) + r")(?!\w)")
            if self.names else None
        )
        # Immutable ids are protected by value, whatever their shape and case (``planted_immutable_id`` is as much an id
        # as a base64 one); the pseudonym is that of the id as discovered, so every spelling gets the same one. The only
        # boundary is a word character (so ``key=ID``, ``/users/ID/`` and ``a-ID`` are all caught); the only floor is
        # ``_MIN_NARRATIVE_ID`` characters for free text, because a shorter value would rewrite ordinary words and
        # numbers (a structured ``immutable_id`` is pseudonymised whatever its length).
        self.id_canonical = {
            i.lower(): i for i in sorted(ids, reverse=True) if len(i) >= _MIN_NARRATIVE_ID and not _PSEUDONYM_RE.match(i)
        }
        self.ids = sorted(self.id_canonical.values(), key=len, reverse=True)
        self.id_re = (
            re.compile(
                _PSEUDONYM_KEEP + r"|(?<!\w)(?P<hit>" + "|".join(re.escape(i) for i in self.ids) + r")(?!\w)",
                re.IGNORECASE,
            )
            if self.ids else None
        )
    # -- text ---------------------------------------------------------------------------------------------
    def text(self, value: str, *, names: bool = True, key: bool = False) -> str:
        """``value`` as text. ``key`` is a mapping key: identifiers and credential assignments only, no name or id
        substitution, no embedded JSON. ``names=False`` is a controlled-vocabulary value (finding id, setting name,
        reason code, status): no user name is substituted into it; identifiers in it are still masked."""
        if not value:
            return value
        if self.blank and not key:
            return TEXT_PLACEHOLDER  # a string below a free-text key (the policy of this profile)
        if not key:
            embedded = self._embedded_json(value)
            if embedded is not None:
                return embedded
        if self.roots:
            value = scrub_run_paths(value, self.roots)
        value = self._secrets(value, minimal=self.markup)
        value = OUTPUT_EMAIL_RE.sub(self._mask_email, value)
        value = _ENCODED_EMAIL_RE.sub(self._mask_encoded_email, value)
        value = _GUID_RE.sub(self._mask_guid, value)
        if not key:
            if names and self.name_re is not None:
                value = self.name_re.sub(self._name, value)
            if self.id_re is not None:
                value = self.id_re.sub(self._identifier, value)
        return value

    @staticmethod
    def _secrets(value: str, *, minimal: bool) -> str:
        # ``minimal``: rendered JSON, HTML, CSV and Markdown. ``key=value`` secrets were redacted in the structure
        # before rendering; the inline pattern cannot tell where a value ends in markup. Mapping keys use the full
        # pattern (a key such as ``password=value`` carries its credential in the key text).
        value = JWT_RE.sub("***redacted-jwt***", BEARER_RE.sub("Bearer ***redacted***", value))
        value = _redact_url_credentials(value)
        if minimal:
            return value

        return _redact_inline_secrets(value)

    def _embedded_json(self, value: str) -> str | None:
        """A string that is a JSON object or array is parsed, redacted as structure and written back the way it was
        laid out, so escapes and quotes stay valid; anything else is ``None`` (redact it as text)."""
        try:
            parsed = _maybe_json(value)
        except _EmbeddedLimitError:
            raise ContextIncompleteError((("<output value>", REASON_LIMIT),)) from None
        if parsed is None:
            return None
        stripped = value.strip()
        lead, trail = value[: len(value) - len(value.lstrip())], value[len(value.rstrip()):]
        redacted = self.walk(parsed)
        return lead + _dump_like(stripped, parsed, redacted) + trail

    @staticmethod
    def _mask_email(match: re.Match[str]) -> str:
        local, domain = match["local"], match["domain"]
        if f"{local}@{domain}".lower() in PUBLIC_ADDRESSES or domain.replace(".", "").isdigit():
            return match[0]
        return f"{match['field'] or ''}{match['quote']}***@{domain}"

    @staticmethod
    def _mask_encoded_email(match: re.Match[str]) -> str:
        from urllib.parse import unquote

        local, domain = match["local"], match["domain"]
        if f"{unquote(local)}@{domain}".lower() in PUBLIC_ADDRESSES or domain.replace(".", "").isdigit():
            return match[0]
        return f"***{match['sep']}{domain}"

    def _mask_guid(self, match: re.Match[str]) -> str:
        label = match["label"] or ""
        guid = match[0][len(label):].lower()
        return label + "Guid " + pseudonym(self.salt, guid)

    def _name(self, match: re.Match[str]) -> str:
        return match["keep"] or _USER_PREFIX + pseudonym(self.salt, match["hit"])

    def _identifier(self, match: re.Match[str]) -> str:
        return match["keep"] or _IMMUTABLE_PREFIX + pseudonym(self.salt, self.id_canonical.get(match["hit"].lower(), match["hit"]))

    # -- structure ----------------------------------------------------------------------------------------
    def walk(self, value: Any, controlled: bool = False) -> Any:
        if isinstance(value, str):
            return self.text(value, names=not controlled)
        if not isinstance(value, (Mapping, list, tuple, set, frozenset)):
            return value
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                raise RedactionDepthError(f"value is nested more than {MAX_DEPTH} levels")
            if isinstance(value, Mapping):
                return self.mapping(value, controlled)
            if isinstance(value, list):
                return [self.walk(item, controlled) for item in value]
            if isinstance(value, tuple):
                return tuple(self.walk(item, controlled) for item in value)
            return type(value)(self.walk(item, controlled) for item in value)
        finally:
            self.depth -= 1

    def mapping(self, record: Mapping[Any, Any], controlled: bool = False) -> dict[Any, Any]:
        user = _is_privileged_user(record)
        group = _is_group(record)
        rows: list[tuple[Any, Any, Any]] = []
        for key, item in record.items():
            norm = _norm(key)
            if norm in _SECRET_NORMS and _non_empty(item):
                item = SECRET_PLACEHOLDER
            elif isinstance(item, str):
                if not item:
                    pass
                elif self.blank:
                    item = TEXT_PLACEHOLDER
                elif norm in _IDENTITY_KEYS:
                    item = item if _PSEUDONYM_RE.match(item) else _IMMUTABLE_PREFIX + pseudonym(self.salt, item)
                elif user and norm == "displayname":
                    item = item if _PSEUDONYM_RE.match(item) else _USER_PREFIX + pseudonym(self.salt, item)
                elif group and norm == "displayname":
                    item = self.text(item, names=False)
                elif str(key).lower() in TENANT_TEXT_KEYS:
                    item = TEXT_PLACEHOLDER
                else:
                    item = self.text(item, names=not controlled and norm not in _CONTROLLED_KEYS)
            elif str(key).lower() in TENANT_TEXT_KEYS:
                # Every string below a free-text key is replaced, but the value still goes through the ordinary walk:
                # its mapping keys are masked and a credential key still replaces its whole value.
                self.blank += 1
                try:
                    item = self.walk(item, controlled or norm in _CONTROLLED_KEYS)
                finally:
                    self.blank -= 1
            else:
                item = self.walk(item, controlled or norm in _CONTROLLED_KEYS)
            if self.blank and isinstance(key, str) and key:
                new_key = TEXT_PLACEHOLDER
            else:
                new_key = self.text(key, key=True) if isinstance(key, str) and key else key
            rows.append((key, new_key, item))
        # Output keys are reserved whether they changed or not, so a rewritten key can never displace one that was
        # already there; a collision takes ``#n`` from a counter kept per rewritten name (linear overall).
        used = {new for old, new, _ in rows if new == old}
        counters: dict[Any, int] = {}
        out: dict[Any, Any] = {}
        for old, new, item in rows:
            if new != old:
                if new in used:
                    suffix = counters.get(new, 2)
                    while f"{new}#{suffix}" in used:
                        suffix += 1
                    counters[new] = suffix + 1
                    new = f"{new}#{suffix}"
                used.add(new)
            out[new] = item
        return out


def redact_output(
    value: Any,
    *,
    profile: str = PROFILE_SHAREABLE,
    context: RedactionContext | None = None,
    markup: bool = False,
) -> Any:
    """``value`` with the identifiers ``profile`` protects removed; same shape, deterministic, idempotent.

    ``markup=True`` is for text that is already rendered (HTML, CSV, Markdown, serialised JSON): it skips the
    inline ``key=value`` secret pattern, which cannot tell where a value ends in markup. Redact the structure
    before rendering; use ``markup=True`` only for the final pass over the rendered text.

    ``profile`` is a name from ``PROFILES``. An unknown name raises ``KeyError``
    (a typo must not silently publish). A value nested deeper than ``MAX_DEPTH`` raises ``RedactionDepthError``.
    ``context`` carries the run salt, run paths and known names; omit it for text with no run (pseudonyms are
    then unsalted).
    """
    if profile not in PROFILES:
        raise KeyError(profile)
    if profile == PROFILE_LOCAL:
        return value
    try:
        return _Redactor(context or RedactionContext(), value, markup).walk(value)
    except RecursionError as exc:
        raise RedactionDepthError("value is nested too deeply to redact") from exc


def _settle(value: Any, depth: int) -> Any:
    if depth > MAX_DEPTH + 1:
        return value
    if isinstance(value, list):
        return [_settle(member, depth + 1) for member in value]
    if not isinstance(value, Mapping):
        return value
    result = {key: _settle(member, depth + 1) for key, member in value.items()}
    rows = result.get("citations")
    if isinstance(rows, list) and all(isinstance(row, Mapping) for row in rows):
        settled = dedupe_citations(rows)
        result["citations"] = settled
        if "citation_summary" in result:
            result["citation_summary"] = build_citation_summary(settled)
        if "citation_count" in result:
            result["citation_count"] = len(settled)
    # A summary copied beside the pack it describes (``report_pack_citation_summary``) follows the pack's own.
    pack = result.get("report_pack")
    if (
        "report_pack_citation_summary" in result
        and isinstance(pack, Mapping)
        and isinstance(pack.get("citation_summary"), Mapping)
    ):
        result["report_pack_citation_summary"] = dict(pack["citation_summary"])
    return result


def settle_citations(payload: Any) -> Any:
    """A redacted payload with every citation list de-duplicated and every summary re-derived.

    Masking can make two citations identical, and a summary computed before masking would then disagree with the
    list it sits beside (``verify-pack`` checks that). This applies to the payload and to every nested container
    that holds a ``citations`` list (a ``report_pack``, a notification section), to the ``citation_summary`` and
    ``citation_count`` beside such a list, and to a ``report_pack_citation_summary`` copied from the nested pack's
    summary. Values without citations are returned unchanged.
    """
    if not isinstance(payload, (Mapping, list)):
        return payload
    return _settle(payload, 0)


def redact_payload(
    value: Any,
    *,
    run_dirs: Iterable[str | Path] = (),
    paths: Iterable[str | Path] = (),
    profile: str = PROFILE_SHAREABLE,
    markup: bool = False,
) -> Any:
    """The complete payload a tool or command returns, redacted with the context of the runs it was built from
    and with its citation summary re-derived. For return values that can leave the machine (MCP tools, notifications)."""
    dirs = list(run_dirs)
    context = context_for_runs(dirs, paths)
    redacted = redact_output(value, profile=profile, context=context, markup=markup)
    if dirs and profile != PROFILE_LOCAL:
        assert_runs_stable(dirs, context)  # the files discovery read are the files there still are
    return settle_citations(redacted)
