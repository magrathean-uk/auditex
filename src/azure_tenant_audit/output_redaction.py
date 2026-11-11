"""Structured redaction and bounded identity discovery for shareable output."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from collections import deque
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .citations import build_citation_summary, dedupe_citations
from .guarded_io import UnsafeRunFileError, current_context, guarded_operation
from .secret_hygiene import _OUTPUT_EMAIL_RE as OUTPUT_EMAIL_RE
from .secret_hygiene import _OUTPUT_GUID_RE as OUTPUT_GUID_RE
from .secret_hygiene import BEARER_RE, JWT_RE

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
        "contact+auditex@magrathean.uk",
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
    # D5: directory people with at least one recorded name spelling that cannot be masked in free text, as
    # ``(reason, count)`` pairs in ``D5_REASONS`` order (never a name). Their name fields are still pseudonymised.
    unmatched_names: tuple[tuple[str, int], ...] = ()
    # D5: the person-name index (``_NameIndex``), built once per context and shared by every call on it. ``None`` is
    # built on first use from ``protected_names`` and ``vocabulary``.
    _index: Any = field(default=None, compare=False, hash=False, repr=False)


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
    return _privileged_keys({_norm(k): v for k, v in record.items()})


def _privileged_keys(keys: Mapping[str, Any]) -> bool:
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


# D5: what marks a mapping as a directory person, and what is read from one (keys compared as ``_norm``).
_D5_PERSON_KINDS = frozenset({"user", "google_user", "admin#directory#user"})
_D5_PERSON_ODATA = "#microsoft.graph.user"
_D5_NAME_FIELDS = ("displayname", "fullname")
_D5_FAMILY_FIELDS = ("surname", "familyname")
_D5_NAME_PART_FIELDS = frozenset({"givenname", "surname", "familyname"})
_D5_ID_FIELDS = (
    "userprincipalname", "principalname", "primaryemail", "mail", "mailnickname", "onpremisessamaccountname",
)
_D5_ADDRESS_FIELDS = ("userprincipalname", "principalname", "primaryemail", "mail")
# A person's identity for the unmatched count: the directory object id (a role or assignment record names the user in
# ``principalId``, so that comes before a record's own ``id``) is authoritative; the user principal name identifies a
# person only for a record without an object id (see ``_unmatched_people``).
_D5_OBJECT_ID_FIELDS = ("principalid", "userid", "objectid", "id")
_D5_PRINCIPAL_FIELDS = ("userprincipalname", "principalname", "primaryemail")

# A discovered person record: ``(canonical, name strings, given name, family name, id strings, identity)``. The
# identity is ``(object id, principal name)``, lower-cased, ``""`` for a missing one (or ``()`` for neither); it decides
# who is counted unmatched. The pseudonym stays that of the canonical name.
_Person = tuple[str, tuple[str, ...], str, str, tuple[str, ...], tuple[str, ...]]


def _is_directory_person(keys: Mapping[str, Any]) -> bool:
    """A user record of either normaliser or raw API, a D3 privileged user, or a user reference (an address and a
    display name, such as an audit initiator). Groups, service principals, applications and devices never are."""
    if str(keys.get("principaltype", "")).lower() in _NOT_USER_TYPES:
        return False
    kind = keys.get("kind")
    if isinstance(kind, str) and kind.lower() in _D5_PERSON_KINDS:
        return True
    if keys.get("odatatype") == _D5_PERSON_ODATA or _privileged_keys(keys):
        return True
    address = keys.get("userprincipalname", keys.get("principalname"))
    shown = keys.get("displayname")
    return isinstance(address, str) and "@" in address and isinstance(shown, str) and bool(shown)


def _usable(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not _PSEUDONYM_RE.match(value)


def _person(keys: Mapping[str, Any]) -> _Person | None:
    """The person a directory-person record describes, or ``None`` when it carries no name and no address."""
    names = [keys[k] for k in _D5_NAME_FIELDS if _usable(keys.get(k))]
    given = keys.get("givenname")
    family = next((keys[k] for k in _D5_FAMILY_FIELDS if _usable(keys.get(k))), None)
    sub = keys.get("name")
    if isinstance(sub, Mapping):  # Google raw: ``name: {givenName, familyName, fullName}``
        parts = {_norm(k): v for k, v in sub.items()}
        names.extend(parts[k] for k in _D5_NAME_FIELDS if _usable(parts.get(k)))
        given = given if _usable(given) else parts.get("givenname")
        family = family or next((parts[k] for k in _D5_FAMILY_FIELDS if _usable(parts.get(k))), None)
    ids = tuple(
        keys[k] for k in _D5_ID_FIELDS
        if _usable(keys.get(k)) and _D5_WORD_RE.search(keys[k].split("@", 1)[0])  # ``***@domain`` is no address
    )
    addresses = [keys[k] for k in _D5_ADDRESS_FIELDS if keys.get(k) in ids and "@" in keys[k]]
    canonical = names[0] if names else (addresses[0] if addresses else None)
    if canonical is None:
        return None
    object_id = next((keys[k] for k in _D5_OBJECT_ID_FIELDS if _usable(keys.get(k))), None)
    principal = next((keys[k] for k in _D5_PRINCIPAL_FIELDS if keys.get(k) in addresses), None)
    identity = (object_id.lower() if object_id else "", principal.lower() if principal else "")
    return (
        canonical, tuple(dict.fromkeys(names)), given if _usable(given) else "", family if _usable(family) else "", ids,
        identity,
    )


@dataclass
class _Found:
    names: set[str] = field(default_factory=set)
    ids: set[str] = field(default_factory=set)
    vocabulary: set[str] = field(default_factory=set)
    keys: set[str] = field(default_factory=set)
    persons: set[_Person] = field(default_factory=set)
    limit_hits: int = 0  # JSON-looking strings above ``_MAX_EMBEDDED_JSON_CHARS`` that were not parsed

    def merge(self, other: _Found) -> None:
        self.names |= other.names
        self.persons |= other.persons
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
                normed = {_norm(k): v for k, v in item.items()}
                privileged = _privileged_keys(normed)
                if _is_directory_person(normed):
                    person = _person(normed)
                    if person is not None:
                        found.persons.add(person)
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
    from .guarded_io import UnsafeRunFileError, current_context

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
        context = current_context()
        if context is not None:
            context._check_file(info, "run-file", _MAX_FILE_BYTES)
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
    except UnsafeRunFileError as exc:
        read_failed = True
        reason = REASON_OVERSIZE if exc.reason == "oversize" else REASON_UNREADABLE
        raise _Unsafe(reason, total) from None
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
        from .guarded_io import UnsafeRunFileError, current_context
        context = current_context()
        if context is not None:
            try:
                context._check_file(info, "run-file", None)
            except UnsafeRunFileError:
                self.problem(parts, REASON_NON_REGULAR)
                return
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

    def _enter(self, frames: list[_Frame], descriptor: int, parts: tuple[str, ...], depth: int) -> None:
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
                    if name.lower().endswith(".json"):
                        self.problem(here, REASON_NON_REGULAR)
                    else:
                        try:
                            target = os.stat(name, dir_fd=frame.descriptor, follow_symlinks=True)
                        except OSError:
                            continue
                        if stat.S_ISDIR(target.st_mode):
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


@guarded_operation
def read_normalized_sections(run_dir: str | Path) -> dict[str, Any]:
    """Read shareable report sections; refuse a failed read even if it later recovers."""
    sections: dict[str, Any] = {}
    try:
        context = current_context()
        run_path = Path(run_dir)
        if (context._absolute(run_path) in context._runs or os.path.lexists(run_path / "run-manifest.json")
                or os.path.lexists(run_path / "operator-inputs")):
            run_fd = os.dup(context.bind_run(run_path))
        else:
            run_fd = context._directory(run_path)
    except UnsafeRunFileError:
        raise
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
    persons: frozenset[_Person] = frozenset()


@guarded_operation
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
    try:
        from .guarded_io import current_context
        context = current_context()
        if os.path.lexists(run_path / "run-manifest.json") or os.path.lexists(run_path / "operator-inputs"):
            run_fd = os.dup(context.bind_run(run_path))
        else:
            run_fd = context._directory(run_path)
    except UnsafeRunFileError:
        raise
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
        frozenset(found.names), frozenset(found.ids), frozenset(found.vocabulary), tuple(labelled), tuple(sorted(scan.fingerprints)),
        frozenset(found.persons),
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
    context, persons = _run_context(run_dir)
    return _with_index(context, persons)


def _with_index(context: RedactionContext, persons: Iterable[_Person]) -> RedactionContext:
    """``context`` with its D5 index: every directory person of its runs (not only administrators), indexed once for
    every call on the context, and the unmatched count taken from it."""
    index = _build_index(_run_persons(persons, context.protected_names), _vocabulary_phrases(context.vocabulary))
    return replace(context, unmatched_names=index.counts(), _index=index)


def _run_persons(persons: Iterable[_Person], names: Iterable[str]) -> tuple[_Person, ...]:
    """The person records, plus a name-only record for a privileged display name that no person record carries: a
    privileged user found by discovery is already a person record, so it is one person, never two."""
    persons = tuple(persons)
    recorded = {name for person in persons for name in person[1]}
    return (*persons, *_names_as_persons(name for name in names if name not in recorded))


def _run_context(run_dir: str | Path) -> tuple[RedactionContext, frozenset[_Person]]:
    """One run's context without its D5 index, and the run's person records for ``_with_index``."""
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
    return RedactionContext(**values), discovery.persons


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
    persons: set[_Person] = set()
    any_run = False
    for index, run_dir in enumerate(run_dirs):
        context, run_persons = _run_context(run_dir)
        persons |= run_persons
        any_run = True
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
    merged = RedactionContext(
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
    # D5: one index over the person records of every run, so a person's records in different runs (and the
    # principal-name references that resolve to them) are one identity, and a role or group name of one run guards the
    # same words in another.
    return _with_index(merged, persons) if any_run else merged


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


# -- D5: person names in free text and ids -------------------------------------------------------------------------
#
# Bounded rule (design M05-T01, sections 3 to 6): every directory person's name and id forms become lower-case token
# phrases (keys) in one dictionary, together with every proper token prefix of every key. Matching is one left-to-right
# pass per string: at a token, the candidate phrase grows one token at a time while the separator is a whitespace run
# or exactly one of ``. _ - ' ’``, the grown phrase is in the dictionary and the window holds at most
# ``_D5_MAX_KEY_TOKENS`` tokens; each step is one dictionary probe and the longest key wins. No regular expression is
# built from names, so the cost per string is independent of the number of people.

_D5_MAX_KEYS_PER_PERSON = 16
_D5_MAX_KEY_TOKENS = 6
_D5_MAX_TOKEN_CHARS = 64
_D5_MIN_KEY_CHARS = 4
_D5_SEPARATORS = frozenset(".-_'’")
_D5_WORD_RE = re.compile(r"[^\W_]+")
# The first alternative keeps pseudonyms (``User <hex>``, ``user-<hex>``) opaque, so a second pass changes nothing and
# a person called ``User`` cannot re-match one. The markup form also keeps HTML tags and character references opaque.
_D5_OPAQUE = rf"(?P<opaque>(?<![^\W_])(?:(?:User|Id|Group|Guid) {_HEX16}|user-{_HEX16})(?![^\W_]))"
_D5_TOKEN_RE = re.compile(_D5_OPAQUE + r"|(?P<tok>[^\W_]+)")
_D5_MARKUP_TOKEN_RE = re.compile(_D5_OPAQUE + r"|(?P<tag><[^<>]{0,4096}>|&#?[A-Za-z0-9]{1,32};)|(?P<tok>[^\W_]+)")
# A whole mapping key of this shape is a product identifier and is never rewritten.
_D5_STRUCTURAL_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*$")
_D5_ID_NEIGHBOURS = frozenset("/\\@=_~%")
_D5_ID_JOINERS = frozenset(".-:+#?&")
_D5_ID_PREFIX = "user-"
_D5_PLACEHOLDER_WORDS = frozenset({"user", "id", "group", "guid", "redacted", "text", "run", "dir"})
_D5_COMMON_WORDS = frozenset(
    {
        "admin", "administrator", "admins", "account", "accounts", "user", "users", "guest", "guests", "member",
        "members", "group", "groups", "team", "teams", "owner", "owners", "service", "services", "support", "help",
        "helpdesk", "info", "information", "contact", "office", "reception", "sales", "finance", "marketing",
        "security", "compliance", "audit", "auditor", "operations", "test", "testing", "demo", "sample", "default",
        "system", "scanner", "printer", "room", "meeting", "meetings", "shared", "mailbox", "mail", "email", "noreply",
        "global", "tenant", "policy", "policies", "report", "reports", "device", "devices", "application", "app",
        "apps", "directory", "identity", "external", "internal", "legal", "payroll", "accounting", "training",
    }
)
# Why a recorded name spelling of a person cannot be masked in free text, in the order the unmatched note lists them.
# ``separator``: a recorded name whose words are joined by something free-text matching does not follow (``Smith
# (Alice)``), so that spelling as written would stay readable. ``limit``: the person has more accepted keys than
# ``_D5_MAX_KEYS_PER_PERSON``, so some were not indexed (the required name forms are kept first).
D5_REASONS = (
    "too_short", "no_letters", "too_many_tokens", "vocabulary", "common_word", "structural", "separator", "limit",
)


def _joins(separator: str) -> bool:
    """Whether the text between two tokens continues a name, for the index and the matcher alike: a whitespace run,
    exactly one of ``_D5_SEPARATORS``, or a comma alone or followed by a whitespace run (``Kovalenko, Priya``)."""
    if separator[:1] == ",":
        rest = separator[1:]
        return not rest or rest.isspace()
    return separator.isspace() or (len(separator) == 1 and separator in _D5_SEPARATORS)


def _written_joinable(raw: str) -> bool:
    """Whether every separator between the words of ``raw`` is one the matcher follows."""
    previous: re.Match[str] | None = None
    for match in _D5_WORD_RE.finditer(raw):
        if previous is not None and not _joins(raw[previous.end():match.start()]):
            return False
        previous = match
    return True


def _swapped(raw: str) -> str | None:
    """``Kovalenko, Priya`` as ``Priya Kovalenko``: a name with one comma between words, its two sides swapped."""
    family, comma, given = raw.partition(",")
    if not comma or "," in given or not _D5_WORD_RE.search(family) or not _D5_WORD_RE.search(given):
        return None
    return f"{given.strip()} {family.strip()}"


def _fold(token: str) -> str:
    return token.lower() if token.isascii() else unicodedata.normalize("NFKC", token).casefold()


def _phrase(text: str) -> str:
    """``text`` as a key phrase: its letter-and-digit tokens, folded, joined by single spaces."""
    return " ".join(_fold(token) for token in _D5_WORD_RE.findall(text))


def _vocabulary_phrases(vocabulary: Iterable[str]) -> frozenset[str]:
    return frozenset(p for p in (_phrase(v) for v in vocabulary if isinstance(v, str)) if p)


_D5_FIXED_VOCABULARY = frozenset(_phrase(v) for v in _STATIC_VOCABULARY) | _D5_PLACEHOLDER_WORDS


def _drop_reason(phrase: str, vocabulary: frozenset[str], raw: str | None = None) -> str | None:
    """Why ``phrase`` must not be matched in free text (one of ``D5_REASONS``), or ``None`` when it is a safe key.
    ``raw`` is the name as recorded, for the structural-shape test."""
    tokens = phrase.split(" ") if phrase else []
    if sum(len(t) for t in tokens) < _D5_MIN_KEY_CHARS:
        return "too_short"
    if not any(c.isalpha() for c in phrase):
        return "no_letters"
    if len(tokens) > _D5_MAX_KEY_TOKENS or any(len(t) > _D5_MAX_TOKEN_CHARS for t in tokens):
        return "too_many_tokens"
    if phrase in _D5_FIXED_VOCABULARY or phrase in vocabulary:
        return "vocabulary"
    if all(t in _D5_COMMON_WORDS or t in _D5_FIXED_VOCABULARY for t in tokens):
        return "common_word"
    if raw is not None and _structural(raw):
        return "structural"
    return None


def _person_keys(person: _Person, vocabulary: frozenset[str]) -> tuple[list[str], str | None]:
    """``(keys, reason)`` for one person record. Every recorded spelling (each name field, and given plus family name)
    is either a key the matcher follows as written, or reported: ``reason`` is the earliest in ``D5_REASONS`` of the
    spellings that cannot be masked, ``None`` when every one can.

    Keys come in priority order and at most ``_D5_MAX_KEYS_PER_PERSON`` are kept: first the required forms (each
    accepted spelling, family plus given name, the comma swap of a ``Last, First`` name), then the joined forms
    (``alicesmith``) and the address forms. A key that does not fit is reported as ``limit``, never dropped silently."""
    _canonical, names, given, family, ids, _identity = person
    required: list[str] = []
    optional: list[str] = []
    reasons: list[str] = []

    def accepted(phrase: str, raw: str | None = None) -> bool:
        return bool(phrase) and _drop_reason(phrase, vocabulary, raw) is None

    def joined(phrase: str) -> None:
        tokens = phrase.split(" ")
        if 2 <= len(tokens) <= 3 and accepted("".join(tokens)):
            optional.append("".join(tokens))  # ``alicesmith``

    spellings = [(raw, True) for raw in names]
    if given and family:
        spellings.append((f"{given} {family}", False))
    for raw, as_named in spellings:
        phrase = _phrase(raw)
        dropped = _drop_reason(phrase, vocabulary, raw if as_named else None)
        if dropped is not None:
            reasons.append(dropped)
            continue
        if not _written_joinable(raw):
            reasons.append("separator")  # the phrase is still a key: it masks the spellings the matcher does follow
        required.append(phrase)
        joined(phrase)
    if given and family and accepted(_phrase(f"{family} {given}")):
        required.append(_phrase(f"{family} {given}"))
    for swapped in map(_swapped, names):
        if swapped is not None and accepted(_phrase(swapped)):
            required.append(_phrase(swapped))
            joined(_phrase(swapped))
    for value in ids:
        local, at, _domain = value.partition("@")
        local_phrase = _phrase(local)
        if local_phrase.count(" ") >= 1 and accepted(local_phrase):  # ``alice.smith``; one token: addresses only
            optional.append(local_phrase)
        if at and accepted(_phrase(value)):
            optional.append(_phrase(value))  # ``alice smith contoso com`` (OneDrive segments)
    keys = list(dict.fromkeys((*required, *optional)))
    if len(keys) > _D5_MAX_KEYS_PER_PERSON:
        reasons.append("limit")
        keys = keys[:_D5_MAX_KEYS_PER_PERSON]
    return keys, min(reasons, key=D5_REASONS.index) if reasons else None


def _combine(current: str | None, new: str) -> str:
    """Merge two index values: ``""`` marks a prefix only; of two people the lexicographically smallest name wins."""
    if not current:
        return new or (current if current is not None else "")
    if not new:
        return current
    return min(current, new)


@dataclass
class _NameIndex:
    """``table`` maps every key phrase to its person's canonical name and every proper prefix of a key to ``""``."""

    table: dict[str, str] = field(default_factory=dict)
    # Coverage, never published: every person with at least one spelling that cannot be masked, as identity group
    # (``oid:``, ``upn:`` or ``name:`` and the value) to the earliest reason in ``D5_REASONS``.
    unmatched: dict[str, str] = field(default_factory=dict)

    def add(self, phrase: str, canonical: str) -> None:
        table = self.table
        cut = phrase.find(" ")
        while cut != -1:
            prefix = phrase[:cut]
            if prefix not in table:
                table[prefix] = ""
            cut = phrase.find(" ", cut + 1)
        table[phrase] = _combine(table.get(phrase), canonical)

    def counts(self) -> tuple[tuple[str, int], ...]:
        tally: dict[str, int] = {}
        for reason in self.unmatched.values():
            tally[reason] = tally.get(reason, 0) + 1
        return tuple((reason, tally[reason]) for reason in D5_REASONS if tally.get(reason))


def _identity(person: _Person) -> tuple[str, str]:
    identity = person[5]
    return (identity[0], identity[1]) if identity else ("", "")


def _unmatched_people(
    pending: list[tuple[str, str, str, str]], persons: Collection[_Person],
) -> dict[str, str]:
    """The people behind ``pending`` records (object id, principal name, canonical name, reason), each with its
    earliest reason. The object id is authoritative: records with different object ids are different people, even
    when they share a principal name. A record without an object id joins the one object id whose records (any of
    ``persons``, matched or not) carry its principal name; with none, or several, it is the principal name's own
    person. A record with neither is identified by its name."""
    wanted = {upn for oid, upn, _canonical, _reason in pending if upn and not oid}
    owners: dict[str, str] = {}  # principal name -> its one object id, or "" when several carry it
    if wanted:
        for person in persons:
            oid, upn = _identity(person)
            if oid and upn in wanted:
                owner = owners.get(upn)
                owners[upn] = oid if owner is None or owner == oid else ""
    people: dict[str, str] = {}
    for oid, upn, canonical, reason in pending:
        if oid:
            group = "oid:" + oid
        elif upn:
            owner = owners.get(upn)
            group = "oid:" + owner if owner else "upn:" + upn
        else:
            group = "name:" + canonical
        current = people.get(group)
        if current is None or D5_REASONS.index(reason) < D5_REASONS.index(current):
            people[group] = reason
    return people


def _build_index(persons: Collection[_Person], vocabulary: frozenset[str]) -> _NameIndex:
    """The index over every person record of a context, identities resolved once over all of them."""
    index = _NameIndex()
    pending: list[tuple[str, str, str, str]] = []
    for person in persons:
        canonical = person[0]
        keys, reason = _person_keys(person, vocabulary)
        for key in keys:
            index.add(key, canonical)
        if reason is not None:
            pending.append((*_identity(person), canonical, reason))
    if pending:
        index.unmatched = _unmatched_people(pending, persons)
    return index


def _names_as_persons(names: Iterable[str]) -> list[_Person]:
    return [(n, (n,), "", "", (), ()) for n in names if _usable(n)]


def _context_index(context: RedactionContext) -> _NameIndex:
    """The context's index, built once (from ``protected_names`` when the context was not built from a run)."""
    index = context._index
    if index is None:
        index = _build_index(_names_as_persons(context.protected_names), _vocabulary_phrases(context.vocabulary))
        object.__setattr__(context, "_index", index)
    return index


def unmatched_names_note(context: RedactionContext) -> str:
    """The fixed line a shareable HTML or Markdown report carries when some directory people's names could not be
    matched safely in free text (``RedactionContext.unmatched_names``); ``""`` otherwise. It never holds a name."""
    counts = context.unmatched_names
    if not counts:
        return ""
    total = sum(count for _, count in counts)
    reasons = ", ".join(f"{reason} {count}" for reason, count in counts)
    return (
        f"Name masking: {total} directory people have names that cannot be matched safely in free text "
        f"({reasons}); their name fields are pseudonymised, the same words elsewhere are left as written."
    )


class _NameMatcher:
    """The bounded D5 pass over one string (see the section comment). ``probes`` counts dictionary probes and
    ``widest`` the largest token window held, for the scan-budget tests."""

    __slots__ = ("table", "overlay", "skip", "salt", "probes", "widest")

    def __init__(self, table: dict[str, str], salt: str, overlay: dict[str, str] | None = None,
                 skip: frozenset[str] = frozenset()) -> None:
        self.table = table
        self.overlay = overlay or {}
        self.skip = skip
        self.salt = salt
        self.probes = 0
        self.widest = 0

    def _probe(self, phrase: str) -> str | None:
        self.probes += 1
        found = self.overlay.get(phrase)
        return self.table.get(phrase) if found is None else found

    def mask(self, text: str, markup: bool = False) -> str:
        if not text:
            return text
        tokens = (_D5_MARKUP_TOKEN_RE if markup else _D5_TOKEN_RE).finditer(text)
        ahead: deque[re.Match[str]] = deque()
        pieces: list[str] = []
        last = 0
        while True:
            match = ahead.popleft() if ahead else next(tokens, None)
            if match is None:
                break
            if match.lastgroup != "tok" or len(match[0]) > _D5_MAX_TOKEN_CHARS:
                continue
            phrase = _fold(match[0])
            value = self._probe(phrase)
            if value is None:
                continue
            best: tuple[int, str, str] | None = None  # (tokens beyond the first, phrase, canonical)
            if value and not markup:
                best = (0, phrase, value)
            end = match
            width = 1
            while width < _D5_MAX_KEY_TOKENS:
                if len(ahead) < width:
                    following = next(tokens, None)
                    if following is None:
                        break
                    ahead.append(following)
                    self.widest = max(self.widest, len(ahead) + 1)
                following = ahead[width - 1]
                if following.lastgroup != "tok" or len(following[0]) > _D5_MAX_TOKEN_CHARS:
                    break
                if not _joins(text[end.end():following.start()]):
                    break
                phrase = phrase + " " + _fold(following[0])
                value = self._probe(phrase)
                if value is None:
                    break
                width += 1
                end = following
                if value:
                    best = (width - 1, phrase, value)
            if best is None or best[1] in self.skip:
                continue
            extra, _phrase_hit, canonical = best
            last_match = ahead[extra - 1] if extra else match
            for _ in range(extra):
                ahead.popleft()
            start, stop = match.start(), last_match.end()
            pieces.append(text[last:start])
            pieces.append(self._replacement(text, start, stop, canonical))
            last = stop
        if not pieces:
            return text
        pieces.append(text[last:])
        return "".join(pieces)

    def _replacement(self, text: str, start: int, stop: int, canonical: str) -> str:
        digest = pseudonym(self.salt, canonical)
        return (_D5_ID_PREFIX if _id_context(text, start, stop) else _USER_PREFIX) + digest


def _id_context(text: str, start: int, stop: int) -> bool:
    """Whether a hit sits in an id, URL or path (``user-<hex>``) rather than prose (``User <hex>``). A comma inside the
    hit (``Kovalenko, Priya``) is prose."""
    if any(not c.isalnum() and not c.isspace() and c != "," for c in text[start:stop]):
        return True
    left = text[start - 1] if start else ""
    right = text[stop] if stop < len(text) else ""
    if (left and left in _D5_ID_NEIGHBOURS) or (right and right in _D5_ID_NEIGHBOURS):
        return True
    if left and left in _D5_ID_JOINERS and start >= 2 and text[start - 2].isalnum():
        return True
    return bool(right and right in _D5_ID_JOINERS and stop + 1 < len(text) and text[stop + 1].isalnum())


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


# Local-only SS 2.1 proof (TargetedUsersCoverage v1). Every redacting profile drops the whole summary and its private
# binding wherever they occur (keys compared with ``_norm``, nested or in embedded JSON), and keeps only ``supplied`` of
# ``operator_inputs.sensitive_users``: its count and HMAC stay in the local manifest. Other ``count`` fields are kept.
_LOCAL_PROOF_NORMS = frozenset({"targeteduserscoverage", "targeteduserscoveragebinding"})
_OPERATOR_INPUTS_NORM = "operatorinputs"
_SENSITIVE_USERS_NORM = "sensitiveusers"
_SENSITIVE_USERS_SHAREABLE_NORMS = frozenset({"supplied"})


def _structured_rewrite(value: Any, rewrite: Callable[[Mapping[Any, Any]], Any]) -> Any:
    """Rewrite valid metadata mappings; withhold malformed containers and scalars."""
    if isinstance(value, Mapping):
        return rewrite(value)
    if isinstance(value, str):
        try:
            parsed = _maybe_json(value)
        except _EmbeddedLimitError:
            raise ContextIncompleteError((("<output value>", REASON_LIMIT),)) from None
        if isinstance(parsed, Mapping):
            stripped = value.strip()
            lead, trail = value[: len(value) - len(value.lstrip())], value[len(value.rstrip()):]
            return lead + _dump_like(stripped, parsed, rewrite(parsed)) + trail
    return {}


def _shareable_sensitive_users(record: Mapping[Any, Any]) -> dict[Any, Any]:
    return {key: item for key, item in record.items()
            if _norm(key) in _SENSITIVE_USERS_SHAREABLE_NORMS and type(item) is bool}


def _shareable_operator_inputs(record: Mapping[Any, Any]) -> dict[Any, Any]:
    return {key: (_structured_rewrite(item, _shareable_sensitive_users) if _norm(key) == _SENSITIVE_USERS_NORM else item)
            for key, item in record.items()}


def _without_local_proof(record: Mapping[Any, Any]) -> Mapping[Any, Any]:
    """``record`` without the local-only SS 2.1 proof fields (see ``_LOCAL_PROOF_NORMS``)."""
    norms = [_norm(key) for key in record]
    if not any(norm in _LOCAL_PROOF_NORMS or norm == _OPERATOR_INPUTS_NORM for norm in norms):
        return record
    out: dict[Any, Any] = {}
    for norm, (key, item) in zip(norms, record.items(), strict=False):
        if norm in _LOCAL_PROOF_NORMS:
            continue
        out[key] = _structured_rewrite(item, _shareable_operator_inputs) if norm == _OPERATOR_INPUTS_NORM else item
    return out


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
        ids = set(context.protected_ids)
        _collect(value, found, names=True)
        if found.limit_hits:
            raise ContextIncompleteError((("<output value>", REASON_LIMIT),))
        ids |= found.ids
        # D5: the context's index (built once per context) plus an overlay for people found only in this value. A
        # role or group name found only in the value protects the same words at lookup time.
        base = _context_index(context)
        context_vocabulary = _vocabulary_phrases(context.vocabulary)
        value_vocabulary = _vocabulary_phrases(found.vocabulary) - context_vocabulary
        persons = found.persons
        persons.update(_names_as_persons(found.names - context.protected_names))
        overlay: dict[str, str] = {}
        if persons:
            table = base.table
            for phrase, canonical in _build_index(persons, context_vocabulary | value_vocabulary).table.items():
                current = table.get(phrase)
                combined = _combine(current, canonical)
                if combined != current:
                    overlay[phrase] = combined
        del found, persons  # this frame's last references to the value's discovery sets
        self.matcher = _NameMatcher(base.table, self.salt, overlay, value_vocabulary)
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
        """``value`` as text. ``key`` is a mapping key: identifiers, credential assignments and person names (unless
        the whole key is a product identifier), no immutable-id substitution, no embedded JSON. ``names=False`` marks a
        controlled-vocabulary value (finding id, setting name, reason code, status); since D5 person names are masked
        in it too (their guard keeps vocabulary words readable) and identifiers in it are still masked."""
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
        # D5 applies to every string, controlled values and group or role names included (DEC-003); a mapping key
        # is skipped only when it is a whole product identifier.
        if not key or not _D5_STRUCTURAL_KEY_RE.match(value):
            value = self.matcher.mask(value, self.markup)
        if not key and self.id_re is not None:
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
            collection_type = type(value)
            return collection_type(self.walk(item, controlled) for item in value)
        finally:
            self.depth -= 1

    def _name_parts(self, record: Mapping[Any, Any], canonical: str, controlled: bool) -> Any:
        """A person's ``name`` sub-mapping (Google raw): full names pseudonymised, name parts replaced."""
        parts = {}
        for key, item in record.items():
            norm = _norm(key)
            if isinstance(item, str) and item and norm in _D5_NAME_FIELDS:
                parts[key] = item if _PSEUDONYM_RE.match(item) else _USER_PREFIX + pseudonym(self.salt, canonical)
            elif isinstance(item, str) and item and norm in _D5_NAME_PART_FIELDS:
                parts[key] = TEXT_PLACEHOLDER
            else:
                parts[key] = item
        return self.walk(parts, controlled)

    def mapping(self, record: Mapping[Any, Any], controlled: bool = False) -> dict[Any, Any]:
        record = _without_local_proof(record)
        normed = {_norm(k): v for k, v in record.items()}
        person = _person(normed) if _is_directory_person(normed) else None
        group = str(normed.get("principaltype", "")).lower() == "group"
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
                elif person is not None and norm in _D5_NAME_FIELDS:
                    item = item if _PSEUDONYM_RE.match(item) else _USER_PREFIX + pseudonym(self.salt, person[0])
                elif person is not None and norm in _D5_NAME_PART_FIELDS:
                    item = TEXT_PLACEHOLDER
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
            elif person is not None and norm == "name" and isinstance(item, Mapping):
                item = self._name_parts(item, person[0], controlled)
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
    """``value`` with protected identifiers and local-only proof fields removed; deterministic and idempotent.

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
