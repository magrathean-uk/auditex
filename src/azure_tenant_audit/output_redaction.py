"""The report-output redaction boundary: one function every shareable writer passes through.

Run directories, evidence stores and ``raw/`` / ``normalized/`` files are private working files (0600 in
0700 directories) and are *not* redacted: the operator needs them whole. Everything that can leave the
operator's machine is redacted here, at the last step before the bytes are written or sent. The inventory
of writers and the decided boundary are in ``docs/reference/security-privacy.md`` ("Output redaction
boundary"); ``auditex/output_writers.py`` holds the machine-readable inventory of writers (it names product modules,
so it lives in the product layer) that ``tests/test_output_redaction.py`` checks against the source, so a new
writer cannot bypass the function silently.

API::

    redact_output(value, *, profile=PROFILE_SHAREABLE, context=None)   # same shape out as in
    context_for_run(run_dir)                                           # salt, run paths, protected names

``value`` may be a ``str``, a mapping, a list, tuple or set, or anything else (returned unchanged). The result
has the same shape: mappings stay mappings with their keys, lists keep their order, numbers, booleans,
``None`` and bytes pass through. A key is changed only when the key text itself holds an identifier
(an e-mail address or a GUID), so verdict fields, policy ids, reason codes and setting names are
untouched. Redaction is deterministic (the pseudonym of a value depends only on the value and the salt),
idempotent (``redact_output(redact_output(x)) == redact_output(x)``) and never raises on odd input.

What a profile redacts (``PROFILES``):

* secrets (``secret_hygiene.redact_text``, plus the values of exact credential keys);
* e-mail local parts, masked as ``***@domain`` exactly like the model projection, except the exact
  public baseline addresses in ``PUBLIC_ADDRESSES``;
* privileged-user display names and on-premises immutable ids, pseudonymised like the projection
  (``User <16 hex>`` / ``Id <16 hex>``, ``sha256(salt NUL text)``, so the same run salt keeps references
  consistent within a run and across the model view);
* dashed GUIDs (``PENDING_PRODUCT_POLICY.redact_guids``), except ``PUBLIC_GUIDS`` and values labelled
  ``Trace ID:`` / ``Correlation ID:``; the replacement is itself a valid GUID so schemas that demand
  one (OSCAL) still validate;
* the operator's run paths (``RedactionContext.run_paths``).

Decisions the documents leave open are the single constant ``PENDING_PRODUCT_POLICY``; flip a field there
(or pass a replacement through ``RedactionContext.policy``) and every writer follows.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .secret_hygiene import BEARER_RE, JWT_RE, OUTPUT_EMAIL_RE, OUTPUT_GUID_RE, redact_text

PROFILE_REPORT_PACK = "report_pack"
PROFILE_SHAREABLE = "shareable"
PROFILE_CUSTOMER_PACK = "customer_pack"
PROFILE_EXPLAINER = "explainer"

SECRET_PLACEHOLDER = "***redacted***"
RUN_DIR_PLACEHOLDER = "<run-dir>"
TEXT_PLACEHOLDER = "<redacted-text>"
GROUP_PREFIX = "Group "


@dataclass(frozen=True)
class RedactionProfile:
    """Which identifier classes one output class has redacted."""

    name: str
    secrets: bool = True
    emails: bool = True
    identities: bool = True
    guids: bool = False
    run_paths: bool = False


# ``report_pack`` is the run bundle's own ``reports/report-pack.json``, written while the run is still open. It is
# a working artifact: its finding ids, proof-table rows and evidence references embed the keys of the records they
# cite (including e-mail addresses and GUIDs), and the validator resolves them against ``normalized/``. Masking
# an identifier there makes the references unresolvable (``unresolved_report_proof_table_ref``), and the run
# salt (the digest of the final manifest) does not exist yet. So the pack carries secrets-redaction only; the
# identifier classes are applied where the pack's content is rendered, exported, sent or handed over, which is
# where every other profile applies the full set.
PROFILES: dict[str, RedactionProfile] = {
    PROFILE_REPORT_PACK: RedactionProfile(PROFILE_REPORT_PACK, emails=False, identities=False),
    PROFILE_SHAREABLE: RedactionProfile(PROFILE_SHAREABLE, guids=True, run_paths=True),
    PROFILE_CUSTOMER_PACK: RedactionProfile(PROFILE_CUSTOMER_PACK, guids=True, run_paths=True),
    PROFILE_EXPLAINER: RedactionProfile(PROFILE_EXPLAINER, guids=True, run_paths=True),
}


@dataclass(frozen=True)
class PendingProductPolicy:
    """Identifier classes the documents are silent or ambiguous about: conservative-but-usable defaults.

    Every field is "decision pending product". ``True`` redacts the class in the shareable profiles.
    """

    # Dashed GUIDs (tenant, object, application and policy ids). On: pseudonymised per run, so references
    # inside one report stay usable and nothing ties back to the tenant.
    redact_guids: bool = True
    # Domain names. Off: DNS, mail-flow and accepted-domain findings are unreadable without them, and the
    # e-mail mask keeps the domain by contract. On: every domain seen in an e-mail address in the output
    # (and ``RedactionContext.domains``), with its subdomains, becomes ``domain-<12 hex>.invalid``.
    redact_domains: bool = False
    # Group display names: records whose ``principal_type`` is ``group`` (``Group <16 hex>``). Off: groups
    # named in findings are what an administrator acts on.
    redact_group_names: bool = False
    # Free-text values under ``TENANT_TEXT_KEYS`` (waiver owner, justification, comments). Off: documented as
    # accountability fields. ``reason`` is deliberately not a key here: it carries reason codes.
    redact_free_text: bool = False
    # Role names are public Microsoft vocabulary for built-in roles and tenant text only for custom roles; the
    # two cannot be told apart from the output alone, so role names are never redacted (no flip implemented).
    redact_role_names: bool = False


PENDING_PRODUCT_POLICY = PendingProductPolicy()

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

# Microsoft role template ids, first-party application ids and the all-zero GUID that the product ships as
# constants (a test checks that every GUID literal under ``src/`` is listed here, so adding one is a
# decision, not an accident). They identify Microsoft's catalogue, not a tenant.
PUBLIC_GUIDS = frozenset(
    {
        "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003",
    "00000000-0000-0000-0000-000000000004", "00000002-0000-0ff1-ce00-000000000000",
    "00000003-0000-0000-c000-000000000000", "00000003-0000-0ff1-ce00-000000000000",
    "00000007-0000-0000-c000-000000000000", "00000009-0000-0000-c000-000000000000",
    "01c0a623-fc9b-48e9-b794-0756f8e8f067", "06b708a9-e830-4db3-a914-8e69da51d44f",
    "10dae51f-b6af-4016-8d66-8c2a99b929b3", "158c047a-c907-4556-b7ef-446551a6b5f7",
    "194ae4cb-b126-40b2-bd5b-6091b380977d", "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "2af84b1e-32c8-42b7-82bc-daa82404023b", "3a2c62db-5318-420d-8d74-23affee5d9d5",
    "475226c6-020e-4fb2-8a90-7a972cbfc1d4", "4ba39ca4-527c-499a-b93d-d9b492c50246",
    "50483e42-d915-4231-9639-7fdb7fd190e5", "62a82d76-70ea-41e2-9197-370581804d09",
    "62e90394-69f5-4237-9190-012177145e10", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "72f988bf-86f1-41af-91ab-2d7cd011db47", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
    "7df0a125-d3be-4c96-aa54-591f83ff541c", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
    "9360feb5-f418-4baa-8175-e2a00bac4301", "966707d0-3269-4727-9be2-8c3a10f19b9d",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
    "a0b1b346-4d3e-4e8b-98f8-753987be4970", "a82116e5-55eb-4c41-a434-62fe8a61c773",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
    "b633e1c5-b582-4048-a93e-9f11b44c7e96", "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "c5393580-f805-4401-95e8-94b7a6ef2fc2", "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",
    "e2a3a72e-5f79-4c64-b1b1-878b674786c9", "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a", "fe930be7-5e62-47db-91af-98c3a49a38b1",
    }
)

# Values of these keys (exact, case-insensitive, ``-`` read as ``_``) are credentials whatever their shape.
_SECRET_KEYS = frozenset(
    {
        "client_secret", "secret_text", "app_secret", "password", "access_token", "refresh_token",
        "id_token", "api_token", "api_key", "key_material", "dsc_export", "private_key",
    }
)

_IMMUTABLE_PREFIX = "Id "
_USER_PREFIX = "User "
_HEX16 = r"[0-9a-f]{16}"
_PSEUDONYM_RE = re.compile(rf"^(?:User|Id|Group) {_HEX16}$")
_GUID_PSEUDONYM_PREFIX = "00000000-0000-4000-8000-"
_DOMAIN_PSEUDONYM_RE = re.compile(r"^domain-[0-9a-f]{12}\.invalid$")
_GUID_RE = OUTPUT_GUID_RE


def _norm(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


@dataclass(frozen=True)
class RedactionContext:
    """Per-output inputs: everything that is not in the value itself.

    ``salt`` is the run salt (see ``run_salt``); with an empty salt the pseudonyms are still deterministic but
    carry no run separation. ``run_paths`` are the spellings of the operator's run directory to remove.
    ``protected_names`` are privileged-user display names the caller already knows (names found inside the
    value are added automatically). ``domains`` extends the domain set when the domain policy is on.
    """

    salt: str = ""
    run_paths: tuple[str, ...] = ()
    protected_names: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()
    policy: PendingProductPolicy = field(default_factory=lambda: PENDING_PRODUCT_POLICY)


def pseudonym(salt: str, text: str) -> str:
    """The projection's pseudonym: the first 16 hex digits of ``sha256(salt NUL text)``."""
    return hashlib.sha256((salt + "\0" + text).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def run_salt(run_dir: str | Path) -> str:
    """The salt ``scuba_projection.project_run`` uses: SHA-256 of the canonical ``run-manifest.json``.

    A missing or unusable manifest gives the digest of ``{}``, as the projection does. Never persisted.
    """
    def canonical(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

    try:
        manifest = json.loads((Path(run_dir) / "run-manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError
        return hashlib.sha256(canonical(manifest).encode()).hexdigest()
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError):
        return hashlib.sha256(canonical({}).encode()).hexdigest()


def run_path_roots(run_dir: str | Path) -> tuple[str, ...]:
    """Every spelling of the run directory a payload may carry, longest first."""
    run_path = Path(run_dir)
    roots = {str(run_path), os.path.abspath(run_path), os.path.realpath(run_path)}
    return tuple(sorted((r.rstrip(os.sep) for r in roots if r and r != os.sep), key=len, reverse=True))


def scrub_run_paths(text: str, roots: Iterable[str]) -> str:
    """Paths below the run become run-relative, the run itself ``<run-dir>``; other mentions are replaced."""
    roots = [r for r in roots if r]
    for root in roots:
        if text == root:
            return RUN_DIR_PLACEHOLDER
        if text.startswith(root + os.sep):
            return text[len(root) + 1:]
    for root in roots:
        text = text.replace(root, RUN_DIR_PLACEHOLDER)
    return text


def context_for_run(run_dir: str | Path, **overrides: Any) -> RedactionContext:
    """The context for outputs derived from one run: its salt, its path spellings and its administrators' names."""
    run_path = Path(run_dir)
    names: set[str] = set()
    try:
        payload = json.loads((run_path / "normalized" / "effective_admin_set.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        payload = None
    if isinstance(payload, Mapping):
        _collect(payload.get("records"), names, set(), True)
    values: dict[str, Any] = {
        "salt": run_salt(run_path),
        "run_paths": run_path_roots(run_path),
        "protected_names": frozenset(names),
    }
    values.update(overrides)
    return RedactionContext(**values)


def _is_privileged_user(record: Mapping[Any, Any]) -> bool:
    keys = {_norm(k): v for k, v in record.items()}
    if "onpremisesimmutableid" in keys or "immutableid" in keys:
        return True
    if str(keys.get("principaltype", "")).lower() == "user" and ("roles" in keys or "rolenames" in keys or "counted" in keys):
        return True
    return keys.get("isuser") is True and ("roles" in keys or "rolenames" in keys)


def _is_group(record: Mapping[Any, Any]) -> bool:
    return str({_norm(k): v for k, v in record.items()}.get("principaltype", "")).lower() == "group"


def _collect(
    value: Any, names: set[str], domains: set[str], want_names: bool, want_domains: bool = False,
    ids: set[str] | None = None,
) -> None:
    """Privileged-user display names and immutable ids (``want_names``) and e-mail domains (``want_domains``) found
    anywhere in ``value``, so the same strings are replaced inside free text of the same output."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if want_domains:
                for match in OUTPUT_EMAIL_RE.finditer(item):
                    domains.add(match["domain"].lower())
        elif isinstance(item, Mapping):
            if want_names and _is_privileged_user(item):
                for key, name in item.items():
                    if _norm(key) == "displayname" and isinstance(name, str) and name and not _PSEUDONYM_RE.match(name):
                        names.add(name)
            if want_names and ids is not None:
                for key, identifier in item.items():
                    if (
                        _norm(key) in ("onpremisesimmutableid", "immutableid")
                        and isinstance(identifier, str)
                        and identifier
                        and not _PSEUDONYM_RE.match(identifier)
                    ):
                        ids.add(identifier)
            stack.extend(item.values())
            stack.extend(k for k in item if isinstance(k, str))
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


class _Redactor:
    def __init__(self, profile: RedactionProfile, context: RedactionContext, value: Any, markup: bool) -> None:
        self.profile = profile
        self.markup = markup
        self.salt = context.salt
        self.policy = context.policy
        self.roots = context.run_paths if profile.run_paths else ()
        names = set(context.protected_names)
        ids: set[str] = set()
        domains = {d.lower() for d in context.domains}
        want_domains = profile.emails and self.policy.redact_domains
        if profile.identities or want_domains:
            _collect(value, names, domains, profile.identities, want_domains, ids)
        self.names = sorted((n for n in names if len(n) >= 4 and not _PSEUDONYM_RE.match(n)), key=len, reverse=True)
        self.name_re = (
            re.compile(r"(?<!\w)(?:" + "|".join(re.escape(n) for n in self.names) + r")(?!\w)") if self.names else None
        )
        self.ids = sorted((i for i in ids if len(i) >= 6), key=len, reverse=True)
        self.id_re = (
            re.compile(r"(?<![\w+/=-])(?:" + "|".join(re.escape(i) for i in self.ids) + r")(?![\w+/=-])") if self.ids else None
        )
        self.domains = sorted(
            (d for d in domains if d and d not in _public_domains() and not _DOMAIN_PSEUDONYM_RE.match(d)),
            key=len, reverse=True,
        ) if want_domains else []
        self.domain_re = (
            re.compile(
                r"(?<![\w-])(?:[\w-]+\.)*(?P<d>" + "|".join(re.escape(d) for d in self.domains) + r")(?![\w-])", re.IGNORECASE
            )
            if self.domains else None
        )

    # -- text ---------------------------------------------------------------------------------------------
    def text(self, value: str) -> str:
        if not value:
            return value
        profile = self.profile
        if self.roots:
            value = scrub_run_paths(value, self.roots)
        if profile.secrets:
            if self.markup:
                # Rendered JSON, HTML, CSV and Markdown: ``key=value`` secrets were redacted in the structure
                # before rendering; the inline-secret pattern would run on into closing quotes and tags here.
                value = JWT_RE.sub("***redacted-jwt***", BEARER_RE.sub("Bearer ***redacted***", value))
            else:
                value = redact_text(value)
        if profile.emails:
            value = OUTPUT_EMAIL_RE.sub(self._mask_email, value)
        if profile.guids and self.policy.redact_guids:
            value = _GUID_RE.sub(self._mask_guid, value)
        if self.name_re is not None:
            value = self.name_re.sub(lambda m: _USER_PREFIX + pseudonym(self.salt, m[0]), value)
        if self.id_re is not None:
            value = self.id_re.sub(lambda m: _IMMUTABLE_PREFIX + pseudonym(self.salt, m[0]), value)
        if self.domain_re is not None:
            value = self.domain_re.sub(lambda m: f"domain-{pseudonym(self.salt, m['d'].lower())[:12]}.invalid", value)
        return value

    @staticmethod
    def _mask_email(match: re.Match[str]) -> str:
        local, domain = match["local"], match["domain"]
        if f"{local}@{domain}".lower() in PUBLIC_ADDRESSES or domain.replace(".", "").isdigit():
            return match[0]
        return f"{match['field'] or ''}{match['quote']}***@{domain}"

    def _mask_guid(self, match: re.Match[str]) -> str:
        if match["label"]:
            return match[0]
        guid = match[0].lower()
        if guid in PUBLIC_GUIDS or guid.startswith(_GUID_PSEUDONYM_PREFIX) or _is_microsoft_app_id(guid):
            return match[0]
        return _GUID_PSEUDONYM_PREFIX + pseudonym(self.salt, guid)[:12]

    # -- structure ----------------------------------------------------------------------------------------
    def walk(self, value: Any, key: str = "") -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Mapping):
            return self.mapping(value)
        if isinstance(value, list):
            return [self.walk(item, key) for item in value]
        if isinstance(value, tuple):
            return tuple(self.walk(item, key) for item in value)
        if isinstance(value, (set, frozenset)):
            return type(value)(self.walk(item, key) for item in value)
        return value

    def mapping(self, record: Mapping[Any, Any]) -> dict[Any, Any]:
        profile = self.profile
        user = profile.identities and _is_privileged_user(record)
        group = profile.identities and self.policy.redact_group_names and _is_group(record)
        out: dict[Any, Any] = {}
        for key, item in record.items():
            norm = _norm(key)
            if isinstance(item, str) and item:
                if profile.secrets and str(key).lower().replace("-", "_") in _SECRET_KEYS:
                    item = SECRET_PLACEHOLDER
                elif profile.identities and norm in ("onpremisesimmutableid", "immutableid"):
                    item = item if _PSEUDONYM_RE.match(item) else _IMMUTABLE_PREFIX + pseudonym(self.salt, item)
                elif user and norm == "displayname":
                    item = item if _PSEUDONYM_RE.match(item) else _USER_PREFIX + pseudonym(self.salt, item)
                elif group and norm == "displayname":
                    item = item if _PSEUDONYM_RE.match(item) else GROUP_PREFIX + pseudonym(self.salt, item)
                elif profile.identities and self.policy.redact_free_text and str(key).lower() in TENANT_TEXT_KEYS:
                    item = TEXT_PLACEHOLDER
                else:
                    item = self.text(item)
            else:
                item = self.walk(item, str(key))
            new_key = self.text(key) if isinstance(key, str) and key else key
            if new_key != key and new_key in out:
                suffix = 2
                while f"{new_key}#{suffix}" in out:
                    suffix += 1
                new_key = f"{new_key}#{suffix}"
            out[new_key] = item
        return out


_MS_APP_ID_RE = re.compile(r"^0000000[0-9a-f]-0000-(?:0000-c000|0ff1-ce00)-000000000000$")


def _is_microsoft_app_id(guid: str) -> bool:
    """Microsoft's first-party resource application ids (``00000003-0000-0000-c000-000000000000`` and kin)."""
    return bool(_MS_APP_ID_RE.match(guid))


def _public_domains() -> frozenset[str]:
    return frozenset(a.split("@", 1)[1] for a in PUBLIC_ADDRESSES)


def redact_output(
    value: Any,
    *,
    profile: str | RedactionProfile = PROFILE_SHAREABLE,
    context: RedactionContext | None = None,
    markup: bool = False,
) -> Any:
    """``value`` with the identifiers ``profile`` protects removed; same shape, same keys, idempotent.

    ``markup=True`` is for text that is already rendered (HTML, CSV, Markdown, serialised JSON): it skips the
    inline ``key=value`` secret pattern, which cannot tell where a value ends in markup. Redact the structure
    before rendering; use ``markup=True`` only for the final pass over the rendered text.

    ``profile`` is a name from ``PROFILES`` or a ``RedactionProfile``. An unknown name raises ``KeyError``
    (a typo must not silently publish). ``context`` carries the run salt, run paths and known names; omit it
    for text with no run (pseudonyms are then unsalted).
    """
    chosen = profile if isinstance(profile, RedactionProfile) else PROFILES[profile]
    return _Redactor(chosen, context or RedactionContext(), value, markup).walk(value)


def redact_for_run(
    value: Any, run_dir: str | Path, *, profile: str | RedactionProfile = PROFILE_SHAREABLE, markup: bool = False
) -> Any:
    """``redact_output`` with the context of ``run_dir`` (its salt, path spellings and administrators' names)."""
    return redact_output(value, profile=profile, context=context_for_run(run_dir), markup=markup)
