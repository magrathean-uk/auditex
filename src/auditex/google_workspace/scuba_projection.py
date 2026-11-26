"""Read-only, bounded, redacted projection of a Google Workspace bundle into the GWS SCuBA rule inputs (design M13 7).

``project_gws_run(run_dir)`` returns the six sections every ``value_rules.gws`` kind reads (``gws_tenant``,
``gws_policies``, ``gws_setting_events``, ``gws_dns``, ``gws_admins``, ``gws_sso``) plus ``.report`` (status, reason
and source files per section, the redaction counts and the bounds), as :func:`auditex.scuba_projection.project_run`
does for Microsoft 365.

- Every file is read through the same guarded run-file reader and scan bounds as ``project_run`` (``Bundle.read``):
  regular files beneath the run folder only, parsed with duplicate keys, non-finite numbers and deep nesting refused.
  Every row a section uses, from a normalised, raw or supporting file (coverage, collection gaps), counts once per
  section against ``scan_max_rows``. Nothing is written and no network is used; the run's pseudonym key is only read.
- The projection reshapes, bounds and redacts. It reduces nothing, applies no default and compares no value with a
  baseline: the verdict logic stays in the engine (design 7).
- Unknown is not safe (design 8.4). A source that was not collected, cannot be read or has the wrong envelope makes
  the section the ``not_collected`` marker. A cut, duplicated, unproven or misjoined input makes its section's
  ``complete`` false, never a pass. Where the bundle attributes a failure to one setting or unit, only that one is
  marked unknown, in the engine's own terms: a ``gws_policies`` entry without a value (the reducer's ``UNUSABLE``), an
  ambiguous event (blank name, no setting) or an unplaceable privileged entry (``user:unresolved``, no OU).
- Redaction is an allow-list. Sections carry fixed catalogue vocabulary, counts, strict RFC 3339 times and
  run-key pseudonyms for users, groups, organisational units and domains. Policy values must match their schema
  projection. DNS TXT records retain only fixed syntax needed by the rule parsers: SPF directives and modifiers
  with synthetic arguments, DKIM version markers, and DMARC policy tags and synthetic contact URIs. The fixed
  public CISA contact uses URI encoding so the parser can still match it. A domain whose own read cannot be proven
  is emitted as a resolver error, with no resolver details.
- Output keys are written as values (``_obj``), never as mapping keys or module constants, so none becomes a product
  field name the shareable redaction keeps (``output_redaction._D5_FIELD_NAMES``, DEC-171).
- ``gws_tenant.as_of`` is the run's collection end. An offline replay is evaluated at an instant the manifest does not
  record (its ``--as-of``), so its ``as_of`` is null and the 2SV kinds answer ``not_assessed``.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from azure_tenant_audit.collection_gaps import section_was_cut
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.data_minimisation import (
    finite_policy_number,
    minimise_policy_settings,
    minimise_policy_value,
    policy_is_unrecognised,
    policy_unit_id,
)
from azure_tenant_audit.google_policy_schema import (
    POLICY_VALUE_SCHEMAS,
    RequiredPolicyField,
)
from azure_tenant_audit.guarded_io import guarded_operation
from azure_tenant_audit.output_redaction import PSEUDONYM_STRATEGY, pseudonym
from azure_tenant_audit.run_files import (
    MAX_RUN_FILE_BYTES,
    UnsafeRunFileError,
    read_run_file,
)
from azure_tenant_audit.value_rules.gws.dns import (
    _MODIFIER,
    _WSP,
    _directive,
    _domain_spec,
    _is_dmarc,
    _is_spf,
    _macro_string,
    _policy,
    _tag_list,
    _uri,
    _uris,
)
from azure_tenant_audit.value_rules.gws.events import _categories
from azure_tenant_audit.value_rules.gws.identity import instant_ns

from ..scuba_projection import (
    DEFAULT_SCAN_MAX_BYTES,
    DEFAULT_SCAN_MAX_CHUNKS,
    DEFAULT_SCAN_MAX_ROWS,
    Bundle,
    Unavailable,
    _clean_text,
    _collector_error,
    _invalid_constant,
    _json,
    _oversize,
    _projection_key,
    _require,
    _scan_bound,
    _shallow,
    _unique_pairs,
)
from .client import SCUBA_ADMIN_EVENTS
from .collectors import (
    POLICY_SECTION_PROBLEMS,
    SCUBA_READ_SECTIONS,
    _event_value_fields,
    _scuba_application_allowed,
    _scuba_group_email,
    policy_problems,
    two_step_subset_differs,
)
from .normalize import (
    _event_org_units,
    _policy_section,
    _policy_settings_read,
    _scuba_read_records,
)

GWS_PROJECTION_VERSION = "2026-11-25.4"
SECTIONS = ("gws_tenant", "gws_policies", "gws_setting_events", "gws_dns", "gws_admins", "gws_sso")
# The projected-section budget. These sections are rule input, never prompt text, so the budget is sized to the
# largest read the collectors make (20,000 events for each of 13 event names) rather than to a prompt; the scan
# bounds are ``project_run``'s.
DEFAULT_MAX_ITEMS = 300_000
DEFAULT_MAX_CHARS = 128 * 1024 * 1024
_DIRECTORY = "google_directory"
_ABSENT = object()
_DOMAIN = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
                     r"[A-Za-z0-9])?)+", re.ASCII)


def _privileged_privileges() -> frozenset[str]:
    """``HIGHLY_PRIVILEGED_PRIVILEGES`` (SG:scubagoggles/provider.py:142-154 at 08a08ce1, CC0-1.0). A function, so the
    product field-name registry does not take privilege names for mapping keys."""
    return frozenset(("ADMIN_OAUTH_PRIVILEGE_GROUP", "ADMIN_ROLE_MANAGEMENT", "GROUPS_ALL", "MANAGE_USER_LICENSES",
                      "MOBILE_ALL", "ORGANIZATION_UNITS_ALL", "SERVICES_ALL", "USERS_ALL", "USERS_CREATE",
                      "USERS_SECURITY", "USERS_UPDATE"))


def _privileged_role_names() -> frozenset[str]:
    """``HIGHLY_PRIVILEGED_ROLE_NAMES`` (SG:scubagoggles/provider.py:159-167 at 08a08ce1), compared upper-cased as
    ``_is_privileged_role`` does (SG:scubagoggles/provider.py:817-829)."""
    return frozenset(("SUPER_ADMIN", "_SEED_ADMIN_ROLE", "USER MANAGEMENT ADMIN", "USER MANAGEMENT ADMINISTRATOR",
                      "SERVICES ADMIN", "MOBILE ADMIN", "GROUPS ADMIN"))


def _dkim_selectors() -> tuple[str, ...]:
    """The pinned DKIM selectors (SG:scubagoggles/provider.py:115)."""
    return ("google", "selector1", "selector2")


def _sso_modes() -> frozenset[str]:
    """The ``InboundSsoAssignment.SsoMode`` values, and the explicit empty mode the engine reads as Google-only
    (design 8.2, ``identity._sso_modes``); any other text is passed as ``unrecognised`` (an unknown mode)."""
    return frozenset(("SSO_OFF", "SSO_MODE_UNSPECIFIED", "", "SAML_SSO", "OIDC_SSO", "DOMAIN_WIDE_SAML_IF_ENABLED"))


def _section_types() -> dict[str, str]:
    """Policy section key to its setting type, for every setting the schema allow-list holds."""
    return {setting.replace(".", "_"): "settings/" + setting for setting in POLICY_VALUE_SCHEMAS}


def _obj(*pairs: tuple[str, Any]) -> dict[str, Any]:
    """An output object. Its keys are values here, never mapping keys in the source (DEC-171)."""
    return dict(pairs)


def _bare(value: Any) -> bool:
    """An OU or group id as the normaliser admits one (``policy_unit_id``: never a customer-id-shaped string); a
    subset of the unit grammar ``value_rules.gws.reduce`` accepts."""
    return policy_unit_id(value)


def _ident(value: Any) -> bool:
    """A readable identity (a user, role, assignee or member id): a non-empty printable string with no blank in it."""
    return isinstance(value, str) and bool(value) and all(char.isprintable() and not char.isspace() for char in value)


def _label(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value.isprintable()


def _role_key(value: Any) -> str | None:
    """A role id (a string or an integer, never a boolean) as text; None unless it is a readable identity."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    return str(value) if _ident(str(value)) else None


def _unit_id(value: Any) -> str | None:
    """A Directory ``orgUnitId`` (``id:<id>``) as its bare id; None unless sound."""
    bare = value.removeprefix("id:") if isinstance(value, str) else None
    return bare if _bare(bare) else None


def _strings(value: Any) -> list[str] | None:
    return list(value) if isinstance(value, list) and all(isinstance(item, str) for item in value) else None


def _instant(value: Any) -> str | None:
    """A strict RFC 3339 timestamp with at most nine fractional digits."""
    return value if instant_ns(value) is not None else None


def _uncut(row: dict[str, Any]) -> bool:
    return (all(key not in row or type(row[key]) is bool
                for key in ("collection_truncated", "collection_limit_reached", "partial"))
            and not section_was_cut(row) and row.get("partial") is not True
            and row.get("truncation_reason") is None)


def _count_agrees(row: dict[str, Any], count: int) -> bool:
    return type(row.get("item_count")) is int and row["item_count"] == count


def _uninterrupted(row: dict[str, Any], *, read_state: bool = False) -> bool:
    """Reject interruption markers. A read-state record can separately attest to a scoped failure."""
    return (_uncut(row) and row.get("collection_status", "collected") == "collected"
            and (read_state or row.get("complete", True) is True)
            and row.get("nextPageToken") is None and row.get("next_page_token") is None)


def _markers_ok(row: dict[str, Any], *, read_state: bool = False) -> bool:
    return (_uninterrupted(row, read_state=read_state) and row.get("status", "ok") == "ok"
            and row.get("error") is None and row.get("error_class") is None)


def _whole(section: Any) -> bool:
    """A whole, readable list with no contradictory status or count."""
    return (isinstance(section, dict) and isinstance(section.get("value"), list) and _markers_ok(section)
            and ("item_count" not in section or _count_agrees(section, len(section["value"]))))


def _row_ok(row: dict[str, Any], count: int) -> bool:
    return row.get("status") == "ok" and _markers_ok(row) and _count_agrees(row, count)


def _envelope_whole(data: dict[str, Any], name: str) -> bool:
    """The writer's normalised envelope carries only its kind, records and optional collection status."""
    return (set(data) <= {"kind", "records", "collection_status"} and data.get("kind") == name
            and data.get("collection_status", "collected") == "collected")


def _read_manifest(bundle: Bundle) -> dict[str, Any]:
    """Use the common guarded opener, preserving the exact decimal token from the manifest."""
    try:
        data = read_run_file(bundle.root, "run-manifest.json", max_bytes=min(bundle.scan_max_bytes, MAX_RUN_FILE_BYTES))
        value = json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=_invalid_constant, parse_float=Decimal)
    except FileNotFoundError:
        raise Unavailable("missing_artifact") from None
    except UnsafeRunFileError as exc:
        if exc.reason == "oversize" and bundle.scan_max_bytes < MAX_RUN_FILE_BYTES:
            raise _scan_bound("scan_max_bytes") from None
        raise
    except (OSError, ValueError, InvalidOperation, RecursionError):
        raise Unavailable() from None
    _require(isinstance(value, dict) and _shallow(value), kind="invalid_type")
    return value


def _duration_ns(value: Any) -> int | None:
    if type(value) is int:
        return value * 10**9 if 0 <= value < 10**12 else None
    if not isinstance(value, Decimal) or not value.is_finite() or value < 0:
        return None
    if not value:
        return 0
    if not -9 <= value.adjusted() < 12:
        return None
    _, digits, exponent = value.as_tuple()
    places = exponent + 9
    if places < 0:
        if any(digits[places:]):
            return None
        digits, places = digits[:places], 0
    return int("".join(map(str, digits))) * 10**places


def _as_of(manifest: dict[str, Any]) -> str | None:
    """Compute the end of a live collection exactly at the rule engine's nanosecond precision."""
    if ("mode" in manifest and manifest["mode"] not in ("domain-delegation", "service_account", "oauth")
            or manifest.get("replay_source") is not None):
        return None
    start = instant_ns(manifest.get("created_utc"))
    duration = _duration_ns(manifest.get("duration_seconds"))
    if start is None or duration is None:
        return None
    seconds, nanos = divmod(start + duration, 10**9)
    try:
        end = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    except OverflowError:
        return None
    fraction = f"{nanos:09d}" if nanos % 1000 else f"{nanos // 1000:06d}"
    return end.isoformat(timespec="seconds").removesuffix("+00:00") + "." + fraction + "Z"


class GwsProjection(dict):
    """The six rule-input sections, with the local projection report on ``report`` (never serialised as evidence)."""

    report: dict[str, Any]


class _Context:
    """One run's reads. A file is read once; its rows count against the bound once in every section that uses them."""

    def __init__(self, bundle: Bundle, key: bytes, manifest: dict[str, Any]):
        self.bundle, self.key, self.manifest, self.as_of = bundle, key, manifest, _as_of(manifest)
        self.cache: dict[str, tuple[Any, int, Unavailable | None]] = {}
        self.users: set[str] = set()
        self.groups: set[str] = set()
        self.domains: set[str] = set()
        self.addresses = 0
        self._coverage_index: dict[tuple[str, str], list[dict[str, Any]]] | None = None
        self._gap_index: dict[str, set[str]] | None = None
        self.begin()

    def begin(self) -> None:
        self.sources: list[str] = []
        self.charged: set[str] = set()
        self.rows = 0
        self.bytes = 0

    def charge(self, label: str, count: int) -> None:
        """Count ``count`` rows of ``label`` against ``scan_max_rows``, once per section."""
        if label in self.charged:
            return
        self.charged.add(label)
        self.rows += count
        if self.rows > self.bundle.scan_max_rows:
            raise _scan_bound("scan_max_rows")

    def read(self, relative: str) -> Any:
        if relative not in self.cache:
            try:
                value = self.bundle.read(relative)
                self.cache[relative] = (value, self.bundle.sizes.get(relative, 0), None)
            except Unavailable as exc:
                self.cache[relative] = (None, 0, exc)
        value, size, error = self.cache[relative]
        if error is not None:
            copy = Unavailable(error.reason)
            copy.detail = dict(error.detail)
            raise copy
        if relative not in self.sources:
            self.sources.append(relative)
            self.bytes += size
        return value

    def optional(self, relative: str) -> Any:
        try:
            return self.read(relative)
        except Unavailable as exc:
            if exc.reason == "missing_artifact":
                return _ABSENT
            raise

    def records(self, name: str, *, required: bool = True) -> tuple[list[dict[str, Any]] | None, bool]:
        """A normalised section's records and whether its envelope says the list is whole (not cut or partial);
        ``(None, False)`` when an optional one is absent. A wrong envelope withholds."""
        relative = f"normalized/{name}.json"
        data = self.read(relative) if required else self.optional(relative)
        if data is _ABSENT:
            return None, False
        _require(isinstance(data, dict), kind="invalid_type")
        if data.get("error") or data.get("error_class"):
            raise _collector_error(data)
        _require(data.get("collection_status", "collected") == "collected", "collection_status")
        records = data.get("records")
        _require(isinstance(records, list), "records", "invalid_type")
        _require(all(isinstance(row, dict) for row in records), "records", "invalid_type")
        self.charge(relative, len(records))
        return records, _envelope_whole(data, name)

    def coverage(self) -> dict[tuple[str, str], list[dict[str, Any]]] | None:
        rows = self.optional("coverage.json")
        if rows is _ABSENT and "coverage_path" not in self.manifest:
            rows = []
        if not isinstance(rows, list):
            return None
        self.charge("coverage.json", len(rows))
        if self._coverage_index is None:
            index: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for row in rows:
                if not isinstance(row, dict) or not all(_label(row.get(key)) for key in ("collector", "name")):
                    return None
                index.setdefault((row["collector"], row["name"]), []).append(row)
            self._coverage_index = index
        return self._coverage_index

    def gaps(self) -> dict[str, set[str]] | None:
        data = self.optional("normalized/collection_gaps.json")
        if data is _ABSENT:
            return {}
        rows = data.get("records") if isinstance(data, dict) else None
        if not isinstance(rows, list) or not _envelope_whole(data, "collection_gaps"):
            return None
        self.charge("normalized/collection_gaps.json", len(rows))
        if self._gap_index is None:
            index: dict[str, set[str]] = {}
            for row in rows:
                if not isinstance(row, dict) or not _ident(row.get("collector")):
                    return None
                # Section-scoped and list gaps use different keys.
                labels = [row[key] for key in ("list", "section") if key in row]
                if not labels or any(not _label(label) for label in labels):
                    return None
                index.setdefault(row["collector"], set()).update(labels)
            self._gap_index = index
        return self._gap_index

    def directory(self) -> dict[str, Any] | None:
        raw = self.optional(f"raw/{_DIRECTORY}.json")
        return raw if isinstance(raw, dict) else None

    def has_whole_list(self, raw: Any, collector: str, name: str) -> bool:
        section = raw.get(name) if isinstance(raw, dict) else None
        if not _whole(section):
            return False
        self.charge(f"raw:{collector}:{name}", len(section["value"]))
        return True

    def read_ok(self, raw: Any, collector: str, name: str, *, direct_count: bool = True) -> bool:
        """Prove a retained list against its own operation log. Offline replays omit successful coverage."""
        if not self.has_whole_list(raw, collector, name):
            return False
        coverage, gaps = self.coverage(), self.gaps()
        if coverage is None or gaps is None or name in gaps.get(collector, ()):
            return False
        rows = coverage.get((collector, name), [])
        if not rows:
            return (not direct_count or self.manifest.get("mode") == "offline"
                    or "coverage_path" not in self.manifest)
        return len(rows) == 1 and _row_ok(rows[0], len(raw[name]["value"]))

    def fanout_ok(self, collector: str, name: str, count: int) -> bool:
        coverage, gaps = self.coverage(), self.gaps()
        if coverage is None or gaps is None or name in gaps.get(collector, ()):
            return False
        rows = coverage.get((collector, name), [])
        return len(rows) == 1 and _row_ok(rows[0], count)

    def tree(self) -> tuple[str | None, dict[str, str | None], bool]:
        """The top unit, the ``ou:<id>`` parent map and whether the topology is complete and sound: one root, every
        unit's chain reaching it with no dangling parent or cycle (as ``value_rules.gws.reduce._topology`` checks)."""
        rows, whole = self.records("google_org_units")
        units, consistent, state = _split(rows or [], "google_org_units", "google_org_unit")
        complete = (consistent and whole and state.get("complete") is True and state.get("root_id_known") is True
                    and type(state.get("malformed_count")) is int and state["malformed_count"] == 0)
        org_units: dict[str, str | None] = {}
        roots: list[str] = []
        for row in units:
            unit, parent, root = row.get("id"), row.get("parent_id"), row.get("is_root")
            if (not _uninterrupted(row) or not _bare(unit) or "ou:" + unit in org_units or type(root) is not bool
                    or (parent is not None if root else not _bare(parent))):
                complete = False
                continue
            org_units["ou:" + unit] = None if root else "ou:" + parent
            if root:
                roots.append("ou:" + unit)
        top = roots[0] if len(roots) == 1 else None
        raw_tree, _ = self.directory_tree()
        if top is None or raw_tree != org_units or not _sound(org_units, top):
            complete = False
        return top, org_units, complete

    def directory_tree(self) -> tuple[dict[str, str | None], dict[str, str]]:
        """Read unique Directory ids and paths, including a root inferred from its children in legacy runs."""
        raw = self.directory()
        if not self.read_ok(raw, _DIRECTORY, "orgUnits"):
            return {}, {}
        topology: dict[str, str | None] = {}
        paths: dict[str, str] = {}
        parent_paths: dict[str, str] = {}
        for row in raw["orgUnits"]["value"]:
            if not isinstance(row, dict) or not _uninterrupted(row):
                return {}, {}
            unit, path = _unit_id(row.get("orgUnitId")), row.get("orgUnitPath")
            if unit is None or not _ou_path(path) or path in paths or "ou:" + unit in topology:
                return {}, {}
            key = "ou:" + unit
            paths[path] = key
            if path == "/":
                if row.get("parentOrgUnitId") not in (None, "") or row.get("parentOrgUnitPath") not in (None, ""):
                    return {}, {}
                topology[key] = None
            else:
                parent, parent_path = _unit_id(row.get("parentOrgUnitId")), row.get("parentOrgUnitPath")
                if parent is None or parent_path != (path.rsplit("/", 1)[0] or "/"):
                    return {}, {}
                topology[key] = "ou:" + parent
                parent_paths[path] = parent_path
        if "/" not in paths:
            roots = {topology[paths[path]] for path, parent in parent_paths.items() if parent == "/"}
            if len(roots) != 1 or (root := next(iter(roots))) in topology:
                return {}, {}
            paths["/"] = root
            topology[root] = None
        if any(paths.get(parent) != topology[paths[path]] for path, parent in parent_paths.items()):
            return {}, {}
        return topology, paths

    def known_tree(self) -> tuple[str | None, dict[str, str | None], bool]:
        """``tree()``, or no tree when ``google_org_units`` cannot be read (an older bundle); a scan bound still
        withholds the section."""
        try:
            return self.tree()
        except Unavailable as exc:
            if exc.reason == "oversize":
                raise
            return None, {}, False

    def group_ids(self) -> dict[str, str] | None:
        """Reconcile group ids and addresses before using them for a join."""
        raw = self.directory()
        if not self.read_ok(raw, _DIRECTORY, "groups"):
            return None
        records, whole = self.records("google_groups", required=False)
        groups = raw["groups"]["value"]
        if not _rows_agree(records, whole, groups, _group_row, _raw_group_row):
            return None
        index: dict[str, str] = {}
        for row in groups:
            group, email = _raw_group_row(row)
            if group in index or email in index or group == email:
                return None
            index[group] = index[email] = group
        return index

    def path_index(self) -> dict[str, str]:
        """A user's path is usable only against the reconciled topology."""
        if not self.known_tree()[2]:
            return {}
        return self.directory_tree()[1]

    def ou(self, unit: str) -> str:
        return "ou:" + pseudonym(self.key, unit)

    def user(self, user_id: str) -> str:
        self.users.add(user_id)
        return "user:" + pseudonym(self.key, "user:" + user_id)

    def group(self, group_id: str) -> str:
        self.groups.add("group:" + group_id)
        return "group:" + pseudonym(self.key, "group:" + group_id)

    def domain(self, name: str) -> str:
        """A domain as a keyed pseudonym under the reserved ``.invalid`` name, so a parent's DMARC record can still
        be told from the domain's own (``_dmarc.invalid``) without the name."""
        self.domains.add(name.lower())
        return "domain:" + pseudonym(self.key, "domain:" + name.lower()) + ".invalid"

    def group_address(self, address: str) -> str:
        """A group the Directory list does not hold, known only by its address (events of a deleted group)."""
        self.groups.add("group-email:" + address.lower())
        return "group:" + pseudonym(self.key, "group-email:" + address.lower())


def _ou_path(value: Any) -> bool:
    return (isinstance(value, str) and value.isprintable() and value.startswith("/")
            and (value == "/" or all(part.strip() and part not in (".", "..") for part in value[1:].split("/"))))


def _rows_agree(records: list[dict] | None, whole: bool, raw: list, normalised_key: Callable, raw_key: Callable) -> bool:
    """Require the same unique, readable row identities and values on both sides of a join."""
    if records is None:
        return not raw
    if (not whole or len(records) != len(raw) or not all(map(_uninterrupted, records))
            or any(isinstance(row, dict) and not _uninterrupted(row) for row in raw)):
        return False
    normalised = {normalised_key(row) for row in records}
    source = {raw_key(row) for row in raw}
    return None not in normalised and len(normalised) == len(records) and source == normalised


def _group_row(row: dict) -> tuple[str, str] | None:
    group, email = row.get("id"), row.get("email")
    if row.get("kind") == "google_group" and _bare(group) and isinstance(email, str) and _scuba_group_email(email):
        return group, email.lower()
    return None


def _raw_group_row(row: Any) -> tuple[str, str] | None:
    if not isinstance(row, dict):
        return None
    return _group_row(_obj(("kind", "google_group"), ("id", row.get("id")), ("email", row.get("email"))))


def _sound(org_units: dict[str, str | None], top: str) -> bool:
    rooted = {top}
    for start in org_units:
        seen, unit = set(), start
        while unit not in rooted:
            if unit in seen or unit not in org_units or org_units[unit] is None:
                return False
            seen.add(unit)
            unit = org_units[unit]
        rooted.update(seen)
    return True


def _split(records: list[dict[str, Any]], section: str, kind: str) -> tuple[list[dict[str, Any]], bool, dict]:
    """The data records, whether there is exactly one read-state record and it counts them, and the state."""
    data = [row for row in records if row.get("kind") == kind]
    states = [row for row in records if row.get("kind") == f"{section}_read_state"]
    state = states[0] if len(states) == 1 else {}
    count = state.get("record_count")
    consistent = (len(states) == 1 and state.get("id") == "read_state" and len(data) + 1 == len(records)
                  and type(count) is int and count == len(data) and type(state.get("complete")) is bool
                  and _markers_ok(state, read_state=True))
    return data, consistent, state


# --- sections ----------------------------------------------------------------------------------------------------


def _tenant(ctx: _Context) -> dict[str, Any]:
    top, org_units, complete = ctx.tree()
    _require(top is not None, "top_unit", "missing_field")
    units = {ctx.ou(unit): ctx.ou(parent) if parent is not None else None for unit, parent in org_units.items()}
    return _obj(("as_of", ctx.as_of), ("top_unit", ctx.ou(top)), ("org_units", units), ("complete", complete))


def _policy_read(ctx: _Context, data: list[dict], state: dict, org_units: dict[str, str | None]) -> bool:
    """Rebuild the policy read from raw rows and require the retained rows and failure attribution to agree.

    Transport failures can hide any policy. Only row validation failures confirmed by the normaliser's own
    classification can be attributed to individual settings.
    """
    collector, name = "google_policies", "policySettings"
    raw = ctx.optional(f"raw/{collector}.json")
    if not ctx.has_whole_list(raw, collector, name):
        return False
    coverage, gaps = ctx.coverage(), ctx.gaps()
    if coverage is None or gaps is None or gaps.get(collector):
        return False
    values = raw[name]["value"]
    for item in values:
        if isinstance(item, dict) and not _uninterrupted(item):
            return False
        query = item.get("policyQuery") if isinstance(item, dict) else None
        if isinstance(query, dict) and not set(query) <= {"orgUnit", "group", "sortOrder", "query", "query_scope"}:
            return False
    operations = {label for owner, label in coverage if owner == collector}
    if operations - {name, "twoStepVerificationPolicies", "policyPlacement"}:
        return False
    placement = coverage.get((collector, "policyPlacement"), [])
    if placement and (len(placement) != 1 or not _placement_failure(placement[0], state, org_units)):
        return False
    if "twoStepVerificationPolicies" in operations and "twoStepVerificationPolicies" not in raw:
        return False
    read_rows = coverage.get((collector, name), [])
    if len(read_rows) != 1 and (read_rows or ctx.manifest.get("mode") != "offline"):
        return False
    if read_rows:
        row = read_rows[0]
        if "policy_row_validation" in row and type(row["policy_row_validation"]) is not bool:
            return False
        if not _row_ok(row, len(values)) and not (
                row.get("status") == "partial" and row.get("policy_row_validation") is True and _uninterrupted(row)
                and _count_agrees(row, len(values)) and row.get("error_class") == "malformed_response"
                and state.get("complete") is False):
            return False
    replayed, _ = _policy_settings_read(raw, [_obj(("name", collector), ("status", "ok"))], [],
                                       {unit[3:] for unit in org_units})
    expected, _, read_state = _split(replayed, "google_policy_settings", "google_policy_setting")

    def policy_key(row: dict) -> str:
        return _json(_obj(*((key, row.get(key)) for key in
                            ("section", "org_unit", "group", "unit_kind", "sort_order", "value"))))

    if "twoStepVerificationPolicies" in raw and (
            not ctx.read_ok(raw, collector, "twoStepVerificationPolicies", direct_count=False)
            or two_step_subset_differs(raw)):
        return False
    if not _rows_agree(data, True, expected, policy_key, policy_key):
        return False
    for key in ("complete", "malformed_count", "unusable_sections", "unusable_scopes"):
        if key not in state or _json(state[key]) != _json(read_state.get(key)):
            return False
    if state.get("complete") is True:
        return True
    # Unattributed malformed rows are counted by the normaliser too. They cannot be restored to a scoped read.
    return bool(read_state.get("unusable_sections") or read_state.get("unusable_scopes")) and _all_failures_attributed(raw)


def _placement_failure(row: dict, state: dict, org_units: dict[str, str | None]) -> bool:
    """A derived placement diagnostic is covered only by a saved scope outside the Directory tree."""
    scopes = state.get("unusable_scopes")
    return (row.get("status") == "partial" and row.get("policy_row_validation") is True
            and _uninterrupted(row) and _count_agrees(row, 0) and row.get("error_class") == "malformed_response"
            and isinstance(scopes, list) and any(
                isinstance(scope, dict) and _bare(scope.get("org_unit"))
                and "ou:" + scope["org_unit"] not in org_units for scope in scopes))


def _all_failures_attributed(raw: dict) -> bool:
    """Reject any raw row whose setting the normaliser cannot identify."""
    return all(policy_is_unrecognised(row) or (
        not (set(policy_problems(row)) & POLICY_SECTION_PROBLEMS)
        and _policy_section(row["setting"].get("type")) is not None)
        for row in minimise_policy_settings(raw["policySettings"]["value"]))


def _policy_value(ctx: _Context, value: Any, schema: Any) -> Any:
    """Redact identifiers using the schema, keeping equality across rule and list references."""
    if value is None:
        return None
    if isinstance(schema, RequiredPolicyField):
        return _policy_value(ctx, value, schema.schema)
    if isinstance(schema, dict):
        # Quarantine resource identifiers are numeric in the API. No rule reads them.
        return {key: _policy_value(ctx, field, schema[key]) for key, field in value.items()
                if not key.lower().endswith("quarantineid")}
    if isinstance(schema, list):
        return [_policy_value(ctx, item, schema[0]) for item in value]
    if schema == "address-lists":
        return [_obj(("id", _policy_value(ctx, item["id"], "reference")),
                     ("entry_count", item["entry_count"]), ("domain_entry_count", item["domain_entry_count"]))
                for item in value]
    if schema == "reference":
        return "ref:" + pseudonym(ctx.key, "policy-reference:" + value)
    if schema == "ip":
        # The list rule tests presence and IP syntax. Keep distinct valid values in documentation space.
        token = pseudonym(ctx.key, "policy-ip:" + value)
        return "2001:db8::" + ":".join(token[i:i + 4] for i in range(0, len(token), 4))
    return value


def _unique_policy_members(value: Any) -> bool:
    if isinstance(value, list):
        return len({_json(item) for item in value}) == len(value) and all(map(_unique_policy_members, value))
    if isinstance(value, dict):
        return all(map(_unique_policy_members, value.values()))
    return True


def _policies(ctx: _Context) -> dict[str, Any]:
    rows, whole = ctx.records("google_policy_settings")
    data, consistent, state = _split(rows or [], "google_policy_settings", "google_policy_setting")
    top, org_units, topology_complete = ctx.known_tree()
    types = _section_types()
    complete = consistent and whole and topology_complete and _policy_read(ctx, data, state, org_units)
    failures = []
    if complete and state["complete"] is False:
        failures = [(section, None, None) for section in state["unusable_sections"]]
        failures.extend((scope["section"], scope["org_unit"], scope["group"]) for scope in state["unusable_scopes"])
    policies, units = [], {}
    for row in data:
        org_unit, group, kind, section = row.get("org_unit"), row.get("group"), row.get("unit_kind"), row.get("section")
        if group is not None and org_unit is None:
            org_unit = top[3:] if top else None  # a group-only policy applies under the top unit (policy_api.py:804-825)
        if (not _bare(org_unit) or group is not None and not _bare(group) or not isinstance(section, str) or section not in types
                or kind != ("group" if group is not None else "org_unit")):
            complete = False  # a policy that cannot be placed is left out; the read is no longer the whole
            continue
        unit = ctx.ou("ou:" + org_unit)
        if group is not None:
            unit += "/" + ctx.group(group)
        units.setdefault(section, set()).add((unit, kind))
        rank = row.get("sort_order")
        entry = _obj(("unit", unit), ("unit_kind", kind), ("section", section),
                     ("sort_order", rank if finite_policy_number(rank) else None))
        value = row.get("value")
        # Only a value equal to its own schema projection is passed; anything else leaves the entry unusable.
        if (isinstance(value, dict) and _unique_policy_members(value)
                and _json(minimise_policy_value(types[section], value)) == _json(value)):
            schema = POLICY_VALUE_SCHEMAS[types[section].removeprefix("settings/")]
            entry.update(_obj(("value", _policy_value(ctx, value, schema))))
        else:
            complete = False
        policies.append(entry)
    for section, org_unit, group in failures or ():
        # The engine's own unknown: an entry with no value makes that (unit, section) UNUSABLE in the reducer.
        base = org_unit or (top[3:] if top else None)
        if base is None:
            complete = False
            continue
        if org_unit is None and group is None:
            targets = {*units.get(section, ()), (ctx.ou(top), "org_unit")}
        else:
            unit = ctx.ou("ou:" + base)
            targets = {(unit + "/" + ctx.group(group), "group")} if group else {(unit, "org_unit")}
        for unit, kind in sorted(targets):
            policies.append(_obj(("unit", unit), ("unit_kind", kind), ("section", section), ("sort_order", None)))
    return _obj(("complete", complete), ("policies", policies))


def _event_fields(row: dict[str, Any], fields: dict[str, tuple[frozenset[str], bool]]) -> tuple | None:
    """The event's name, setting, value and application from the shipped vocabulary; None when the name or setting
    is outside it (the event cannot be told). A value outside it is ``unrecognised``; a present application outside it
    is blank (ambiguous for the events kind), so a malformed field never reads as an absent one."""
    name, setting = row.get("event"), row.get("setting")
    if name not in SCUBA_ADMIN_EVENTS:
        return None
    if "setting" in row and not (isinstance(setting, str) and (setting.strip() in fields or setting == "unrecognised")):
        return None
    value = row.get("new_value")
    if "new_value" in row and isinstance(value, str):
        allowed = fields.get(name) or fields.get(setting.strip() if isinstance(setting, str) else "")
        known, categories = allowed or (frozenset(), False)
        if not (allowed and (_categories(value, known) is not None if categories else value in known)):
            value = "unrecognised"
    elif value is not None:
        value = None
    application = row.get("application")
    if "application" in row and not (isinstance(application, str) and (
            _scuba_application_allowed(application) or application == "unrecognised")):
        application = ""
    return name, setting, value, application


def _event_key(row: dict[str, Any]) -> tuple | None:
    time = instant_ns(row.get("event_time"))
    fields = ("event", "setting", "new_value", "org_unit", "group_email", "application")
    if time is None or any(key in row and not isinstance(row[key], str) for key in fields):
        return None
    return (time, *(row.get(key) for key in fields))


def _event_read(ctx: _Context, data: list[dict], state: dict, org_units: dict[str, str | None]) -> bool:
    collector = "google_setting_events"
    name = SCUBA_READ_SECTIONS[collector]
    raw = ctx.optional(f"raw/{collector}.json")
    if not ctx.read_ok(raw, collector, name, direct_count=False):
        return False
    coverage, gaps = ctx.coverage(), ctx.gaps()
    if gaps.get(collector):
        return False
    saved = raw[name]["value"]
    if any(isinstance(row, dict) and not _uninterrupted(row) for row in saved):
        return False
    replayed = _scuba_read_records(
        collector, _obj((collector, raw)), [_obj(("name", collector), ("status", "ok"))], [],
        event_org_units=_event_org_units(ctx.directory(), {unit[3:] for unit in org_units}),
    )
    expected, _, read_state = _split(replayed, collector, "google_setting_event")
    if read_state.get("complete") is not True or not _rows_agree(data, True, expected, _event_key, _event_key):
        return False
    start, end = (instant_ns(state.get(key)) for key in ("window_start", "window_end"))
    if start is None or end is None or start >= end or (start, end) != tuple(
            instant_ns(read_state.get(key)) for key in ("window_start", "window_end")):
        return False

    # Live collection logs each event-name stream. Offline replay may only have the saved activities and window.
    streams = {label for owner, label in coverage if owner == collector and label != name}
    if not streams:
        return (collector, name) in coverage or ctx.manifest.get("mode") == "offline"
    if streams != set(SCUBA_ADMIN_EVENTS):
        return False
    counts: Counter[str] = Counter()
    for activity in saved:
        labels = {event["name"] for event in activity["events"]}
        if len(labels) != 1:
            return False
        counts.update(labels)
    return all(ctx.fanout_ok(collector, label, counts[label]) for label in streams)


def _events(ctx: _Context) -> dict[str, Any]:
    rows, whole = ctx.records("google_setting_events")
    data, consistent, state = _split(rows or [], "google_setting_events", "google_setting_event")
    _, org_units, topology_complete = ctx.known_tree()
    complete = (consistent and whole and state.get("complete") is True and topology_complete
                and _event_read(ctx, data, state, org_units))
    groups: dict[str, str] = {}
    if any("group_email" in row for row in data):
        try:
            index = ctx.group_ids()
            complete = complete and index is not None
            groups = index or {}
        except Unavailable as exc:
            if exc.reason == "oversize":
                raise
            complete = False
    fields = _event_value_fields()
    events = []
    for row in data:
        org_unit, group = row.get("org_unit"), row.get("group_email")
        unit = None  # absent, malformed or unresolved: the kind treats the event as ambiguous
        if "group_email" in row:
            if "org_unit" not in row and isinstance(group, str) and _scuba_group_email(group):
                # A group event (``GROUP_EMAIL`` set) is the group's, whatever OU it names (SG:scubagoggles/rego/
                # Utils.rego:276). A group the list no longer holds keeps its address pseudonym.
                group_id = groups.get(group.lower())
                unit = ctx.group(group_id) if group_id else ctx.group_address(group)
        elif _bare(org_unit) and "ou:" + org_unit in org_units:
            unit = ctx.ou("ou:" + org_unit)
        told = _event_fields(row, fields)
        name, setting, value, application = told if told else ("", None, None, None)
        if name == "DELETE_APPLICATION_SETTING" and row.get("new_value") is not None:
            # A delete carries no value (L04 drops the target of one that does): malformed, so it cannot be placed
            # and the events kind holds it ambiguous rather than a reset or a delete it can rank.
            unit = None
        time = _instant(row.get("event_time"))
        relevant = name in fields or isinstance(setting, str) and setting in fields
        if (time is None or not name or relevant and (application in ("", "unrecognised")
                or name != "TOGGLE_CAA_ENABLEMENT" and unit is None
                or name != "DELETE_APPLICATION_SETTING" and value in (None, "unrecognised"))):
            complete = False
        events.append(_obj(("time", time), ("event", name), ("setting", setting),
                           ("new_value", value), ("unit", unit), ("application", application)))
    # The log window is the read's own record; without one it is null and the events kind concludes nothing.
    return _obj(("complete", complete), ("window_start", _instant(state.get("window_start"))),
                ("window_end", _instant(state.get("window_end"))), ("events", events))


def _contact(token: str, ctx: _Context) -> str:
    """One rua or ruf URI as the DNS kind reads it (``dns._uri``): malformed stays malformed, another valid scheme
    stays valid with no address, and each ``mailto:`` recipient is CISA's exact address or a placeholder."""
    found = _uri(token)
    if found is None:
        return "invalid"
    if not found:
        return "https://example.invalid"
    out = []
    for local, host in found:
        if local == "reports" and host.lower() == "dmarc.cyber.dhs.gov":
            out.append("%72eports@%64marc.cyber.dhs.gov")
        else:
            ctx.addresses += 1
            out.append("contact@example.invalid")
    return "mailto:" + "%2C".join(out)


def _reading(record: str) -> tuple | None:
    """What the DMARC rows read from one record: the policy as applied, and the rua and ruf recipient counts and
    whether CISA's address is among the rua ones."""
    tags = _tag_list(record) if _is_dmarc(record) else None
    applied = _policy(tags) if tags is not None else None
    if applied is None:
        return None
    rua, ruf = _uris(applied.get("rua")), _uris(applied.get("ruf"))
    cisa = rua is not None and any(local == "reports" and host.lower() == "dmarc.cyber.dhs.gov" for local, host in rua)
    return (applied["p"], applied.get("sp"), None if rua is None else len(rua), cisa,
            None if ruf is None else len(ruf))


def _dmarc_text(record: str, ctx: _Context) -> str:
    """A DMARC answer rewritten to the tags the rows read (``v``, ``p``, ``sp``, ``rua``, ``ruf``), with no address
    but CISA's; a TXT answer that is not DMARC is ``unrecognised``. The rewrite must read exactly as the original."""
    if not _is_dmarc(record):
        return "unrecognised"
    tags = _tag_list(record)
    if tags is None:
        return "v=DMARC1; ="  # a DMARC record whose tag list is malformed, as the original
    parts = ["v=DMARC1"]
    for name in ("p", "sp"):
        if name in tags:
            parts.append(f"{name}={tags[name].lower() if tags[name].lower() in ('none', 'quarantine', 'reject') else 'invalid'}")
    for name in ("rua", "ruf"):
        if name in tags:
            parts.append(f"{name}=" + ",".join(_contact(token.strip(_WSP), ctx) for token in tags[name].split(",")))
    text = "; ".join(parts)
    _require(_reading(text) == _reading(record), "dmarc.records", "unseen_shape")
    return text


def _spf_text(record: str) -> str:
    """Redact SPF arguments while preserving the terms, their order and their syntax validity."""
    if not _is_spf(record):
        return "unrecognised"
    terms = ["v=spf1"]
    for term in record[6:].split(" "):
        if not term:
            continue
        if not all(0x21 <= ord(char) <= 0x7E for char in term):
            return "v=spf1 invalid"
        directive = _directive(term)
        if isinstance(directive, tuple):
            qualifier, mechanism = directive
            suffix = _obj(("include", ":example.invalid"), ("exists", ":example.invalid"),
                          ("ip4", ":192.0.2.1"), ("ip6", ":2001:db8::1")).get(mechanism, "")
            terms.append(qualifier.removeprefix("+") + mechanism + suffix)
            continue
        modifier = _MODIFIER.fullmatch(term)
        if directive is False or modifier is None:
            return "v=spf1 invalid"
        name, argument = modifier[1].lower(), modifier[2]
        if name in ("redirect", "exp"):
            if not _domain_spec(argument):
                return "v=spf1 invalid"
            terms.append(name + "=example.invalid")
        elif _macro_string(argument) is None:
            return "v=spf1 invalid"
        else:
            terms.append("other=redacted")
    return " ".join(terms)


def _domain_name(value: Any) -> bool:
    return isinstance(value, str) and _DOMAIN.fullmatch(value) is not None


def _listed(rows: list[Any]) -> dict[str, tuple[bool, bool]] | None:
    """Verified flags and alias scope from a unique, readable Directory listing."""
    names: dict[str, tuple[bool, bool]] = {}

    def add(name: Any, verified: Any, alias: bool) -> bool:
        if not _domain_name(name) or type(verified) is not bool or name.lower() in names:
            return False
        names[name.lower()] = verified, alias
        return True

    for row in rows:
        if not isinstance(row, dict) or not add(row.get("domainName", row.get("domain")),
                                                row.get("verified"), False):
            return None
        aliases = row.get("domainAliases", [])
        if not isinstance(aliases, list):
            return None
        for alias in aliases:
            if not isinstance(alias, dict) or not add(alias.get("domainAliasName"), alias.get("verified"), True):
                return None
    return names


def _dns_scope(ctx: _Context, raw: Any) -> dict[str, bool] | None:
    if not ctx.read_ok(raw, "google_dns_posture", "domains"):
        return None
    listed = _listed(raw["domains"]["value"])
    if listed is None:
        return None
    rows, whole = ctx.records("google_domains", required=False)
    if rows is not None:
        if not whole:
            return None
        scope: dict[str, bool] = {}
        for row in rows:
            name, kind = row.get("domain_name"), row.get("domain_kind")
            if (row.get("kind") != "google_domain" or not _domain_name(name) or name.lower() in scope
                    or kind not in ("alias", "primary", "secondary")):
                return None
            scope[name.lower()] = kind == "alias"
            if "verified" in row and (type(row["verified"]) is not bool or name.lower() not in listed
                                      or row["verified"] != listed[name.lower()][0]):
                return None
        if scope != {name: alias for name, (_, alias) in listed.items()}:
            return None
    return {name: alias for name, (verified, alias) in listed.items() if verified}


def _txt_list(value: Any) -> list[str] | None:
    records = _strings(value)
    if records is None or len(set(records)) != len(records) or any(
            not _clean_text(record) or not record.strip() for record in records):
        return None
    return records


def _dns_answers(row: dict[str, Any]) -> tuple[tuple | None, tuple | None, tuple | None]:
    """Read each retained TXT answer without applying its baseline predicate."""
    spf, dkim, dmarc = (row.get(part) if isinstance(row.get(part), dict) else {} for part in ("spf", "dkim", "dmarc"))
    spf_records = _txt_list(spf.get("records")) if _markers_ok(spf) else None
    selectors = dkim.get("selectors") if _markers_ok(dkim) else None
    dkim_records = [_txt_list(selectors.get(selector)) if isinstance(selectors, dict) else None
                    for selector in _dkim_selectors()]
    query, inherited, dmarc_records = dmarc.get("query_name"), dmarc.get("inherited"), _txt_list(dmarc.get("records"))
    name = row.get("domain")
    own = isinstance(name, str) and query == "_dmarc." + name
    parent = (isinstance(name, str) and isinstance(query, str) and query.startswith("_dmarc.")
              and _domain_name(query[7:]) and name.endswith("." + query[7:]))
    return (tuple(sorted(spf_records)) if spf_records is not None else None,
            tuple(tuple(sorted(records)) for records in dkim_records) if None not in dkim_records else None,
            (query, inherited, tuple(sorted(dmarc_records)))
            if _markers_ok(dmarc) and dmarc_records is not None
            and (inherited is True and parent or inherited is False and own) else None)


def _no_resolver_error(row: dict[str, Any]) -> bool:
    return _markers_ok(row) and (row.get("resolver_error") is None or row["resolver_error"] is False)


def _dns(ctx: _Context) -> dict[str, Any]:
    records, whole = ctx.records("google_dns_posture")
    data = [row for row in records if row.get("kind") == "google_domain_posture"]
    states = len(records) != len(data)
    _require(not data or any("alias" in row or isinstance(row.get("dmarc"), dict) and "query_name" in row["dmarc"]
                             for row in data), "dmarc.query_name", "missing_field")
    raw = ctx.optional("raw/google_dns_posture.json")
    posture_read = ctx.read_ok(raw, "google_dns_posture", "domainPosture", direct_count=False)
    scope = _dns_scope(ctx, raw)
    if states:
        _, consistent, state = _split(records, "google_dns_posture", "google_domain_posture")
        whole = whole and consistent and state.get("complete") is True
    raw_rows = raw["domainPosture"]["value"] if posture_read else []
    raw_names = Counter(row["domain"].lower() for row in raw_rows if isinstance(row, dict)
                        and _domain_name(row.get("domain")))
    norm_names = Counter(row["domain"].lower() for row in data if _domain_name(row.get("domain")))
    raw_by_name = {row["domain"].lower(): row for row in raw_rows if isinstance(row, dict)
                   and _domain_name(row.get("domain"))}
    complete = (whole and posture_read and bool(scope)
                and len(raw_rows) == len(raw_names) and len(data) == len(norm_names)
                and set(raw_names) == set(norm_names) == set(scope))

    coverage = ctx.coverage() or {}
    complete = complete and {label for owner, label in coverage if owner == "google_dns_posture"
                             and label.startswith("posture:")} == {
        "posture:" + row["domain"] for row in data if _domain_name(row.get("domain"))}
    domains = []
    for row in data:
        name = row.get("domain")
        if not isinstance(name, str) or not name:
            continue
        label = name.lower()
        host = ctx.domain(name) if _domain_name(name) else ""
        listed_alias = (scope or {}).get(label)
        alias = row.get("alias", listed_alias)
        if type(alias) is not bool or listed_alias is not None and alias != listed_alias:
            alias = None
        twin = raw_by_name.get(label)
        raw_alias = twin.get("alias", listed_alias) if twin is not None else None
        answers = _dns_answers(row)
        read = (whole and posture_read and host and type(listed_alias) is bool and alias is listed_alias
                and raw_alias is listed_alias and raw_names[label] == norm_names[label] == 1
                and ctx.fanout_ok("google_dns_posture", "posture:" + name, 1)
                and _no_resolver_error(row) and _no_resolver_error(twin)
                and answers == _dns_answers(twin) and None not in answers)
        complete = complete and bool(read)
        domains.append(_project_domain(ctx, row, name, host, alias, bool(read)))
    return _obj(("complete", complete), ("domains", domains))


def _project_domain(ctx: _Context, row: dict[str, Any], name: str, host: str, alias: bool | None,
                    read: bool) -> dict[str, Any]:
    spf, dkim, dmarc = (row.get(part) if isinstance(row.get(part), dict) else {} for part in ("spf", "dkim", "dmarc"))
    selectors = dkim.get("selectors") if isinstance(dkim.get("selectors"), dict) else {}
    inherited, query = dmarc.get("inherited"), dmarc.get("query_name")
    if isinstance(query, str):
        if host and query == "_dmarc." + name:
            query = "_dmarc." + host
        elif host and query.startswith("_dmarc.") and len(query) > 7 and name.endswith("." + query[7:]):
            query = "_dmarc.invalid"
        else:
            query = "unrecognised"
    spf_records, dmarc_records = _strings(spf.get("records")), _strings(dmarc.get("records"))
    dkim_records = {selector: _strings(selectors.get(selector)) for selector in _dkim_selectors()}
    return _obj(
        ("domain", host), ("alias", alias), ("resolver_error", not read),
        ("spf", _obj(("records", None if spf_records is None else [_spf_text(text) for text in spf_records]))),
        ("dkim", _obj(("selectors", {selector: None if answers is None else [
            "v=DKIM1;" if text.startswith("v=DKIM1;") else "unrecognised" for text in answers]
            for selector, answers in dkim_records.items()}))),
        ("dmarc", _obj(("query_name", query if isinstance(query, str) else None),
                       ("inherited", inherited if isinstance(inherited, bool) else None),
                       ("records", None if dmarc_records is None else [_dmarc_text(text, ctx) for text in dmarc_records]))),
    )


def _roles(raw: dict[str, Any] | None) -> dict[str, bool | None]:
    """Role id to whether the role is highly privileged (SG:scubagoggles/provider.py:817-829); None for a role whose
    fields cannot be read."""
    roles: dict[str, bool | None] = {}
    for role in raw["roles"]["value"]:
        key = _role_key(role.get("roleId")) if isinstance(role, dict) else None
        if key is None or not _uninterrupted(role):
            return {}
        # ``isSuperAdminRole`` absent is false, as ScubaGoggles reads it; the privilege list must be read unless the
        # flag or the name already makes the role privileged.
        super_admin, name, privileges = role.get("isSuperAdminRole", False), role.get("roleName"), role.get(
            "rolePrivileges")
        privileges_seen = set()
        if "rolePrivileges" in role:
            if not isinstance(privileges, list):
                return {}
            for privilege in privileges:
                if not isinstance(privilege, dict) or not _ident(privilege.get("privilegeName")):
                    return {}
                service = privilege.get("serviceId")
                if "serviceId" in privilege and not _ident(service):
                    return {}
                identity = service, privilege["privilegeName"]
                if identity in privileges_seen:
                    return {}
                privileges_seen.add(identity)
        verdict: bool | None
        if type(super_admin) is not bool or "roleName" in role and not _label(name):
            verdict = None
        elif super_admin or isinstance(name, str) and name.upper() in _privileged_role_names():
            verdict = True
        elif not isinstance(privileges, list):
            verdict = None
        else:
            verdict = any(name in _privileged_privileges() for _, name in privileges_seen)
        if key in roles:
            return {}
        roles[key] = verdict
    return roles


def _admins(ctx: _Context) -> dict[str, Any]:
    """``complete`` proves the super admin count: the user read whole in both files (the normalised envelope as the
    writer makes it), one normalised row per distinct raw account, every id a readable identity, and each counted flag
    a real boolean in the raw read. The role-dependent inventory (roles, their assignments, delegated-admin flags) is
    separate: when it cannot be read, the privileged list gains one unplaceable entry (``user:unresolved``, no OU), so
    COMMONCONTROLS.6.1 cannot conclude while 6.2 still can."""
    users, users_whole = ctx.records("google_users")
    raw = ctx.directory()
    raw_users: dict[str, dict[str, Any]] = {}
    complete = users_whole and ctx.read_ok(raw, _DIRECTORY, "users")
    for row in raw["users"]["value"] if complete else []:
        user_id = row.get("id") if isinstance(row, dict) else None
        if not _ident(user_id) or user_id in raw_users or not _uninterrupted(row):
            complete = False
            continue
        raw_users[user_id] = row
    people: list[tuple[str, bool, Any]] = []
    emails: dict[str, str] = {}
    known: set[str] = set()
    super_admins, inventory = 0, True
    for row in users:
        user_id, admin, delegated = row.get("id"), row.get("is_admin"), row.get("is_delegated_admin")
        twin = raw_users.get(user_id) if _ident(user_id) else None
        if (not _uninterrupted(row) or row.get("kind") != "google_user" or twin is None
                or user_id in known or type(admin) is not bool
                or type(twin.get("isAdmin")) is not bool or twin["isAdmin"] != admin):
            complete = False  # an unread, blank, repeated or coerced account proves no count
            continue
        known.add(user_id)
        if type(delegated) is not bool or type(twin.get("isDelegatedAdmin")) is not bool \
                or twin["isDelegatedAdmin"] != delegated:
            inventory, delegated = False, False  # a delegated admin may be missed
        super_admins += admin
        path, email = row.get("org_unit_path"), row.get("primary_email")
        if not _ou_path(path) or path != twin.get("orgUnitPath"):
            path = None
        if not isinstance(email, str) or not _scuba_group_email(email) or email != twin.get("primaryEmail"):
            inventory = False
        elif email.lower() in emails:
            inventory = False
        else:
            emails[email.lower()] = user_id
        people.append((user_id, admin or delegated, path))
    if len(people) != len(raw_users):
        complete = False
    assigned = _usable_dependency(lambda: _assigned(ctx, raw), None)
    if assigned is None or assigned - known:
        # An unreadable or misjoined role inventory, or a privileged role held by anything but a user (a group), makes
        # accounts privileged that no user row shows (ScubaGoggles counts user assignees only, provider.py:804-809).
        inventory = False
    by_path = _usable_dependency(ctx.path_index, {})
    member_of, memberships_complete = _usable_dependency(lambda: _memberships(ctx, raw, known, emails), ({}, False))
    privileged = [
        _obj(("user", ctx.user(user_id)),
             # Unplaceable (an unknown or shared path, an unproven unit tree): null, which the SSO kind cannot place.
             ("org_unit", ctx.ou(by_path[path]) if path in by_path else None),
             ("groups", sorted(member_of.get(user_id, ()))))
        for user_id, flagged, path in people if flagged or user_id in (assigned or ())]
    if not inventory:
        privileged.append(_obj(("user", "user:unresolved"), ("org_unit", None), ("groups", [])))
    return _obj(("complete", complete), ("super_admin_count", super_admins), ("privileged", privileged),
                ("memberships_complete", memberships_complete))


def _usable_dependency(read: Callable, fallback: Any) -> Any:
    """A refused dependent read cannot undo independently proven evidence. A scan bound withholds the section."""
    try:
        return read()
    except Unavailable as exc:
        if exc.reason == "oversize":
            raise
        return fallback


def _assignment_key(role: Any, assignee: Any, assignment: Any, scope: Any, unit: Any) -> tuple | None:
    role = _role_key(role)
    if role is None or not _ident(assignee) or not _ident(assignment):
        return None
    if scope not in (None, "CUSTOMER", "ORG_UNIT") or (unit is not None and not _ident(unit)):
        return None
    if (scope == "ORG_UNIT") != (unit is not None):
        return None
    return assignment, role, assignee, scope, unit


def _raw_assignment_key(row: Any) -> tuple | None:
    if not isinstance(row, dict):
        return None
    role, who = row.get("roleId"), row.get("assignedTo")
    return _assignment_key(role, who, row.get("roleAssignmentId", f"{role}:{who}"),
                           row.get("scopeType"), row.get("orgUnitId"))


def _normalised_assignment_key(row: dict) -> tuple | None:
    if row.get("kind") != "google_role_assignment":
        return None
    role, who = row.get("role_id"), row.get("assigned_to")
    return _assignment_key(role, who, row.get("id", f"{role}:{who}"), row.get("scope_type"), row.get("org_unit_id"))


def _assigned(ctx: _Context, raw: dict[str, Any] | None) -> set[str] | None:
    """Prove the role inventory independently of the user count."""
    rows, whole = ctx.records("google_role_assignments", required=False)
    if not (ctx.read_ok(raw, _DIRECTORY, "roles") and ctx.read_ok(raw, _DIRECTORY, "roleAssignments")):
        return None
    assignments = raw["roleAssignments"]["value"]
    if not _rows_agree(rows, whole, assignments, _normalised_assignment_key, _raw_assignment_key):
        return None
    roles = _roles(raw)
    if len(roles) != len(raw["roles"]["value"]) or None in roles.values():
        return None
    assigned, seen = set(), set()
    for item in assignments:
        assignment, role, who, _, _ = _raw_assignment_key(item)
        if assignment in seen or role not in roles:
            return None
        seen.add(assignment)
        if roles[role]:
            assigned.add(who)
    return assigned


def _member_key(group: Any, email: Any, kind: Any, identity: Any) -> tuple | None:
    if (not isinstance(group, str) or not (_scuba_group_email(group) or _bare(group)) or kind != "USER"
            or not _ident(identity)):
        return None
    if email is not None and (not isinstance(email, str) or not _scuba_group_email(email)):
        return None
    return group.lower(), email.lower() if email else None, identity


def _raw_member_key(row: Any) -> tuple | None:
    if not isinstance(row, dict):
        return None
    group, email = row.get("groupEmail"), row.get("email")
    member = row.get("id", email)
    if not _ident(member) or "email" in row and email is None:
        return None
    return _member_key(group, email, row.get("type"), f"{group}:{member}")


def _normalised_member_key(row: dict) -> tuple | None:
    if row.get("kind") != "google_group_member" or "email" in row and row["email"] is None:
        return None
    return _member_key(row.get("group_email"), row.get("email"), row.get("type"), row.get("id"))


def _memberships(ctx: _Context, raw: dict[str, Any] | None, known: set[str],
                 emails: dict[str, str]) -> tuple[dict[str, set[str]], bool]:
    """Prove every direct membership and its identity against both lists and each group's coverage."""
    groups = ctx.group_ids()
    if groups is None or not ctx.read_ok(raw, _DIRECTORY, "groupMembers", direct_count=False):
        return {}, False
    if "groupMembersErrors" in raw and (
            not ctx.has_whole_list(raw, _DIRECTORY, "groupMembersErrors") or raw["groupMembersErrors"]["value"]):
        return {}, False
    errors, errors_whole = ctx.records("google_group_member_errors", required=False)
    if errors or errors is not None and not errors_whole:
        return {}, False
    normalised, whole = ctx.records("google_group_members", required=False)
    members = raw["groupMembers"]["value"]
    if not _rows_agree(normalised, whole, members, _normalised_member_key, _raw_member_key):
        return {}, False
    kept = Counter(member["groupEmail"] for member in members)
    labels = {group["email"]: group["id"] for group in raw["groups"]["value"]}
    if kept.keys() - labels.keys() or any(
            not ctx.fanout_ok(_DIRECTORY, "groupMembers:" + label, kept[label]) for label in labels):
        return {}, False
    coverage, gaps = ctx.coverage(), ctx.gaps()
    expected = {"groupMembers:" + label for label in labels}
    if ({name for collector, name in coverage if collector == _DIRECTORY and name.startswith("groupMembers:")}
            - expected or any(label.startswith("groupMembers:") for label in gaps.get(_DIRECTORY, ()))):
        return {}, False

    member_of: dict[str, set[str]] = {}
    seen: set[tuple[str, str]] = set()
    for member in members:
        group = labels[member["groupEmail"]]
        email = member.get("email")
        by_email = emails.get(email.lower()) if email else None
        user = member.get("id", by_email)
        if user is None or by_email is not None and user != by_email or (group, user) in seen:
            return {}, False
        seen.add((group, user))
        if user in known:
            member_of.setdefault(user, set()).add(ctx.group(group))
    return member_of, True


def _sso_key(org_unit: Any, group: Any, mode: Any) -> tuple | None:
    if not isinstance(mode, str) or mode not in _sso_modes():
        return None
    if (org_unit is None) == (group is None):
        return None
    if isinstance(org_unit, str) and org_unit.startswith("orgUnits/") and _bare(org_unit[9:]):
        return org_unit, None, mode
    if isinstance(group, str) and group.startswith("groups/") and (_bare(group[7:]) or _scuba_group_email(group[7:])):
        return None, group, mode
    return None


def _raw_sso_key(row: Any) -> tuple | None:
    if not isinstance(row, dict) or ("targetOrgUnit" in row) == ("targetGroup" in row):
        return None
    return _sso_key(row.get("targetOrgUnit"), row.get("targetGroup"), row.get("ssoMode"))


def _normalised_sso_key(row: dict) -> tuple | None:
    if ("target_org_unit" in row) == ("target_group" in row):
        return None
    return _sso_key(row.get("target_org_unit"), row.get("target_group"), row.get("sso_mode"))


def _sso(ctx: _Context) -> dict[str, Any]:
    collector = "google_sso_assignments"
    rows, whole = ctx.records(collector)
    data, consistent, state = _split(rows, collector, "google_sso_assignment")
    name = SCUBA_READ_SECTIONS[collector]
    raw = ctx.optional(f"raw/{collector}.json")
    complete = (consistent and whole and state.get("complete") is True and ctx.read_ok(raw, collector, name)
                and _rows_agree(data, True, raw[name]["value"], _normalised_sso_key, _raw_sso_key))
    _, units, topology_complete = ctx.known_tree()
    groups = ctx.group_ids() if any("target_group" in row for row in data) else {}
    assignments, targets = [], set()
    for row in data:
        org_unit, group, mode = row.get("target_org_unit"), row.get("target_group"), row.get("sso_mode")
        if (group is None) == (org_unit is None) or not isinstance(mode, str):
            complete = False
            continue
        target = None
        if isinstance(org_unit, str) and org_unit.startswith("orgUnits/") and _bare(org_unit[9:]):
            unit = "ou:" + org_unit[9:]
            target = ctx.ou(unit)
            complete = complete and topology_complete and unit in units
        elif isinstance(group, str) and group.startswith("groups/"):
            label = group[7:]
            group_id = (groups or {}).get(label, (groups or {}).get(label.lower()))
            if group_id is None and _bare(label):
                group_id = label  # retain the projected target for diagnostics, withhold the verdict
                complete = False
            target = ctx.group(group_id) if group_id else None
        if target is None:
            complete = False
            continue
        complete = complete and target not in targets and mode in _sso_modes()
        targets.add(target)
        assignments.append(_obj(("target", target), ("sso_mode", mode if mode in _sso_modes() else "unrecognised")))
    return _obj(("complete", complete), ("assignments", assignments))


_BUILDERS: dict[str, Callable[[_Context], dict[str, Any]]] = {
    "gws_tenant": _tenant, "gws_policies": _policies, "gws_setting_events": _events, "gws_dns": _dns,
    "gws_admins": _admins, "gws_sso": _sso}


@guarded_operation
def project_gws_run(run_dir: str | Path, *,
                    max_items: int = DEFAULT_MAX_ITEMS, max_chars: int = DEFAULT_MAX_CHARS,
                    scan_max_rows: int = DEFAULT_SCAN_MAX_ROWS, scan_max_bytes: int = DEFAULT_SCAN_MAX_BYTES,
                    scan_max_chunks: int = DEFAULT_SCAN_MAX_CHUNKS) -> GwsProjection:
    """Read a Google Workspace bundle without writes into the six GWS SCuBA rule-input sections.

    The bounds are ``project_run``'s: the scan bounds limit each section's source reads (rows, bytes, chunk files)
    and ``max_items`` and ``max_chars`` budget each projected section; exhausting one withholds the section as
    ``oversize``. A bundle of another platform gives every section the marker with ``not_applicable_to_platform``.
    """
    bounds = {"max_items": max_items, "max_chars": max_chars, "scan_max_rows": scan_max_rows,
              "scan_max_bytes": scan_max_bytes, "scan_max_chunks": scan_max_chunks}
    if any(type(value) is not int or value < 1 for value in bounds.values()):
        raise ValueError("Projection bounds must be positive integers")
    bundle = Bundle(Path(os.path.abspath(run_dir)), scan_max_rows, scan_max_bytes, scan_max_chunks)
    failure: Unavailable | None = None
    manifest: dict[str, Any] = {}
    manifest_sources = []
    try:
        manifest = _read_manifest(bundle)
        manifest_sources = ["run-manifest.json"]
        if manifest.get("platform") != "google_workspace":
            failure = Unavailable("not_applicable_to_platform")
    except Unavailable as exc:
        failure = exc
    result = GwsProjection()
    report: dict[str, dict[str, Any]] = {}
    ctx = None
    if failure is None:
        # Only a Google run's own key is read (never created); refusals of a damaged key propagate.
        ctx = _Context(bundle, _projection_key(run_dir, True), manifest)
    for section in SECTIONS:
        if ctx is not None:
            ctx.begin()
        try:
            if failure is not None or ctx is None:
                raise failure or Unavailable()
            value = _BUILDERS[section](ctx)
            try:
                _json(value).encode()  # a lone surrogate or a non-finite number is not interchange data
            except (ValueError, UnicodeError, TypeError, RecursionError):
                raise Unavailable() from None
            if _oversize(value, max_items, max_chars):
                raise Unavailable("oversize")
        except (Unavailable, ValueError, TypeError, KeyError, OverflowError) as exc:
            result[section] = dict(NOT_COLLECTED)
            reason = getattr(exc, "reason", "incomplete_shape")
            detail = getattr(exc, "detail", {"field": "$", "kind": "unseen_shape"})
            sources = manifest_sources if ctx is None else ["run-manifest.json", *ctx.sources]
            report[section] = {"status": "not_collected", "reason": reason, "source": sources}
            if reason in {"incomplete_shape", "collector_error"} or reason == "oversize" and detail.get("kind") == "scan_bound":
                report[section]["detail"] = detail
        else:
            result[section] = value
            report[section] = {"status": "projected", "reason": None, "source": ["run-manifest.json", *ctx.sources]}
        if ctx is not None and (ctx.rows or ctx.bytes):
            report[section]["scan"] = {"rows": ctx.rows, "bytes": ctx.bytes, "chunks": 0}
    redaction = _obj(("enabled", True), ("strategy", PSEUDONYM_STRATEGY),
                     ("user_ids", len(ctx.users) if ctx else 0), ("group_ids", len(ctx.groups) if ctx else 0),
                     ("email_addresses", ctx.addresses if ctx else 0), ("domain_names", len(ctx.domains) if ctx else 0))
    result.report = {"schema_version": GWS_PROJECTION_VERSION, "sections": report, "redaction": redaction,
                     "bounds": bounds}
    return result
