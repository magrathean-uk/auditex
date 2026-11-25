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
- Redaction is an allow-list. A section holds only fixed vocabulary (event and setting names, values and applications
  the shipped catalogue names, SSO modes, ``unrecognised`` for anything else), keyed pseudonyms of user and group ids
  (``user:<hex>``, ``group:<hex>``, stable within a run and unlinkable across runs), OU ids, counts, times in strict
  RFC 3339 and verdict-relevant DNS text. Policy values must equal their own schema projection
  (``data_minimisation.minimise_policy_value``), else the value is dropped and the entry is unusable. DMARC records are
  rewritten to the tags the rows read, with every reporting address other than CISA's replaced by a placeholder, so the
  engine's contact count and exact CISA check give the same answer; an SPF answer becomes ``v=spf1 -all`` or
  ``v=spf1 ?all`` as GMAIL.3.1 would judge it, and a DKIM answer keeps only its ``v=DKIM1;`` prefix.
  OU names and paths, addresses, the customer id, display names and free text never reach a section.
- Output keys are written as values (``_obj``), never as mapping keys or module constants, so none becomes a product
  field name the shareable redaction keeps (``output_redaction._D5_FIELD_NAMES``, DEC-171).
- ``gws_tenant.as_of`` is the run's collection end. An offline replay is evaluated at an instant the manifest does not
  record (its ``--as-of``), so its ``as_of`` is null and the 2SV kinds answer ``not_assessed``.
"""
from __future__ import annotations

import math
import os
import re
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from azure_tenant_audit.collection_gaps import section_was_cut
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.data_minimisation import (
    finite_policy_number,
    minimise_policy_value,
    policy_is_unrecognised,
    policy_unit_id,
)
from azure_tenant_audit.google_policy_schema import POLICY_VALUE_SCHEMAS
from azure_tenant_audit.guarded_io import guarded_operation
from azure_tenant_audit.output_redaction import PSEUDONYM_STRATEGY, pseudonym
from azure_tenant_audit.value_rules.gws.dns import (
    _WSP,
    _is_dmarc,
    _is_spf,
    _policy,
    _spf_passes,
    _tag_list,
    _uri,
    _uris,
)
from azure_tenant_audit.value_rules.gws.events import _categories, _time

from ..scuba_projection import (
    DEFAULT_SCAN_MAX_BYTES,
    DEFAULT_SCAN_MAX_CHUNKS,
    DEFAULT_SCAN_MAX_ROWS,
    Bundle,
    Unavailable,
    _collector_error,
    _json,
    _oversize,
    _projection_key,
    _require,
    _scan_bound,
)
from .client import SCUBA_ADMIN_EVENTS
from .collectors import (
    POLICY_SECTION_PROBLEMS,
    _event_value_fields,
    _scuba_application_allowed,
    _scuba_group_email,
    policy_problems,
)
from .normalize import _policy_section, _unrecognised_system_alert

GWS_PROJECTION_VERSION = "2026-11-25.2"
SECTIONS = ("gws_tenant", "gws_policies", "gws_setting_events", "gws_dns", "gws_admins", "gws_sso")
# The projected-section budget. These sections are rule input, never prompt text, so the budget is sized to the
# largest read the collectors make (20,000 events for each of 13 event names) rather than to a prompt; the scan
# bounds are ``project_run``'s.
DEFAULT_MAX_ITEMS = 300_000
DEFAULT_MAX_CHARS = 128 * 1024 * 1024
_DIRECTORY = "google_directory"
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
    """The ``InboundSsoAssignment.SsoMode`` values; any other text is passed as ``unrecognised`` (an unknown mode)."""
    return frozenset(("SSO_OFF", "SSO_MODE_UNSPECIFIED", "SAML_SSO", "OIDC_SSO", "DOMAIN_WIDE_SAML_IF_ENABLED"))


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


def _unit_id(value: Any) -> str | None:
    """A Directory ``orgUnitId`` (``id:<id>``) as its bare id; None unless sound."""
    bare = value.removeprefix("id:") if isinstance(value, str) else None
    return bare if _bare(bare) else None


def _strings(value: Any) -> list[str] | None:
    return list(value) if isinstance(value, list) and all(isinstance(item, str) for item in value) else None


def _instant(value: Any) -> str | None:
    """A strict RFC 3339 time as the events kind reads it (``events._time``); anything else is null."""
    return value if isinstance(value, str) and _time(value) is not None else None


def _whole(section: Any) -> bool:
    """A raw list section that is a list, uncut, and carries no error or partial marker."""
    return (isinstance(section, dict) and isinstance(section.get("value"), list) and not section_was_cut(section)
            and not section.get("error") and not section.get("error_class") and not section.get("partial")
            and not section.get("truncation_reason"))


def _row_ok(row: dict[str, Any]) -> bool:
    return (row.get("status") in (None, "ok") and row.get("collection_truncated") is not True
            and not row.get("truncation_reason") and not row.get("partial"))


def _as_of(manifest: dict[str, Any]) -> str | None:
    """The run's collection end: ``created_utc`` plus ``duration_seconds``, in UTC. None when either is unusable, and
    for an offline replay: it is evaluated at its ``--as-of`` or its own clock, which the manifest does not record."""
    if manifest.get("mode") == "offline" or manifest.get("replay_source"):
        return None
    created, duration = manifest.get("created_utc"), manifest.get("duration_seconds")
    if not isinstance(created, str) or isinstance(duration, bool) or not isinstance(duration, (int, float)):
        return None
    try:
        if not math.isfinite(duration) or duration < 0:
            return None
        start = datetime.fromisoformat(created)
        if start.tzinfo is None:
            return None
        end = (start + timedelta(seconds=duration)).astimezone(UTC)
    except (ValueError, OverflowError):
        return None
    return end.isoformat(timespec="microseconds").replace("+00:00", "Z")


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
        self.addresses = 0
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
                return None
            raise

    def records(self, name: str, *, required: bool = True) -> tuple[list[dict[str, Any]] | None, bool]:
        """A normalised section's records and whether its envelope says the list is whole (not cut or partial);
        ``(None, False)`` when an optional one is absent. A wrong envelope withholds."""
        relative = f"normalized/{name}.json"
        data = self.read(relative) if required else self.optional(relative)
        if data is None:
            return None, False
        _require(isinstance(data, dict), kind="invalid_type")
        if data.get("error") or data.get("error_class"):
            raise _collector_error(data)
        _require(data.get("collection_status", "collected") == "collected", "collection_status")
        records = data.get("records")
        _require(isinstance(records, list), "records", "invalid_type")
        _require(all(isinstance(row, dict) for row in records), "records", "invalid_type")
        self.charge(relative, len(records))
        whole = not section_was_cut(data) and not data.get("partial") and not data.get("truncation_reason")
        return records, whole

    def coverage(self) -> list[dict[str, Any]] | None:
        """The coverage rows; None when they cannot be read. The writer leaves the file out only when no row was
        recorded."""
        rows = self.optional("coverage.json")
        if rows is None and "coverage_path" not in self.manifest:
            rows = []
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            return None
        self.charge("coverage.json", len(rows))
        return rows

    def gaps(self) -> list[dict[str, Any]] | None:
        data = self.optional("normalized/collection_gaps.json")
        if data is None:
            return []
        rows = data.get("records") if isinstance(data, dict) else None
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            return None
        self.charge("normalized/collection_gaps.json", len(rows))
        return rows

    def directory(self) -> dict[str, Any] | None:
        raw = self.optional(f"raw/{_DIRECTORY}.json")
        return raw if isinstance(raw, dict) else None

    def read_ok(self, raw: dict[str, Any] | None, collector: str, name: str, *, fanout: bool = False) -> bool:
        """Whether one list read is complete: its raw section is whole, and no coverage row or collection gap of it
        reports a failure or a cut. ``fanout`` covers the per-object reads (``name:<key>``)."""
        section = raw.get(name) if isinstance(raw, dict) else None
        if not _whole(section):
            return False
        self.charge(f"raw:{collector}:{name}", len(section["value"]))
        coverage, gaps = self.coverage(), self.gaps()
        if coverage is None or gaps is None:
            return False

        def about(row: Any, field: str) -> bool:
            label = row.get(field) if isinstance(row, dict) else None
            return isinstance(label, str) and (label == name or fanout and label.startswith(name + ":"))

        if any(row.get("collector") == collector and about(row, "name") and not _row_ok(row) for row in coverage):
            return False
        return not any(row.get("collector") == collector and about(row, "list") for row in gaps)

    def fanout_ok(self, collector: str, name: str) -> bool:
        """Positive evidence that one per-object read ran and finished: a coverage row of that exact name, all ok."""
        rows = [row for row in self.coverage() or [] if row.get("collector") == collector and row.get("name") == name]
        return bool(rows) and all(_row_ok(row) and row.get("status") == "ok" for row in rows)

    def tree(self) -> tuple[str | None, dict[str, str | None], bool]:
        """The top unit, the ``ou:<id>`` parent map and whether the topology is complete and sound: one root, every
        unit's chain reaching it with no dangling parent or cycle (as ``value_rules.gws.reduce._topology`` checks)."""
        rows, whole = self.records("google_org_units")
        units, consistent, state = _split(rows or [], "google_org_units", "google_org_unit")
        complete = consistent and whole and state.get("complete") is True and state.get("root_id_known") is True
        org_units: dict[str, str | None] = {}
        roots: list[str] = []
        for row in units:
            unit, parent, root = row.get("id"), row.get("parent_id"), row.get("is_root")
            if (not _bare(unit) or "ou:" + unit in org_units or type(root) is not bool
                    or (parent is not None if root else not _bare(parent))):
                complete = False
                continue
            org_units["ou:" + unit] = None if root else "ou:" + parent
            if root:
                roots.append("ou:" + unit)
        top = roots[0] if len(roots) == 1 else None
        if top is None or not _sound(org_units, top):
            complete = False
        return top, org_units, complete

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
        """Lower-case address and id to group id, from a whole Directory group list; None when it is not whole."""
        raw = self.directory()
        if not self.read_ok(raw, _DIRECTORY, "groups"):
            return None
        index: dict[str, str] = {}
        for group in raw["groups"]["value"]:
            group_id, email = (group.get("id"), group.get("email")) if isinstance(group, dict) else (None, None)
            if not _bare(group_id) or group_id in index:
                return None
            index[group_id] = group_id
            if isinstance(email, str) and email:
                if email.lower() in index:
                    return None
                index[email.lower()] = group_id
        return index

    def path_index(self) -> dict[str, str | None]:
        """Org unit path to ``ou:<id>`` from the raw Directory list (``None``: two units share it), checked against
        the complete normalised topology; empty when either cannot be trusted. An older read lists no root row: its
        root is the parent of the top-level units (``parentOrgUnitPath`` ``/``), as the normaliser infers it."""
        top, org_units, complete = self.known_tree()
        raw = self.directory()
        if not complete or top is None or not self.read_ok(raw, _DIRECTORY, "orgUnits"):
            return {}
        by_path: dict[str, str | None] = {}
        inferred: set[str | None] = set()
        for row in raw["orgUnits"]["value"]:
            unit = _unit_id(row.get("orgUnitId")) if isinstance(row, dict) else None
            path = row.get("orgUnitPath") if isinstance(row, dict) else None
            if unit is None or "ou:" + unit not in org_units or not isinstance(path, str) or not path.startswith("/"):
                return {}
            by_path[path] = None if path in by_path else "ou:" + unit
            if path != "/" and row.get("parentOrgUnitPath") == "/":
                inferred.add(_unit_id(row.get("parentOrgUnitId")))
        if "/" in by_path:
            return by_path if by_path["/"] == top and inferred <= {top[3:]} else {}
        if inferred != {top[3:]}:
            return {}
        by_path["/"] = top
        return by_path

    def user(self, user_id: str) -> str:
        self.users.add(user_id)
        return "user:" + pseudonym(self.key, "user:" + user_id)

    def group(self, group_id: str) -> str:
        self.groups.add("group:" + group_id)
        return "group:" + pseudonym(self.key, "group:" + group_id)

    def group_address(self, address: str) -> str:
        """A group the Directory list does not hold, known only by its address (events of a deleted group)."""
        self.groups.add("group-email:" + address.lower())
        return "group:" + pseudonym(self.key, "group-email:" + address.lower())


def _sound(org_units: dict[str, str | None], top: str) -> bool:
    for start in org_units:
        seen, unit = set(), start
        while unit != top:
            if unit in seen or unit not in org_units or org_units[unit] is None:
                return False
            seen.add(unit)
            unit = org_units[unit]
    return True


def _split(records: list[dict[str, Any]], section: str, kind: str) -> tuple[list[dict[str, Any]], bool, dict]:
    """The data records, whether there is exactly one read-state record and it counts them, and the state."""
    data = [row for row in records if row.get("kind") == kind]
    states = [row for row in records if row.get("kind") == f"{section}_read_state"]
    state = states[0] if len(states) == 1 else {}
    count = state.get("record_count")
    consistent = len(states) == 1 and len(data) + 1 == len(records) and type(count) is int and count == len(data)
    return data, consistent, state


# --- sections ----------------------------------------------------------------------------------------------------


def _tenant(ctx: _Context) -> dict[str, Any]:
    top, org_units, complete = ctx.tree()
    _require(top is not None, "top_unit", "missing_field")
    return _obj(("as_of", ctx.as_of), ("top_unit", top), ("org_units", org_units), ("complete", complete))


def _attributed(ctx: _Context, state: dict[str, Any]) -> list[tuple[str, str | None, str | None]] | None:
    """The (section, org unit, group) failures the normaliser attributed (``unusable_sections``: every unit), when
    they are the only reason the read is not complete: the Policy API read itself whole, and every unreadable row
    attributed to its section. None otherwise."""
    sections, scopes, types = state.get("unusable_sections"), state.get("unusable_scopes"), _section_types()
    if not isinstance(sections, list) or not isinstance(scopes, list) or not (sections or scopes):
        return None
    found: list[tuple[str, str | None, str | None]] = []
    for section in sections:
        if section not in types:
            return None
        found.append((section, None, None))
    for scope in scopes:
        section = scope.get("section") if isinstance(scope, dict) else None
        org_unit, group = (scope.get("org_unit"), scope.get("group")) if isinstance(scope, dict) else (None, None)
        if section not in types or not (org_unit is None or _bare(org_unit)) or not (group is None or _bare(group)):
            return None
        found.append((section, org_unit, group))
    raw = ctx.optional("raw/google_policies.json")
    section = raw.get("policySettings") if isinstance(raw, dict) else None
    if not _whole(section) or not section["value"]:
        return None
    ctx.charge("raw:google_policies:policySettings", len(section["value"]))
    coverage, gaps = ctx.coverage(), ctx.gaps()
    if coverage is None or gaps is None or any(row.get("collector") == "google_policies" for row in gaps):
        return None
    for row in coverage:
        # A row validation failure is the attributed one; any other failed or cut row may hide any setting.
        if row.get("collector") == "google_policies" and not (
                _row_ok(row) or row.get("policy_row_validation") is True
                and row.get("collection_truncated") is not True and not row.get("truncation_reason")):
            return None
    for item in section["value"]:
        if policy_is_unrecognised(item):
            continue
        problems = set(policy_problems(item))
        setting = item.get("setting") if isinstance(item, dict) else None
        if not problems and _unrecognised_system_alert(setting):
            continue
        if problems & POLICY_SECTION_PROBLEMS or not isinstance(setting, dict) or _policy_section(
                setting.get("type")) is None:
            return None  # a policy whose section cannot be told may be any rule's
    return found


def _policies(ctx: _Context) -> dict[str, Any]:
    rows, whole = ctx.records("google_policy_settings")
    data, consistent, state = _split(rows or [], "google_policy_settings", "google_policy_setting")
    top = ctx.known_tree()[0]  # without a unit tree a group-only policy cannot be placed
    types = _section_types()
    complete = consistent and whole
    failures = None
    if complete and state.get("complete") is not True:
        failures = _attributed(ctx, state)
        complete = failures is not None
    policies, units = [], {}
    for row in data:
        org_unit, group, kind, section = row.get("org_unit"), row.get("group"), row.get("unit_kind"), row.get("section")
        if group is not None and org_unit is None:
            org_unit = top[3:] if top else None  # a group-only policy applies under the top unit (policy_api.py:804-825)
        if (not _bare(org_unit) or group is not None and not _bare(group) or section not in types
                or kind != ("group" if group is not None else "org_unit")):
            complete = False  # a policy that cannot be placed is left out; the read is no longer the whole
            continue
        unit = f"ou:{org_unit}/{ctx.group(group)}" if group is not None else f"ou:{org_unit}"
        units.setdefault(section, set()).add((unit, kind))
        rank = row.get("sort_order")
        entry = _obj(("unit", unit), ("unit_kind", kind), ("section", section),
                     ("sort_order", rank if finite_policy_number(rank) else None))
        value = row.get("value")
        # Only a value equal to its own schema projection is passed; anything else leaves the entry unusable.
        if "value" in row and minimise_policy_value(types[section], value) == value:
            entry.update(_obj(("value", deepcopy(value))))
        policies.append(entry)
    for section, org_unit, group in failures or ():
        # The engine's own unknown: an entry with no value makes that (unit, section) UNUSABLE in the reducer.
        base = org_unit or (top[3:] if top else None)
        if base is None:
            complete = False
            continue
        if org_unit is None and group is None:
            targets = {*units.get(section, ()), (top, "org_unit")}
        else:
            targets = {(f"ou:{base}/{ctx.group(group)}" if group else f"ou:{base}", "group" if group else "org_unit")}
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


def _events(ctx: _Context) -> dict[str, Any]:
    rows, whole = ctx.records("google_setting_events")
    data, consistent, state = _split(rows or [], "google_setting_events", "google_setting_event")
    complete = consistent and whole and state.get("complete") is True
    org_units = ctx.known_tree()[1]  # without a unit tree no OU event can be placed
    groups: dict[str, str] = {}
    if any("group_email" in row for row in data):
        try:
            groups = ctx.group_ids() or {}
        except Unavailable as exc:
            if exc.reason == "oversize":
                raise
            # An unreadable group list leaves group events on their address pseudonym; the events still stand.
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
            unit = "ou:" + org_unit
        told = _event_fields(row, fields)
        name, setting, value, application = told if told else ("", None, None, None)
        events.append(_obj(("time", _instant(row.get("event_time"))), ("event", name), ("setting", setting),
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
            out.append("reports@dmarc.cyber.dhs.gov")
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


def _dns(ctx: _Context) -> dict[str, Any]:
    records, whole = ctx.records("google_dns_posture")
    data = [row for row in records if row.get("kind") == "google_domain_posture"]
    states = [row for row in records if row.get("kind") != "google_domain_posture"]

    def new_shape(row: dict[str, Any]) -> bool:
        return "alias" in row or isinstance(row.get("dmarc"), dict) and "query_name" in row["dmarc"]

    # A bundle collected before the DMARC tree walk and the selector map has none of their fields: not collected.
    _require(not data or any(new_shape(row) for row in data), "dmarc.query_name", "missing_field")
    # The posture read itself must be whole, whether or not the normaliser wrote a read-state record.
    raw = ctx.optional("raw/google_dns_posture.json")
    complete = (whole and ctx.read_ok(raw, "google_dns_posture", "domains")
                and ctx.read_ok(raw, "google_dns_posture", "domainPosture")
                and len(raw["domainPosture"]["value"]) == len(data))
    if states:
        _, consistent, state = _split(records, "google_dns_posture", "google_domain_posture")
        complete = complete and consistent and state.get("complete") is True
    kinds: dict[str, Any] = {}
    for row in ctx.records("google_domains", required=False)[0] or []:
        if isinstance(row.get("domain_name"), str):
            name = row["domain_name"].lower()
            kinds[name] = row.get("domain_kind") if name not in kinds else None
    domains, seen = [], set()
    for row in data:
        name = row.get("domain")
        if not isinstance(name, str) or not name:
            complete = False
            continue
        if name.lower() in seen:
            complete = False  # one domain read twice may disagree with itself
        seen.add(name.lower())
        host = name if _DOMAIN.fullmatch(name) else ""  # blank: the kind holds the entry unusable
        kind = kinds.get(name.lower())
        listed = (kind == "alias") if kind in ("alias", "primary", "secondary") else None
        alias = row.get("alias") if "alias" in row else listed
        if not isinstance(alias, bool) or listed is not None and alias != listed:
            alias = None  # malformed or contradicting the Directory domain kind: the domain's scope is unknown
        error = row.get("resolver_error")
        spf, dkim, dmarc = (row.get(part) if isinstance(row.get(part), dict) else {} for part in ("spf", "dkim", "dmarc"))
        selectors = dkim.get("selectors") if isinstance(dkim.get("selectors"), dict) else {}
        inherited, query = dmarc.get("inherited"), dmarc.get("query_name")
        if isinstance(query, str) and not (query == "_dmarc." + host or query.startswith("_dmarc.") and len(query) > 7
                                            and host.endswith("." + query[7:])):
            query = "unrecognised"  # neither the domain's own nor a parent's name: the kind holds it unusable
        spf_records, dmarc_records = _strings(spf.get("records")), _strings(dmarc.get("records"))
        dkim_records = {selector: _strings(selectors.get(selector)) for selector in _dkim_selectors()}

        domains.append(_obj(
            ("domain", host), ("alias", alias),
            # Only the fact of a resolver failure is kept, never its message (a resolver URL or local detail).
            ("resolver_error", not (error is None or error is False)),
            # An SPF answer becomes what GMAIL.3.1 reads of it (``dns._is_spf``, ``dns._spf_passes``).
            ("spf", _obj(("records", None if spf_records is None else [
                ("v=spf1 -all" if _spf_passes(text) else "v=spf1 ?all") if _is_spf(text) else "unrecognised"
                for text in spf_records]))),
            ("dkim", _obj(("selectors", {selector: None if answers is None else [
                "v=DKIM1;" if text.startswith("v=DKIM1;") else "unrecognised" for text in answers]
                for selector, answers in dkim_records.items()}))),
            ("dmarc", _obj(("query_name", query if isinstance(query, str) else None),
                           ("inherited", inherited if isinstance(inherited, bool) else None),
                           ("records", None if dmarc_records is None else [
                               _dmarc_text(text, ctx) for text in dmarc_records]))),
        ))
    return _obj(("complete", complete), ("domains", domains))


def _roles(raw: dict[str, Any] | None) -> dict[str, bool | None]:
    """Role id to whether the role is highly privileged (SG:scubagoggles/provider.py:817-829); None for a role whose
    fields cannot be read."""
    roles: dict[str, bool | None] = {}
    for role in raw["roles"]["value"]:
        role_id = role.get("roleId") if isinstance(role, dict) else None
        if not isinstance(role_id, (str, int)) or isinstance(role_id, bool) or str(role_id) == "":
            continue
        # ``isSuperAdminRole`` absent is false, as ScubaGoggles reads it; the privilege list must be read unless the
        # flag or the name already makes the role privileged.
        super_admin, name, privileges = role.get("isSuperAdminRole", False), role.get("roleName"), role.get(
            "rolePrivileges")
        verdict: bool | None
        if type(super_admin) is not bool or name is not None and not isinstance(name, str):
            verdict = None
        elif super_admin or isinstance(name, str) and name.upper() in _privileged_role_names():
            verdict = True
        elif not isinstance(privileges, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("privilegeName"), str) for item in privileges):
            verdict = None
        else:
            verdict = any(item["privilegeName"] in _privileged_privileges() for item in privileges)
        key = str(role_id)
        roles[key] = verdict if key not in roles or roles[key] == verdict else None
    return roles


def _admins(ctx: _Context) -> dict[str, Any]:
    """``complete`` proves the super admin count: the user read whole in both files, one normalised row per distinct
    raw account, and each counted flag a real boolean in the raw read. The role-dependent inventory (roles, their
    assignments, delegated-admin flags) is separate: when it cannot be read, the privileged list gains one
    unplaceable entry (``user:unresolved``, no OU), so COMMONCONTROLS.6.1 cannot conclude while 6.2 still can."""
    users, users_whole = ctx.records("google_users")
    raw = ctx.directory()
    raw_users: dict[str, dict[str, Any]] = {}
    complete = users_whole and ctx.read_ok(raw, _DIRECTORY, "users")
    for row in raw["users"]["value"] if complete else []:
        user_id = row.get("id") if isinstance(row, dict) else None
        if not isinstance(user_id, str) or not user_id or user_id in raw_users:
            complete = False
            continue
        raw_users[user_id] = row
    people: list[tuple[str, bool, Any]] = []
    known: set[str] = set()
    super_admins, inventory = 0, True
    for row in users:
        user_id, admin, delegated = row.get("id"), row.get("is_admin"), row.get("is_delegated_admin")
        twin = raw_users.get(user_id) if isinstance(user_id, str) else None
        if (twin is None or user_id in known or type(admin) is not bool
                or type(twin.get("isAdmin")) is not bool or twin["isAdmin"] != admin):
            complete = False  # an unread, repeated or coerced account proves no count
            continue
        known.add(user_id)
        if type(delegated) is not bool or type(twin.get("isDelegatedAdmin")) is not bool \
                or twin["isDelegatedAdmin"] != delegated:
            inventory, delegated = False, False  # a delegated admin may be missed
        super_admins += admin
        people.append((user_id, admin or delegated, row.get("org_unit_path")))
    if len(people) != len(raw_users):
        complete = False
    assignments, assignments_whole = ctx.records("google_role_assignments", required=False)
    roles_read = ctx.read_ok(raw, _DIRECTORY, "roles")
    if not (roles_read and ctx.read_ok(raw, _DIRECTORY, "roleAssignments")
            and (assignments is not None and assignments_whole or not raw["roleAssignments"]["value"])
            and len(raw["roleAssignments"]["value"]) == len(assignments or [])):
        inventory = False
    roles = _roles(raw) if roles_read else {}
    assigned: set[str] = set()
    for row in assignments or []:
        role_id, assignee = row.get("role_id"), row.get("assigned_to")
        verdict = roles.get(str(role_id)) if isinstance(role_id, (str, int)) and not isinstance(role_id, bool) else None
        if not isinstance(assignee, str) or not assignee or verdict is None:
            inventory = False  # an assignment to a role that cannot be read may make its holder privileged
        elif verdict:
            assigned.add(assignee)
    # ScubaGoggles counts user assignees only (provider.py:804-809). A privileged role held by anything else (a group)
    # makes accounts privileged that no user row shows, so the privileged list is not the whole.
    if assigned - known:
        inventory = False
    by_path = ctx.path_index()
    member_of, memberships_complete = _memberships(ctx, raw, known, users)
    privileged = [
        _obj(("user", ctx.user(user_id)),
             # Unplaceable (an unknown or shared path, an unproven unit tree): null, which the SSO kind cannot place.
             ("org_unit", by_path.get(path) if isinstance(path, str) else None),
             ("groups", sorted(member_of.get(user_id, ()))))
        for user_id, flagged, path in people if flagged or user_id in assigned]
    if not inventory:
        privileged.append(_obj(("user", "user:unresolved"), ("org_unit", None), ("groups", [])))
    return _obj(("complete", complete), ("super_admin_count", super_admins), ("privileged", privileged),
                ("memberships_complete", memberships_complete))


def _memberships(ctx: _Context, raw: dict[str, Any] | None, known: set[str],
                 users: list[dict[str, Any]]) -> tuple[dict[str, set[str]], bool]:
    """User id to the pseudonyms of the groups it is a direct member of, and whether that is every membership: the
    group and member lists whole, a finished member read for every group, no member error, and every member a user
    resolved by its stable id (else by its address). A member the tenant's user list does not hold is not one of its
    admins."""
    groups = ctx.group_ids()
    complete = (groups is not None and ctx.read_ok(raw, _DIRECTORY, "groupMembers", fanout=True)
                and _whole(raw.get("groupMembersErrors", {"value": []})) and not raw.get(
                    "groupMembersErrors", {"value": []})["value"])
    errors, _ = ctx.records("google_group_member_errors", required=False)
    complete = complete and not errors
    if not complete:
        return {}, False
    for group in raw["groups"]["value"]:
        if not ctx.fanout_ok(_DIRECTORY, "groupMembers:" + str(group.get("email") or group.get("id"))):
            complete = False  # no proof that this group's members were read
    emails: dict[str, str | None] = {}
    for row in users:
        email, user_id = row.get("primary_email"), row.get("id")
        if isinstance(email, str) and email and user_id in known:
            emails[email.lower()] = None if email.lower() in emails else user_id
    member_of: dict[str, set[str]] = {}
    for member in raw["groupMembers"]["value"]:
        if not isinstance(member, dict):
            complete = False
            continue
        group_email, member_id, email = member.get("groupEmail"), member.get("id"), member.get("email")
        group_id = groups.get(group_email.lower()) if isinstance(group_email, str) else None
        # A nested group or an all-users (CUSTOMER) member makes members no user row lists: not resolved here.
        if group_id is None or member.get("type") != "USER":
            complete = False
            continue
        if isinstance(member_id, str) and member_id:
            user_id = member_id if member_id in known else None
        else:
            user_id = emails.get(email.lower()) if isinstance(email, str) else None
            if user_id is None:
                complete = False  # a member known only by an address no single account holds
                continue
        if user_id is not None:
            member_of.setdefault(user_id, set()).add(ctx.group(group_id))
    return member_of, complete


def _sso(ctx: _Context) -> dict[str, Any]:
    rows, whole = ctx.records("google_sso_assignments")
    data, consistent, state = _split(rows or [], "google_sso_assignments", "google_sso_assignment")
    complete = consistent and whole and state.get("complete") is True
    groups: dict[str, str] | None = None
    assignments = []
    for row in data:
        org_unit, group, mode = row.get("target_org_unit"), row.get("target_group"), row.get("sso_mode")
        if (group is None) == (org_unit is None) or not isinstance(mode, str):
            complete = False
            continue
        target = None
        if isinstance(org_unit, str) and org_unit.startswith("orgUnits/") and _bare(org_unit[9:]):
            target = "ou:" + org_unit[9:]
        elif isinstance(group, str) and group.startswith("groups/"):
            if _bare(group[7:]):
                target = ctx.group(group[7:])
            else:
                if groups is None:
                    groups = ctx.group_ids() or {}
                group_id = groups.get(group[7:].lower())
                target = ctx.group(group_id) if group_id else None
        if target is None:
            complete = False
            continue
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
    try:
        manifest = bundle.read("run-manifest.json")
        _require(isinstance(manifest, dict), kind="invalid_type")
        if manifest.get("platform") != "google_workspace":
            failure = Unavailable("not_applicable_to_platform")
    except Unavailable as exc:
        failure = exc
    manifest_sources = list(bundle.sources)
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
                     ("email_addresses", ctx.addresses if ctx else 0))
    result.report = {"schema_version": GWS_PROJECTION_VERSION, "sections": report, "redaction": redaction,
                     "bounds": bounds}
    return result
