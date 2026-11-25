"""Read-only, bounded, redacted projection of a Google Workspace bundle into the GWS SCuBA rule inputs (design M13 7).

``project_gws_run(run_dir)`` returns the six sections every ``value_rules.gws`` kind reads (``gws_tenant``,
``gws_policies``, ``gws_setting_events``, ``gws_dns``, ``gws_admins``, ``gws_sso``) plus ``.report`` (status, reason
and source files per section, the redaction counts and the bounds), as :func:`auditex.scuba_projection.project_run`
does for Microsoft 365.

- Every file is read through the same guarded run-file reader and scan bounds as ``project_run`` (``Bundle.read``):
  regular files beneath the run folder only, parsed with duplicate keys, non-finite numbers and deep nesting refused.
  Nothing is written and no network is used; the run's pseudonym key is only read (a keyless run uses its temporary
  session key).
- The projection reshapes, bounds and redacts. It reduces nothing, applies no default and compares no value with a
  baseline: the verdict logic stays in the engine (design 7).
- Unknown is not safe (design 8.4). A source that was not collected, cannot be read or has the wrong envelope makes
  the section the ``not_collected`` marker. A record that cannot be reshaped (a target that cannot be placed, a field
  of the wrong type) is left out and the section's ``complete`` is false, so no rule reads the remainder as the whole.
  A record field the kinds type-check themselves (a time, a value, a DNS record list) is passed on, or as null when it
  has the wrong type, and the kind answers ``not_assessed`` for it.
- Redaction: user and group ids become keyed pseudonyms (``user:<hex>``, ``group:<hex>``) under the run's key, so they
  are stable within a run and unlinkable across runs; OU ids stay, OU names and paths, addresses, the customer id and
  display names never reach a section. An address left in a setting or event string is masked to ``***@<domain>``.
  Public DNS text in ``gws_dns`` is kept verbatim, as the Microsoft 365 DNS rule sections keep it: GMAIL 4.3 and 4.4
  read the DMARC reporting addresses.
- Sources beyond the normalised sections: the Directory roles (``isSuperAdminRole``, ``rolePrivileges``) and the org
  unit paths and names are not normalised, so they come from ``raw/google_directory.json``; read completeness comes
  from ``coverage.json`` and ``normalized/collection_gaps.json``, as the normaliser judges it.
"""
from __future__ import annotations

import math
import os
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from azure_tenant_audit.collection_gaps import section_was_cut
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.data_minimisation import policy_unit_id
from azure_tenant_audit.guarded_io import guarded_operation
from azure_tenant_audit.output_redaction import PSEUDONYM_STRATEGY, pseudonym

from ..scuba_projection import (
    _EMAIL,
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

GWS_PROJECTION_VERSION = "2026-11-25"
SECTIONS = ("gws_tenant", "gws_policies", "gws_setting_events", "gws_dns", "gws_admins", "gws_sso")
# The projected-section budget. These sections are rule input, never prompt text, so the budget is sized to the
# largest read the collectors make (20,000 events for each of 13 event names) rather than to a prompt; the scan
# bounds are ``project_run``'s.
DEFAULT_MAX_ITEMS = 300_000
DEFAULT_MAX_CHARS = 128 * 1024 * 1024
_DIRECTORY = "google_directory"


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


def _bare(value: Any) -> bool:
    """An OU or group id as the normaliser admits one (``policy_unit_id``: never a customer-id-shaped string); a
    subset of the unit grammar ``value_rules.gws.reduce`` accepts."""
    return policy_unit_id(value)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _strings(value: Any) -> list[str] | None:
    return list(value) if isinstance(value, list) and all(isinstance(item, str) for item in value) else None


def _as_of(manifest: dict[str, Any]) -> str | None:
    """The run's collection end: ``created_utc`` plus ``duration_seconds``, in UTC; None when either is unusable."""
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
    """One run's reads. A file is read once and listed as a source of every section that uses it."""

    def __init__(self, bundle: Bundle, key: bytes, manifest: dict[str, Any]):
        self.bundle, self.key, self.manifest, self.as_of = bundle, key, manifest, _as_of(manifest)
        self.cache: dict[str, tuple[Any, int, Unavailable | None]] = {}
        self.users: set[str] = set()
        self.groups: set[str] = set()
        self._index: tuple[dict[str, str | None], dict[str, str | None], bool] | None = None
        self.begin()

    def begin(self) -> None:
        self.sources: list[str] = []
        self.rows = 0
        self.bytes = 0

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

    def records(self, name: str, *, required: bool = True) -> list[dict[str, Any]] | None:
        """A normalised section's records; None when an optional one is absent. A wrong envelope withholds."""
        relative = f"normalized/{name}.json"
        fresh = relative not in self.sources
        data = self.read(relative) if required else self.optional(relative)
        if data is None:
            return None
        _require(isinstance(data, dict), kind="invalid_type")
        if data.get("error") or data.get("error_class"):
            raise _collector_error(data)
        _require(data.get("collection_status", "collected") == "collected", "collection_status")
        records = data.get("records")
        _require(isinstance(records, list), "records", "invalid_type")
        _require(all(isinstance(row, dict) for row in records), "records", "invalid_type")
        self.rows += len(records) if fresh else 0
        if self.rows > self.bundle.scan_max_rows:
            raise _scan_bound("scan_max_rows")
        return records

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

    # --- shared Directory evidence ---------------------------------------------------------------------------------

    def directory(self) -> dict[str, Any] | None:
        raw = self.optional(f"raw/{_DIRECTORY}.json")
        return raw if isinstance(raw, dict) else None

    def read_ok(self, raw: dict[str, Any] | None, collector: str, name: str, *, fanout: bool = False) -> bool:
        """Whether one list read is complete: its raw section is an uncut list with no error, and no coverage row or
        collection gap of it reports a failure or a cut. ``fanout`` covers the per-object reads (``name:<key>``)."""
        section = raw.get(name) if isinstance(raw, dict) else None
        if (not isinstance(section, dict) or not isinstance(section.get("value"), list) or section_was_cut(section)
                or section.get("error") or section.get("error_class")):
            return False
        coverage = self.optional("coverage.json")
        if coverage is None and "coverage_path" not in self.manifest:
            coverage = []  # the writer leaves the file out only when no coverage row was recorded
        gaps = self.optional("normalized/collection_gaps.json")
        if not isinstance(coverage, list) or gaps is not None and not (
                isinstance(gaps, dict) and isinstance(gaps.get("records"), list)):
            return False

        def about(row: Any, field: str) -> bool:
            label = row.get(field) if isinstance(row, dict) else None
            return isinstance(label, str) and (label == name or fanout and label.startswith(name + ":"))

        for row in coverage:
            if not isinstance(row, dict):
                return False
            if row.get("collector") == collector and about(row, "name") and (
                    row.get("status") not in (None, "ok") or row.get("collection_truncated") is True
                    or row.get("truncation_reason") or row.get("partial")):
                return False
        return not any(isinstance(row, dict) and row.get("collector") == collector and about(row, "list")
                       for row in (gaps or {}).get("records", []))

    def ou_index(self) -> tuple[dict[str, str | None], dict[str, str | None], bool]:
        """Org unit path and name to ``ou:<id>`` from the raw Directory list (``None``: two units share it), and
        whether the list is complete with one root at ``/``. Paths and names stay here; no section carries them."""
        if self._index is None:
            raw = self.directory()
            by_path: dict[str, str | None] = {}
            by_name: dict[str, str | None] = {}
            ok = self.read_ok(raw, _DIRECTORY, "orgUnits")
            roots = 0
            for row in raw["orgUnits"]["value"] if ok else []:
                unit = row.get("orgUnitId") if isinstance(row, dict) else None
                unit = unit.removeprefix("id:") if isinstance(unit, str) else None
                path, name = (row.get("orgUnitPath"), row.get("name")) if isinstance(row, dict) else (None, None)
                if not _bare(unit) or not isinstance(path, str) or not isinstance(name, str):
                    ok = False
                    continue
                roots += path == "/"
                for index, label in ((by_path, path), (by_name, name)):
                    index[label] = None if label in index else "ou:" + unit
            self._index = (by_path, by_name, ok and roots == 1)
        return self._index

    def ou_by_name(self, name: Any) -> str | None:
        """An event's ``ORG_UNIT_NAME`` as its unit; None (an event the kind treats as ambiguous) for a name two units
        share, an incomplete unit list, or a name no current unit holds. ScubaGoggles drops the last as a deleted unit
        (``FilterEventsOU``, SG:scubagoggles/rego/Utils.rego:423-438), but a renamed unit's events carry its old name
        too, so the name is unknown, not proof that the unit is gone."""
        _, by_name, ok = self.ou_index()
        return by_name.get(name) if isinstance(name, str) and name and ok else None

    def group_index(self) -> tuple[dict[str, str], bool]:
        """Group email (lower case) or id to group id, and whether the group memberships were read in full."""
        raw = self.directory()
        groups = self.records("google_groups", required=False) or []
        members = self.records("google_group_members", required=False) or []
        errors = self.records("google_group_member_errors", required=False) or []
        ok = (self.read_ok(raw, _DIRECTORY, "groups") and self.read_ok(raw, _DIRECTORY, "groupMembers", fanout=True)
              and not errors and len(raw["groups"]["value"]) == len(groups)
              and len(raw["groupMembers"]["value"]) == len(members))
        by_key: dict[str, str] = {}
        for group in groups:
            group_id, email = group.get("id"), group.get("email")
            if not _bare(group_id):
                ok = False
                continue
            by_key[group_id] = group_id
            if isinstance(email, str) and email:
                by_key[email.lower()] = group_id
        return by_key, ok


# --- sections ----------------------------------------------------------------------------------------------------


def _group_id(groups: dict[str, str], value: Any) -> str | None:
    """A group named by its id or its address (any case), as the Directory group list holds it."""
    if not isinstance(value, str) or not value:
        return None
    return groups.get(value, groups.get(value.lower()))


def _split(records: list[dict[str, Any]], section: str, kind: str) -> tuple[list[dict[str, Any]], bool, dict]:
    """The data records, whether the one read-state record says the read is complete and counts them, and the state."""
    data = [row for row in records if row.get("kind") == kind]
    states = [row for row in records if row.get("kind") == f"{section}_read_state"]
    state = states[0] if len(states) == 1 else {}
    count = state.get("record_count")
    complete = (len(states) == 1 and len(data) + 1 == len(records) and state.get("complete") is True
                and type(count) is int and count == len(data))
    return data, complete, state


def _tenant(ctx: _Context) -> dict[str, Any]:
    units, complete, state = _split(ctx.records("google_org_units"), "google_org_units", "google_org_unit")
    complete = complete and state.get("root_id_known") is True
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
    _require(len(roots) == 1, "top_unit", "missing_field")
    return {"as_of": ctx.as_of, "top_unit": roots[0], "org_units": org_units, "complete": complete}


def _policies(ctx: _Context) -> dict[str, Any]:
    data, complete, _ = _split(ctx.records("google_policy_settings"), "google_policy_settings", "google_policy_setting")
    policies = []
    for row in data:
        org_unit, group, kind, section = row.get("org_unit"), row.get("group"), row.get("unit_kind"), row.get("section")
        if (not _bare(org_unit) or group is not None and not _bare(group)
                or kind != ("group" if group is not None else "org_unit") or not isinstance(section, str) or not section):
            complete = False  # a policy that cannot be placed is left out; the read is no longer the whole
            continue
        unit = f"ou:{org_unit}/{ctx.group(group)}" if group is not None else f"ou:{org_unit}"
        entry = {"unit": unit, "unit_kind": kind, "section": section, "sort_order": row.get("sort_order")}
        if "value" in row:
            entry["value"] = deepcopy(row["value"])
        policies.append(entry)
    return {"complete": complete, "policies": policies}


def _events(ctx: _Context) -> dict[str, Any]:
    data, complete, state = _split(ctx.records("google_setting_events"), "google_setting_events", "google_setting_event")
    groups: dict[str, str] = {}
    if any(row.get("group_email") is not None for row in data):
        try:
            groups, _ = ctx.group_index()
        except Unavailable:
            pass  # unreadable group lists leave group events on their address pseudonym; the events still stand
    events = []
    for row in data:
        name = row.get("event")
        if not isinstance(name, str) or not name:
            complete = False
            continue
        group, org_unit = row.get("group_email"), row.get("org_unit_name")
        if group is not None:
            # A group event (``GROUP_EMAIL`` set) is the group's, whatever OU it names (SG:scubagoggles/rego/Utils.rego:276).
            group_id = _group_id(groups, group)
            unit = ctx.group(group_id) if group_id is not None else (
                ctx.group_address(group) if isinstance(group, str) and group else None)
        else:
            unit = ctx.ou_by_name(org_unit) if org_unit is not None else None
        events.append({"time": _text(row.get("time")), "event": name, "setting": _text(row.get("setting")),
                       "new_value": _text(row.get("new_value")), "unit": unit,
                       "application": _text(row.get("application"))})
    # The log window is the read's own record; without one it is null and the events kind concludes nothing.
    return {"complete": complete, "window_start": _text(state.get("window_start")),
            "window_end": _text(state.get("window_end")), "events": events}


def _dns(ctx: _Context) -> dict[str, Any]:
    records = ctx.records("google_dns_posture")
    data = [row for row in records if row.get("kind") == "google_domain_posture"]
    states = [row for row in records if row.get("kind") != "google_domain_posture"]

    def new_shape(row: dict[str, Any]) -> bool:
        return "alias" in row or isinstance(row.get("dmarc"), dict) and "query_name" in row["dmarc"]

    # A bundle collected before the DMARC tree walk and the selector map has none of their fields: not collected.
    _require(not data or any(new_shape(row) for row in data), "dmarc.query_name", "missing_field")
    if states:
        _, complete, _ = _split(records, "google_dns_posture", "google_domain_posture")
    else:
        raw = ctx.optional("raw/google_dns_posture.json")
        complete = (isinstance(raw, dict) and ctx.read_ok(raw, "google_dns_posture", "domains")
                    and isinstance(raw.get("domainPosture"), dict) and not section_was_cut(raw["domainPosture"])
                    and isinstance(raw["domainPosture"].get("value"), list)
                    and len(raw["domainPosture"]["value"]) == len(data))
    kinds: dict[str, Any] = {}
    for row in ctx.records("google_domains", required=False) or []:
        if isinstance(row.get("domain_name"), str):
            kinds[row["domain_name"].lower()] = row.get("domain_kind")
    domains = []
    for row in data:
        name = row.get("domain")
        if not isinstance(name, str) or not name:
            complete = False
            continue
        alias, kind = row.get("alias"), kinds.get(name.lower())
        if not isinstance(alias, bool):
            # Older normalised records name the kind on the Directory domain list only; an unknown kind stays unknown.
            alias = kind == "alias" if kind in ("alias", "primary", "secondary") else None
        error = row.get("resolver_error")
        spf, dkim, dmarc = (row.get(part) if isinstance(row.get(part), dict) else {} for part in ("spf", "dkim", "dmarc"))
        selectors = dkim.get("selectors") if isinstance(dkim.get("selectors"), dict) else {}
        inherited = dmarc.get("inherited")
        domains.append({
            "domain": name, "alias": alias,
            # Only the fact of a resolver failure is kept, never its message (a resolver URL or local detail).
            "resolver_error": not (error is None or error is False),
            "spf": {"records": _strings(spf.get("records"))},
            "dkim": {"selectors": {selector: _strings(selectors.get(selector)) for selector in _dkim_selectors()}},
            "dmarc": {"query_name": _text(dmarc.get("query_name")),
                      "inherited": inherited if isinstance(inherited, bool) else None,
                      "records": _strings(dmarc.get("records"))},
        })
    return {"complete": complete, "domains": domains}


def _roles(raw: dict[str, Any] | None) -> dict[str, bool | None] | None:
    """Role id to whether the role is highly privileged (SG:scubagoggles/provider.py:817-829); None for a role whose
    fields cannot be read, and None overall when the roles list cannot be read."""
    section = raw.get("roles") if isinstance(raw, dict) else None
    rows = section.get("value") if isinstance(section, dict) else None
    if not isinstance(rows, list):
        return None
    roles: dict[str, bool | None] = {}
    for role in rows:
        role_id = role.get("roleId") if isinstance(role, dict) else None
        if not isinstance(role_id, (str, int)) or isinstance(role_id, bool) or str(role_id) == "":
            return None
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
    users = ctx.records("google_users")
    assignments = ctx.records("google_role_assignments", required=False) or []
    raw = ctx.directory()
    roles = _roles(raw)
    complete = (roles is not None and all(ctx.read_ok(raw, _DIRECTORY, name) for name in ("users", "roles",
                                                                                            "roleAssignments"))
                and len(raw["users"]["value"]) == len(users)
                and len(raw["roleAssignments"]["value"]) == len(assignments))
    assigned: set[str] = set()
    for row in assignments:
        role_id, assignee = row.get("role_id"), row.get("assigned_to")
        verdict = (roles or {}).get(str(role_id)) if isinstance(role_id, (str, int)) and not isinstance(role_id, bool) \
            else None
        if not isinstance(assignee, str) or not assignee or verdict is None:
            complete = False  # an assignment to a role that cannot be read may make its holder privileged
        elif verdict:
            assigned.add(assignee)
    # ScubaGoggles counts user assignees only (provider.py:804-809). A privileged role held by anything else (a group)
    # makes accounts privileged that no user row shows, so the privileged list is not the whole.
    if assigned - {row.get("id") for row in users}:
        complete = False
    by_path, _, placed = ctx.ou_index()
    if not placed:
        by_path = {}
    groups, memberships_complete = ctx.group_index()
    member_of: dict[str, set[str]] = {}
    for row in ctx.records("google_group_members", required=False) or []:
        group, email = row.get("group_email"), row.get("email")
        group_id = _group_id(groups, group)
        # A nested group or an all-users (CUSTOMER) member makes members no user row lists: not resolved here.
        if group_id is None or not isinstance(email, str) or not email or row.get("type") != "USER":
            memberships_complete = False
            continue
        member_of.setdefault(email.lower(), set()).add(ctx.group(group_id))
    privileged, super_admins = [], 0
    for row in users:
        user_id, admin, delegated = row.get("id"), row.get("is_admin"), row.get("is_delegated_admin")
        if not isinstance(user_id, str) or not user_id or type(admin) is not bool or type(delegated) is not bool:
            complete = False
            continue
        super_admins += admin
        if not (admin or delegated or user_id in assigned):
            continue
        email, path = row.get("primary_email"), row.get("org_unit_path")
        if not isinstance(email, str) or not email:
            memberships_complete = False
        privileged.append({
            "user": ctx.user(user_id),
            # Unplaceable (an unknown or shared path, an incomplete unit list): null, which the SSO kind cannot place.
            "org_unit": by_path.get(path) if isinstance(path, str) else None,
            "groups": sorted(member_of.get(email.lower(), ())) if isinstance(email, str) else [],
        })
    return {"complete": complete, "super_admin_count": super_admins, "privileged": privileged,
            "memberships_complete": memberships_complete}


def _sso(ctx: _Context) -> dict[str, Any]:
    data, complete, _ = _split(ctx.records("google_sso_assignments"), "google_sso_assignments", "google_sso_assignment")
    assignments = []
    for row in data:
        org_unit, group, mode = row.get("target_org_unit"), row.get("target_group"), row.get("sso_mode")
        org_id = org_unit.removeprefix("orgUnits/") if isinstance(org_unit, str) else None
        group_id = group.removeprefix("groups/") if isinstance(group, str) else None
        if (group is None) == (org_unit is None) or not isinstance(mode, str):
            complete = False
            continue
        if isinstance(org_unit, str) and org_unit.startswith("orgUnits/") and _bare(org_id):
            target = "ou:" + org_id
        elif isinstance(group, str) and group.startswith("groups/") and _bare(group_id):
            target = ctx.group(group_id)
        else:
            complete = False
            continue
        assignments.append({"target": target, "sso_mode": mode})
    return {"complete": complete, "assignments": assignments}


_BUILDERS = {"gws_tenant": _tenant, "gws_policies": _policies, "gws_setting_events": _events, "gws_dns": _dns,
             "gws_admins": _admins, "gws_sso": _sso}


def _mask(value: Any, counts: dict[str, int]) -> Any:
    """Mask every address left in a string (``***@<domain>``), as ``project_run`` masks its evidence."""
    if isinstance(value, str):
        def mask(match: re.Match) -> str:
            counts["email_addresses"] += 1
            return "***@" + match[1]
        return _EMAIL.sub(mask, value)
    if isinstance(value, list):
        return [_mask(item, counts) for item in value]
    if isinstance(value, dict):
        return {key: _mask(item, counts) for key, item in value.items()}
    return value


@guarded_operation
def project_gws_run(run_dir: str | Path, *,
                    max_items: int = DEFAULT_MAX_ITEMS, max_chars: int = DEFAULT_MAX_CHARS,
                    scan_max_rows: int = DEFAULT_SCAN_MAX_ROWS, scan_max_bytes: int = DEFAULT_SCAN_MAX_BYTES,
                    scan_max_chunks: int = DEFAULT_SCAN_MAX_CHUNKS) -> GwsProjection:
    """Read a Google Workspace bundle without writes into the six GWS SCuBA rule-input sections.

    The bounds are ``project_run``'s: the scan bounds limit each source read (rows, bytes, chunk files) and
    ``max_items`` and ``max_chars`` budget each projected section; exhausting one withholds the section as
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
    counts = {"user_ids": 0, "group_ids": 0, "email_addresses": 0}
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
            value = _mask(_BUILDERS[section](ctx), counts) if section != "gws_dns" else _BUILDERS[section](ctx)
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
    if ctx is not None:
        counts["user_ids"], counts["group_ids"] = len(ctx.users), len(ctx.groups)
    result.report = {"schema_version": GWS_PROJECTION_VERSION, "sections": report,
                     "redaction": {"enabled": True, "strategy": PSEUDONYM_STRATEGY, **counts}, "bounds": bounds}
    return result
