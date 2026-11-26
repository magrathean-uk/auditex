"""Reduction of ``gws_policies`` to one value per (unit, section), as ScubaGoggles v1.1.0 does (design 3 and 8.1).

- Policies are ranked by ``sort_order``, highest first, per (unit, section) (SG:scubagoggles/policy_api.py:776).
  ``max`` keeps the winner; ``merge`` fills fields the winner lacks from lower policies (:1042-1067); ``list`` keeps
  every value (:1069-1095); ``max_map`` merges list entries by primary key (:973-1040).
- A group-scoped unit (``ou:<id>/group:<pseudonym>``) is its own unit, never ranked against an OU (:784-825).
- Pinned defaults fill the top unit only (:1097-1170), and only when both the policy read and the tenant topology
  are complete and the topology holds the top unit as its one root. A topology with a cycle, or a complete one with
  an OU whose parent chain does not reach that root, is broken (review B4): it is incomplete and no unit inherits
  the top unit's values, so a dangling or looping OU never borrows a compliant root value. ScubaGoggles' "absent service status is DISABLED"
  is not copied: ``service_on`` answers ``unknown`` (divergence D3).
- Unknown is not safe: an envelope that cannot be placed raises ``Unusable``; a value that cannot be reduced reduces
  to ``UNUSABLE`` for that (unit, section) only. A unit key outside the design 7 grammar (``ou:<id>`` or
  ``ou:<id>/group:<pseudonym>``, each part printable ASCII without ``/``, so no NUL or other control character), or
  naming an OU that a complete topology does not hold, cannot be placed (review B4, round 3): that (unit, section)
  is ``UNUSABLE`` and the section is listed in ``Units.unplaced``, so it never inherits a compliant value. A value
  that is not plain JSON data (NaN, an infinity, an integer over 1024 bits, a non-text key, a foreign type) or is
  nested deeper than 64 levels is ``UNUSABLE`` too, before any comparison: it can neither hide a tie nor raise
  ``RecursionError``. So does a tie (D11): two policies at the rank that decides a value
  disagreeing on it. The deciding rank is the winner's for ``max``, and each field's (``merge``) or each map item
  field's (``max_map``) own highest rank, so the read order of equal-ranked policies never changes the answer.
"""
from __future__ import annotations

import copy
import json
import math
import re
from dataclasses import dataclass
from typing import Any, NamedTuple

from .catalogue import section_semantics

ON, OFF, UNKNOWN = "on", "off", "unknown"
_ID = r"[\x21-\x2e\x30-\x7e]+"  # printable ASCII without space or "/"
_OU = re.compile(rf"ou:{_ID}")
_GROUP = re.compile(rf"(ou:{_ID})/group:{_ID}")
_DEPTH = 64
_INT_BITS = 1024


class Unusable(ValueError):
    """``gws_policies`` or ``gws_tenant`` has the wrong shape for the sections a rule reads."""


class _Sentinel:
    def __init__(self, name: str):
        self._name = name

    def __repr__(self) -> str:
        return self._name


UNUSABLE = _Sentinel("UNUSABLE")
MISSING = _Sentinel("MISSING")


@dataclass(frozen=True)
class Units:
    top: str
    complete: bool
    values: dict[str, dict[str, Any]]
    explicit: dict[str, frozenset[tuple[str, str]]]
    inherits: bool = True
    unplaced: frozenset[str] = frozenset()


class _Placed(NamedTuple):
    unit: str
    section: str
    rank: float
    value: Any


def _sort_order(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            or isinstance(value, float) and math.isfinite(value))


def _chains(org_units: dict[str, str | None], top: str) -> set[str]:
    """How each OU's parent chain ends: ``top``, ``root`` (another root), ``dangling`` (a parent outside the map) or
    ``cycle``. One pass: every OU is walked once and its outcome shared by the whole path."""
    ends: dict[str, str] = {}
    for start in org_units:
        path, seen, unit = [], set(), start
        while True:
            if unit in ends:
                outcome = ends[unit]
                break
            if unit not in org_units:
                outcome = "dangling"
                break
            if unit in seen:
                outcome = "cycle"
                break
            seen.add(unit)
            path.append(unit)
            if org_units[unit] is None:
                outcome = "top" if unit == top else "root"
                break
            unit = org_units[unit]
        for unit in path:
            ends[unit] = outcome
    return set(ends.values())


def _topology(tenant: Any) -> tuple[str, bool, bool, frozenset[str] | None]:
    """The top unit, whether the tenant topology is complete, and whether units inherit the top unit's values
    (design 7: ``top_unit``, ``org_units``, ``complete``), and the OUs a declared-complete topology holds (``None``
    for a partial one, which may not name every OU). A top unit that is not an OU, or an ``org_units`` map of
    the wrong shape, cannot be placed. A complete topology must hold the top unit as its only root; a partial one is
    carried through as incomplete, so no default is applied on a root the read never confirmed. A cycle, a second
    root or a parent chain that does not reach the top unit breaks the topology, complete or not: incomplete, and no
    inheritance (review B4, rounds 2 and 3)."""
    if not isinstance(tenant, dict) or not isinstance(tenant.get("top_unit"), str) \
            or not _OU.fullmatch(tenant["top_unit"]):
        raise Unusable("gws_tenant has no top unit")
    top, org_units = tenant["top_unit"], tenant.get("org_units")
    if not isinstance(org_units, dict) or any(
            not isinstance(unit, str) or not _OU.fullmatch(unit)
            or parent is not None and (not isinstance(parent, str) or not _OU.fullmatch(parent))
            for unit, parent in org_units.items()):
        raise Unusable("gws_tenant has no usable org unit map")
    complete = tenant.get("complete") is True
    roots = [unit for unit, parent in org_units.items() if parent is None]
    if complete and roots != [top]:
        raise Unusable("gws_tenant does not hold its top unit as the root")
    ends = _chains(org_units, top)
    broken = ends != {"top"}
    return top, complete and not broken, not broken, frozenset(org_units) if complete else None


def _placed(unit: str, kind: str, known: frozenset[str] | None) -> bool:
    """The unit key follows design 7 and its OU is one a complete topology holds (review B4, round 3)."""
    match = (_GROUP if kind == "group" else _OU).fullmatch(unit)
    if match is None:
        return False
    return known is None or (match.group(1) if kind == "group" else unit) in known


def _plain(value: Any) -> bool:
    """Plain JSON data within ``_DEPTH`` levels: text-keyed objects, lists, text, booleans, null, finite numbers and
    integers up to ``_INT_BITS`` bits. Iterative, so a deep or cyclic value is refused, never a ``RecursionError``."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list):
            if depth >= _DEPTH:
                return False
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    return False
                stack.extend((part, depth + 1) for part in item.values())
            else:
                stack.extend((part, depth + 1) for part in item)
        elif isinstance(item, float):
            if not math.isfinite(item):
                return False
        elif isinstance(item, int):
            if item.bit_length() > _INT_BITS:
                return False
        elif item is not None and not isinstance(item, str):
            return False
    return True


def _entries(sections: Any, keys: set[str]) -> tuple[str, bool, bool, list[_Placed], frozenset[str]]:
    if not isinstance(sections, dict):
        raise Unusable("sections is not a mapping")
    top, tenant_complete, inherits, known = _topology(sections.get("gws_tenant"))
    read = sections.get("gws_policies")
    if not isinstance(read, dict) or not isinstance(read.get("policies"), list):
        raise Unusable("gws_policies is not a policy list")
    kept, unplaced = [], set()
    for entry in read["policies"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("section"), str) or not entry["section"].strip():
            raise Unusable("gws_policies holds an entry without a section")
        if entry["section"] not in keys:
            continue
        unit, kind = entry.get("unit"), entry.get("unit_kind")
        if (not isinstance(unit, str) or not unit.strip() or not isinstance(kind, str) or kind not in {"org_unit", "group"}
                or (kind == "group") != ("/group:" in unit) or unit == top and kind == "group"):
            raise Unusable("gws_policies holds an entry that cannot be placed")
        # A malformed or unknown unit key, or an unrankable, valueless or non-plain value: only this (unit, section)
        # becomes unusable, and an unplaced key also marks its section (review B4, round 3).
        placed = _placed(unit, kind, known)
        if not placed:
            unplaced.add(entry["section"])
        rank = entry.get("sort_order")
        usable = placed and _sort_order(rank) and "value" in entry and _plain(entry["value"])
        kept.append(_Placed(unit, entry["section"], rank if usable else math.inf,
                            entry["value"] if usable else UNUSABLE))
    return top, tenant_complete and read.get("complete") is True, inherits, kept, frozenset(unplaced)


class _Tie(Exception):
    pass


def _canonical(value: Any) -> str:
    """Type-aware equality: ``true`` and ``1`` differ, as they do in the evidence. ``_entries`` admits only plain
    values; one that still cannot be written is undecidable (``_Tie``), never equal to another such value."""
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise _Tie from error


def _tiers(group: list[_Placed]) -> list[list[Any]]:
    """The values by rank, highest first; within a rank in canonical order, never in read order. One pass groups
    the records by rank (review M3)."""
    by_rank: dict[float, list[Any]] = {}
    for entry in group:
        by_rank.setdefault(entry.rank, []).append(entry.value)
    return [sorted(by_rank[rank], key=_canonical) for rank in sorted(by_rank, reverse=True)]


def _decided(tiers: list[list[dict]]) -> dict[str, Any]:
    """Each field from the highest rank that holds it; equal-ranked values that disagree on it are a tie (D11)."""
    merged: dict[str, Any] = {}
    for tier in tiers:
        found: dict[str, list[Any]] = {}
        for value in tier:
            for name, part in value.items():
                if name not in merged:
                    found.setdefault(name, []).append(part)
        for name in sorted(found):
            candidates = found[name]
            first = _canonical(candidates[0])
            if any(_canonical(candidate) != first for candidate in candidates[1:]):
                raise _Tie
            merged[name] = copy.deepcopy(candidates[0])
    return merged


def _max(tiers: list[list[Any]]) -> Any:
    top = tiers[0]
    if any(not isinstance(value, dict) for value in top):
        return UNUSABLE
    if any(_canonical(value) != _canonical(top[0]) for value in top[1:]):
        return UNUSABLE
    return copy.deepcopy(top[0])


def _merge(tiers: list[list[Any]]) -> Any:
    if any(not isinstance(value, dict) for tier in tiers for value in tier):
        return UNUSABLE
    try:
        return _decided(tiers)
    except _Tie:
        return UNUSABLE


def _list(tiers: list[list[Any]]) -> Any:
    if any(not isinstance(value, dict) for tier in tiers for value in tier):
        return UNUSABLE
    return [copy.deepcopy(value) for tier in tiers for value in tier]


def _max_map(tiers: list[list[Any]], field: str, key: str) -> Any:
    def usable(value):
        return (isinstance(value, dict) and isinstance(value.get(field), list)
                and all(isinstance(item, dict) and isinstance(item.get(key), str | int) and not isinstance(
                    item.get(key), bool) for item in value[field])
                and len({item[key] for item in value[field]}) == len(value[field]))
    if any(not usable(value) for tier in tiers for value in tier):
        return UNUSABLE
    try:
        # Fields beside the map merge as ``merge`` does; each map item merges field by field at its own rank.
        merged = _decided([[{name: part for name, part in value.items() if name != field} for value in tier]
                           for tier in tiers])
        # One pass groups the items by key and rank (review M3). Keys keep their first place: rank, then the
        # canonical order of equal-ranked policies, then the place in that policy's list, so one policy's list
        # keeps its own order and read order never matters.
        by_key: dict[Any, dict[int, list[dict]]] = {}
        for index, tier in enumerate(tiers):
            for value in tier:
                for item in value[field]:
                    by_key.setdefault(item[key], {}).setdefault(index, []).append(item)
        items = [_decided([ranks[index] for index in sorted(ranks)]) for ranks in by_key.values()]
    except _Tie:
        return UNUSABLE
    merged[field] = items
    return merged


def _reduce(section: str, group: list[_Placed]) -> Any:
    semantics = section_semantics(section)
    reducer = semantics["reducer"]
    if any(entry.value is UNUSABLE for entry in group):
        return UNUSABLE
    try:
        tiers = _tiers(group)
        if reducer == "merge":
            return _merge(tiers)
        if reducer == "list":
            return _list(tiers)
        if reducer == "max_map":
            return _max_map(tiers, next(iter(semantics["fields"])), semantics["key"])
        return _max(tiers)
    except _Tie:
        return UNUSABLE


def effective_units(sections: dict, section_keys: list[str] | tuple[str, ...]) -> Units:
    """``{unit: {section: value}}`` for the given section keys, defaults on the top unit, plus the explicit fields.

    The top unit is always present. Entries for other section keys are not read, so a malformed value there never
    reaches this rule (keep-finding 4). A section key without pinned semantics is a programming error.
    """
    keys = set(section_keys)
    for key in keys:
        section_semantics(key)
    top, complete, inherits, entries, unplaced = _entries(sections, keys)
    grouped: dict[tuple[str, str], list[_Placed]] = {}
    for entry in entries:
        grouped.setdefault((entry.unit, entry.section), []).append(entry)
    values: dict[str, dict[str, Any]] = {top: {}}
    explicit: dict[str, set[tuple[str, str]]] = {top: set()}
    for (unit, section), group in grouped.items():
        value = _reduce(section, group)
        values.setdefault(unit, {})[section] = value
        fields = explicit.setdefault(unit, set())
        if isinstance(value, dict):
            fields.update((section, field) for field in value)
    if complete:
        for section in sorted(keys):
            default = section_semantics(section).get("default")
            if default is None:
                continue
            current = values[top].get(section)
            if current is None:
                values[top][section] = copy.deepcopy(default)
            elif isinstance(current, dict):
                for field, value in default.items():
                    current.setdefault(field, copy.deepcopy(value))
    return Units(top, complete, values, {unit: frozenset(fields) for unit, fields in explicit.items()}, inherits,
                 unplaced)


def effective(units: Units, unit: str, section: str, field: str) -> Any:
    """The unit's own value, else the top unit's (``GetApiSettingValue``, SG:scubagoggles/rego/Utils.rego:496-505).

    ``MISSING`` when neither holds the field; ``UNUSABLE`` when the value that applies could not be reduced, or when
    the unit lacks the field and a broken topology (review B4) leaves nothing it may inherit.
    """
    inherits = units.inherits or unit == units.top
    for source in (unit, units.top) if inherits else (unit,):
        value = units.values.get(source, {}).get(section, MISSING)
        if value is UNUSABLE:
            return UNUSABLE
        if isinstance(value, dict) and field in value:
            return value[field]
        if value is not MISSING and not isinstance(value, dict):
            return UNUSABLE
    return MISSING if inherits else UNUSABLE


def _state(units: Units, unit: str, section: str) -> str | None:
    """None only when the unit has no status record at all; a record without a readable ``serviceState`` (``{}``, an
    unrelated field, an unknown state) is ``unknown``, never inherited."""
    value = units.values.get(unit, {}).get(section, MISSING)
    if value is MISSING:
        return None
    state = value.get("serviceState") if isinstance(value, dict) else None
    if not isinstance(state, str) or state.upper() not in {"ENABLED", "DISABLED"}:
        return UNKNOWN
    return ON if state.upper() == "ENABLED" else OFF


def service_on(units: Units, unit: str, service: str) -> str:
    """``AppEnabled`` (SG:scubagoggles/rego/Utils.rego:605-625): the unit's explicit state, else the top unit's.

    ``on``, ``off`` or ``unknown``. Only an absent status record inherits. An absent top-level status is ``unknown``,
    not DISABLED (D3); a supplied record without a readable or known state is ``unknown`` at either level.
    ``<service>_service_status`` must be among the reduced keys.
    """
    section = f"{service}_service_status"
    own = _state(units, unit, section)
    if own is not None:
        return own
    if not units.inherits:
        return UNKNOWN
    top = _state(units, units.top, section)
    return UNKNOWN if top is None else top
