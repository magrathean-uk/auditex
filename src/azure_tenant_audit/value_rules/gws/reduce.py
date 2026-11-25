"""Reduction of ``gws_policies`` to one value per (unit, section), as ScubaGoggles v1.1.0 does (design 3 and 8.1).

- Policies are ranked by ``sort_order``, highest first, per (unit, section) (SG:scubagoggles/policy_api.py:776).
  ``max`` keeps the winner; ``merge`` fills fields the winner lacks from lower policies (:1042-1067); ``list`` keeps
  every value (:1069-1095); ``max_map`` merges list entries by primary key (:973-1040).
- A group-scoped unit (``ou:<id>/group:<pseudonym>``) is its own unit, never ranked against an OU (:784-825).
- Pinned defaults fill the top unit only (:1097-1170), and only when both the policy read and the tenant topology
  are complete and the topology holds the top unit as its one root. ScubaGoggles' "absent service status is DISABLED"
  is not copied: ``service_on`` answers ``unknown`` (divergence D3).
- Unknown is not safe: an envelope that cannot be placed raises ``Unusable``; a value that cannot be reduced reduces
  to ``UNUSABLE`` for that (unit, section) only. So does a tie (D11): two policies at the rank that decides a value
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
_OU = re.compile(r"ou:[^/\s]+")


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


class _Placed(NamedTuple):
    unit: str
    section: str
    rank: float
    value: Any


def _sort_order(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            or isinstance(value, float) and math.isfinite(value))


def _topology(tenant: Any) -> tuple[str, bool]:
    """The top unit and whether the tenant topology is complete (design 7: ``top_unit``, ``org_units``,
    ``complete``). A top unit that is not an OU, or an ``org_units`` map of the wrong shape, cannot be placed. A
    complete topology must hold the top unit as its only root; a partial one is carried through as incomplete, so no
    default is applied on a root the read never confirmed."""
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
    return top, complete


def _entries(sections: Any, keys: set[str]) -> tuple[str, bool, list[_Placed]]:
    if not isinstance(sections, dict):
        raise Unusable("sections is not a mapping")
    top, tenant_complete = _topology(sections.get("gws_tenant"))
    read = sections.get("gws_policies")
    if not isinstance(read, dict) or not isinstance(read.get("policies"), list):
        raise Unusable("gws_policies is not a policy list")
    kept = []
    for entry in read["policies"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("section"), str):
            raise Unusable("gws_policies holds an entry without a section")
        if entry["section"] not in keys:
            continue
        unit, kind = entry.get("unit"), entry.get("unit_kind")
        if (not isinstance(unit, str) or not unit or not isinstance(kind, str) or kind not in {"org_unit", "group"}
                or (kind == "group") != ("/group:" in unit) or unit == top and kind == "group"):
            raise Unusable("gws_policies holds an entry that cannot be placed")
        # Placed but unrankable or valueless: only this (unit, section) becomes unusable.
        rank = entry.get("sort_order")
        usable = _sort_order(rank) and "value" in entry
        kept.append(_Placed(unit, entry["section"], rank if usable else math.inf,
                            entry["value"] if usable else UNUSABLE))
    return top, tenant_complete and read.get("complete") is True, kept


def _canonical(value: Any) -> str:
    """Type-aware equality: ``true`` and ``1`` differ, as they do in the evidence."""
    if value is UNUSABLE:
        return "\0unusable"
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return "\0unusable"


def _tiers(group: list[_Placed]) -> list[list[Any]]:
    """The values by rank, highest first; within a rank in canonical order, never in read order."""
    ranks = sorted({entry.rank for entry in group}, reverse=True)
    return [sorted((entry.value for entry in group if entry.rank == rank), key=_canonical) for rank in ranks]


class _Tie(Exception):
    pass


def _decided(tiers: list[list[dict]]) -> dict[str, Any]:
    """Each field from the highest rank that holds it; equal-ranked values that disagree on it are a tie (D11)."""
    merged: dict[str, Any] = {}
    for tier in tiers:
        for name in sorted({name for value in tier for name in value} - set(merged)):
            candidates = [value[name] for value in tier if name in value]
            if any(_canonical(candidate) != _canonical(candidates[0]) for candidate in candidates[1:]):
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
        first: dict[Any, tuple[int, str]] = {}
        for index, tier in enumerate(tiers):
            for value in tier:
                for item in value[field]:
                    first.setdefault(item[key], (index, _canonical(item[key])))
        items = [_decided([[item for value in tier for item in value[field] if item[key] == item_key]
                           for tier in tiers])
                 for item_key in sorted(first, key=first.__getitem__)]
    except _Tie:
        return UNUSABLE
    merged[field] = items
    return merged


def _reduce(section: str, group: list[_Placed]) -> Any:
    semantics = section_semantics(section)
    reducer = semantics["reducer"]
    if any(entry.value is UNUSABLE for entry in group):
        return UNUSABLE
    tiers = _tiers(group)
    if reducer == "merge":
        return _merge(tiers)
    if reducer == "list":
        return _list(tiers)
    if reducer == "max_map":
        return _max_map(tiers, next(iter(semantics["fields"])), semantics["key"])
    return _max(tiers)


def effective_units(sections: dict, section_keys: list[str] | tuple[str, ...]) -> Units:
    """``{unit: {section: value}}`` for the given section keys, defaults on the top unit, plus the explicit fields.

    The top unit is always present. Entries for other section keys are not read, so a malformed value there never
    reaches this rule (keep-finding 4). A section key without pinned semantics is a programming error.
    """
    keys = set(section_keys)
    for key in keys:
        section_semantics(key)
    top, complete, entries = _entries(sections, keys)
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
    return Units(top, complete, values, {unit: frozenset(fields) for unit, fields in explicit.items()})


def effective(units: Units, unit: str, section: str, field: str) -> Any:
    """The unit's own value, else the top unit's (``GetApiSettingValue``, SG:scubagoggles/rego/Utils.rego:496-505).

    ``MISSING`` when neither holds the field; ``UNUSABLE`` when the value that applies could not be reduced.
    """
    for source in (unit, units.top):
        value = units.values.get(source, {}).get(section, MISSING)
        if value is UNUSABLE:
            return UNUSABLE
        if isinstance(value, dict) and field in value:
            return value[field]
        if value is not MISSING and not isinstance(value, dict):
            return UNUSABLE
    return MISSING


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
    top = _state(units, units.top, section)
    return UNKNOWN if top is None else top
