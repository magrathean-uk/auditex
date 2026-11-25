"""Reduction of ``gws_policies`` to one value per (unit, section), as ScubaGoggles v1.1.0 does (design 3 and 8.1).

- Policies are ranked by ``sort_order``, highest first, per (unit, section) (SG:scubagoggles/policy_api.py:776).
  ``max`` keeps the winner; ``merge`` fills fields the winner lacks from lower policies (:1042-1067); ``list`` keeps
  every value (:1069-1095); ``max_map`` merges list entries by primary key (:973-1040).
- A group-scoped unit (``ou:<id>/group:<pseudonym>``) is its own unit, never ranked against an OU (:784-825).
- Pinned defaults fill the top unit only (:1097-1170), and only when the read is complete. ScubaGoggles' "absent
  service status is DISABLED" is not copied: ``service_on`` answers ``unknown`` (divergence D3).
- Unknown is not safe: an envelope that cannot be placed raises ``Unusable``; a value that cannot be reduced, or two
  different values at the winning sort order, reduces to ``UNUSABLE`` for that (unit, section) only.
"""
from __future__ import annotations

import copy
import json
import math
from dataclasses import dataclass
from typing import Any

from .catalogue import section_semantics

ON, OFF, UNKNOWN = "on", "off", "unknown"


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


def _sort_order(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            or isinstance(value, float) and math.isfinite(value))


def _entries(sections: dict, keys: set[str]) -> tuple[str, bool, list[dict]]:
    if not isinstance(sections, dict):
        raise Unusable("sections is not a mapping")
    tenant, read = sections.get("gws_tenant"), sections.get("gws_policies")
    if not isinstance(tenant, dict) or not isinstance(tenant.get("top_unit"), str) or not tenant["top_unit"]:
        raise Unusable("gws_tenant has no top unit")
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
                or (kind == "group") != ("/group:" in unit) or unit == tenant["top_unit"] and kind == "group"):
            raise Unusable("gws_policies holds an entry that cannot be placed")
        # Placed but unrankable or valueless: only this (unit, section) becomes unusable.
        kept.append(entry if _sort_order(entry.get("sort_order")) and "value" in entry
                    else {**entry, "sort_order": math.inf, "value": UNUSABLE})
    return tenant["top_unit"], read.get("complete") is True, kept


def _max(ranked: list[dict]) -> Any:
    winner = ranked[0]
    if not isinstance(winner["value"], dict):
        return UNUSABLE
    return copy.deepcopy(winner["value"])


def _merge(ranked: list[dict]) -> Any:
    if any(not isinstance(entry["value"], dict) for entry in ranked):
        return UNUSABLE
    merged = copy.deepcopy(ranked[0]["value"])
    for entry in ranked[1:]:
        for field, value in entry["value"].items():
            merged.setdefault(field, copy.deepcopy(value))
    return merged


def _list(ranked: list[dict]) -> Any:
    if any(not isinstance(entry["value"], dict) for entry in ranked):
        return UNUSABLE
    return [copy.deepcopy(entry["value"]) for entry in ranked]


def _max_map(ranked: list[dict], field: str, key: str) -> Any:
    def usable(value):
        return (isinstance(value, dict) and isinstance(value.get(field), list)
                and all(isinstance(item, dict) and isinstance(item.get(key), str | int) and not isinstance(
                    item.get(key), bool) for item in value[field]))
    if any(not usable(entry["value"]) for entry in ranked):
        return UNUSABLE
    if any(len({item[key] for item in entry["value"][field]}) != len(entry["value"][field]) for entry in ranked):
        return UNUSABLE
    merged = copy.deepcopy(ranked[0]["value"])
    by_key = {item[key]: item for item in merged[field]}
    for entry in ranked[1:]:
        for item in entry["value"][field]:
            if item[key] in by_key:
                for name, value in item.items():
                    by_key[item[key]].setdefault(name, copy.deepcopy(value))
            else:
                by_key[item[key]] = copy.deepcopy(item)
                merged[field].append(by_key[item[key]])
    return merged


def _tied(ranked: list[dict], reducer: str) -> bool:
    """Two different values share the winning sort order: which one Google applies is unknown."""
    if reducer == "list":
        return False
    top = [_canonical(entry["value"]) for entry in ranked if entry["sort_order"] == ranked[0]["sort_order"]]
    return any(value != top[0] for value in top[1:])


def _canonical(value: Any) -> str:
    """Type-aware equality: ``true`` and ``1`` differ, as they do in the evidence."""
    if value is UNUSABLE:
        return "\0unusable"
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return "\0unusable"


def _reduce(section: str, group: list[dict]) -> Any:
    semantics = section_semantics(section)
    reducer = semantics["reducer"]
    # Stable sort, highest first: equal sort orders keep the read order, as sorted(reverse=True) does in ScubaGoggles.
    ranked = sorted(group, key=lambda entry: entry["sort_order"], reverse=True)
    if any(entry["value"] is UNUSABLE for entry in ranked) or _tied(ranked, reducer):
        return UNUSABLE
    if reducer == "merge":
        return _merge(ranked)
    if reducer == "list":
        return _list(ranked)
    if reducer == "max_map":
        return _max_map(ranked, next(iter(semantics["fields"])), semantics["key"])
    return _max(ranked)


def effective_units(sections: dict, section_keys: list[str] | tuple[str, ...]) -> Units:
    """``{unit: {section: value}}`` for the given section keys, defaults on the top unit, plus the explicit fields.

    The top unit is always present. Entries for other section keys are not read, so a malformed value there never
    reaches this rule (keep-finding 4). A section key without pinned semantics is a programming error.
    """
    keys = set(section_keys)
    for key in keys:
        section_semantics(key)
    top, complete, entries = _entries(sections, keys)
    grouped: dict[tuple[str, str], list[dict]] = {}
    for entry in entries:
        grouped.setdefault((entry["unit"], entry["section"]), []).append(entry)
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
    value = units.values.get(unit, {}).get(section, MISSING)
    if value is MISSING or isinstance(value, dict) and "serviceState" not in value:
        return None
    state = value.get("serviceState") if isinstance(value, dict) else None
    if not isinstance(state, str) or state.upper() not in {"ENABLED", "DISABLED"}:
        return UNKNOWN
    return ON if state.upper() == "ENABLED" else OFF


def service_on(units: Units, unit: str, service: str) -> str:
    """``AppEnabled`` (SG:scubagoggles/rego/Utils.rego:605-625): the unit's explicit state, else the top unit's.

    ``on``, ``off`` or ``unknown``. An absent top-level status is ``unknown``, not DISABLED (D3); an unreadable or
    unknown state is ``unknown`` at either level. ``<service>_service_status`` must be among the reduced keys.
    """
    section = f"{service}_service_status"
    own = _state(units, unit, section)
    if own is not None:
        return own
    top = _state(units, units.top, section)
    return UNKNOWN if top is None else top
