"""``setting``: one field of one policy section, compared with one pinned value (design M13 section 8.2).

The row's ``params`` are pure data: ``section`` (the underscore section key), ``field`` (or ``fields``, tried in order;
two present fields that differ make the value unusable, divergence D7), ``op``, ``value``, ``service`` (the product
whose ``<service>_service_status`` gates the unit, or null) and ``scope`` (``all_units``, the default: every unit that
holds the field plus the top unit with its pinned default; or ``explicit_only``: only units that hold the field, no
default, as ScubaGoggles' ``AppExplicitStatus`` rules do, SG:scubagoggles/rego/Utils.rego:634-637).

``op`` is the *violation* predicate: a unit violates when its value ``<op>`` the pinned value. ``eq``, ``ne``,
``in`` and ``not_in`` compare a boolean exactly and a string exactly, as the pinned Rego does (``!=``, ``in``); only
rows whose Rego folds case (CC.5.1, SG:scubagoggles/rego/Commoncontrols.rego:735, and the explicit service states,
SG:scubagoggles/rego/Utils.rego:634-637) set ``case: "fold"`` (the default is ``"exact"``), and then only ASCII text is folded, so ``ſTRONG`` never
becomes ``STRONG``. Every string row pins the field's vocabulary in ``known`` with its source in ``source`` (``eq`` and
``in`` would otherwise pass an unknown constant): a value outside it is unusable, never met and never a violation
(review M1). ``lt`` and ``gt`` compare whole numbers. ``duration_gt`` and
``duration_ne`` parse ``<digits>[smhdSMHD]`` into seconds (SG:scubagoggles/rego/Utils.rego:655-664); anything else is
unusable.

A unit whose service is on (or unknown) and that holds no value of its own is evaluated on its effective value
(design 8.1: its own, else the inherited value through ``reduce.effective``, else the top unit's value or pinned
default), so a sub-unit that switches the service on under a non-compliant top value is not met. ``explicit_only``
rows never inherit. A service state that is absent, unreadable or non-ASCII (``dıſabled``) in any unit is
unknown (D3, D12) and never confirms met; a positively read violation in a unit whose service is on still wins. A
supplied service-status record without a readable ``serviceState`` is unusable, not absent (review B3). A policy
record for one of the rule's sections whose unit key ``reduce`` cannot place (not ``ou:<id>`` or
``ou:<id>/group:<pseudonym>`` in printable ASCII, design 7, or an OU a complete topology does not hold) makes the
section shape unusable (review B4, rounds 2 and 3).

Decision order, the first rule that applies decides: the shared section gate (``gws.assess``); a wrong-shaped
envelope; an incomplete read; the service off in every unit; no unit known to be on while a state is unknown; a
violating value in a unit whose service is on; any unit whose service state is unknown; an unusable value; an absent top-level value with no pinned default (or, for ``explicit_only``, no explicit value at all);
met. A value that cannot be read never answers met. No input value enters an answer: code, text and citation all come
from the row's cell in ``configs/scuba-gws-rules-setting-*.json``.
"""
from __future__ import annotations

import re
from typing import Any, NamedTuple

from ..helpers import _int
from ..record import _rec
from .catalogue import section_semantics
from .reduce import (
    MISSING,
    OFF,
    ON,
    UNKNOWN,
    UNUSABLE,
    Unusable,
    effective,
    effective_units,
    service_on,
)

_DURATION = re.compile(r"([0-9]+)([smhdSMHD])")
_NAMES = {"section", "field", "fields", "op", "value", "service", "scope", "known", "source", "case"}


class Params(NamedTuple):
    section: str
    fields: tuple[str, ...]
    op: str
    value: Any
    service: str | None
    scope: str
    known: frozenset[str] | None = None
    fold: bool = False


def _seconds(value: Any) -> int | None:
    match = _DURATION.fullmatch(value) if isinstance(value, str) else None
    if match is None or not match.group(1).isascii():
        return None
    try:
        digits = int(match.group(1))
    except ValueError:  # more digits than Python converts: unusable, never a value
        return None
    return digits * (1, 60, 3600, 86400)["smhd".index(match.group(2).lower())]


def _text(value: Any, fold: bool = False) -> str | None:
    """The constant, upper-cased only when the row folds case. Non-ASCII text is unusable: Unicode folding would turn
    ``ſTRONG`` into ``STRONG``."""
    if not isinstance(value, str) or not value or not value.isascii():
        return None
    return value.upper() if fold else value


def _params(params: Any) -> Params:
    """The validated parameters of one row; a malformed row is a programming error, never an answer."""
    if not isinstance(params, dict) or set(params) - _NAMES or not {"section", "op", "value"} <= set(params):
        raise ValueError("Invalid GWS setting parameters")
    section, op, pinned = params["section"], params["op"], params["value"]
    one, many = params.get("field"), params.get("fields")
    if (one is None) == (many is None):
        raise ValueError("Invalid GWS setting parameters")
    fields = (one,) if many is None else tuple(many) if isinstance(many, list) else ()
    service, scope = params.get("service"), params.get("scope", "all_units")
    if (not isinstance(section, str) or not fields or len(set(fields)) != len(fields)
            or any(not isinstance(name, str) or not name for name in fields)
            or service is not None and not isinstance(service, str) or scope not in ("all_units", "explicit_only")):
        raise ValueError("Invalid GWS setting parameters")
    strings: list | None = None
    if op in ("eq", "ne"):
        valid = type(pinned) is bool or isinstance(pinned, str) and bool(pinned)
        strings = [pinned] if isinstance(pinned, str) else None
    elif op in ("in", "not_in"):
        valid = isinstance(pinned, list) and bool(pinned) and all(isinstance(item, str) and item for item in pinned)
        strings = pinned if valid else None
    elif op in ("lt", "gt"):
        valid = type(pinned) is int
    elif op in ("duration_gt", "duration_ne"):
        valid = _seconds(pinned) is not None
    else:
        valid = False
    if not valid:
        raise ValueError("Invalid GWS setting parameters")
    known, cite, case = params.get("known"), params.get("source"), params.get("case", "exact")
    fold = case == "fold"
    if case not in ("exact", "fold") or (known is None) != (cite is None) or fold and strings is None:
        raise ValueError("Invalid GWS setting parameters")
    if known is None:
        # Every string row pins its vocabulary: eq and in would otherwise pass an unknown constant, and ne and not_in
        # would call it a violation instead of unusable (review M1).
        if strings is not None:
            raise ValueError("Invalid GWS setting parameters")
        return Params(section, fields, op, pinned, service, scope)
    if (strings is None or not isinstance(cite, str) or not cite or not isinstance(known, list) or not known
            or any(not isinstance(item, str) or not item or not item.isascii() for item in known)
            or len(set(known)) != len(known) or not set(strings) <= set(known)
            or fold and any(item != item.upper() for item in known)):
        raise ValueError("Invalid GWS setting parameters")
    return Params(section, fields, op, pinned, service, scope, frozenset(known), fold)


def _violates(op: str, actual: Any, pinned: Any, known: frozenset[str] | None = None,
              fold: bool = False) -> bool | None:
    """True: the value violates; False: it complies; None: it is not usable as the pinned value's type, or is a
    string outside the row's vocabulary."""
    if op in ("eq", "ne") and type(pinned) is bool:
        if type(actual) is not bool:
            return None
        return (actual == pinned) if op == "eq" else actual != pinned
    if op in ("eq", "ne", "in", "not_in"):
        text = _text(actual, fold)
        if text is None or known is not None and text not in known:
            return None
        member = text == pinned if op in ("eq", "ne") else text in pinned
        return member if op in ("eq", "in") else not member
    if op in ("lt", "gt"):
        number = _int(actual)
        if number is None:
            return None
        return number < pinned if op == "lt" else number > pinned
    seconds = _seconds(actual)
    if seconds is None:
        return None
    return seconds > _seconds(pinned) if op == "duration_gt" else seconds != _seconds(pinned)


def _read(units: Any, unit: str, section: str, fields: tuple[str, ...], explicit_only: bool,
          state_field: bool = False) -> Any:
    """The unit's own value of the field: ``MISSING`` when it holds none (a non-top unit is then not evaluated),
    ``UNUSABLE`` when its section could not be reduced or its fields disagree (D7). A supplied service-status record
    without its state field is ``UNUSABLE``, not ``MISSING`` (review B3). The caller adds inheritance."""
    block = units.values.get(unit, {}).get(section, MISSING)
    if block is UNUSABLE or block is not MISSING and not isinstance(block, dict):
        return UNUSABLE
    if block is MISSING:
        return MISSING
    if state_field and not any(name in block for name in fields):
        return UNUSABLE
    held = units.explicit.get(unit, frozenset())
    if explicit_only and not any((section, name) in held for name in fields):
        return MISSING
    found = [block[name] for name in fields if name in block]
    if not found:
        return MISSING
    if any((type(item), item) != (type(found[0]), found[0]) for item in found[1:]):
        return UNUSABLE
    return found[0]


def _inherited(units: Any, unit: str, section: str, fields: tuple[str, ...]) -> Any:
    """The value a unit with no value of its own is evaluated on (design 8.1): the inherited value through
    ``reduce.effective`` (the top unit's value or pinned default). ``UNUSABLE`` when the topology leaves nothing it may
    inherit or the inherited fields disagree (D7)."""
    found = [effective(units, unit, section, name) for name in fields]
    if any(item is UNUSABLE for item in found):
        return UNUSABLE
    found = [item for item in found if item is not MISSING]
    if not found:
        return MISSING
    if any((type(item), item) != (type(found[0]), found[0]) for item in found[1:]):
        return UNUSABLE
    return found[0]


def _service(units: Any, unit: str, service: str) -> str:
    """``reduce.service_on``, except that the state record it decides on must hold ASCII text: Python's ``upper``
    folds ``dıſabled`` to ``DISABLED``, an unknown state that D12 keeps unknown (review B2)."""
    state = service_on(units, unit, service)
    section = f"{service}_service_status"
    record = units.values.get(unit, {}).get(section, MISSING)
    if record is MISSING:
        record = units.values.get(units.top, {}).get(section, MISSING)
    raw = record.get("serviceState") if isinstance(record, dict) else None
    return UNKNOWN if isinstance(raw, str) and not raw.isascii() else state


def _answer(policy_id: str, row: dict, cell: str) -> dict:
    entry = row["cells"][cell]
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_texts"][0], cell, entry["cited"])


def setting(policy_id: str, row: dict, sections: dict) -> dict:
    section, fields, op, pinned, service, scope, known, fold = _params(row["params"])
    keys = [section] if service is None else [section, f"{service}_service_status"]
    try:
        units = effective_units(sections, keys)
    except Unusable:
        return _answer(policy_id, row, "section_shape_unusable")
    if units.unplaced:
        return _answer(policy_id, row, "section_shape_unusable")
    if not units.complete:
        return _answer(policy_id, row, "policy_read_incomplete")
    states = {unit: ON if service is None else _service(units, unit, service) for unit in units.values}
    if all(state == OFF for state in states.values()):
        return _answer(policy_id, row, "service_off_everywhere")
    if ON not in states.values() and UNKNOWN in states.values():
        return _answer(policy_id, row, "service_status_absent")
    # A service-state field holds ENABLED or DISABLED; any other text is an unknown state, not a value to compare (D12).
    state_field = any(section_semantics(section)["fields"].get(name) == "state" for name in fields)
    explicit_only = scope == "explicit_only"
    violates = unusable = False
    evaluated = 0
    for unit in sorted(units.values):
        value = _read(units, unit, section, fields, explicit_only, state_field)
        if value is MISSING and not explicit_only and unit != units.top and states[unit] != OFF:
            value = _inherited(units, unit, section, fields)
        if value is MISSING:
            continue
        evaluated += 1
        verdict = None if value is UNUSABLE else _violates(op, value, pinned, known, fold)
        if state_field and _text(value, True) not in ("ENABLED", "DISABLED"):
            verdict = None
        if states[unit] != ON or verdict is False:
            continue
        if verdict:
            violates = True
        else:
            unusable = True
    if violates:
        return _answer(policy_id, row, "unit_violates")
    # An unknown service state anywhere never confirms met, whatever that unit holds (design 8.4, D3, D12; review B1).
    if UNKNOWN in states.values():
        return _answer(policy_id, row, "service_status_absent")
    if unusable:
        return _answer(policy_id, row, "setting_value_unusable")
    top_absent = _read(units, units.top, section, fields, explicit_only, state_field) is MISSING
    if evaluated == 0 or top_absent and not explicit_only:
        return _answer(policy_id, row, "setting_absent")
    return _answer(policy_id, row, "no_unit_violates")


KINDS = {"setting": setting}
