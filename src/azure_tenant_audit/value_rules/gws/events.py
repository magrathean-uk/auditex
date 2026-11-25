"""``setting_event``: the 12 ScubaGoggles v1.1.0 policies decided from admin setting-change logs (design M13 8.2).

Each row's ``params`` hold ``setting_slots``: one slot per setting the policy needs, each naming its ``setting_names`` (or,
for COMMONCONTROLS.2.1, its ``event_names``, read with no unit) and either ``good_values`` and ``bad_values`` or the
``required_values`` a comma list must hold (CHAT.5.2). ``groups`` says whether group-scoped events count;
``top_delete`` is ``violates`` where the Rego counts a top-level delete as non-compliant (CHAT.5.x); ``service`` names
the service gate (GEMINI.1.1).

- The tenant topology must be complete and unbroken, and the event read complete with a usable log window
  (``window_start`` before ``window_end``); otherwise nothing is concluded, not even a violation or a service off
  everywhere: a cut topology cannot tell a deleted OU from a live one.
- The last event per (slot, unit) wins (SG:scubagoggles/rego/Utils.rego:230-234), compared at full RFC 3339 precision as
  ``time.parse_rfc3339_ns`` does (Utils.rego:284-286); names of one slot share one stream (GEMINI.2.1,
  SG:scubagoggles/rego/Gemini.rego:90-105). Two last events at one time that disagree are unusable. A time that is not
  strict RFC 3339 with an in-range zone, or lies outside the read's window, is unreadable.
- ``DELETE_APPLICATION_SETTING`` is a value, as SG:scubagoggles/rego/Utils.rego:318-346 makes it. Below the top unit
  it hands the setting back to the parent, which is checked on its own. At the top unit it returns the setting to a
  default no log shows, so it counts as no top-level event (D1, D15) unless the row says it ``violates``.
- An event for an OU outside the topology is for a deleted OU and is skipped, as ScubaGoggles' ``FilterEventsOU``
  does (SG:scubagoggles/rego/Utils.rego:423-438), as is a group event for a setting that is not group-scoped, whatever
  else the event holds. An event that might be the slot's but cannot be told (a blank or malformed event name, a
  setting change with a null or blank setting, a padded spelling, a blank application, no unit or a malformed one) is
  ambiguous: it never answers met, and it voids any violation it is not proven older than. A known other setting and
  a setting-less non-setting event (``TOGGLE_CAA_ENABLEMENT``) stay isolated. The setting name is the identity, as in
  ScubaGoggles, which never reads ``APPLICATION_NAME``; a readable application is carried, not compared.
- A value outside the row's good and bad values, a null value, a CHAT.5.2 payload that is not a category list, or an
  unreadable time is unusable, never compliant.
- A violation at the top unit counts only once every slot has a readable, current top-level event (Chat.rego:323-349):
  a slot whose top value is absent, unreadable, tied with a reset or possibly superseded voids it. A child or group
  violation counts on its own (D17, D19) and wins over unusable values elsewhere. With no violation, an unusable
  value answers not_assessed, then a top unit lacking any slot's event answers ``no_setting_event`` (D1), else met.
- The service gate skips a bad or unreadable value only where the service is off and no unit that could inherit the
  value has it on or unknown; a bad value under an unknown state is unusable.

Where this is stricter than ScubaGoggles, always toward not_assessed or a positively read violation (design 8.3
D15 to D19, in order): a top-level delete is no event (ScubaGoggles passes it); a string outside the pinned values is
unusable where the Rego fails anything but the good value (GMAIL.13.1, CC.2.1, CC.3.x); a CHAT.5.1 child OU is judged
per setting, not only when it has all four (Chat.rego:283-296); a GEMINI.1.1 group event carries no OU, so its bad
value is a violation only with the service on in every unit, else unusable (Gemini.rego:38-39 reads the event's OU).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from typing import Any

from ..record import _rec
from .reduce import (
    _OU,
    OFF,
    ON,
    UNKNOWN,
    Units,
    Unusable,
    _Sentinel,
    _topology,
    effective_units,
    service_on,
)

_GROUP = re.compile(r"group:[^/\s]+")
# RE2's ``\s`` (Chat.rego:415-423) is ASCII whitespace; a no-break space must not join a category.
_SPACES = re.compile(r"\s+", re.ASCII)
_ASCII_SPACE = " \t\n\r\f\v"
# Hours 00-23 and minutes 00-59 in the clock and the offset (some Pythons roll 24:00 or +00:99 over); a fraction past
# 18 digits is not a time any log writes. A leap second (60) parses here and fails in fromisoformat.
_RFC3339 = re.compile(r"(\d{4}-\d{2}-\d{2})[Tt]((?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60))(?:\.(\d{1,18}))?"
                      r"([Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)", re.ASCII)
_EVENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _delete_event() -> str:
    # Kept in a function so the product field-name registry does not take the event name as a mapping key.
    return "DELETE_APPLICATION_SETTING"


_DELETE = _Sentinel("DELETE")
_UNREADABLE = _Sentinel("UNREADABLE")


@dataclass(frozen=True)
class _Slot:
    names: frozenset[str]
    by_event: bool
    good: frozenset[str]
    bad: frozenset[str]
    required: frozenset[str] | None


def _answer(policy_id: str, row: dict, cell: str) -> dict:
    entry = row["cells"][cell]
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_texts"][0], cell,
                list(row["sections"]))


def _strings(value: Any) -> frozenset[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise ValueError("Invalid setting_event params")
    return frozenset(value)


def _slots(params: dict) -> list[_Slot]:
    """The row's slots, checked; a malformed shipped row is a product fault, never an answer."""
    slots = params.get("setting_slots")
    if not isinstance(slots, list) or not slots:
        raise ValueError("Invalid setting_event params")
    parsed = []
    for slot in slots:
        if not isinstance(slot, dict) or len({"setting_names", "event_names"} & slot.keys()) != 1:
            raise ValueError("Invalid setting_event params")
        by_event = "event_names" in slot
        names = _strings(slot["event_names" if by_event else "setting_names"])
        if "required_values" in slot:
            if {"good_values", "bad_values"} & slot.keys():
                raise ValueError("Invalid setting_event params")
            good, bad, required = frozenset(), frozenset(), _strings(slot["required_values"])
        else:
            good, bad, required = _strings(slot.get("good_values")), _strings(slot.get("bad_values")), None
            if good & bad:
                raise ValueError("Invalid setting_event params")
        parsed.append(_Slot(names, by_event, good, bad, required))
    if params.get("top_delete", "absent") not in {"absent", "violates"} or not isinstance(
            params.get("groups", False), bool):
        raise ValueError("Invalid setting_event params")
    return parsed


def _events(section: Any) -> list[dict]:
    if not isinstance(section, dict) or not isinstance(section.get("events"), list):
        raise Unusable("gws_setting_events is not an event list")
    for event in section["events"]:
        if (not isinstance(event, dict) or not isinstance(event.get("event"), str)
                or not (event.get("setting") is None or isinstance(event["setting"], str))
                or not (event.get("application") is None or isinstance(event["application"], str))):
            raise Unusable("gws_setting_events holds an event without a name")
    return section["events"]


def _time(value: Any) -> Fraction | None:
    """An RFC 3339 time as exact seconds since the epoch, at the nanosecond precision ScubaGoggles compares
    (``time.parse_rfc3339_ns``, SG:scubagoggles/rego/Utils.rego:284-286, 318-320, which drops digits past the
    ninth); anything else, including an out-of-range field or offset, is unreadable and never raises."""
    match = _RFC3339.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    day, clock, fraction, zone = match.groups()
    try:
        whole = datetime.fromisoformat(f"{day}T{clock}{'+00:00' if zone in 'Zz' else zone}")
        seconds = Fraction((whole - _EPOCH) // timedelta(seconds=1))
    except (ValueError, OverflowError):
        return None
    return seconds + Fraction(int(fraction[:9].ljust(9, "0")), 10 ** 9) if fraction else seconds


def _window(section: dict) -> tuple[Fraction, Fraction]:
    start, end = _time(section.get("window_start")), _time(section.get("window_end"))
    if start is None or end is None or start >= end:
        raise Unusable("gws_setting_events has no usable log window")
    return start, end


def _value(event: dict, by_event: bool) -> Any:
    if not by_event and event["event"] == _delete_event():
        return _DELETE
    value = event.get("new_value")
    return value if isinstance(value, str) else _UNREADABLE


def _categories(value: str, known: frozenset[str]) -> frozenset[str] | None:
    """A read category list (Chat.rego:415-447), bracketed or bare, or None when the payload is not one: empty,
    unbalanced brackets, an empty item, or an item outside the pinned categories (``known``): an unrelated field
    or an unrecognised category is never a readable value and never helps a verdict. ``[]`` is a read, empty list."""
    text = value.strip(_ASCII_SPACE)
    if text.startswith("["):
        if len(text) < 2 or not text.endswith("]"):
            return None
        text = text[1:-1].strip(_ASCII_SPACE)
        if not text:
            return frozenset()
    elif not text or text.endswith("]"):
        return None
    items = [_SPACES.sub(" ", part).strip(" ") for part in text.split(",")]
    if not all(item in known for item in items):
        return None
    return frozenset(items)


def _classify(slot: _Slot, value: Any, top: bool, top_delete: str) -> str:
    """``good``, ``bad``, ``unusable``, ``absent`` (a top-level delete, D1) or ``inherit`` (a lower delete)."""
    if value is _DELETE:
        if not top:
            return "inherit"
        return "bad" if top_delete == "violates" else "absent"
    if value is _UNREADABLE:
        return "unusable"
    if slot.required is not None:
        enabled = _categories(value, slot.required)
        if enabled is None:
            return "unusable"
        return "bad" if slot.required - enabled else "good"
    if value in slot.bad:
        return "bad"
    return "good" if value in slot.good else "unusable"


def _last(entries: list[tuple[Fraction | None, Any]]) -> tuple[Fraction | None, Any]:
    """The time and value of the latest event; an unreadable time anywhere in the stream, or a tie at the latest
    time between different values, is unreadable."""
    if any(when is None for when, _ in entries):
        return None, _UNREADABLE
    latest = max(when for when, _ in entries)
    values = {repr(value) if isinstance(value, _Sentinel) else "v:" + value
              for when, value in entries if when == latest}
    if len(values) != 1:
        return latest, _UNREADABLE
    return latest, next(value for when, value in entries if when == latest)


def _clean(value: Any) -> bool:
    """A readable identity string: non-blank, with no surrounding whitespace."""
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _identity(slot: _Slot, event: dict) -> str:
    """``match``, ``skip`` or ``ambiguous``: whether the event is this slot's, positively not, or cannot be told.
    A known other setting, and a setting-less event that is not a setting change (``TOGGLE_CAA_ENABLEMENT``), stay
    isolated. A blank or malformed event name, a setting change whose setting is null or blank, a padded spelling of
    this slot's setting, or a blank or padded application might be this slot's and is never read as a value."""
    name, setting, application = event["event"], event.get("setting"), event.get("application")
    name_ok = _EVENT_NAME.fullmatch(name) is not None
    readable = name_ok and (application is None or _clean(application))
    if slot.by_event:
        if name in slot.names:
            return "match" if readable else "ambiguous"
        return "ambiguous" if not name_ok and not _clean(setting) else "skip"
    if isinstance(setting, str) and setting.strip():
        if setting.strip() not in slot.names:
            return "skip"
        return "match" if readable and _clean(setting) else "ambiguous"
    return "ambiguous" if not name_ok or name.endswith("_APPLICATION_SETTING") else "skip"


class _Gate:
    """The service gate (``AppEnabled``, SG:scubagoggles/rego/Utils.rego:605-625, with D3 and D12)."""

    def __init__(self, units: Units, service: str, org_units: dict[str, str | None], complete: bool):
        self.units, self.service, self.org_units, self.complete = units, service, org_units, complete
        self.candidates = sorted({units.top, *org_units, *units.values})
        self.states = {unit: service_on(units, unit, service) for unit in self.candidates}

    def _below(self, unit: str, ancestor: str) -> bool:
        seen: set[str] = set()
        while unit is not None and unit not in seen:
            if unit == ancestor:
                return True
            seen.add(unit)
            unit = self.org_units.get(unit)
        return False

    def bad_at_ou(self, unit: str) -> str:
        """What a bad value at an OU unit means: ``violates``, ``skip`` or ``unusable``."""
        state = service_on(self.units, unit, self.service)
        if state == ON:
            return "violates"
        if state == UNKNOWN or not self.units.inherits or not self.complete:
            return "unusable"
        # Off here: skipped only if no unit that could take the value has the service on or unknown; an incomplete
        # topology may hide such a unit.
        for candidate, other in self.states.items():
            if candidate != unit and other != OFF and (
                    unit == self.units.top or self._below(candidate.split("/group:")[0], unit)):
                return "unusable"
        return "skip"

    def bad_at_group(self) -> str:
        # A group event carries no OU here; only a service on in every unit makes its bad value a violation.
        return "violates" if all(state == ON for state in self.states.values()) else "unusable"


def setting_event(policy_id: str, row: dict, sections: dict) -> dict:
    params = row["params"]
    slots = _slots(params)
    service = params.get("service")
    try:
        top, topology_complete, _, _ = _topology(sections.get("gws_tenant"))
        org_units = sections["gws_tenant"]["org_units"]
        events = _events(sections.get("gws_setting_events"))
        units = effective_units(sections, [f"{service}_service_status"]) if service else None
    except Unusable:
        return _answer(policy_id, row, "section_shape_unusable")
    if sections["gws_setting_events"].get("complete") is not True:
        return _answer(policy_id, row, "event_read_incomplete")
    try:
        start, end = _window(sections["gws_setting_events"])
    except Unusable:
        return _answer(policy_id, row, "section_shape_unusable")
    if not topology_complete:
        # A cut or broken topology cannot tell a deleted OU from a live one, nor prove a universal service state.
        return _answer(policy_id, row, "section_shape_unusable")
    gate = None
    if service:
        if sections["gws_policies"].get("complete") is not True:
            return _answer(policy_id, row, "policy_read_incomplete")
        gate = _Gate(units, service, org_units, topology_complete)
        if all(state == OFF for state in gate.states.values()):
            return _answer(policy_id, row, "service_off_everywhere")
        if gate.states[top] == UNKNOWN and ON not in gate.states.values():
            return _answer(policy_id, row, "service_status_absent")

    top_delete, groups = params.get("top_delete", "absent"), params.get("groups", False)
    unusable = absent = False
    top_ready = True  # every slot has a readable, current top-level event (Chat.rego:364-379, Assuredcontrols 174-178)
    violations: list[tuple[bool, Fraction | None, list[Fraction | None]]] = []
    for slot in slots:
        streams: dict[tuple[str, str], list[tuple[Fraction | None, Any]]] = {}
        ambiguous: list[Fraction | None] = []
        for event in events:
            identity = _identity(slot, event)
            if identity == "skip":
                continue
            unit = event.get("unit")
            # Known scope first: whatever its identity, an event for a deleted OU or, on a setting that is not
            # group-scoped, for a group never reaches this slot (FilterEventsOU, Utils.rego:423-438).
            if not slot.by_event and isinstance(unit, str):
                if _OU.fullmatch(unit) and unit != top and unit not in org_units:
                    continue  # an OU the complete topology does not hold: deleted
                if _GROUP.fullmatch(unit) and not groups:
                    continue
            when = _time(event.get("time"))
            if when is not None and not start <= when <= end:
                when = None  # dated outside the read's own window: not usable evidence
            if identity == "ambiguous":
                ambiguous.append(when)
                continue
            if slot.by_event:
                place = ("tenant", "")
            elif isinstance(unit, str) and _OU.fullmatch(unit):
                place = ("ou", unit)
            elif isinstance(unit, str) and _GROUP.fullmatch(unit):
                place = ("group", unit)
            else:
                ambiguous.append(when)  # cannot be placed: it might be any unit's change, or a delete
                continue
            streams.setdefault(place, []).append((when, _value(event, slot.by_event)))
        unusable = unusable or bool(ambiguous)
        top_place = ("tenant", "") if slot.by_event else ("ou", top)
        if top_place not in streams:
            absent = True
            top_ready = False
        for place, entries in streams.items():
            when, value = _last(entries)
            verdict = _classify(slot, value, place == top_place, top_delete)
            if place == top_place and (verdict not in {"good", "bad"} or any(
                    other is None or when is None or other >= when for other in ambiguous)):
                # The top unit's own event for this slot is not established: absent, unreadable, tied with a reset,
                # or possibly superseded by an ambiguous change (review M13-L12 round 2 B1).
                top_ready = False
            if verdict == "absent":
                absent = True
            elif verdict == "unusable":
                # A proven off unit nothing inherits from cannot weaken the in-scope result (design 8.2 step 4).
                if gate is None or place[0] != "ou" or gate.bad_at_ou(place[1]) != "skip":
                    unusable = True
            elif verdict == "bad":
                effect = "violates"
                if gate is not None:
                    effect = gate.bad_at_group() if place[0] == "group" else gate.bad_at_ou(place[1])
                if effect == "violates":
                    violations.append((place == top_place, when, ambiguous))
                elif effect == "unusable":
                    unusable = True
    for at_top, when, ambiguous in violations:
        # An ambiguous change not proven older might have superseded the violation; the top unit's own violation
        # counts only once every slot has a top-level event (Chat.rego:323-349, 364-377; children per D17, D19).
        if any(other is None or when is None or other >= when for other in ambiguous):
            unusable = True
        elif not at_top or top_ready:
            return _answer(policy_id, row, "unit_violates")
    if unusable:
        return _answer(policy_id, row, "event_value_unusable")
    if absent:
        return _answer(policy_id, row, "no_setting_event")
    return _answer(policy_id, row, "no_unit_violates")


KINDS = {"setting_event": setting_event}
