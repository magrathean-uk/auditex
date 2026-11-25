"""``setting_event``: the 12 ScubaGoggles v1.1.0 policies decided from admin setting-change logs (design M13 8.2).

Each row's ``params`` hold ``setting_slots``: one slot per setting the policy needs, each naming its ``setting_names`` (or,
for COMMONCONTROLS.2.1, its ``event_names``, read with no unit) and either ``good_values`` and ``bad_values`` or the
``required_values`` a comma list must hold (CHAT.5.2). ``groups`` says whether group-scoped events count;
``top_delete`` is ``violates`` where the Rego counts a top-level delete as non-compliant (CHAT.5.x); ``service`` names
the service gate (GEMINI.1.1).

- The last event per (slot, unit) wins (SG:scubagoggles/rego/Utils.rego:230-234); names of one slot share one stream
  (GEMINI.2.1, SG:scubagoggles/rego/Gemini.rego:90-105). Two last events at one time that disagree are unusable.
- ``DELETE_APPLICATION_SETTING`` is a value, as SG:scubagoggles/rego/Utils.rego:318-346 makes it. Below the top unit
  it hands the setting back to the parent, which is checked on its own. At the top unit it returns the setting to a
  default no log shows, so it counts as no top-level event (D1) unless the row says it ``violates``.
- An event for an OU outside a complete topology is for a deleted OU and is skipped, as ScubaGoggles' ``FilterEventsOU``
  does (SG:scubagoggles/rego/Utils.rego:423-438). An event that cannot be placed otherwise (no unit, a malformed one,
  an OU outside an incomplete topology) never answers met: a bad or unreadable value or a delete there is unusable.
- A value outside the row's good and bad values, a null value or an unreadable time is unusable, never compliant.
- One violation wins over unusable values elsewhere. With no violation, an unusable value answers not_assessed, then
  a top unit lacking any slot's event answers not_assessed ``no_setting_event`` (D1), else met.
- The service gate skips a bad value only where the service is off, the topology is complete and no unit that could
  inherit the value has it on or unknown; a bad value under an unknown state is unusable.

Where this is stricter than ScubaGoggles, always toward not_assessed or a positively read violation (for the lead to
number in design 8.3): a top-level delete is no event (ScubaGoggles passes it); a string outside the pinned values is
unusable where the Rego fails anything but the good value (GMAIL.13.1, CC.2.1, CC.3.x); a CHAT.5.1 child OU is judged
per setting, not only when it has all four (Chat.rego:283-296); a GEMINI.1.1 group event carries no OU, so its bad
value is a violation only with the service on in every unit, else unusable (Gemini.rego:38-39 reads the event's OU).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
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
                or not (event.get("setting") is None or isinstance(event["setting"], str))):
            raise Unusable("gws_setting_events holds an event without a name")
    return section["events"]


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _value(event: dict, by_event: bool) -> Any:
    if not by_event and event["event"] == _delete_event():
        return _DELETE
    value = event.get("new_value")
    return value if isinstance(value, str) else _UNREADABLE


def _classify(slot: _Slot, value: Any, top: bool, top_delete: str) -> str:
    """``good``, ``bad``, ``unusable``, ``absent`` (a top-level delete, D1) or ``inherit`` (a lower delete)."""
    if value is _DELETE:
        if not top:
            return "inherit"
        return "bad" if top_delete == "violates" else "absent"
    if value is _UNREADABLE:
        return "unusable"
    if slot.required is not None:
        enabled = {_SPACES.sub(" ", part).strip(" []") for part in value.split(",")}
        return "bad" if slot.required - enabled else "good"
    if value in slot.bad:
        return "bad"
    return "good" if value in slot.good else "unusable"


def _last(entries: list[tuple[datetime | None, Any]]) -> Any:
    """The value of the latest event; an unreadable time anywhere in the stream, or a tie at the latest time between
    different values, is unreadable."""
    if any(when is None for when, _ in entries):
        return _UNREADABLE
    latest = max(when for when, _ in entries)
    values = {repr(value) if isinstance(value, _Sentinel) else "v:" + value
              for when, value in entries if when == latest}
    if len(values) != 1:
        return _UNREADABLE
    return next(value for when, value in entries if when == latest)


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
        top, topology_complete, _ = _topology(sections.get("gws_tenant"))
        org_units = sections["gws_tenant"]["org_units"]
        events = _events(sections.get("gws_setting_events"))
        units = effective_units(sections, [f"{service}_service_status"]) if service else None
    except Unusable:
        return _answer(policy_id, row, "section_shape_unusable")
    if sections["gws_setting_events"].get("complete") is not True:
        return _answer(policy_id, row, "event_read_incomplete")
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
    violation = unusable = absent = False
    for slot in slots:
        streams: dict[tuple[str, str], list[tuple[datetime | None, Any]]] = {}
        for event in events:
            if (event["event"] if slot.by_event else event.get("setting")) not in slot.names:
                continue
            value = _value(event, slot.by_event)
            unit = event.get("unit")
            if slot.by_event:
                place = ("tenant", "")
            elif isinstance(unit, str) and _OU.fullmatch(unit) and (unit == top or unit in org_units):
                place = ("ou", unit)
            elif isinstance(unit, str) and _OU.fullmatch(unit) and topology_complete:
                continue  # an OU the complete topology does not hold: deleted
            elif isinstance(unit, str) and _GROUP.fullmatch(unit):
                if not groups:
                    continue  # the setting is not group-scoped (FilterEventsOU drops group events)
                place = ("group", unit)
            else:
                # Cannot be placed: a bad or unreadable value here might be any unit's, and a delete might be the
                # top unit's (D1, or a violation where the row says so).
                if value is _DELETE or _classify(slot, value, False, top_delete) in {"bad", "unusable"}:
                    unusable = True
                continue
            streams.setdefault(place, []).append((_time(event.get("time")), value))
        top_place = ("tenant", "") if slot.by_event else ("ou", top)
        if top_place not in streams:
            absent = True
        for place, entries in streams.items():
            verdict = _classify(slot, _last(entries), place == top_place, top_delete)
            if verdict == "absent":
                absent = True
            elif verdict == "unusable":
                unusable = True
            elif verdict == "bad":
                effect = "violates"
                if gate is not None:
                    effect = gate.bad_at_group() if place[0] == "group" else gate.bad_at_ou(place[1])
                if effect == "violates":
                    violation = True
                elif effect == "unusable":
                    unusable = True
    if violation:
        return _answer(policy_id, row, "unit_violates")
    if unusable:
        return _answer(policy_id, row, "event_value_unusable")
    if absent:
        return _answer(policy_id, row, "no_setting_event")
    return _answer(policy_id, row, "no_unit_violates")


KINDS = {"setting_event": setting_event}
