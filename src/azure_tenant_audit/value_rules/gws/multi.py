"""``settings_multi``: the 14 policies whose verdict combines fields or depends on another field's mode (design M13
sections 3 item 5, 8.2 and 14).

One catalogue kind; ``params.kind`` names the sub-kind, one per ScubaGoggles Rego pattern:

- ``sharing_mode`` (DRIVEDOCS 1.2 to 1.5 and 1.7, SG:scubagoggles/rego/Drive.rego:93-123, 158-188, 225-255,
  291-302, 389-400): the effective ``externalSharingMode`` picks the checks that apply. An ``own`` check reads only
  the unit's own value and an absent one never counts (1.2 DISALLOWED, :93-104); an ``effective`` check reads the
  unit's value, else the top unit's, and applies only when the mode or its field is explicit in the unit.
- ``own_any_bad`` (GMAIL 5.5, 7.6 and 9.1, GROUPS 4.1, COMMONCONTROLS 12.1; SG Gmail.rego:620-634, 1015-1028,
  1154-1196, Groups.rego:243-262, Commoncontrols.rego:1636-1670): a field present in the unit with a value outside
  ``good`` violates; absent fields are ignored. At the top unit ``required`` says whether one (``any``) or every
  (``all``) field must be present for the unit to be read at all.
- ``effective_any_bad`` (DRIVEDOCS 3.1, COMMONCONTROLS 11.1; Drive.rego:619-638, Commoncontrols.rego:1568-1600):
  any effective field outside ``good`` violates.
- ``effective_all_bad`` (DRIVEDOCS 5.1, CHAT 4.1; Drive.rego:723-741, Chat.rego:211-221): the unit violates only
  when every effective field is outside ``good``; one field read as compliant decides the unit.

"Effective" is the unit's own value, else the top unit's (design 8.1). A unit other than the top unit is evaluated
only when at least one participating field is explicit in it; the top unit always is, its pinned defaults included.
Unknown is not safe (design 8.4): a wrong type, an unknown enum or an ``*_UNSPECIFIED`` value is unusable; an absent
value at the top unit with no pinned default is ``setting_absent``; neither ever answers met. Answers carry only the
catalogued constant texts.
"""
from __future__ import annotations

from typing import Any, NamedTuple

from ..record import _rec
from .catalogue import section_semantics
from .reduce import (
    MISSING,
    OFF,
    ON,
    UNUSABLE,
    Unusable,
    effective,
    effective_units,
    service_on,
)

# Unit results, ordered: a violation wins, then an unknown service state, then an unusable value, then an absent one.
_OK, _ABSENT, _UNUSABLE, _SERVICE_UNKNOWN, _BAD = range(5)


class _Check(NamedTuple):
    section: str
    field: str
    type: str
    good: tuple
    known: tuple
    mode: str | None
    scope: str


class _Params(NamedTuple):
    kind: str
    service: str | None
    checks: tuple[_Check, ...]
    mode: _Check | None
    required: str | None


def _bad_params() -> None:
    raise ValueError("Invalid GWS settings_multi params")


def _check(raw: Any, sharing: bool, is_mode: bool = False) -> _Check:
    allowed = {"section", "field", "good", "values"} | ({"mode", "scope"} if sharing and not is_mode else set())
    if not isinstance(raw, dict) or set(raw) - allowed or not isinstance(raw.get("section"), str) \
            or not isinstance(raw.get("field"), str):
        _bad_params()
    fields = section_semantics(raw["section"])["fields"]
    kind = fields.get(raw["field"])
    good = raw.get("good", [])
    if kind not in {"bool", "enum", "state"} or not isinstance(good, list) or (not good and not is_mode):
        _bad_params()
    if kind == "bool":
        known: tuple = (False, True)
        if "values" in raw or is_mode:
            _bad_params()
    else:
        values = raw.get("values")
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values) \
                or len(set(values)) != len(values):
            _bad_params()
        known = tuple(values)
    if any(type(value) is not type(known[0]) or value not in known for value in good):
        _bad_params()
    mode, scope = raw.get("mode"), raw.get("scope", "effective")
    if sharing and not is_mode and (not isinstance(mode, str) or scope not in {"own", "effective"}):
        _bad_params()
    return _Check(raw["section"], raw["field"], kind, tuple(good), known, mode, scope)


def _params(raw: Any) -> _Params:
    """The row's params, refused with ``ValueError`` when malformed (the dispatcher answers ``rule_evaluation_failed``);
    ``tests/test_gws_value_rules_multi.py`` loads every shipped row through here."""
    if not isinstance(raw, dict) or raw.get("kind") not in {"sharing_mode", "own_any_bad", "effective_any_bad",
                                                             "effective_all_bad"}:
        _bad_params()
    kind = raw["kind"]
    sharing = kind == "sharing_mode"
    allowed = {"kind", "service", "checks"} | ({"mode"} if sharing else set()) | (
        {"required"} if kind == "own_any_bad" else set())
    service = raw.get("service")
    if set(raw) - allowed or "service" not in raw or service is not None and (
            not isinstance(service, str) or not service):
        _bad_params()
    if service is not None:
        section_semantics(f"{service}_service_status")
    if not isinstance(raw.get("checks"), list) or not raw["checks"]:
        _bad_params()
    checks = tuple(_check(item, sharing) for item in raw["checks"])
    if len({(check.section, check.field, check.mode) for check in checks}) != len(checks):
        _bad_params()
    mode = _check(raw.get("mode"), sharing, is_mode=True) if sharing else None
    if mode is not None and any(check.mode not in mode.known for check in checks):
        _bad_params()
    required = raw.get("required")
    if (kind == "own_any_bad") != (required in {"any", "all"}):
        _bad_params()
    return _Params(kind, service, checks, mode, required)


def _own(units, unit: str, section: str, field: str) -> Any:
    """The unit's own value (at the top unit, pinned defaults included); ``MISSING`` or ``UNUSABLE``."""
    value = units.values.get(unit, {}).get(section, MISSING)
    if value is MISSING:
        return MISSING
    if not isinstance(value, dict):
        return UNUSABLE
    return value.get(field, MISSING)


def _judge(check: _Check, value: Any) -> int:
    if value is MISSING:
        return _ABSENT
    if value is UNUSABLE:
        return _UNUSABLE
    if check.type == "bool":
        if not isinstance(value, bool):
            return _UNUSABLE
    else:
        if not isinstance(value, str):
            return _UNUSABLE
        value = value.upper() if check.type == "state" else value
        if value not in check.known:
            return _UNUSABLE
    return _OK if value in check.good else _BAD


def _explicit(units, unit: str, pairs: list[tuple[str, str]]) -> bool | None:
    """Whether any participating field is the unit's own; None when it cannot be told (an unreducible section)."""
    unknown = False
    for section, field in pairs:
        value = _own(units, unit, section, field)
        if value is UNUSABLE:
            unknown = True
        elif value is not MISSING:
            return True
    return None if unknown else False


def _worst(results: list[int]) -> int:
    return max(results, default=_OK)


def _sharing_mode(units, unit: str, params: _Params) -> int:
    mode = params.mode
    value = effective(units, unit, mode.section, mode.field)
    picked = _judge(mode, value)
    if picked in {_ABSENT, _UNUSABLE}:
        return picked
    results = []
    for check in params.checks:
        if check.mode != value:
            continue
        if check.scope == "own":
            own = _own(units, unit, check.section, check.field)
            results.append(_OK if own is MISSING else _judge(check, own))
            continue
        explicit = _explicit(units, unit, [(mode.section, mode.field), (check.section, check.field)])
        if explicit is None:
            results.append(_UNUSABLE)
        elif explicit:
            results.append(_judge(check, effective(units, unit, check.section, check.field)))
    return _worst(results)


def _own_any_bad(units, unit: str, params: _Params) -> int:
    results = [_judge(check, _own(units, unit, check.section, check.field)) for check in params.checks]
    if _BAD in results or _UNUSABLE in results or unit != units.top:
        return _worst([result for result in results if result != _ABSENT])
    absent = [check for check, result in zip(params.checks, results, strict=True) if result == _ABSENT]
    if absent and (params.required == "all" or len(absent) == len(results)):
        # An absent top-level service state is D3's ``service_status_absent``, never DISABLED.
        return _SERVICE_UNKNOWN if any(check.type == "state" for check in absent) else _ABSENT
    return _OK


def _effective_any_bad(units, unit: str, params: _Params) -> int:
    return _worst([_judge(check, effective(units, unit, check.section, check.field)) for check in params.checks])


def _effective_all_bad(units, unit: str, params: _Params) -> int:
    results = [_judge(check, effective(units, unit, check.section, check.field)) for check in params.checks]
    if _OK in results:
        return _OK
    # Violating only when every field is read as violating: an absent or unusable field leaves the unit unknown.
    unknown = [result for result in results if result != _BAD]
    return max(unknown) if unknown else _BAD


def _evaluator(kind: str):
    # Chosen by comparison, not a mapping: a sub-kind name is a params value, never a product field name.
    if kind == "sharing_mode":
        return _sharing_mode
    if kind == "own_any_bad":
        return _own_any_bad
    return _effective_any_bad if kind == "effective_any_bad" else _effective_all_bad


def _answer(policy_id: str, row: dict, cell: str) -> dict:
    entry = row["cells"][cell]
    return _rec(policy_id, entry["verdict"], entry["reason_code"], entry["reason_texts"][0], cell,
                list(entry["cited"]))


def settings_multi(policy_id: str, row: dict, sections: dict) -> dict:
    params = _params(row["params"])
    pairs = [(check.section, check.field) for check in params.checks]
    if params.mode is not None:
        pairs.insert(0, (params.mode.section, params.mode.field))
    keys = sorted({section for section, _ in pairs} | (
        {f"{params.service}_service_status"} if params.service else set()))
    try:
        units = effective_units(sections, keys)
    except Unusable:
        return _answer(policy_id, row, "section_shape_unusable")
    if not units.complete:
        return _answer(policy_id, row, "policy_read_incomplete")
    states = {unit: service_on(units, unit, params.service) for unit in units.values} if params.service else {}
    if params.service and ON not in states.values():
        off = all(state == OFF for state in states.values())
        return _answer(policy_id, row, "service_off_everywhere" if off else "service_status_absent")
    evaluate = _evaluator(params.kind)
    results = []
    for unit in sorted(units.values):
        explicit = True if unit == units.top else _explicit(units, unit, pairs)
        if explicit is False:
            continue
        state = states.get(unit, ON)
        if state == OFF:
            continue
        if state != ON:
            results.append(_SERVICE_UNKNOWN)
        elif explicit is None:
            results.append(_UNUSABLE)
        else:
            results.append(evaluate(units, unit, params))
    worst = _worst(results)
    cell = {_BAD: "unit_violates", _SERVICE_UNKNOWN: "service_status_absent", _UNUSABLE: "setting_value_unusable",
            _ABSENT: "setting_absent", _OK: "no_unit_violates"}[worst]
    return _answer(policy_id, row, cell)


KINDS = {settings_multi.__name__: settings_multi}
