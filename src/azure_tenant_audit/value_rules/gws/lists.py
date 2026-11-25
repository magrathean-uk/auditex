"""``gws_list_settings``: Gmail address-list and rule-state policies, API access controls and system alert rules
(design M13 8.2).

GMAIL 14.1, 17.1, 18.1 to 18.3 and COMMONCONTROLS 10.1, 10.2 and 13.1. Each row names one ``check`` in its params.
The logic of SG:scubagoggles/parsers/gmail_rules_parser.py and SG:scubagoggles/parsers/system_rules_parser.py is
transcribed here over the minimised shapes (design section 6, first row): an address list is ``{id, entry_count,
domain_entry_count}``, so the rule works on list ids and counts and never sees an address.

- A Gmail rule (override, storage rule or address list) is on when its ``gmail_rule_states`` entry says
  ``enabled: true`` in the unit's own entry, as ``_enabled_rules(ou_policies)`` reads it; the top unit's states are
  never borrowed. ScubaGoggles reads an absent entry as disabled; here an absent, unreadable or non-bool entry is
  unknown, and every rule state the check reads must be readable before the answer is met (review round 2).
- Address lists are read at the top unit with the top unit's rule states, as ``_gmail_address_lists`` does.
- ``ServiceToScopeMapping`` (SG:scubagoggles/rego/Commoncontrols.rego:1345-1364), the high-risk scope groups (:1411)
  and the 30 system alert rule names with their default states (SG:scubagoggles/parsers/system_rules_parser.py:16-114)
  are pinned in the row params with their cites, never in code.
- CC.10.1 follows D6 and CC.10.2 D2: no ``api_controls_google_services`` in any unit is unknown. An unreadable or
  unrecognised service entry blocks both answers for 10.1 and a met for 10.2.
- A unit with the service on that holds no section of its own is judged by the top unit's section, with the top
  unit's rule states, even when the service is off at the top unit (review B1).
- Unknown is not safe (design 8.4): a malformed, blank, wrong-typed, inconsistent or unrecognised value (a missing or
  non-bool rule state, a blank id, an id spelled two ways, a list with more domain entries than entries, an unknown
  enum, an unnamed alert row, a string that is not an IP address or range) or a referenced list that was not read
  never answers met or not_met. Gmail ids are non-blank strings or integers. No top-level value is unknown (8.2 step
  6) whatever the top unit's service state. One positively read
  violation wins over unusable values elsewhere, except where the unusable value could be the violation itself.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from ..record import _rec
from .reduce import (
    MISSING,
    OFF,
    ON,
    UNKNOWN,
    UNUSABLE,
    Units,
    Unusable,
    effective_units,
    service_on,
)

_CITED = ("gws_tenant", "gws_policies")


def _say(policy_id: str, cell: str) -> dict:
    """The constant answer of one cell; no input value ever enters a text."""
    for name, verdict, code, text in (
        ("section_shape_unusable", "not_assessed", "data_unusable_section_shape",
         "Data unusable: the Google Workspace policy or org unit evidence has the wrong shape for this check."),
        ("policy_read_incomplete", "not_assessed", "data_unavailable_policy_read_incomplete",
         "Data unavailable: the Google Workspace policy or org unit read was incomplete, so an unset value cannot be "
         "told from an unread one."),
        ("service_off_everywhere", "not_applicable", "service_off_everywhere",
         "Not applicable: the service this policy covers is read as off in every org unit and group."),
        ("service_status_absent", "not_assessed", "data_unavailable_service_status_absent",
         "Data unavailable: the service on or off status could not be read for a unit this policy covers."),
        ("unit_violates", "not_met", "unit_violates",
         "Requirement not met: at least one org unit or group holds a value this policy forbids."),
        ("setting_value_unusable", "not_assessed", "data_unusable_setting_value",
         "Data unusable: a setting, list or rule state this policy reads is malformed, unknown or ambiguous."),
        ("setting_absent", "not_assessed", "data_unavailable_setting_absent",
         "Data unavailable: the setting this policy reads was not returned and no default is pinned, so compliance "
         "is unknown."),
        ("no_unit_violates", "met", "no_unit_violates",
         "Requirement met: no org unit or group holds a value this policy forbids."),
    ):
        if name == cell:
            return _rec(policy_id, verdict, code, text, cell, list(_CITED))
    raise ValueError("Unknown gws_list_settings cell")


def _flag(mapping: dict, name: str) -> bool | None:
    """An enable flag: absent (proto3 JSON omits a false bool) or false is off, true is on, anything else (an explicit
    null included) is unknown."""
    if name not in mapping or mapping[name] is False:
        return False
    return True if mapping[name] is True else None


def _id(value: Any) -> bool:
    """A Gmail rule or list id: a non-blank string or an integer (the L03 minimiser keeps integer ids and the L02
    ``max_map`` reducer keys on them, review round 2 B3). A blank string, a bool, a float or any other type identifies
    no rule or list."""
    if isinstance(value, str):
        return bool(value.strip())
    return isinstance(value, int) and not isinstance(value, bool)


def _ids(value: Any) -> bool:
    """A list of usable Gmail list ids."""
    return isinstance(value, list) and all(_id(item) for item in value)


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _matches(items: Any, field: str, wanted: Any) -> list[dict] | None:
    """The entries of ``items`` whose ``field`` is ``wanted``; None when the list cannot be read, holds an entry
    without a usable id (that entry may be the one wanted, review B3), or holds an id that reads the same as
    ``wanted`` but is spelled differently (``42`` against ``"42"``, ``" o1"`` against ``"o1"``): which one is meant
    is unknown (review round 2 B3)."""
    if not isinstance(items, list) or any(not isinstance(item, dict) or not _id(item.get(field)) for item in items):
        return None
    found = [item for item in items if str(item[field]).strip() == str(wanted).strip()]
    if any(type(item[field]) is not type(wanted) or item[field] != wanted for item in found):
        return None
    return found


def _rule_state(units: Units, unit: str, rule_id: Any) -> bool | None:
    """``enabled`` of one Gmail rule in the unit's own ``gmail_rule_states`` (gmail_rules_parser.py:277-293); None
    when the unit holds no readable entry for it (ScubaGoggles: disabled; here unknown), when the id is unusable, when
    entries for it disagree, or when ``enabled`` is anything but a JSON bool: ``1``, ``0``, ``1.0`` and ``0.0`` equal
    ``True`` and ``False`` in Python and must never pass for them (review round 2 B1)."""
    if not _id(rule_id):
        return None
    value = units.values.get(unit, {}).get("gmail_rule_states", MISSING)
    found = _matches(value.get("ruleStates") if isinstance(value, dict) else None, "ruleId", rule_id)
    states = [item.get("enabled") for item in found or ()]
    if not states or any(not isinstance(state, bool) for state in states) or len(set(states)) != 1:
        return None
    return states[0]


def _list_has_domains(units: Units, list_id: Any) -> bool | None:
    """Whether one top-level address list is on and holds a domain-shaped entry (``_gmail_address_lists`` and
    ``_gmail_domain_addr``); None when the list, its counts or its state cannot be read, or the counts are
    impossible: more domain entries than entries, or a domain count with no readable total (review B2). The list's
    state is read even when it holds no domain entry: an unreadable state never confirms met (review round 2)."""
    if not _id(list_id):
        return None
    value = units.values[units.top].get("gmail_email_address_lists", MISSING)
    found = _matches(value.get("emailAddressList") if isinstance(value, dict) else None, "id", list_id)
    counts = {(_count(item.get("entry_count")), _count(item.get("domain_entry_count"))) for item in found or ()}
    if len(counts) != 1:
        return None
    total, domains = counts.pop()
    if total is None or domains is None or domains > total:
        return None
    state = _rule_state(units, units.top, list_id)
    return None if state is None else state and domains > 0


def _override_fields(check: str) -> tuple[str, str | None]:
    """The enable flag and the address-list field one check reads in a spam override (gmail_rules_parser.py). Kept
    out of module-level constants and dict displays, which the redaction registry reads as product field names."""
    if check == "gmail_hide_warning_all":
        return "hideWarningBannerForAll", None
    if check == "gmail_bypass_domains":
        return "bypassSelectedSenders", "bypassSenderAllowlist"
    return "hideWarningBannerFromSelectedSenders", "hideWarningBannerSenderAllowlist"


def _override(units: Units, unit: str, override: Any, check: str) -> bool | None:
    """Whether one spam override violates the check. Every field the check reads must be readable whatever the
    others say: the primary key (a blank or wrong-typed ``ruleId`` is unknown even with the flag false, review round
    2 B4), the enable flag, the address-list field and the override's rule state. A list is looked up only when the
    flag is on, since an off flag never applies it."""
    if not isinstance(override, dict) or not _id(override.get("ruleId")):
        return None
    enable, allow = _override_fields(check)
    on = _flag(override, enable)
    if on is None or allow is not None and not _ids(override.get(allow, [])):
        return None
    state = _rule_state(units, unit, override["ruleId"])
    if state is None:
        return None
    if not state or not on or allow is None:
        return state and on
    found = [_list_has_domains(units, list_id) for list_id in override.get(allow, [])]
    if True in found:
        return True
    return None if None in found else False


def _overrides(check: str):
    def judge(units: Units, unit: str, value: Any) -> bool | None:
        overrides = value.get("spamOverride") if isinstance(value, dict) else None
        if not isinstance(overrides, list):
            return None
        found = [_override(units, unit, override, check) for override in overrides]
        if True in found:
            return True
        return None if None in found else False
    return judge


def _storage(units: Units, unit: str, value: Any) -> bool | None:
    """GMAIL.17.1: the storage rule's ``enabled`` (the parser's ``mail_storage``) must be true."""
    rule_id = value.get("ruleId") if isinstance(value, dict) else None
    if not _id(rule_id):
        return None
    state = _rule_state(units, unit, rule_id)
    return None if state is None else not state


def _gate(units: Units, service: str, scope: list[str]) -> str | None:
    states = {service_on(units, unit, service) for unit in scope}
    if ON in states:
        return None
    return "service_status_absent" if UNKNOWN in states else "service_off_everywhere"


def _scan(units: Units, section: str, service: str, judge) -> str:
    """Every unit with the service on or unknown (``some OU, settings in input.policies``), each judged by its own
    section or, without one, by the top unit's section with the top unit's rule states: the top unit's setting
    applies on behalf of a unit that inherits it, even with the service off at the top (review B1). One
    violation wins over unusable values and unknown service states elsewhere. Reached only on a complete read, so the
    topology is unbroken and every unit inherits the top unit."""
    gate = _gate(units, service, sorted(units.values))
    if gate:
        return gate
    # Design 8.2 step 6 and 8.4: no top-level value and no pinned default is unknown, even with the service off at
    # the top unit and a child holding its own value (review round 2 B2).
    absent = units.values[units.top].get(section, MISSING) is MISSING
    unusable = unknown_service = False
    for unit in sorted(units.values):
        state = service_on(units, unit, service)
        if state == OFF:
            continue
        source = unit if units.values[unit].get(section, MISSING) is not MISSING else units.top
        value = units.values[source].get(section, MISSING)
        if value is MISSING:
            outcome = None
        else:
            outcome = None if value is UNUSABLE else judge(units, source, value)
        if state == UNKNOWN:
            unknown_service = unknown_service or outcome is not False
        elif outcome is True:
            return "unit_violates"
        elif outcome is None and value is not MISSING:
            unusable = True
    if unusable:
        return "setting_value_unusable"
    if unknown_service:
        return "service_status_absent"
    return "setting_absent" if absent else "no_unit_violates"


def _ip_allowlist(units: Units) -> str:
    """GMAIL.14.1: the top unit's allow-list (Gmail.rego:1445-1448). The list is domain-wide, so it counts when Gmail
    is on in any unit; ScubaGoggles counts it only when Gmail is on at the top unit (proposed divergence, lead)."""
    gate = _gate(units, "gmail", sorted(units.values))
    if gate:
        return gate
    value = units.values[units.top].get("gmail_email_spam_filter_ip_allowlist", MISSING)
    if value is MISSING or isinstance(value, dict) and "allowedIpAddresses" not in value:
        return "setting_absent"
    addresses = value.get("allowedIpAddresses") if isinstance(value, dict) else None
    if not isinstance(addresses, list) or not all(_address(item) for item in addresses):
        return "setting_value_unusable"
    return "unit_violates" if addresses else "no_unit_violates"


def _address(item: Any) -> bool:
    """An IPv4 or IPv6 address or CIDR range; a blank or arbitrary string is not one (review B6)."""
    if not isinstance(item, str):
        return False
    try:
        ipaddress.ip_network(item, strict=False)
    except ValueError:
        return False
    return True


def _api_scopes(units: Units, params: dict) -> tuple[bool, bool, set[str]]:
    """Whether any unit holds ``api_controls_google_services``, whether any of it is unreadable or outside the pinned
    mapping, and every pinned scope group read (``EnabledScopes``, every OU and group). A scope group outside the
    mapping may be another spelling of a pinned one, so it is unusable (review B4)."""
    known = {scope for service in params["values"] for scope in service["scopes"]}
    present = unusable = False
    scopes: set[str] = set()
    for unit in sorted(units.values):
        value = units.values[unit].get("api_controls_google_services", MISSING)
        if value is MISSING:
            continue
        present = True
        services = value.get("services") if isinstance(value, dict) else None
        if not isinstance(services, list):
            unusable = True
            continue
        for service in services:
            group = service.get("scopesGroup") if isinstance(service, dict) else None
            if isinstance(group, str) and group in known:
                scopes.add(group)
            else:
                unusable = True
    return present, unusable, scopes


def _restricted(units: Units, params: dict) -> str:
    """CC.10.1: every pinned service has one of its scope groups restricted somewhere (Commoncontrols.rego:1366-1379).
    An unreadable or unrecognised entry answers neither met nor not_met (review B4); D6 for an absent section."""
    present, unusable, scopes = _api_scopes(units, params)
    if not present:
        return "setting_absent"
    if unusable:
        return "setting_value_unusable"
    if all(set(service["scopes"]) & scopes for service in params["values"]):
        return "no_unit_violates"
    return "unit_violates"


def _high_risk(units: Units, params: dict) -> str:
    """CC.10.2: no unit restricts a service to its high-risk scope group only (Commoncontrols.rego:1411-1418); D2. A
    scope group outside the pinned mapping may be a high-risk one under another spelling, so it is unknown."""
    present, unusable, scopes = _api_scopes(units, params)
    if scopes & set(params["scopes"]):
        return "unit_violates"
    if unusable:
        return "setting_value_unusable"
    return "no_unit_violates" if present else "setting_absent"


def _system_alerts(units: Units, params: dict) -> str:
    """CC.13.1: every pinned system rule ACTIVE at the top unit, a rule not returned taking its pinned default
    (``SystemRulesParser``; Commoncontrols.rego:1736-1741). A returned row without a readable, non-blank name may be
    any pinned rule, a default or a duplicate that contradicts a named state, so it answers neither met nor not_met
    (review B5); duplicates that disagree are unknown."""
    value = units.values[units.top].get("rule_system_defined_alerts", MISSING)
    if value is not MISSING and not isinstance(value, list):
        return "setting_value_unusable"
    pinned = {rule["name"] for rule in params["rules"]}
    seen: dict[str, set] = {}
    anonymous = False
    for entry in [] if value is MISSING else value:
        name = entry.get("displayName") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name.strip():
            anonymous = True
        elif name in pinned:
            state = entry.get("state")
            seen.setdefault(name, set()).add(state if isinstance(state, str) else None)
    if anonymous:
        return "setting_value_unusable"
    explicit = default = unknown = False
    for rule in params["rules"]:
        states = seen.get(rule["name"])
        if states is None:
            if rule["value"] != "ACTIVE":
                default = True
        elif len(states) != 1 or not states <= {"ACTIVE", "INACTIVE"}:
            unknown = True
        elif states == {"INACTIVE"}:
            explicit = True
    if explicit:
        return "unit_violates"
    if unknown:
        return "setting_value_unusable"
    return "unit_violates" if default else "no_unit_violates"


def _plan(check: Any) -> tuple[tuple[str, ...], Any]:
    """The policy sections a check reduces and its evaluator; an unknown check is a catalogue fault."""
    gmail = ("gmail_service_status", "gmail_rule_states")
    if check == "gmail_ip_allowlist":
        return ("gmail_service_status", "gmail_email_spam_filter_ip_allowlist"), lambda units, _: _ip_allowlist(units)
    if check == "gmail_mail_storage":
        return (*gmail, "gmail_comprehensive_mail_storage"), lambda units, _: _scan(
            units, "gmail_comprehensive_mail_storage", "gmail", _storage)
    if check == "gmail_hide_warning_all":
        # Reads the override flag and its rule state only, so address-list evidence never changes it (review M1).
        return (*gmail, "gmail_spam_override_lists"), lambda units, _: _scan(
            units, "gmail_spam_override_lists", "gmail", _overrides(check))
    if check in {"gmail_bypass_domains", "gmail_warning_domains"}:
        return (*gmail, "gmail_spam_override_lists", "gmail_email_address_lists"), lambda units, _: _scan(
            units, "gmail_spam_override_lists", "gmail", _overrides(check))
    if check == "api_services_restricted":
        return ("api_controls_google_services",), _restricted
    if check == "api_no_high_risk":
        return ("api_controls_google_services",), _high_risk
    if check == "system_alerts_active":
        return ("rule_system_defined_alerts",), _system_alerts
    raise ValueError("Unknown gws_list_settings check")


def gws_list_settings(policy_id: str, row: dict, sections: dict) -> dict:
    keys, evaluate = _plan(row["params"].get("check"))
    try:
        units = effective_units(sections, keys)
    except Unusable:
        return _say(policy_id, "section_shape_unusable")
    if not units.complete:
        return _say(policy_id, "policy_read_incomplete")
    return _say(policy_id, evaluate(units, row["params"]))


KINDS = {"gws_list_settings": gws_list_settings}
