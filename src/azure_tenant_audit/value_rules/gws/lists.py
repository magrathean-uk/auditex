"""``lists``: Gmail address-list and rule-state policies, API access controls and system alert rules (design M13 8.2).

GMAIL 14.1, 17.1, 18.1 to 18.3 and COMMONCONTROLS 10.1, 10.2 and 13.1. Each row names one ``check`` in its params.
The logic of SG:scubagoggles/parsers/gmail_rules_parser.py and SG:scubagoggles/parsers/system_rules_parser.py is
transcribed here over the minimised shapes (design section 6, first row): an address list is ``{id, entry_count,
domain_entry_count}``, so the rule works on list ids and counts and never sees an address.

- A Gmail rule (override, storage rule or address list) is on when its ``gmail_rule_states`` entry says
  ``enabled: true`` in the unit's own entry, as ``_enabled_rules(ou_policies)`` reads it; the top unit's states are
  never borrowed. ScubaGoggles reads an absent entry as disabled; here an absent or unreadable entry is unknown, and it
  only matters when the rule would otherwise decide the answer.
- Address lists are read at the top unit with the top unit's rule states, as ``_gmail_address_lists`` does.
- ``ServiceToScopeMapping`` (SG:scubagoggles/rego/Commoncontrols.rego:1345-1364), the high-risk scope groups (:1411)
  and the 30 system alert rule names with their default states (SG:scubagoggles/parsers/system_rules_parser.py:16-114)
  are pinned in the row params with their cites, never in code.
- CC.10.1 follows D6 and CC.10.2 D2: no ``api_controls_google_services`` in any unit is unknown. An unreadable
  service entry can only hide a restriction, so it blocks a not_met for 10.1 and never a met.
- Unknown is not safe (design 8.4): a malformed value, a missing rule state, an unknown enum or a referenced list that
  was not read never answers met. One positively read violation wins over unusable values elsewhere.
"""
from __future__ import annotations

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
    raise ValueError("Unknown lists cell")


def _flag(mapping: dict, name: str) -> bool | None:
    """An enable flag: absent (proto3 JSON omits a false bool) or false is off, true is on, anything else (an explicit
    null included) is unknown."""
    if name not in mapping or mapping[name] is False:
        return False
    return True if mapping[name] is True else None


def _rule_state(units: Units, unit: str, rule_id: Any) -> bool | None:
    """``enabled`` of one Gmail rule in the unit's own ``gmail_rule_states`` (gmail_rules_parser.py:277-293); None
    when the unit holds no readable entry for it (ScubaGoggles: disabled; here unknown)."""
    value = units.values.get(unit, {}).get("gmail_rule_states", MISSING)
    if not isinstance(value, dict) or not isinstance(value.get("ruleStates"), list):
        return None
    for item in value["ruleStates"]:
        if isinstance(item, dict) and item.get("ruleId") == rule_id:
            enabled = item.get("enabled")
            return enabled if isinstance(enabled, bool) else None
    return None


def _list_has_domains(units: Units, list_id: Any) -> bool | None:
    """Whether one top-level address list is on and holds a domain-shaped entry (``_gmail_address_lists`` and
    ``_gmail_domain_addr``); None when the list, its count or its state cannot be read."""
    if not isinstance(list_id, str | int) or isinstance(list_id, bool):
        return None
    value = units.values[units.top].get("gmail_email_address_lists", MISSING)
    if not isinstance(value, dict) or not isinstance(value.get("emailAddressList"), list):
        return None
    for entry in value["emailAddressList"]:
        if isinstance(entry, dict) and entry.get("id") == list_id:
            count = entry.get("domain_entry_count")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                return None
            if count == 0:
                return False
            return _rule_state(units, units.top, list_id)
    return None


def _override_effect(units: Units, override: dict, check: str) -> bool | None:
    """Whether one spam override would violate the check if it is on."""
    if check == "gmail_hide_warning_all":
        return _flag(override, "hideWarningBannerForAll")
    if check == "gmail_bypass_domains":
        enable, allow = "bypassSelectedSenders", "bypassSenderAllowlist"
    else:
        enable, allow = "hideWarningBannerFromSelectedSenders", "hideWarningBannerSenderAllowlist"
    on = _flag(override, enable)
    if on is False:
        return False
    list_ids = override.get(allow, [])
    if not isinstance(list_ids, list):
        return None
    found = [_list_has_domains(units, list_id) for list_id in list_ids]
    if all(item is False for item in found):
        return False
    return True if on is True and True in found else None


def _overrides(check: str):
    def judge(units: Units, unit: str, value: Any) -> bool | None:
        overrides = value.get("spamOverride") if isinstance(value, dict) else None
        if not isinstance(overrides, list):
            return None
        result: bool | None = False
        for override in overrides:
            if not isinstance(override, dict):
                result = None
                continue
            state = _rule_state(units, unit, override.get("ruleId"))
            if state is False:
                continue
            effect = _override_effect(units, override, check)
            if effect is True and state is True:
                return True
            if effect is not False:
                result = None
        return result
    return judge


def _storage(units: Units, unit: str, value: Any) -> bool | None:
    """GMAIL.17.1: the storage rule's ``enabled`` (the parser's ``mail_storage``) must be true."""
    rule_id = value.get("ruleId") if isinstance(value, dict) else None
    if not isinstance(rule_id, str) or not rule_id:
        return None
    state = _rule_state(units, unit, rule_id)
    return None if state is None else not state


def _gate(units: Units, service: str, scope: list[str]) -> str | None:
    states = {service_on(units, unit, service) for unit in scope}
    if ON in states:
        return None
    return "service_status_absent" if UNKNOWN in states else "service_off_everywhere"


def _scan(units: Units, section: str, service: str, judge) -> str:
    """Every unit holding the section with the service on (``some OU, settings in input.policies``); one violation
    wins over unusable values and unknown service states elsewhere."""
    gate = _gate(units, service, sorted(units.values))
    if gate:
        return gate
    unusable = unknown_service = False
    for unit in sorted(units.values):
        value = units.values[unit].get(section, MISSING)
        if value is MISSING:
            continue
        state = service_on(units, unit, service)
        if state == OFF:
            continue
        outcome = None if value is UNUSABLE else judge(units, unit, value)
        if state == UNKNOWN:
            unknown_service = unknown_service or outcome is not False
        elif outcome is True:
            return "unit_violates"
        elif outcome is None:
            unusable = True
    if unusable:
        return "setting_value_unusable"
    if unknown_service:
        return "service_status_absent"
    if units.values[units.top].get(section, MISSING) is MISSING:
        return "setting_absent"
    return "no_unit_violates"


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
    if not isinstance(addresses, list) or any(not isinstance(item, str) for item in addresses):
        return "setting_value_unusable"
    return "unit_violates" if addresses else "no_unit_violates"


def _api_scopes(units: Units) -> tuple[bool, bool, set[str]]:
    """Whether any unit holds ``api_controls_google_services``, whether any of it is unreadable, and every scope
    group read (``EnabledScopes``, every OU and group)."""
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
            if isinstance(group, str) and group:
                scopes.add(group)
            else:
                unusable = True
    return present, unusable, scopes


def _restricted(units: Units, params: dict) -> str:
    """CC.10.1: every pinned service has one of its scope groups restricted somewhere (Commoncontrols.rego:1366-1379).
    An unreadable entry may be a missing restriction, so it blocks not_met; D6 for an absent section."""
    present, unusable, scopes = _api_scopes(units)
    if not present:
        return "setting_absent"
    if all(set(service["scopes"]) & scopes for service in params["values"]):
        return "no_unit_violates"
    return "setting_value_unusable" if unusable else "unit_violates"


def _high_risk(units: Units, params: dict) -> str:
    """CC.10.2: no unit restricts a service to its high-risk scope group only (Commoncontrols.rego:1411-1418); D2. A
    scope group outside the pinned mapping may be a high-risk one under another spelling, so it is unknown."""
    present, unusable, scopes = _api_scopes(units)
    if scopes & set(params["scopes"]):
        return "unit_violates"
    known = {scope for service in params["values"] for scope in service["scopes"]}
    if unusable or scopes - known:
        return "setting_value_unusable"
    return "no_unit_violates" if present else "setting_absent"


def _system_alerts(units: Units, params: dict) -> str:
    """CC.13.1: every pinned system rule ACTIVE at the top unit, a rule not returned taking its pinned default
    (``SystemRulesParser``; Commoncontrols.rego:1736-1741). A returned rule without a readable name may be any
    pinned rule, so no default is trusted beside it; duplicates that disagree are unknown."""
    value = units.values[units.top].get("rule_system_defined_alerts", MISSING)
    if value is not MISSING and not isinstance(value, list):
        return "setting_value_unusable"
    pinned = {rule["name"] for rule in params["rules"]}
    seen: dict[str, set] = {}
    anonymous = False
    for entry in [] if value is MISSING else value:
        name = entry.get("displayName") if isinstance(entry, dict) else None
        if not isinstance(name, str):
            anonymous = True
        elif name in pinned:
            state = entry.get("state")
            seen.setdefault(name, set()).add(state if isinstance(state, str) else None)
    explicit = default = unknown = False
    for rule in params["rules"]:
        states = seen.get(rule["name"])
        if states is None:
            if anonymous:
                unknown = True
            elif rule["value"] != "ACTIVE":
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
    if check in {"gmail_bypass_domains", "gmail_warning_domains", "gmail_hide_warning_all"}:
        return (*gmail, "gmail_spam_override_lists", "gmail_email_address_lists"), lambda units, _: _scan(
            units, "gmail_spam_override_lists", "gmail", _overrides(check))
    if check == "api_services_restricted":
        return ("api_controls_google_services",), _restricted
    if check == "api_no_high_risk":
        return ("api_controls_google_services",), _high_risk
    if check == "system_alerts_active":
        return ("rule_system_defined_alerts",), _system_alerts
    raise ValueError("Unknown lists check")


def lists(policy_id: str, row: dict, sections: dict) -> dict:
    keys, evaluate = _plan(row["params"].get("check"))
    try:
        units = effective_units(sections, keys)
    except Unusable:
        return _say(policy_id, "section_shape_unusable")
    if not units.complete:
        return _say(policy_id, "policy_read_incomplete")
    return _say(policy_id, evaluate(units, row["params"]))


KINDS = {"lists": lists}
