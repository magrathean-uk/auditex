"""Cross-kind value-rule helpers (spec v3.9 sections 2, 3 and 3.3; reference ``ref_impl.py`` of the pinned kit).

Helpers return records built by ``record._rec``; the shipped inventory is enforced once at the dispatch
boundary (``value_rules.assess``), so a helper can be unit-tested for a policy whose kind ships later.
No helper puts an input value into a text: texts interpolate only section, field and setting names from
the policy parameters, or names from a closed list.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Iterable

from azure_tenant_audit.scuba_precheck import gate_value

from .record import BAD_SECTION_LIST, EMPTY_SECTION, ITEM_LABEL, ITEM_VALUE, _A, _marker, _rec

__all__ = ["_marker", "_int", "_lst", "_list_state", "_flag", "_label", "_scan_bad_wins", "_scan_good_wins",
           "_shape", "_licence_cell", "_p2_gate", "_gate_slider", "_env_cell", "_accepted", "PRESET_RE", "BUILTIN",
           "_empty3", "_cover", "_state", "_preset_pair", "_cite"]


# ---- typed readers ----
def _int(value: Any) -> int | None:
    """A typed integer: int (never bool) or an integral float; else None."""
    if type(value) is int:
        return value
    if type(value) is float and value.is_integer():
        return int(value)
    return None


def _lst(data: Any, *path: str, null_parent_empty: bool = False) -> list[str] | None:
    """List of strings at ``path``. A null leaf is an empty list (Graph's unset collection); an absent key, a
    non-list or a non-string element is None (unusable). With ``null_parent_empty`` a null parent gives []."""
    cur = data
    for key in path:
        if cur is None and null_parent_empty:
            return []
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    if cur is None:
        return []
    if isinstance(cur, list) and all(type(item) is str for item in cur):
        return cur
    return None


def _cite(order: Iterable[str], *names: str) -> list[str]:
    """``names`` in the rule's section order (the catalogue's ``sections``)."""
    return [name for name in order if name in names]


# ---- list sections: the common cells of every list policy (spec 2.1; D14, D15) ----
def _list_state(policy_id: str, sections: dict[str, Any], name: str) -> tuple[dict | None, list[dict]]:
    """(record or None, object items). Not a list -> section_not_a_list; no object element -> no_usable_items.
    Non-object elements beside a usable object are ignored."""
    value = sections[name]
    if not isinstance(value, list):
        return _A(policy_id, BAD_SECTION_LIST, f"Data unusable: {name} is not a list of objects; the policy was not assessed.",
                  "section_not_a_list", [name]), []
    items = [item for item in value if isinstance(item, dict)]
    if not items:
        return _A(policy_id, EMPTY_SECTION, f"Data unavailable: {name} holds no objects; the policy was not assessed.",
                  "no_usable_items", [name]), []
    return None, items


def _flag(item: dict, field: str, bad: bool) -> str:
    """'bad' (the boolean equals ``bad``), 'clear' (the other boolean) or 'unusable' (absent, null, not a boolean)."""
    if field not in item or type(item[field]) is not bool:
        return "unusable"
    return "bad" if item[field] == bad else "clear"


def _label(key: str, null_ok: bool = False) -> Callable[[dict], bool]:
    """Whether an object is visible to the Rego's result set: a string label; with ``null_ok`` (TEAMS 4.1, EXO 5.1,
    whose Rego only counts the set) the key present with a string or null."""
    if null_ok:
        return lambda item: key in item and (item[key] is None or type(item[key]) is str)
    return lambda item: type(item.get(key)) is str


def _scan_bad_wins(policy_id: str, params: dict[str, Any], sections: dict[str, Any],
                   evaluate: Callable[[dict], str], label_ok: Callable[[dict], bool]) -> dict:
    """Monotone violation scan (spec 3, C7 and C11): one labelled bad object is not_met even if others are
    unusable; an unlabelled bad object is not_assessed (D17); met needs every object usable and clear."""
    name = params["section"]
    out, items = _list_state(policy_id, sections, name)
    if out:
        return out
    bad_labelled = bad_unlabelled = unusable = 0
    for item in items:
        state = evaluate(item)
        if state == "bad":
            if label_ok(item):
                bad_labelled += 1
            else:
                bad_unlabelled += 1
        elif state == "unusable":
            unusable += 1
    what = params["what"]
    if bad_labelled:
        return _rec(policy_id, "not_met", "violation_found", f"Requirement not met: {what} (found in {name}).", "flag_bad")
    if bad_unlabelled:
        seen = params.get("seen", "that " + what)
        return _A(policy_id, ITEM_LABEL,
                  f"Data unusable: an object in {name} shows {seen} but carries no name or identity; the policy was not assessed.",
                  "flag_bad_unlabelled", [name])
    if unusable:
        return _A(policy_id, ITEM_VALUE,
                  f"Data unusable: an object in {name} lacks a usable value for the field the policy reads; the policy was not assessed.",
                  "flag_unusable", [name])
    return _rec(policy_id, "met", "no_violation_found", f"Requirement met: no object in {name} shows that {what}.", "all_clear")


def _scan_good_wins(policy_id: str, params: dict[str, Any], sections: dict[str, Any]) -> dict:
    """Existence scan (any_true_is_met): a labelled true object is met; an unlabelled one is not_assessed (D17); no true
    object and some unusable is not_assessed (D16); every object explicitly false is not_met."""
    name, field, label = params["section"], params["field"], params["label"]
    out, items = _list_state(policy_id, sections, name)
    if out:
        return out
    good_labelled = good_unlabelled = unusable = 0
    for item in items:
        state = _flag(item, field, True)              # "bad" here means the field is true, the wanted state
        if state == "bad":
            if label in item:
                good_labelled += 1
            else:
                good_unlabelled += 1
        elif state == "unusable":
            unusable += 1
    what = params["what"]
    if good_labelled:
        return _rec(policy_id, "met", "enabled_found", f"Requirement met: {what}.", "flag_true")
    if good_unlabelled:
        return _A(policy_id, ITEM_LABEL,
                  f"Data unusable: an object in {name} shows that {what} but carries no identity; the policy was not assessed.",
                  "flag_true_unlabelled", [name])
    if unusable:
        return _A(policy_id, ITEM_VALUE,
                  f"Data unusable: an object in {name} lacks a usable value for {field}; the policy was not assessed.",
                  "flag_unusable", [name])
    return _rec(policy_id, "not_met", "not_enabled", f"Requirement not met: no object in {name} shows that {what}.", "none_enabled")


# ---- shape and licence cells of the v3.3 and v3.4 kinds (stages 4 to 7) ----
def _shape(policy_id: str, sections: dict[str, Any], lists: Iterable[str], objects: Iterable[str],
           order: Iterable[str]) -> dict | None:
    """Every section in ``lists`` must be a list (section_not_a_list, D14); every element of ``objects`` an object
    (list_element_unusable, D47). ``order`` is the rule's section order."""
    for name in lists:
        if not isinstance(sections[name], list):
            return _A(policy_id, BAD_SECTION_LIST, f"Data unusable: {name} is not a list of objects; the policy was not assessed.",
                      "section_not_a_list", [name])
    for name in objects:
        if any(not isinstance(item, dict) for item in sections[name]):
            return _A(policy_id, "data_unusable_list_element",
                      f"Data unusable: {name} holds an element that is not an object; the policy was not assessed.",
                      "list_element_unusable", _cite(order, name))
    return None


LICENCE_WORDS = {"defender_license": ("the Defender settings", "the anti-phishing settings"),
                 "defender_dlp_license": ("the DLP settings", "the DLP policies and rules")}
LICENCE_NOT_DETECTED = "licence not detected"


def _licence_cell(policy_id: str, sections: dict[str, Any], key: str, licence_name: str | None = None) -> dict | None:
    """Licence tri-state (main ruling 3; C12, D21): absent is section_not_collected (earlier); not a boolean is
    licence_flag_unusable; false is licence_false ("licence not detected", code data_unavailable_no_licence); true
    proceeds."""
    value = sections[key]
    unknown_what, read_what = LICENCE_WORDS[key]
    if type(value) is not bool:
        return _A(policy_id, "data_unavailable_licence_flag_unusable",
                  f"Data unavailable: {key} is not a boolean, so it is unknown whether {unknown_what} could be read; the policy was not assessed.",
                  "licence_flag_unusable", [key])
    if value is False:
        return _A(policy_id, "data_unavailable_no_licence",
                  f"Data unavailable: {LICENCE_NOT_DETECTED}: no {licence_name or 'Defender for Office 365'} licence was found "
                  f"(a false read can also mean missing permissions or a failed command), so {read_what} could not be read; "
                  "the policy was not assessed.", "licence_false", [key])
    return None


AAD_P2 = "AAD_PREMIUM_P2"


def _p2_gate(policy_id: str, sections: dict[str, Any]) -> dict | None:
    """Entra ID P2 gate (D55; v3.7 AAD-B6: an entry without ServicePlanId counts for nothing)."""
    plans = sections["service_plans"]
    if not isinstance(plans, list):
        return _A(policy_id, BAD_SECTION_LIST, "Data unusable: service_plans is not a list of objects; the policy was not assessed.",
                  "section_not_a_list", ["service_plans"])
    if not any(isinstance(item, dict) and item.get("ServicePlanName") == AAD_P2 and "ServicePlanId" in item for item in plans):
        return _A(policy_id, "data_unavailable_no_licence",
                  f"Data unavailable: {LICENCE_NOT_DETECTED}: no Microsoft Entra ID P2 service plan was found (this can also mean "
                  "missing permissions or a failed read), so the policy was not assessed.",
                  "licence_not_detected", ["service_plans"])
    return None


SLIDER_RULE = {"section": "SPO_tenant", "path": ["SharingCapability"], "value_type": "integer",
               "allowed_values": [0, 1, 2, 3]}


def _gate_slider(sections: dict[str, Any]) -> int | None:
    """The SharePoint sharing slider exactly as the shared precheck reads it (``scuba_precheck.gate_value``): one
    source for the gate decision. A singleton list or an object of SPO_tenant; SharingCapability an integer 0 to 3."""
    return gate_value(SLIDER_RULE, sections)


ENVIRONMENT_TEXT = ("Data unusable: scuba_config does not state the M365 environment as commercial, gcc, gcchigh or dod; "
                    "the policy was not assessed.")


def _env_cell(policy_id: str, sections: dict[str, Any]) -> dict | None:
    """Teams environment gates (C9, D19): after the closed gate and section_not_collected, the rule proceeds only when
    ``scuba_config.M365Environment`` is exactly ``commercial``; anything else is environment_unknown."""
    config = sections["scuba_config"]
    environment = config.get("M365Environment") if isinstance(config, dict) else None
    if type(environment) is str and environment == "commercial":
        return None
    return _A(policy_id, "data_unusable_environment_field", ENVIRONMENT_TEXT, "environment_unknown", ["scuba_config"])


# ---- H1 to H5: Defender preset and rule resolution (vector coverage in stages 4 and 5) ----
PRESET_RE = (re.compile(r"Strict Preset Security Policy", re.I), re.compile(r"Standard Preset Security Policy", re.I))  # H2
BUILTIN = "Built-In Protection Policy"


def _accepted(sections: dict[str, Any]) -> set[str] | None:
    """H1 (v3.1 ruling 5, D31): the accepted domains, trimmed and lower-cased, or None when the section is absent, a
    marker, not a list, empty, or any element lacks a usable DomainName (partial or unknown)."""
    value = sections.get("accepted_domains")
    if not isinstance(value, list) or not value:
        return None
    names = set()
    for item in value:
        if not isinstance(item, dict) or type(item.get("DomainName")) is not str or not item["DomainName"].strip():
            return None
        names.add(item["DomainName"].strip().lower())
    return names


def _empty3(item: dict, key: str) -> bool | None:
    """True: null or []; False: a non-empty list; None: absent or another type."""
    if key not in item:
        return None
    value = item[key]
    if value is None:
        return True
    return (len(value) == 0) if isinstance(value, list) else None


EXCEPT_KEYS = ("ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")


def _cover(item: dict, accepted: set[str] | None, trace: dict, excl: str = "unknown") -> str:
    """H3: 'q' the rule covers all recipients, 'x' it does not, 'u' unknown. A non-empty SentTo or SentToMemberOf
    narrows ('x'); RecipientDomainIs alone covers only when it includes every accepted domain (fewer: 'x'; accepted
    domains unknown or a non-string domain: 'u'); a non-empty ExceptIf* on an otherwise covering rule is 'u', or 'x'
    with ``excl='narrows'`` when every exclusion is a list (SS 6.x, D41)."""
    states = [_empty3(item, key) for key in ("SentTo", "SentToMemberOf", "RecipientDomainIs")]
    if states[0] is False or states[1] is False:
        return "x"
    if None in states:
        return "u"
    if states[2] is False:
        trace["via"] = True
        domains = item["RecipientDomainIs"]
        if accepted is None or not isinstance(domains, list) or any(type(d) is not str for d in domains):
            return "u"
        if not accepted <= {d.strip().lower() for d in domains}:
            return "x"
        if not accepted <= set(domains):
            trace["case"] = True
    exclusions = [item[key] for key in EXCEPT_KEYS if key in item and item[key] is not None
                  and not (isinstance(item[key], list) and not item[key])]
    if exclusions:
        if excl == "narrows" and all(isinstance(value, list) for value in exclusions):
            trace["excl"] = True
            return "x"
        return "u"
    return "q"


def _state(rule: dict) -> str | None:
    """H4: a rule's State, exactly Enabled or Disabled; anything else is None (rule_state_unusable, D47)."""
    value = rule.get("State")
    return value if type(value) is str and value in ("Enabled", "Disabled") else None


def _preset_pair(rules: list[dict], policies: list[dict], tier: re.Pattern, other: re.Pattern
                 ) -> tuple[list[dict], list[dict], bool]:
    """H5: (rules matching the tier, policies matching it, topology usable). Not usable when more than one rule or policy
    matches, or a matching rule also matches the other tier."""
    mine = [rule for rule in rules if tier.search(rule["Identity"])]
    matched = [policy for policy in policies if tier.search(policy["Identity"])]
    usable = len(mine) <= 1 and len(matched) <= 1 and not any(other.search(rule["Identity"]) for rule in mine)
    return mine, matched, usable
