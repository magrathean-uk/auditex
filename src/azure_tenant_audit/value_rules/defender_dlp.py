"""SCuBA value rules ported from the v3.9 reference (spec section 3.3).

Reads the in-memory rule view; output text uses only constant policy parameters.
Divergence ids stay in test fixtures. Collection and missing-section checks are
owned by the dispatch boundary.
"""
from __future__ import annotations

import json
import re

from .defender_cascade import _join_key
from .helpers import _cite, _licence_cell, _shape
from .record import _A, _rec

DLP_TYPES = ("U.S. Social Security Number (SSN)", "U.S. Individual Taxpayer Identification Number (ITIN)", "Credit Card Number")
_DLP_RX = re.compile(r"(U.S. Social Security Number \(SSN\))|(U.S. Individual Taxpayer Identification Number \(ITIN\))|(Credit Card Number)")
DLP_LOCATIONS = (("Exchange", "ExchangeLocation", "Exchange"), ("SharePoint", "SharePointLocation", "SharePoint"), ("OneDrive", "OneDriveLocation", "OneDriveForBusiness"),
                 ("Teams", "TeamsLocation", "Teams"), ("Devices", "EndpointDlpLocation", "EndpointDevices"))
DLP_KEYS = ("Name", "ParentPolicyName", "BlockAccess", "BlockAccessScope", "NotifyUser", "NotifyUserType")


def _dlp_names(rule):
    """Info-type names of a rule exactly as the Rego reads them (InfoTypeMatches), or None when they cannot be read exactly. Basic rule: the `name` of each
    ContentContainsSensitiveInformation entry (null = none). Advanced rule: the three literals found by regex in AdvancedRule as a plain string (quotes swapped,
    'rn' removed as the Rego does); a match that exists only because of the 'rn' removal is a Rego artefact (never gold): None."""
    adv = rule.get("IsAdvancedRule")
    if adv is False:
        if "ContentContainsSensitiveInformation" not in rule:
            return None
        c = rule["ContentContainsSensitiveInformation"]
        if c is None:
            return set()
        if not isinstance(c, list) or any(not isinstance(e, dict) or type(e.get("name")) is not str for e in c):
            return None
        return {e["name"] for e in c}
    if adv is True:
        t = rule.get("AdvancedRule")
        if type(t) is not str:
            return None
        raw = t.replace("'", '"')
        stripped = t.replace("rn", "").replace("'", '"')
        names = {m.group(0) for m in _DLP_RX.finditer(stripped)}
        return names if names == {m.group(0) for m in _DLP_RX.finditer(raw)} else None
    return None


def _dlp_not_exception(rule):
    """v3.7 (lens B DLP-F1, D102): True when an advanced rule's JSON shows a required information type inside an `Operator: Not` condition (an exception: content with that type
    is excluded from the rule). Unparsable text is left to the plain-string reading."""
    if rule.get("IsAdvancedRule") is not True or type(rule.get("AdvancedRule")) is not str:
        return False
    try:
        doc = json.loads(rule["AdvancedRule"].replace("'", '"'))
    except ValueError:
        return False

    def walk(n, inside):
        if isinstance(n, dict):
            op = n.get("Operator")
            inside = inside or (type(op) is str and op.lower() == "not")
            return any(walk(v, inside) for v in n.values())
        if isinstance(n, list):
            return any(walk(v, inside) for v in n)
        return inside and type(n) is str and bool(_DLP_RX.search(n))
    return walk(doc, False)


def _dlp_rule(rule, parents_by_name):
    """(class, names) for the SensitiveRules join: excluded, sens, unusable or exception.

    Sensitive rules must be enabled, name an information type and join to an
    enabled parent policy in Mode Enable.
    """
    d = rule.get("Disabled")
    if type(d) is not bool:
        return "unusable", None
    if d:
        return "excluded", None
    names = _dlp_names(rule)
    if names is None:
        return "unusable", None
    if not names:
        return "excluded", names
    if _dlp_not_exception(rule):
        return "exception", names
    if any(k not in rule for k in DLP_KEYS):
        return "unusable", names                  # the Rego builds its set from all six keys: a rule without one is silently dropped
    ps = parents_by_name.get(_join_key(rule["ParentPolicyName"]), [])
    if len(ps) != 1 or type(ps[0].get("Enabled")) is not bool or type(ps[0].get("Mode")) is not str:
        return "unusable", names
    return ("sens" if ps[0]["Enabled"] and ps[0]["Mode"] == "Enable" else "excluded"), names


def _dlp(policy_id, sp, sections):
    out = _licence_cell(policy_id, sections, "defender_dlp_license", "Microsoft Purview Data Loss Prevention")
    if out:
        return out
    POL, RUL = "dlp_compliance_policies", "dlp_compliance_rules"
    out = _shape(policy_id, sections, [POL, RUL], [POL, RUL], sp["sections"])
    if out:
        return out
    pols, rules = sections[POL], sections[RUL]

    def A(code, text, cell, cited, **d):
        return _A(policy_id, code, text, cell, _cite(sp["sections"], *cited), **d)

    parents_by_name = {}
    for p in pols:
        parents_by_name.setdefault(_join_key(p.get("Name")), []).append(p)
    cls = [(r,) + _dlp_rule(r, parents_by_name) for r in rules]
    sens = [(r, n) for r, k, n in cls if k == "sens"]
    exc = sum(1 for _, k, _ in cls if k == "exception")
    unus = sum(1 for _, k, _ in cls if k == "unusable") + exc
    need = sp["need"]

    def unusable_rules():
        text = (
            "Data unusable: a DLP rule shows a required information type only inside a condition with Operator Not (an exception), so it is unknown whether the rule protects "
            "that type; the policy was not assessed."
            if exc and exc == unus else
            "Data unusable: a DLP rule or its parent policy lacks a readable Disabled flag, IsAdvancedRule flag, info-type names, key or parent "
            "policy state, so it is unknown whether it protects the three types; the policy was not assessed."
        )
        return A("data_unusable_dlp_rule", text, "sensitive_rule_unusable", [RUL, POL])

    full = [(r, n) for r, n in sens if all(t in n for t in DLP_TYPES)]
    if need == "types":
        have = {t for t in DLP_TYPES if any(t in n for _, n in sens)}
        if len(have) == 3:
            return _rec(policy_id, "met", "all_types_protected", f"Requirement met: {sp['good']}.", "all_types_protected", None)
        if unus:
            return unusable_rules()
        return _rec(policy_id, "not_met", "types_not_protected", f"Requirement not met: {sp['bad']}.", "types_missing", None, missing=[t for t in DLP_TYPES if t not in have])
    if not full:
        if unus:
            return unusable_rules()
        return _rec(policy_id, "not_met", "no_full_protection_rule", f"Requirement not met: no enabled DLP rule protects all three information types ({sp['bad']}).",
                    "no_full_protection_rule", None)
    if need == "locations":
        def parent(r):
            # Exactly one exists (_dlp_rule); Name may be any JSON value.
            return parents_by_name[_join_key(r["ParentPolicyName"])][0]

        loc_state = {}
        for loc, key, prod in DLP_LOCATIONS:
            sts = []
            for r, _ in full:
                p = parent(r)
                lst, wl = p.get(key), p.get("Workload")
                if not isinstance(lst, list) or type(wl) is not str:
                    sts.append("unusable")
                else:
                    sts.append("yes" if "All" in lst and prod in wl else "no")
            loc_state[loc] = sts
        missing = [loc for loc, s in loc_state.items() if "yes" not in s]
        loose = set()                              # the Rego's value membership (D53): a policy named like any string value of a full rule also counts
        for r, _ in full:
            loose |= {v for k, v in r.items() if k in ("Name", "ParentPolicyName", "BlockAccessScope", "NotifyUserType") and type(v) is str}
        loose_missing = []
        for loc, key, prod in DLP_LOCATIONS:
            if not any(isinstance(p.get(key), list) and "All" in p[key] and type(p.get("Workload")) is str and prod in p["Workload"] and type(p.get("Name")) is str and p["Name"] in loose for p in pols):
                loose_missing.append(loc)
        extra = {"value_membership": True} if bool(missing) != bool(loose_missing) else {}
        if not missing:
            return _rec(policy_id, "met", "all_locations_covered", f"Requirement met: {sp['good']}.", "all_locations_covered", None, **extra)
        if unus or any("unusable" in loc_state[m] for m in missing):
            return A("data_unusable_dlp_policy", "Data unusable: a DLP policy that protects the three types has a location list or Workload that is not readable, or a rule cannot be read; "
                     "the policy was not assessed.", "dlp_policy_unusable", [POL, RUL], **extra)
        return _rec(policy_id, "not_met", "location_not_covered", f"Requirement not met: {sp['bad']} (not covered: " + ", ".join(missing) + ").", "location_not_covered", None,
                    missing=missing, **extra)
    bad, unusable = 0, 0
    for r, _ in full:
        if need == "blocking":
            b, s = r["BlockAccess"], r["BlockAccessScope"]
            if b is False:
                bad += 1
            elif b is True:
                if type(s) is str and s == "All":
                    continue
                if type(s) is str and s == "PerUser":
                    bad += 1
                else:
                    unusable += 1
            else:
                unusable += 1
        else:
            n = r["NotifyUser"]
            if isinstance(n, list):
                bad += 0 if n else 1
            else:
                unusable += 1
    if bad:
        return _rec(policy_id, "not_met", "full_protection_rule_not_" + ("blocking" if need == "blocking" else "notifying"), f"Requirement not met: {sp['bad']}.",
                    "rule_not_blocking" if need == "blocking" else "rule_not_notifying", None)
    if unusable:
        return A("data_unusable_" + ("block_flag" if need == "blocking" else "notify_user"), f"Data unusable: {sp['unusable']}; the policy was not assessed.",
                 "block_flag_unusable" if need == "blocking" else "notify_unusable", [RUL])
    if unus:
        return unusable_rules()
    return _rec(policy_id, "met", "all_full_protection_rules_" + ("block" if need == "blocking" else "notify"), f"Requirement met: {sp['good']}.",
                "all_rules_block" if need == "blocking" else "all_rules_notify", None)


def dlp_rules(policy_id: str, row: dict, sections: dict) -> dict:
    return _dlp(policy_id, {**row["params"], "sections": row["sections"]}, sections)


KINDS = {"dlp_rules": dlp_rules}
