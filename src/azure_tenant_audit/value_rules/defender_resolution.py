"""Safe Links policy resolution (SS 7.x), ported from the v3.9 reference.

A preset needs both its EOP and Defender rules. Custom policy resolution judges
an earlier partial rule before the covering rule or Built-In fallback.
accepted_domains is optional and only informs domain-scope comparisons.
"""
from __future__ import annotations

from .helpers import BUILTIN, PRESET_RE, _accepted, _cover, _licence_cell
from .record import BAD_SECTION_LIST, ITEM_VALUE, _A, _rec


def _is_num(value):
    """Reference numeric Priority contract: booleans are not numbers."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _safelinks(policy_id, sp, sections):
    trace = {}
    rec = _safelinks_core(policy_id, sp, sections, trace)
    if trace.get("via"):
        rec["detail"]["via_domain_scope"] = True
    if trace.get("eop_only") and rec["cell"] != "preset_covers" and rec["detail"].get("div") is None:
        rec["detail"]["div"] = "D100"
    return rec


def _preset_states(rules, accepted, trace):
    """v3.7: per preset tier ('Strict', 'Standard') the cover states ('q' / 'x' / 'u') of the enabled rules whose Identity matches it, plus the states that belong to no tier
    (an unreadable Identity or State may be any tier). A disabled rule is skipped (as the Rego)."""
    by, anyu = {"Strict": [], "Standard": []}, []
    for r in rules:
        if not isinstance(r, dict):
            continue
        ident = r.get("Identity")
        if type(ident) is not str:
            anyu.append("u")
            continue
        tiers = [n for n, rx in zip(("Strict", "Standard"), PRESET_RE) if rx.search(ident)]
        if not tiers:
            continue
        if "State" not in r:
            s = "u"
        elif r["State"] != "Enabled":
            continue
        else:
            s = _cover(r, accepted, trace)
        for n in tiers:
            by[n].append(s)
    return by, anyu


def _safelinks_core(policy_id, sp, sections, trace):
    for name in ("protection_policy_rules", "safe_links_policies", "safe_links_rules", "atp_policy_rules"):
        if not isinstance(sections[name], list):
            return _A(policy_id, BAD_SECTION_LIST, f"Data unusable: {name} is not a list of objects; the policy was not assessed.", "section_not_a_list", [name])
    lic = _licence_cell(policy_id, sections, "defender_license")      # v3.7 (lens B DEF-F3, D101): Safe Links need Defender for Office 365; a false read can be a failed command
    if lic:
        return lic
    if not sections["protection_policy_rules"] and not sections["safe_links_rules"]:
        # v3.1 ruling 5 (D30): an empty rule list is not_met (no preset applies to anyone). Read as both lists empty (see the spec, Q11).
        return _rec(policy_id, "not_met", "no_rules_configured",
                    f"Requirement not met: no preset security policy rule and no Safe Links rule exists, so no Standard, Strict or custom Safe Links policy applies ({sp['what']}).",
                    "no_rules_configured", None)
    accepted = _accepted(sections)
    # v3.7 (lens B DEF-F2, D100): a preset applies Safe Links only when both its EOP rule (protection_policy_rules) and its Defender rule (atp_policy_rules) are enabled and cover everyone
    eop, eop_u = _preset_states([e for e in sections["protection_policy_rules"]], accepted, trace)
    atp, atp_u = _preset_states([e for e in sections["atp_policy_rules"]], accepted, trace)
    maybe = False
    for tier in ("Strict", "Standard"):
        e, a_ = eop[tier], atp[tier]
        if "q" in e and "q" in a_:
            return _rec(policy_id, "met", "preset_covers_all_recipients",
                        f"Requirement met: an enabled Standard or Strict preset security policy applies to all recipients, in both its Exchange Online Protection and its Defender for Office 365 rule ({sp['what']}).", "preset_covers", None)
        if "q" in e:
            trace["eop_only"] = True          # D100: the EOP part covers, the Defender part does not (the Rego reads the EOP rule alone and says met)
        if ((("q" in e) or ("u" in e) or eop_u) and (("q" in a_) or ("u" in a_) or atp_u)) and ("u" in e or "u" in a_ or eop_u or atp_u):
            maybe = True
    if maybe:
        return _A(policy_id, "data_unusable_preset_rule",
                  "Data unusable: a protection policy rule that may be a preset (Exchange Online Protection or Defender for Office 365 part) has an unreadable identity, state or recipient scope; the policy was not assessed.",
                  "preset_rule_unusable", ["protection_policy_rules", "atp_policy_rules"])
    rules = [e for e in sections["safe_links_rules"] if isinstance(e, dict)]
    cand, unk, partial = [], False, []
    for r in rules:
        if "State" not in r:
            unk = True
        elif r["State"] == "Enabled":
            c = _cover(r, accepted, trace)
            if c == "q":
                cand.append(r)
            elif c == "u":
                unk = True
            else:
                partial.append(r)
    if unk:
        return _A(policy_id, "data_unusable_safe_links_rule",
                  "Data unusable: an enabled Safe Links rule has an unreadable recipient scope; the policy was not assessed.", "rule_unusable", ["safe_links_rules"])
    if not cand:
        applied = BUILTIN
    else:
        if any(not _is_num(r.get("Priority")) for r in cand) or any(type(r.get("SafeLinksPolicy")) is not str for r in cand):
            return _A(policy_id, "data_unusable_safe_links_rule", "Data unusable: a covering Safe Links rule has no numeric Priority or no policy name; the policy was not assessed.",
                      "rule_unusable", ["safe_links_rules"])
        low = min(r["Priority"] for r in cand)
        top = [r for r in cand if r["Priority"] == low]
        if len(top) > 1:
            return _A(policy_id, "data_unusable_rule_priority_tie",
                      "Data unusable: two covering Safe Links rules share the lowest Priority; the policy was not assessed.", "rule_priority_tie", ["safe_links_rules"])
        applied = top[0]["SafeLinksPolicy"]
    # v3.7 (lens B DEF-F1, D98; as SS 6.x D32): an enabled rule that covers only some recipients and applies before the covering rule (a lower Priority number, or no covering
    # rule at all) gives those recipients its policy; when that policy is exported with a flag off, the named recipients get a non-compliant policy: not_met. A partial rule
    # whose precedence or policy cannot be read is left as in v3.6 (it does not decide).
    low_cov = min(r["Priority"] for r in cand) if cand else None
    # Policies by Identity, built once (a string Identity is the only thing a string name equals): one list scan per
    # partial rule was quadratic in rules times policies.
    by_identity: dict = {}
    for e in sections["safe_links_policies"]:
        if isinstance(e, dict) and type(e.get("Identity")) is str:
            by_identity.setdefault(e["Identity"], []).append(e)
    for r in partial:
        pr = r.get("Priority")
        if cand and not (_is_num(pr) and pr < low_cov):
            continue
        name = r.get("SafeLinksPolicy")
        pp = by_identity.get(name, []) if type(name) is str else []
        if len(pp) == 1 and any(type(pp[0].get(f)) is bool and not pp[0][f] for f in sp["flags"]):
            return _rec(policy_id, "not_met", "partial_scope_policy_flag_off",
                        f"Requirement not met: an enabled Safe Links rule applies to some recipients only and its policy does not enable {sp['what']}, so those recipients get a non-compliant policy.",
                        "partial_rule_noncompliant", None, div="D98")
    pols = by_identity.get(applied, [])
    if not pols:
        return _A(policy_id, "data_unavailable_applied_policy_not_exported",
                  "Data unavailable: the applied Safe Links policy is not in safe_links_policies; the policy was not assessed.", "policy_not_in_export",
                  ["safe_links_policies"])
    if len(pols) > 1:
        return _A(policy_id, "data_unusable_applied_policy_duplicated",
                  "Data unusable: the applied Safe Links policy appears more than once; the policy was not assessed.", "policy_duplicated", ["safe_links_policies"])
    flags = [("unusable" if type(pols[0].get(f)) is not bool else ("on" if pols[0][f] else "off")) for f in sp["flags"]]
    if "off" in flags:
        return _rec(policy_id, "not_met", "applied_policy_flag_off", f"Requirement not met: the applied Safe Links policy does not enable {sp['what']}.",
                    "policy_flag_off", None, applied="built_in" if applied == BUILTIN else "custom")
    if "unusable" in flags:
        return _A(policy_id, ITEM_VALUE, "Data unusable: the applied Safe Links policy lacks a boolean value for a flag the policy reads; the policy was not assessed.",
                  "policy_flag_unusable", ["safe_links_policies"])
    return _rec(policy_id, "met", "applied_policy_flags_on", f"Requirement met: the applied Safe Links policy enables {sp['what']}.", "policy_flags_ok", None,
                applied="built_in" if applied == BUILTIN else "custom")


def safelinks_resolution(policy_id: str, row: dict, sections: dict) -> dict:
    return _safelinks(policy_id, row["params"], sections)


KINDS = {"safelinks_resolution": safelinks_resolution}
