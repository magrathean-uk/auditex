"""SCuBA value rules ported from the v3.9 reference (spec section 3.3).

Reads the in-memory rule view; output text uses only constant policy parameters.
Divergence ids stay in test fixtures. Collection and missing-section checks are
owned by the dispatch boundary.
"""
from __future__ import annotations

from .helpers import (PRESET_RE, _accepted, _cite, _cover, _empty3, _licence_cell,
                      _preset_pair, _shape, _state)
from .record import _A, _rec

CASCADE_PRESETS = tuple(zip(("Strict", "Standard"), PRESET_RE))


def _join_key(value):
    """Hash a JSON join value with Python equality, without normalising it.

    Lists stay ordered, objects ignore key order, and numeric/boolean equality
    is retained. Container tags keep objects, lists and scalar values distinct.
    """
    if isinstance(value, dict):
        return (dict, frozenset((k, _join_key(v)) for k, v in value.items()))
    if isinstance(value, list):
        return (list, tuple(_join_key(v) for v in value))
    return value


def _is_num(value):
    """Priority accepts numbers, including fractional floats, but never booleans."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


CASCADE = {"malware": dict(ad="accepted_domains", pol="anti_malware_policies", cr="anti_malware_rules", pp="protection_policy_rules", link="MalwareFilterPolicy",
                           fallback="Default", bi=None, label="default"),
           "attachment": dict(ad="accepted_domains", pol="safe_attachment_policies", cr="safe_attachment_rules", pp="atp_policy_rules", link="SafeAttachmentPolicy",
                              fallback="Built-In Protection Policy", bi="built_in_protection_rules", label="builtin")}
FILE_REQUIRED = ("exe", "cmd", "vbe")
ATTACH_OK, ATTACH_BAD = ("Block", "DynamicDelivery"), ("Allow", "Replace")
CASCADE_MET = {"Strict": ("strict_covers_compliant", "strict_preset_covers_all_recipients_compliant"),
               "Standard": ("standard_covers_compliant", "standard_preset_covers_all_recipients_compliant"),
               "custom": ("custom_covers_compliant", "custom_policy_covers_all_recipients_compliant"),
               "default": ("default_compliant", "default_policy_applies_compliant"),
               "builtin": ("builtin_compliant", "built_in_protection_policy_applies_compliant")}
CASCADE_NOT_MET = {"Strict": ("preset_noncompliant", "applied_preset_noncompliant"), "Standard": ("preset_noncompliant", "applied_preset_noncompliant"),
                   "custom": ("custom_noncompliant", "applied_custom_policy_noncompliant"),
                   "default": ("default_noncompliant", "applied_default_policy_noncompliant"),
                   "builtin": ("builtin_noncompliant", "applied_built_in_protection_policy_noncompliant")}


EXCEPT_KEYS = ("ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")


def _cover_custom(item, accepted, trace):
    """H3 for the custom rules of SS 1.x and 2.x: `_cover` with "narrows", plus: a rule that would cover everyone but lacks an ExceptIf* key is unreadable (the Rego's
    RuleFieldEmpty is undefined on an absent key, so the rule silently does not cover: D47). Presets never read ExceptIf*."""
    cv = _cover(item, accepted, trace, "narrows")
    if cv == "q" and any(k not in item for k in EXCEPT_KEYS):
        return "u"
    return cv


def _cascade_leaf(sp, pol):
    """Class of one judged policy: 'ok', 'bad' (evidence of non-compliance) or 'unusable'. 1.1: EnableFileFilter true and exe, cmd, vbe in FileTypes (exact
    strings, as the Rego); EnableFileFilter false, or a required type missing from a FileTypes list, is bad; a non-boolean flag or FileTypes not a list is unusable.
    1.2: ZapEnabled. 1.3: Action Block or DynamicDelivery ok, Allow or Replace bad, any other value unusable (closed enum, C8)."""
    leaf = sp["leaf"]
    if leaf == "file_types":
        f, ft = pol.get("EnableFileFilter"), pol.get("FileTypes")
        if f is False:
            return "bad"
        if type(f) is not bool or not isinstance(ft, list):
            return "unusable"
        have = {x for x in ft if type(x) is str}
        return "bad" if any(t not in have for t in FILE_REQUIRED) else "ok"
    if leaf == "zap":
        z = pol.get("ZapEnabled")
        return "unusable" if type(z) is not bool else ("ok" if z else "bad")
    a = pol.get("Action")
    if type(a) is str and a in ATTACH_OK:
        return "ok"
    if type(a) is str and a in ATTACH_BAD:
        return "bad"
    return "unusable"


def _cascade(policy_id, sp, sections):
    c = CASCADE[sp["variant"]]
    AD, POL, CR, PP, BI = c["ad"], c["pol"], c["cr"], c["pp"], c["bi"]

    def A(code, text, cell, cited, **d):
        return _A(policy_id, code, text, cell, _cite(sp["sections"], *cited), **d)

    if sp.get("licence"):
        out = _licence_cell(policy_id, sections, "defender_license")
        if out:
            return out
    out = _shape(policy_id, sections, [AD, POL, CR, PP] + ([BI] if BI else []), [POL, CR, PP] + ([BI] if BI else []), sp["sections"])
    if out:
        return out
    pols, rules, pres = sections[POL], sections[CR], sections[PP]
    if any(type(p.get("Identity")) is not str or not p["Identity"].strip() for p in pols) or len({p["Identity"] for p in pols if type(p.get("Identity")) is str}) != len(pols):
        return A("data_unusable_policy_record", f"Data unusable: a policy in {POL} has no readable Identity or two policies share one; the policy was not assessed.",
                 "policy_unusable", [POL])
    policies_by_identity = {p["Identity"]: p for p in pols}

    def topo():
        return A("data_unusable_preset_topology", "Data unusable: a preset security policy rule cannot be tied to exactly one policy of its kind; the policy was not assessed.",
                 "preset_topology_unusable", [PP, POL])

    def state_err(sec):
        return A("data_unusable_rule_state", "Data unusable: a rule's State is not exactly Enabled or Disabled; the policy was not assessed.",
                 "rule_state_unusable", [sec])

    def scope_err(sec, t):
        return A("data_unusable_rule_scope", "Data unusable: an enabled rule has a recipient scope that cannot be read (absent or untyped field, or unknown accepted domains); "
                 "the policy was not assessed.", "rule_scope_unusable", [sec, *([AD] if t.get("via") else [])])
    if any(type(r.get("Identity")) is not str for r in pres):
        return topo()
    accepted = _accepted(sections)
    flags, side, selected = {}, [], None            # side: partial tiers (tier, policy)
    for tier, rx in CASCADE_PRESETS:
        other = next(o for t2, o in CASCADE_PRESETS if t2 != tier)
        mine, mp, ok = _preset_pair(pres, pols, rx, other)
        if not ok:
            return topo()
        if not mine:
            if mp:
                return topo()
            continue
        r = mine[0]
        st = _state(r)
        if st is None:
            return state_err(PP)
        if st == "Disabled":
            continue
        t = {}
        cov = _cover(r, accepted, t, "narrows")
        if cov == "u":
            return scope_err(PP, t)
        if not mp:
            return topo()
        if (cov == "q" and t.get("via")) or (cov == "x" and t.get("excl")):
            flags["preset_scope"] = True          # D45: the Rego never lets a domain-scoped preset cover, and ignores ExceptIf* on a preset
        if cov == "q":
            selected = (tier, mp[0])
            break
        side.append((tier, mp[0]))
    if selected is None:
        enabled = []
        for r in rules:
            st = _state(r)
            if st is None:
                return state_err(CR)
            if st == "Enabled":
                enabled.append(r)
        if enabled:
            if any(not _is_num(r.get("Priority")) for r in enabled):
                return A("data_unusable_rule_priority", f"Data unusable: an enabled rule in {CR} has no numeric Priority (the lowest Priority decides which rule applies); "
                         "the policy was not assessed.", "priority_unusable", [CR])
            low = min(r["Priority"] for r in enabled)
            top = [r for r in enabled if r["Priority"] == low]
            if len(top) > 1:
                return A("data_unusable_rule_priority_tie", f"Data unusable: two enabled rules in {CR} share the lowest Priority; the policy was not assessed.",
                         "rule_priority_tie", [CR])

            def resolve(r):
                link = r.get(c["link"])
                return policies_by_identity.get(link) if type(link) is str else None
            t = {}
            cov0 = _cover_custom(top[0], accepted, t)
            if cov0 == "u":
                return scope_err(CR, t)
            tgt0 = resolve(top[0])
            if tgt0 is None:
                return A("data_unusable_custom_topology", f"Data unusable: an enabled rule in {CR} does not name exactly one policy of {POL}; the policy was not assessed.",
                         "custom_topology_unusable", [CR, POL])
            if t.get("case"):
                flags["case_or_space"] = True
            if cov0 == "q":
                selected = ("custom", tgt0)
            else:
                for r in enabled:
                    if r is top[0]:
                        continue
                    t2 = {}
                    cv = _cover_custom(r, accepted, t2)
                    if cv == "u":
                        return scope_err(CR, t2)
                    if cv == "q":
                        return A("data_unusable_hidden_covering_rule", f"Data unusable: the enabled rule with the lowest Priority in {CR} applies to some recipients only and a "
                                 "rule with a higher Priority number covers everyone; the policy that applies to the remaining recipients was not judged; "
                                 "the policy was not assessed.", "hidden_covering_rule", [CR])
                    tg = resolve(r)
                    if tg is None:
                        return A("data_unusable_custom_topology", f"Data unusable: an enabled rule in {CR} does not name exactly one policy of {POL}; the policy was not assessed.",
                                 "custom_topology_unusable", [CR, POL])
                    if t2.get("case"):
                        flags["case_or_space"] = True
                    side.append(("custom", tg))
                side.append(("custom", tgt0))
    if selected is None and not rules and any(
            p["Identity"] != c["fallback"]
            and not any(rx.search(p["Identity"]) for _, rx in CASCADE_PRESETS)
            and _cascade_leaf(sp, p) != "ok" for p in pols):
        # v3.7 (lens A F4, D95; R12): a custom policy that is not compliant (or not readable) while the rule list is empty: the list may come from a failed command
        return A("data_unavailable_custom_policy_without_rule", f"Data unavailable: a custom policy that does not carry the required settings exists but {CR} is empty (which can also mean a failed command), so whether it applies to anyone is unknown; the policy was not assessed.",
                 "custom_policy_without_rule", [POL, CR])
    if selected is None:
        if BI is None:
            tgt = [p for p in pols if p["Identity"] == c["fallback"]]
            selected = ("default", tgt[0]) if tgt else None
            if selected is None:
                return A("data_unavailable_applied_policy_not_exported", f"Data unavailable: the applied policy ({c['fallback']}) is not in {POL}; the policy was not assessed.",
                         "policy_not_in_export", [POL])
        else:
            st3 = []
            for e in sections[BI]:
                ex = [_empty3(e, k) for k in ("ExceptIfSentTo", "ExceptIfSentToMemberOf", "ExceptIfRecipientDomainIs")]
                st3.append("q" if all(x is True for x in ex) else ("x" if any(x is False for x in ex) else "u"))
            if "q" in st3:
                tgt = [p for p in pols if p["Identity"] == c["fallback"]]
                if not tgt:
                    return A("data_unavailable_applied_policy_not_exported", f"Data unavailable: the applied policy ({c['fallback']}) is not in {POL}; the policy was not assessed.",
                             "policy_not_in_export", [POL])
                selected = ("builtin", tgt[0])
            elif not st3 or "u" in st3:
                return A("data_unusable_builtin_rule", f"Data unusable: {BI} holds no rule with readable exclusions; the policy was not assessed.",
                         "builtin_rule_unusable", [BI])
            elif side:
                if any(_cascade_leaf(sp, p) == "bad" for _, p in side):
                    # v3.9 (N6, D99 before D44): a partly scoped policy that the evidence shows to be non-compliant gives its recipients a non-compliant policy whatever the built-in rule excludes
                    return _rec(policy_id, "not_met", "partial_tier_policy_noncompliant",
                                f"Requirement not met: a policy that applies to some recipients only is non-compliant ({sp['bad']}).", "partial_tier_violation", None,
                                **{k: True for k in flags})
                return A("data_unusable_partial_tier_may_cover", "Data unusable: the built-in protection rule has exclusions and a partly scoped policy exists that may cover "
                         "the excluded recipients; the policy was not assessed.", "partial_tier_may_cover", [BI, PP, CR])
            else:
                return _rec(policy_id, "not_met", "no_policy_covers_all_recipients",
                            f"Requirement not met: no policy applies to all recipients ({sp['bad']}).", "no_policy_covers_all", None)
    tier, pol = selected
    cls = _cascade_leaf(sp, pol)
    side_cls = [_cascade_leaf(sp, p) for _, p in side]
    fl = {k: True for k in flags}
    if cls == "bad":
        cell, code = CASCADE_NOT_MET[tier]
        return _rec(policy_id, "not_met", code, f"Requirement not met: {sp['bad']}.", cell, None, **fl)
    if "bad" in side_cls:
        # v3.7 (main 5 Nov 04:07 GMT, D99; aligns SS 1.x with SS 6.x D32 and 7.x D98): a policy that applies to some recipients and is non-compliant is evidence of non-compliance
        return _rec(policy_id, "not_met", "partial_tier_policy_noncompliant",
                    f"Requirement not met: a policy that applies to some recipients only is non-compliant ({sp['bad']}).", "partial_tier_violation", None, **fl)
    if cls == "unusable":
        return A(sp["leaf_code"], f"Data unusable: {sp['leaf_text']}; the policy was not assessed.", "policy_leaf_unusable", [POL], **fl)
    if any(s != "ok" for s in side_cls):
        return A("data_unusable_partial_tier", "Data unusable: a policy that applies to some recipients only cannot be read; only the policy "
                 "that applies to everyone is judged; the policy was not assessed.", "partial_tier_noncompliant", [POL, PP, CR], **fl)
    cell, code = CASCADE_MET[tier]
    return _rec(policy_id, "met", code, f"Requirement met: {sp['good']}.", cell, None, **fl)


def policy_cascade(policy_id: str, row: dict, sections: dict) -> dict:
    return _cascade(policy_id, {**row["params"], "sections": row["sections"]}, sections)


KINDS = {"policy_cascade": policy_cascade}
