"""Anti-spam cascade (SS 6.1/6.2), ported from the v3.9 reference.

Strict, Standard, custom and Default tiers are judged until a covering tier
shields those below it. Custom precedence that cannot be established remains
not assessed; list order does not stand in for missing Priority.
The policy rows for these kinds are enabled in configs/scuba-value-rules.json.
"""
from __future__ import annotations

from .helpers import PRESET_RE, _accepted, _cover
from .record import BAD_SECTION_LIST, _A, _rec


SPAM_SLOTS = ("SpamAction", "HighConfidenceSpamAction", "PhishSpamAction", "HighConfidencePhishAction")


SPAM_ALLOWED = ("MoveToJmf", "Quarantine", "Redirect", "Delete")


SPAM_OTHER = ("AddXHeader", "BccMessage", "ModifySubject", "NoAction")


POLICY_TYPES = ("Strict", "Standard", "Custom")


SPAM_PRESETS = (("Strict", PRESET_RE[0]), ("Standard", PRESET_RE[1]))


SPAM_MET = {"Strict": ("strict_covers_compliant", "strict_preset_covers_all_recipients_compliant"),
            "Standard": ("standard_covers_compliant", "standard_preset_covers_all_recipients_compliant"),
            "custom": ("custom_covers_compliant", "custom_policy_covers_all_recipients_compliant"),
            "default": ("default_compliant", "default_policy_applies_compliant")}


SPAM_NOT_MET = {"Strict": ("preset_noncompliant", "applied_preset_noncompliant"), "Standard": ("preset_noncompliant", "applied_preset_noncompliant"),
                "custom": ("custom_noncompliant", "applied_custom_policy_noncompliant"), "default": ("default_noncompliant", "applied_default_policy_noncompliant")}


def _spam_leaf(sp, pol):
    """Class of one judged policy: 'ok', 'bad' (evidence of non-compliance) or 'unusable'; second value: an unusable field beside a bad one.
    6.1: all four actions in the allowed set = ok; one recognised action outside it = bad (also when another slot is unusable); an absent, null,
    unrecognised or Delete-on-high-confidence-phish slot is unusable. 6.2: AllowedSenderDomains [] = ok, non-empty list of strings = bad, else unusable."""
    if sp["leaf"] == "actions":
        bad = unusable = False
        for slot in SPAM_SLOTS:
            v = pol.get(slot)
            if type(v) is not str or (v not in SPAM_ALLOWED and v not in SPAM_OTHER) or (slot == "HighConfidencePhishAction" and v == "Delete"):
                unusable = True
            elif v in SPAM_OTHER:
                bad = True
        return ("bad", unusable) if bad else (("unusable", False) if unusable else ("ok", False))
    v = pol.get("AllowedSenderDomains")
    if not isinstance(v, list) or any(type(x) is not str for x in v):
        return "unusable", False
    return ("bad", False) if v else ("ok", False)


def _spam_cascade(policy_id, sp, sections):
    names = sp["sections"]
    AD, POL, CR, PP = names

    def A(code, text, cell, cited, **detail):
        return _A(policy_id, code, text, cell, [n for n in names if n in cited], **detail)

    for n in names:
        if not isinstance(sections[n], list):
            return A(BAD_SECTION_LIST, f"Data unusable: {n} is not a list of objects; the policy was not assessed.", "section_not_a_list", [n])
    for n in (POL, CR, PP):
        if any(not isinstance(e, dict) for e in sections[n]):
            return A("data_unusable_list_element", f"Data unusable: {n} holds an element that is not an object; the policy was not assessed.", "list_element_unusable", [n])
    pols, rules, pres = sections[POL], sections[CR], sections[PP]
    for p in pols:
        ident = p.get("Identity")
        if type(ident) is not str or not ident.strip() or type(p.get("IsDefault")) is not bool or p.get("RecommendedPolicyType") not in POLICY_TYPES:
            return A("data_unusable_policy_record", "Data unusable: a hosted content filter policy has no readable Identity, IsDefault flag or RecommendedPolicyType; the policy was not assessed.",
                     "policy_unusable", [POL])
    ids = [p["Identity"] for p in pols]
    if len(ids) != len(set(ids)):
        return A("data_unusable_policy_duplicated", "Data unusable: two hosted content filter policies share one Identity; the policy was not assessed.", "policy_duplicated", [POL])
    defaults = [p for p in pols if p["IsDefault"]]
    if not defaults:
        return A("data_unavailable_default_policy_absent", "Data unavailable: no Default hosted content filter policy is exported (every tenant has exactly one); the policy was not assessed.",
                 "no_default_policy", [POL])
    if len(defaults) > 1:
        return A("data_unusable_default_policy_ambiguous", "Data unusable: more than one hosted content filter policy is marked Default; the policy was not assessed.",
                 "default_policy_ambiguous", [POL])
    by_id = {p["Identity"]: p for p in pols}
    topo_preset = lambda: A("data_unusable_preset_topology", "Data unusable: a preset security policy rule cannot be tied to exactly one policy of its kind; the policy was not assessed.",
                            "preset_topology_unusable", [PP, POL])
    topo_custom = lambda: A("data_unusable_custom_topology", "Data unusable: a custom anti-spam rule does not point at exactly one custom policy; the policy was not assessed.",
                            "custom_topology_unusable", [CR, POL])
    if any(type(r.get("Identity")) is not str for r in pres):
        return topo_preset()
    accepted = _accepted(sections)
    trace = {}

    def state(r, section):
        s = r.get("State")
        if type(s) is str and s in ("Enabled", "Disabled"):
            return s, None
        return None, A("data_unusable_rule_state", "Data unusable: a rule's State is not exactly Enabled or Disabled; the policy was not assessed.", "rule_state_unusable", [section])

    def scope(r, section):
        t = {}
        cov = _cover(r, accepted, t, "narrows")
        if cov == "u":
            return None, t, A("data_unusable_rule_scope", "Data unusable: an enabled rule has a recipient scope that cannot be read (absent or untyped field, or unknown accepted domains); the policy was not assessed.",
                              "rule_scope_unusable", [section, *([AD] if t.get("via") else [])], **({"via_domain_scope": True} if t.get("via") else {}))
        return cov, t, None

    walk, shield = [], None                      # judged tiers: (tier, class, cover, unusable-beside-bad)
    for tier, rx in SPAM_PRESETS:
        mine = [r for r in pres if rx.search(r["Identity"])]
        if not mine:
            if any(p["RecommendedPolicyType"] == tier for p in pols):
                return topo_preset()
            continue
        r = mine[0]
        if len(mine) > 1 or any(o.search(r["Identity"]) for t2, o in SPAM_PRESETS if t2 != tier):
            return topo_preset()
        st, err = state(r, PP)
        if err:
            return err
        if st == "Disabled":
            continue
        link = r.get("HostedContentFilterPolicy")
        target = by_id.get(link) if type(link) is str else None
        if target is None or target["RecommendedPolicyType"] != tier or target["IsDefault"]:
            return topo_preset()
        cov, t, err = scope(r, PP)
        if err:
            return err
        trace.update(t)
        if cov == "q" and t.get("via"):
            trace["preset_via"] = True
        cls, beside = _spam_leaf(sp, target)
        walk.append((tier, cls, cov, beside))
        if cov == "q":
            shield = tier
            break
    if shield is None:
        linked, enabled = set(), []
        for r in rules:
            st, err = state(r, CR)
            if err:
                return err
            if st == "Disabled":
                continue
            link = r.get("HostedContentFilterPolicy")
            target = by_id.get(link) if type(link) is str else None
            if target is None or target["RecommendedPolicyType"] != "Custom" or target["IsDefault"] or link in linked:
                return topo_custom()
            linked.add(link)
            cov, t, err = scope(r, CR)
            if err:
                return err
            cls, beside = _spam_leaf(sp, target)
            enabled.append((cls, cov, beside, t))
        if not rules and any(p["RecommendedPolicyType"] == "Custom" and not p["IsDefault"] and _spam_leaf(sp, p)[0] != "ok" for p in pols):
            # v3.7 (lens A F4, D95; R12): a custom policy that is not compliant (or not readable) while the rule list is empty: the list may come from a failed Get-HostedContentFilterRule,
            # so whether the custom policy applies to anyone is unknown
            return A("data_unavailable_custom_policy_without_rule", "Data unavailable: a custom anti-spam policy that does not carry the required settings exists but no anti-spam rule is exported (the rule list is empty, which can also mean a failed command), so whether it applies to anyone is unknown; the policy was not assessed.",
                     "custom_policy_without_rule", [POL, CR], div="D95")
        covering = {e[0] for e in enabled if e[1] == "q"}
        partial = [e for e in enabled if e[1] == "x"]
        order_dep = lambda: A("data_unavailable_custom_policy_priority", "Data unavailable: which custom anti-spam policy applies first depends on the rule Priority, which the export does not carry; the policy was not assessed.",
                              "custom_order_dependent", [CR])
        leaf_unusable = lambda: A(sp["leaf_code"], f"Data unusable: {sp['leaf_text']}; the policy was not assessed.", "policy_leaf_unusable", [POL])
        if covering:
            if "ok" in covering and "bad" in covering:
                return order_dep()
            if "unusable" in covering:
                return leaf_unusable()
            if covering == {"bad"}:
                e = next(e for e in enabled if e[1] == "q")
                walk.append(("custom", "bad", "q", e[2]))
                trace.update(e[3])
            else:
                if any(e[0] == "bad" for e in partial):
                    return order_dep()
                if any(e[0] == "unusable" for e in partial):
                    return leaf_unusable()
                trace.update(next(e for e in enabled if e[1] == "q")[3])
            shield = "custom"
        else:
            for e in partial:
                if e[0] != "ok":
                    walk.append(("custom", e[0], "x", e[2]))
                    trace.update(e[3])
    if shield is None:
        cls, beside = _spam_leaf(sp, defaults[0])
        walk.append(("default", cls, "q", beside))
        shield = "default"
    bad = [w for w in walk if w[1] == "bad"]
    if bad:
        cell, code = SPAM_NOT_MET[bad[0][0]]
        flags = {"via_domain_scope": bool(trace.get("via")), "case_or_space": bool(trace.get("case")),
                 "partial_bad": any(w[2] == "x" for w in bad), "leaf_beside_bad": any(w[3] for w in bad), "exclusion": bool(trace.get("excl")),
                 "preset_domain_scope": bool(trace.get("preset_via"))}
        return _rec(policy_id, "not_met", code, f"Requirement not met: {sp['bad']}.", cell, None, **{k: True for k, v in flags.items() if v})
    if any(w[1] == "unusable" for w in walk):
        return A(sp["leaf_code"], f"Data unusable: {sp['leaf_text']}; the policy was not assessed.", "policy_leaf_unusable", [POL])
    cell, code = SPAM_MET[shield]
    flags = {"via_domain_scope": bool(trace.get("via")), "case_or_space": bool(trace.get("case")), "exclusion": bool(trace.get("excl")),
             "preset_domain_scope": bool(trace.get("preset_via"))}
    return _rec(policy_id, "met", code, f"Requirement met: {sp['good']}.", cell, None, **{k: True for k, v in flags.items() if v})


def spam_cascade(policy_id: str, row: dict, sections: dict) -> dict:
    return _spam_cascade(policy_id, {**row["params"], "sections": row["sections"]}, sections)


KINDS = {"spam_cascade": spam_cascade}
