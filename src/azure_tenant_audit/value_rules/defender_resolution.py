"""Safe Links policy resolution (SS 7.x), ported from the v3.9 reference.

A preset needs both its EOP and Defender rules. Custom policy resolution judges
an earlier partial rule before the covering rule or Built-In fallback.
accepted_domains is optional and only informs domain-scope comparisons.
"""
from __future__ import annotations

from typing import NamedTuple

from .helpers import (
    BUILTIN,
    EXCEPT_KEYS,
    PRESET_RE,
    _accepted,
    _cover,
    _empty3,
    _licence_cell,
)
from .record import _A, BAD_SECTION_LIST, ITEM_VALUE, _not_collected, _rec


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
        tiers = [n for n, rx in zip(("Strict", "Standard"), PRESET_RE, strict=False) if rx.search(ident)]
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


BI = "built_in_protection_rules"
LATE_SECTIONS = {"safelinks_resolution": frozenset({BI})}


def _safelinks_core(policy_id, sp, sections, trace):
    # Review R003/R099: a row that lists built_in_protection_rules reads the Built-In Protection rule's exclusions and
    # judges empty rule lists like any tenant where no rule covers everyone. The shipped 7.x rows list it (lane rules-followup).
    builtin_scope = BI in sp.get("sections", ())
    # Review R003 (repair): the Built-In rule is a late section. A covering rule decides without it; the Built-In fallback
    # answers section_not_collected when it is missing or marked (assess lets it through when it alone is missing).
    # Repair round 2: so is its shape; a covering rule decides even when the section is not a list.
    builtin_missing = _not_collected(policy_id, sections, [BI]) if builtin_scope else None
    for name in ("protection_policy_rules", "safe_links_policies", "safe_links_rules", "atp_policy_rules"):
        if not isinstance(sections[name], list):
            return _A(policy_id, BAD_SECTION_LIST, f"Data unusable: {name} is not a list of objects; the policy was not assessed.", "section_not_a_list", [name])
    lic = _licence_cell(policy_id, sections, "defender_license")      # v3.7 (lens B DEF-F3, D101): Safe Links need Defender for Office 365; a false read can be a failed command
    if lic:
        return lic
    if not builtin_scope and not sections["protection_policy_rules"] and not sections["safe_links_rules"]:
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
    # that may apply first with an unreadable policy leaves its recipients unjudged (R100, below), as does one of unknown Priority; one that an earlier partial rule
    # fully shadows never applies.
    low_cov = min(r["Priority"] for r in cand) if cand else None
    # Policies by Identity, built once (a string Identity is the only thing a string name equals): one list scan per
    # partial rule was quadratic in rules times policies.
    by_identity: dict = {}
    for e in sections["safe_links_policies"]:
        if isinstance(e, dict) and type(e.get("Identity")) is str:
            by_identity.setdefault(e["Identity"], []).append(e)
    partial_unread = None
    # Bot review wave 2 (item 59): a non-compliant partial rule of unknown Priority may apply before the covering rule.
    order_unknown = False
    shadow, preset = _Shadows(partial), _preset_scopes(sections)

    def covered(rule):
        # Item 58: preset policies apply before every custom rule, so a rule both enabled parts of one preset tier
        # cover never applies.
        return preset(rule) or shadow(rule)

    for r in partial:
        pr = r.get("Priority")
        name = r.get("SafeLinksPolicy")
        pp = by_identity.get(name, []) if type(name) is str else []
        # Repair round 2: a known false flag decides even when another flag is unreadable.
        off = len(pp) == 1 and any(pp[0].get(f) is False for f in sp["flags"])
        readable = off or (len(pp) == 1 and all(type(pp[0].get(f)) is bool for f in sp["flags"]))
        if cand and not (_is_num(pr) and pr < low_cov):
            # After the covering rule this rule never applies. One of unknown Priority may apply first: a compliant
            # policy decides nothing there (v3.6), a non-compliant one leaves the order deciding (item 59) and an
            # unreadable one leaves its recipients unjudged (R100 repair).
            if _is_num(pr) or covered(r):
                continue
            if off:
                order_unknown = True
                continue
            if readable or partial_unread is not None:
                continue
        elif readable:
            if off and not covered(r):
                return _rec(policy_id, "not_met", "partial_scope_policy_flag_off",
                            f"Requirement not met: an enabled Safe Links rule applies to some recipients only and its policy does not enable {sp['what']}, so those recipients get a non-compliant policy.",
                            "partial_rule_noncompliant", None, div="D98")
            continue
        elif partial_unread is not None or covered(r):
            continue
        # Review R100: a partial rule that may apply first gives its recipients its policy; when that policy is missing,
        # duplicated or lacks a boolean flag, those recipients are unjudged (as data_unusable_partial_tier in SS 1.x).
        partial_unread = "missing" if not pp else ("duplicated" if len(pp) > 1 else "flag")
    if builtin_scope and applied == BUILTIN:
        if builtin_missing:
            return builtin_missing
        if not isinstance(sections[BI], list):
            return _A(policy_id, BAD_SECTION_LIST, f"Data unusable: {BI} is not a list of objects; the policy was not assessed.", "section_not_a_list", [BI])
        out = _builtin_exclusions(policy_id, sp, sections, partial)
        if out:
            return out
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
    if partial_unread == "missing":
        return _A(policy_id, "data_unavailable_applied_policy_not_exported",
                  "Data unavailable: the applied Safe Links policy is not in safe_links_policies; the policy was not assessed.", "policy_not_in_export",
                  ["safe_links_policies"], partial_scope=True)
    if partial_unread == "duplicated":
        return _A(policy_id, "data_unusable_applied_policy_duplicated",
                  "Data unusable: the applied Safe Links policy appears more than once; the policy was not assessed.", "policy_duplicated", ["safe_links_policies"],
                  partial_scope=True)
    if partial_unread == "flag":
        return _A(policy_id, ITEM_VALUE, "Data unusable: the applied Safe Links policy lacks a boolean value for a flag the policy reads; the policy was not assessed.",
                  "policy_flag_unusable", ["safe_links_policies"], partial_scope=True)
    if order_unknown:
        return _A(policy_id, "data_unusable_safe_links_rule",
                  "Data unusable: a partly scoped Safe Links rule whose policy turns off a flag the policy reads has no numeric "
                  "Priority, so it may apply before the covering rule; the policy was not assessed.", "rule_unusable", ["safe_links_rules"])
    return _rec(policy_id, "met", "applied_policy_flags_on", f"Requirement met: the applied Safe Links policy enables {sp['what']}.", "policy_flags_ok", None,
                applied="built_in" if applied == BUILTIN else "custom")


_SCOPE_IN = ("SentTo", "SentToMemberOf", "RecipientDomainIs")


def _scope_values(rule, key):
    """A scope condition's values: an empty frozenset when unset, None when unreadable."""
    value = rule.get(key)
    if value is None or value == []:
        return frozenset()
    if isinstance(value, list) and all(type(v) is str for v in value):
        return frozenset(value)
    return None


def _scope(rule):
    """(include conditions, exceptions) as tuples of (key, values) for the condition kinds set; None when unreadable."""
    inc = tuple((k, _scope_values(rule, k)) for k in _SCOPE_IN)
    exc = tuple((k, _scope_values(rule, k)) for k in EXCEPT_KEYS)
    if any(v is None for _, v in (*inc, *exc)):
        return None
    return tuple((k, v) for k, v in inc if v), tuple((k, v) for k, v in exc if v)


class _Shadows:
    """Review R100 (repair): ``shadows(rule)`` is True when enabled partial rules with a lower numeric Priority apply
    to every recipient ``rule`` names, so ``rule`` never applies. Sound whether Exchange joins different conditions with
    AND or OR: one earlier rule sets the same condition kinds, its values include the later one's, and its exceptions
    are none or the same. When the later rule sets one condition kind, several earlier rules that set only that kind
    (exceptions none or the same) may share its values between them (repair round 2). Built on first use and indexed by
    value; each posting holds a distinct scope once, with its lowest Priority, and the lowest Priority of a scope that
    covers a looked-up scope is kept, so rules with the same scope cost one step each, in whatever order they are
    listed and whatever earlier scopes overlap them (bot review wave 2, item 60, and its repair round 1)."""

    def __init__(self, partial):
        self._partial = partial
        self._postings = None
        self._first = None
        self._cover = {}

    def _build(self):
        postings, self._first = {}, {}
        for rule in self._partial:
            pr, sc = rule.get("Priority"), _scope(rule)
            if not _is_num(pr) or sc is None or not sc[0]:
                continue
            inc, exc = sc
            shape = (tuple(k for k, _ in inc), exc)
            for k, values in inc:
                for value in values:
                    scopes = postings.setdefault((shape, k, value), {})
                    scopes[inc] = min(pr, scopes.get(inc, pr))
                    if len(inc) == 1:
                        key = (k, exc, value)
                        self._first[key] = min(pr, self._first.get(key, pr))
        self._postings = {key: [(dict(inc), pr) for inc, pr in scopes.items()] for key, scopes in postings.items()}

    def _lowest_cover(self, shape, inc):
        """The lowest Priority of an indexed rule of ``shape`` whose include values contain ``inc``'s."""
        key = (shape, inc)
        if key not in self._cover:
            mine, lowest = dict(inc), float("inf")
            lists = [self._postings.get((shape, k, value), ()) for k, values in inc for value in values]
            for theirs, earlier_pr in min(lists, key=len):
                if earlier_pr < lowest and all(mine[k] <= theirs[k] for k in shape[0]):
                    lowest = earlier_pr
            self._cover[key] = lowest
        return self._cover[key]

    def __call__(self, rule):
        pr, sc = rule.get("Priority"), _scope(rule)
        if not _is_num(pr) or sc is None or not sc[0]:
            return False
        if self._postings is None:
            self._build()
        inc, exc = sc
        if len(inc) == 1:
            (k, values), never = inc[0], float("inf")
            if all(min(self._first.get((k, (), v), never), self._first.get((k, exc, v), never)) < pr for v in values):
                return True
        keys = tuple(k for k, _ in inc)
        return any(self._lowest_cover(shape, inc) < pr for shape in {(keys, ()), (keys, exc)})


class _Reach(NamedTuple):
    """A rule's recipient scope (repair round 2 of items 50, 58 and 61). Exchange joins a rule's conditions with AND:
    a recipient is in scope only when it matches every condition set and no exception. ``to``, ``groups`` and
    ``domains`` hold the SentTo, SentToMemberOf and RecipientDomainIs values (None: the condition is unset and matches
    everyone); ``not_to``, ``not_groups`` and ``not_domains`` the exceptions. Values are casefolded. When ``to`` is set
    the recipients it names less those ExceptIfSentTo names are the only ones the rule may reach, so ``not_to`` is
    folded into it and left empty. Group membership and recipient domains are unknown."""
    to: frozenset | None
    groups: frozenset | None
    domains: frozenset | None
    not_to: frozenset
    not_groups: frozenset
    not_domains: frozenset


def _fold(values):
    return frozenset(v.casefold() for v in values)


def _reach(rule):
    """The one scope model citing, preset shadowing and Built-In exclusion coverage all read; None when unreadable."""
    sc = _scope(rule) if isinstance(rule, dict) else None
    if sc is None:
        return None
    inc, exc = ({k: _fold(v) for k, v in part} for part in sc)
    not_to = exc.get("ExceptIfSentTo", frozenset())
    to = inc["SentTo"] - not_to if "SentTo" in inc else None
    return _Reach(to, inc.get("SentToMemberOf"), inc.get("RecipientDomainIs"), frozenset() if to is not None else not_to,
                  exc.get("ExceptIfSentToMemberOf", frozenset()), exc.get("ExceptIfRecipientDomainIs", frozenset()))


def _covers(earlier, later):
    """True when every recipient ``later`` may reach is in ``earlier``'s scope (both ``_Reach``). Each condition
    ``earlier`` sets, ``later`` sets too with no more values; each recipient ``earlier`` excepts by name is one
    ``later`` cannot reach; each group or domain ``earlier`` excepts, ``later`` excepts as well."""
    if later.to is not None and not later.to:
        return True                                   # its own exceptions remove every recipient it names
    for mine, theirs in ((later.to, earlier.to), (later.groups, earlier.groups), (later.domains, earlier.domains)):
        if theirs is not None and (mine is None or not mine <= theirs):
            return False
    named_out = not (later.to & earlier.not_to) if later.to is not None else earlier.not_to <= later.not_to
    return named_out and earlier.not_groups <= later.not_groups and earlier.not_domains <= later.not_domains


def _preset_scopes(sections):
    """Bot review wave 2 (item 58): ``covered(rule)`` is True when, for one preset tier, an enabled EOP rule
    (protection_policy_rules) and an enabled Defender rule (atp_policy_rules) both apply to every recipient ``rule``
    may reach. Presets apply before every custom policy, so those recipients never get ``rule``'s policy."""
    tiers = {}
    for name, part in (("protection_policy_rules", 0), ("atp_policy_rules", 1)):
        for r in sections[name]:
            if not isinstance(r, dict) or type(r.get("Identity")) is not str or r.get("State") != "Enabled":
                continue
            scope = _reach(r)
            if scope is None:
                continue
            for tier, rx in zip(("Strict", "Standard"), PRESET_RE, strict=False):
                if rx.search(r["Identity"]):
                    tiers.setdefault(tier, ([], []))[part].append(scope)

    def covered(rule):
        if not tiers:
            return False
        scope = _reach(rule)
        if scope is None or (scope.to is None and scope.groups is None and scope.domains is None):
            return False
        return any(all(any(_covers(earlier, scope) for earlier in scopes) for scopes in parts)
                   for parts in tiers.values())

    return covered


def _excluded_recipients(rules):
    """The recipients the Built-In rules name in ExceptIfSentTo, casefolded, when that is their only exclusion kind;
    None when a group or domain exclusion (or an unreadable one) leaves the excluded recipients unknown."""
    out = set()
    for rule in rules:
        sc = _scope(rule) if isinstance(rule, dict) else None
        if sc is None or any(k != "ExceptIfSentTo" for k, _ in sc[1]):
            return None
        out.update(v.casefold() for k, values in sc[1] for v in values)
    return out


def _may_cover(rule, excluded):
    """The excluded recipients a partly scoped rule may reach (``_reach``): with SentTo set, those it names and does
    not except; otherwise all but those it excepts by name. None when the excluded recipients are unknown."""
    scope = _reach(rule) if excluded is not None else None
    if scope is None:
        return excluded
    return excluded & scope.to if scope.to is not None else excluded - scope.not_to


def _preset_reach(sections, excluded):
    """Item 61 and its repair round 1: the excluded recipients a partly scoped preset may cover, the union over tiers of
    what both its parts (EOP and Defender) may cover. A rule whose Identity is unreadable may be any tier and one whose
    State is unreadable may be enabled; a disabled rule covers no one. With the excluded recipients unknown: True when
    some tier has a rule in both parts, else False."""
    reach = {tier: [set(), set()] for tier in ("Strict", "Standard")}
    seen = {tier: [False, False] for tier in reach}
    for part, name in enumerate(("protection_policy_rules", "atp_policy_rules")):
        for r in sections[name]:
            if not isinstance(r, dict):
                continue
            ident = r.get("Identity")
            if type(ident) is not str:
                tiers, may = list(reach), excluded
            else:
                tiers = [n for n, rx in zip(reach, PRESET_RE, strict=False) if rx.search(ident)]
                if not tiers or ("State" in r and r["State"] != "Enabled"):
                    continue
                may = _may_cover(r, excluded) if "State" in r else excluded
            for tier in tiers:
                seen[tier][part] = True
                if excluded is not None:
                    reach[tier][part] |= may
    if excluded is None:
        return any(all(parts) for parts in seen.values())
    return set().union(*(eop & atp for eop, atp in reach.values()))


def _builtin_state(rule):
    """'q' the Built-In rule excludes no one, 'x' it excludes someone, 'u' an exclusion list is absent or malformed."""
    if not isinstance(rule, dict):
        return "u"
    empty = []
    for key in EXCEPT_KEYS:
        value = _empty3(rule, key)
        if value is None or (value is False and any(type(v) is not str or not v.strip() for v in rule[key])):
            return "u"
        empty.append(value)
    return "q" if all(empty) else "x"


def _builtin_exclusions(policy_id, sp, sections, partial):
    """As SS 1.3 reads the Built-In Protection rule (defender_cascade, attachment variant): None when it covers everyone,
    else the record for recipients it excludes. The rule list exports no Priority; Built-In applies last. A partly
    scoped rule that provably names none of the excluded recipients cannot cover them (repair round 2)."""
    # Bot review wave 2 (item 66): an organisation has one Built-In Protection rule. Several rows, or an exclusion
    # list with an element that is not a recipient name, leave its exclusions unknown.
    if len(sections[BI]) > 1:
        return _A(policy_id, "data_unusable_builtin_rule", f"Data unusable: {BI} holds more than one rule; the policy was not assessed.",
                  "builtin_rule_unusable", [BI])
    state = _builtin_state(sections[BI][0]) if sections[BI] else "u"
    if state == "q":
        return None
    if state == "u":
        return _A(policy_id, "data_unusable_builtin_rule", f"Data unusable: {BI} holds no rule with readable exclusions; the policy was not assessed.",
                  "builtin_rule_unusable", [BI])
    excluded = _excluded_recipients(sections[BI])
    # Bot review wave 2 (item 61, repair round 1): each known exclusion is judged on its own, for custom rules and
    # presets alike; one that nothing may cover gets no Safe Links policy.
    preset = _preset_reach(sections, excluded)
    if excluded is None:
        custom = bool(partial)
    else:
        reached = set().union(*(_may_cover(r, excluded) for r in partial))
        custom, uncovered = bool(reached), reached | preset != excluded
        preset = bool(preset)
    if (custom or preset) and not (excluded is not None and uncovered):
        # Item 50 (repair round 1): name and cite only what may cover an excluded recipient.
        if preset and custom:
            what, cited = "a partly scoped preset security policy and Safe Links rule exist", [
                "atp_policy_rules", BI, "protection_policy_rules", "safe_links_rules"]
        elif preset:
            what, cited = ("a partly scoped Standard or Strict preset security policy exists",
                           ["atp_policy_rules", BI, "protection_policy_rules"])
        else:
            what, cited = "a partly scoped Safe Links rule exists", [BI, "safe_links_rules"]
        return _A(policy_id, "data_unusable_partial_tier_may_cover", f"Data unusable: the built-in protection rule has exclusions and {what} "
                  "that may cover the excluded recipients; the policy was not assessed.", "partial_tier_may_cover", cited)
    return _rec(policy_id, "not_met", "no_policy_covers_all_recipients",
                f"Requirement not met: the Built-In Protection rule excludes some recipients and no Safe Links rule or preset covers them, so they get no Safe Links "
                f"policy ({sp['what']}).", "no_policy_covers_all", None)


def safelinks_resolution(policy_id: str, row: dict, sections: dict) -> dict:
    return _safelinks(policy_id, {**row["params"], "sections": row["sections"]}, sections)


KINDS = {"safelinks_resolution": safelinks_resolution}
