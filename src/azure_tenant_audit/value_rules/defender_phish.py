"""SCuBA value rules ported from the v3.9 reference (spec section 3.3).

Reads the in-memory rule view; output text uses only constant policy parameters.
Divergence ids stay in test fixtures. Collection and missing-section checks are
owned by the dispatch boundary.
"""
from __future__ import annotations

from .defender_cascade import _cover_custom, _join_key
from .defender_targeted_users import (
    BINDING_KEY,
    COVERAGE_KEY,
    binding_from_config,
    membership,
    membership_from_coverage,
)
from .helpers import PRESET_RE, _accepted, _cite, _cover, _licence_cell, _shape, _state
from .record import _A, EMPTY_SECTION, _rec

UNACCEPTABLE_ACTIONS = ("noaction", "bccmessage")
ACCEPTABLE_ACTIONS = ("movetojmf", "quarantine", "redirect")
SAFETY_TIPS = ("EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips", "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips",
               "EnableViaTag", "EnableUnauthenticatedSender")
PHISH_RANK = {"Strict": 0, "Standard": 1, "Custom": 2, "Default": 3}


def _email_of(entry):
    """SensitiveUserEmail (SecuritySuite.rego utils:321-331): 'name;email' -> the second part, bare entry -> itself; lower-cased and trimmed. None when the Rego
    drops the entry (an empty email part)."""
    parts = entry.split(";")
    if len(parts) > 1:
        e = parts[1].strip().lower()
        return e or None
    return entry.strip().lower() or None


def _tf(v):
    return "t" if v is True else ("f" if v is False else "u")


def _action_class(v):
    if type(v) is not str:
        return "u"
    lv = v.lower()
    return "f" if lv in UNACCEPTABLE_ACTIONS else ("t" if lv in ACCEPTABLE_ACTIONS else "u")


def _all_c(cs):
    """Conjunction over t, f, u: any f wins, else any u, else t."""
    return "f" if "f" in cs else ("u" if "u" in cs else "t")


def _phish_content(need, pol, cfg, binding=None):
    """Content conjuncts of one enabled anti-phish policy (everything except recipient coverage): t, f or u.

    SS 2.1 membership comes from the policy's TargetedUsersCoverage when it carries one, checked against the private
    binding (an invalid or unbound summary is u, never a literal fallback); otherwise from the literal list, as a
    ScubaGear export or reference input supplies it. An explicit false flag or action stays decisive either way.
    """
    if need == "org_domains":
        return _all_c([_tf(pol.get("EnableOrganizationDomainsProtection")), _action_class(pol.get("TargetedDomainProtectionAction"))])
    if need == "safety_tips":
        return _all_c([_tf(pol.get(k)) for k in SAFETY_TIPS])
    if need == "users":
        flag, act = _tf(pol.get("EnableTargetedUserProtection")), _action_class(pol.get("TargetedUserProtectionAction"))
        if COVERAGE_KEY in pol:
            inc = membership_from_coverage(pol[COVERAGE_KEY], cfg, binding)
        else:
            inc = membership(pol.get("TargetedUsersToProtect"), cfg).value
        return _all_c([flag, act, inc])
    flag, act, lst = _tf(pol.get("EnableTargetedDomainsProtection")), _action_class(pol.get("TargetedDomainProtectionAction")), pol.get("TargetedDomainsToProtect")

    def norm(x):
        return x.strip().lower() or None
    if not isinstance(lst, list) or any(type(x) is not str for x in lst if x is not None):
        inc = "u"
    else:
        have = {n for n in (norm(x) for x in lst if x is not None) if n}
        inc = "t" if have and cfg <= have else "f"
    return _all_c([flag, act, inc])


def _phish_cfg(policy_id, sp, sections):
    """(set of configured values, unusable flag) for SS 2.1 (emails) and 2.3 (domains), or (None, False) for 2.2 and 2.4. The config path is as v3.1."""
    if sp.get("list_key") is None:
        return None, False
    cfg = sections["scuba_config"] or {}
    sec = {}
    for top, key in (("SecuritySuite", policy_id), ("Defender", sp["alias"])):
        block = cfg.get(top)
        if isinstance(block, dict) and key in block:
            sec = block[key]
            break
    lst = (sec.get(sp["list_key"]) if isinstance(sec, dict) else None) or []
    vals, bad = set(), False
    for x in lst:
        if x is None:
            continue
        if type(x) is not str:
            bad = True
            continue
        s = x.strip().lower()
        if not s:
            continue
        if sp["need"] == "users":
            if s.count(";") > 1:
                bad = True
                continue
            e = _email_of(s)
            if e is None:
                bad = True
                continue
            vals.add(e)
        else:
            vals.add(s)
    return vals, bad


def _phish_core(policy_id, sp, sections, cfg, cfg_bad, binding=None):
    AD, POL, AR, PP = "accepted_domains", "anti_phish_policies", "anti_phish_rules", "protection_policy_rules"

    def A(code, text, cell, cited, **d):
        return _A(policy_id, code, text, cell, _cite(sp["sections"], *cited), **d)

    ATP = "atp_policy_rules" in sp["sections"]       # v3.7 (lens B DEF-F2, D100): SS 2.1-2.3 read the Defender part of a preset (its ATP rule) beside the EOP part
    out = _shape(policy_id, sections, [AD, POL, AR, PP] + (["atp_policy_rules"] if ATP else []), [POL, AR, PP] + (["atp_policy_rules"] if ATP else []), sp["sections"])
    if out:
        return out
    pols, rules, pres = sections[POL], sections[AR], sections[PP]
    atp = sections["atp_policy_rules"] if ATP else None
    if not pols:
        return A(EMPTY_SECTION, f"Data unavailable: {POL} holds no objects (every tenant has a Default anti-phish policy); the policy was not assessed.",
                 "no_usable_items", [POL])
    if any(type(p.get("Identity")) is not str or not p["Identity"].strip() or type(p.get("IsDefault")) is not bool for p in pols) or \
            len({p["Identity"] for p in pols}) != len(pols):
        return A("data_unusable_policy_record", f"Data unusable: a policy in {POL} has no readable Identity or IsDefault flag, or two share one Identity; the policy was not assessed.",
                 "policy_unusable", [POL])
    if any(type(r.get("Identity")) is not str for r in pres):
        return A("data_unusable_preset_topology", "Data unusable: a preset security policy rule has no readable Identity; the policy was not assessed.",
                 "preset_topology_unusable", [PP])
    if ATP and any(type(r.get("Identity")) is not str for r in atp):
        return A("data_unusable_preset_topology", "Data unusable: a Defender for Office 365 preset rule has no readable Identity; the policy was not assessed.",
                 "preset_topology_unusable", ["atp_policy_rules"])
    rule_sets = [(PP, [r for r in pres if any(rx.search(r["Identity"]) for rx in PRESET_RE)]), (AR, rules)]
    if ATP:
        rule_sets.append(("atp_policy_rules", [r for r in atp if any(rx.search(r["Identity"]) for rx in PRESET_RE)]))
    for sec, rs in rule_sets:
        if any(_state(r) is None for r in rs):
            return A("data_unusable_rule_state", "Data unusable: a rule's State is not exactly Enabled or Disabled; the policy was not assessed.", "rule_state_unusable", [sec])
    accepted = _accepted(sections)
    rules_by_policy = {}
    unreadable_link = False
    for r in rules:
        if _state(r) == "Enabled":
            link = r.get("AntiPhishPolicy")
            unreadable_link |= type(link) is not str
            rules_by_policy.setdefault(_join_key(link), []).append(r)
    coverage_by_policy = {}

    def coverage(key):
        # Summarise each join group once, even when many policies share a Name.
        # Coverage combines by existence, so repeated rules cannot change it.
        if key not in coverage_by_policy:
            classes, case = set(), False
            for r in rules_by_policy.get(key, []):
                trace = {}
                cv = _cover_custom(r, accepted, trace)
                if cv == "q" and accepted is None:
                    cv = "u"                       # D46: custom cover needs known tenant domains
                classes.add(cv)
                case |= bool(trace.get("case"))
            coverage_by_policy[key] = classes, case
        return coverage_by_policy[key]

    flags = {}
    info = []                                    # (tier, policy, reach, content)
    for p in pols:
        ident = p["Identity"]
        tier = "Strict" if PRESET_RE[0].search(ident) else "Standard" if PRESET_RE[1].search(ident) else ("Default" if p["IsDefault"] else "Custom")
        en = p.get("Enabled")
        if en is False or (sp["need"] == "safety_tips" and tier in ("Strict", "Standard")):
            continue                                   # 2.4: presets come from their rules alone (below), the Rego never reads the preset policy
        reach = "q" if tier == "Default" else None
        if tier in ("Strict", "Standard"):
            rx = PRESET_RE[0] if tier == "Strict" else PRESET_RE[1]
            other = PRESET_RE[1] if tier == "Strict" else PRESET_RE[0]
            mine = [r for r in pres if rx.search(r["Identity"])]
            if len(mine) > 1 or any(other.search(r["Identity"]) for r in mine):
                return A("data_unusable_preset_topology", "Data unusable: a preset security policy rule cannot be tied to exactly one policy of its kind; the policy was not assessed.",
                         "preset_topology_unusable", [PP, POL])
            if not mine or _state(mine[0]) == "Disabled":
                reach = "n"
            else:
                t = {}
                reach = _cover(mine[0], accepted, t, "narrows")
                if (reach == "q" and t.get("via")) or (reach == "x" and t.get("excl")):
                    flags["preset_scope"] = True
            if ATP:
                minea = [r for r in atp if rx.search(r["Identity"])]
                if len(minea) > 1 or any(other.search(r["Identity"]) for r in minea):
                    return A("data_unusable_preset_topology", "Data unusable: a preset security policy rule cannot be tied to exactly one policy of its kind; the policy was not assessed.",
                             "preset_topology_unusable", ["atp_policy_rules", POL])
                if not minea or _state(minea[0]) == "Disabled":
                    r2 = "n"
                else:
                    t2 = {}
                    r2 = _cover(minea[0], accepted, t2, "narrows")
                    if (r2 == "q" and t2.get("via")) or (r2 == "x" and t2.get("excl")):
                        flags["preset_scope"] = True
                both = "n" if "n" in (reach, r2) else "u" if "u" in (reach, r2) else "x" if "x" in (reach, r2) else "q"
                if both != reach:
                    flags["atp_part"] = True           # D100: the Defender part of the preset differs from the EOP part, which the Rego reads alone
                reach = both
        elif tier == "Custom":
            if unreadable_link:
                reach = "u"
            cl = set()
            for key in {_join_key(p.get("Name")), _join_key(ident)}:
                classes, case = coverage(key)
                cl.update(classes)
                if case:
                    flags["case_or_space"] = True
            if reach != "u":
                reach = "q" if "q" in cl else ("u" if "u" in cl else ("x" if "x" in cl else "n"))
        if en is not True:
            reach = "u"
        info.append((tier, p, reach, _phish_content(sp["need"], p, cfg, binding)))
    if sp["need"] == "safety_tips":
        # Rego (PresetRecipientsCovered): an enabled preset rule that covers all recipients is compliant, the preset policy is not inspected (or even required)
        for tier, rx, other in (("Strict", PRESET_RE[0], PRESET_RE[1]), ("Standard", PRESET_RE[1], PRESET_RE[0])):
            mine = [r for r in pres if rx.search(r["Identity"])]
            if len(mine) > 1 or any(other.search(r["Identity"]) for r in mine):
                return A("data_unusable_preset_topology", "Data unusable: a preset security policy rule cannot be tied to exactly one policy of its kind; the policy was not assessed.",
                         "preset_topology_unusable", [PP, POL])
            if mine and _state(mine[0]) == "Enabled":
                t = {}
                reach = _cover(mine[0], accepted, t, "narrows")
                if (reach == "q" and t.get("via")) or (reach == "x" and t.get("excl")):
                    flags["preset_scope"] = True
                info.append((tier, {}, reach, "t"))
    Q = [i for i in info if i[3] == "t" and i[2] == "q"]
    M = [i for i in info if i[2] in ("q", "u") and i[3] in ("t", "u") and (i[2], i[3]) != ("q", "t")]
    fl = {k: True for k in flags}
    if Q:
        best = min(PHISH_RANK[i[0]] for i in Q)
        shadow = [i for i in info if i[2] in ("q", "x", "u") and i[3] in ("f", "u") and
                  (PHISH_RANK[i[0]] < best or (best == PHISH_RANK["Custom"] and i[0] == "Custom"))]
        if shadow:
            return A("data_unusable_qualifier_shadowed", "Data unusable: a policy that qualifies exists, but a policy of higher or undetermined precedence that does not qualify, or cannot be read, "
                     "may apply to some or all recipients; the policy was not assessed.", "qualifier_shadowed", [POL, AR, PP], **fl)
        if cfg_bad:
            return A("data_unusable_config_entry", "Data unusable: an entry of the ScubaGear configuration list cannot be read exactly (not a string, an empty or ambiguous "
                     "name;email); the policy was not assessed.", "config_entry_unusable", ["scuba_config"])
        tier = min((i for i in Q), key=lambda i: PHISH_RANK[i[0]])[0]
        cell = "preset_qualifies" if tier in ("Strict", "Standard") else ("custom_qualifies" if tier == "Custom" else "default_qualifies")
        return _rec(policy_id, "met", {"preset_qualifies": "preset_policy_qualifies", "custom_qualifies": "custom_policy_qualifies",
                                       "default_qualifies": "default_policy_qualifies"}[cell], f"Requirement met: {sp['good']}.", cell, None, **fl)
    if M:
        if any(i[3] == "u" for i in M):
            return A("data_unusable_policy_field", "Data unusable: an anti-phish policy that could qualify has a field that is absent, null or not a recognised value; the policy was not assessed.",
                     "policy_field_unusable", [POL], **fl)
        return A("data_unusable_policy_scope", "Data unusable: the recipient scope of a policy that qualifies cannot be read (absent or untyped field, or unknown accepted domains); "
                 "the policy was not assessed.", "policy_scope_unusable", [AR, PP, AD], **fl)
    if not any(p["IsDefault"] for p in pols) or len([p for p in pols if p["IsDefault"]]) > 1:
        return A("data_unusable_default_policy", "Data unusable: the export does not hold exactly one Default anti-phish policy; the policy was not assessed.",
                 "default_policy_unusable", [POL])
    if not rules and any(i[0] == "Custom" and i[2] == "n" and i[3] in ("t", "u") for i in info):
        # v3.7 (lens A F4, D95; R12): a custom anti-phish policy that qualifies by its content has no rule while the rule list is empty (possibly a failed command): not_met would hide it
        return A("data_unavailable_custom_policy_without_rule", "Data unavailable: a custom anti-phish policy that could qualify exists but no anti-phish rule is exported (the rule list is empty, which can also mean a failed command), so whether it applies to anyone is unknown; the policy was not assessed.",
                 "custom_policy_without_rule", [POL, AR], **fl)
    return _rec(policy_id, "not_met", "no_qualifying_policy", f"Requirement not met: {sp['bad']}.", "no_qualifying_policy", None, **fl)


def _phish(policy_id, sp, sections):
    out = _licence_cell(policy_id, sections, "defender_license")
    if out:
        return out
    cfg, cfg_bad, binding = None, False, None
    if sp.get("list_key") is not None:
        c0 = sections["scuba_config"]
        if c0 is not None and not isinstance(c0, dict):
            return _A(policy_id, "data_unusable_config_shape", "Data unusable: scuba_config is not an object; the policy was not assessed.", "config_shape_unusable", ["scuba_config"])
        c0 = c0 or {}
        blk = {}
        for top, key in (("SecuritySuite", policy_id), ("Defender", sp["alias"])):
            b = c0.get(top)
            if isinstance(b, dict) and key in b:
                blk = b[key]
                break
        lst = blk.get(sp["list_key"]) if isinstance(blk, dict) else None
        if lst is not None and not isinstance(lst, list):
            return _A(policy_id, "data_unusable_config_list", f"Data unusable: the configured {sp['list_key']} is not a list; the policy was not assessed.",
                      "config_list_unusable", ["scuba_config"])
        if not any(isinstance(x, str) and x.strip() for x in (lst or [])):
            return _A(policy_id, "data_unavailable_config_list_empty",
                      f"Data unavailable: cannot be assessed: no operator-named {sp['noun']} in the ScubaGear configuration; the policy was not assessed.",
                      "config_list_empty", ["scuba_config"])
        cfg, cfg_bad = _phish_cfg(policy_id, sp, sections)
        if not cfg:
            return _A(policy_id, "data_unusable_config_entry", "Data unusable: an entry of the ScubaGear configuration list cannot be read exactly (not a string, an empty or ambiguous "
                      "name;email); the policy was not assessed.", "config_entry_unusable", ["scuba_config"])
        if sp["need"] == "users" and isinstance(blk, dict):
            # Private run-bundle config only: the verified SensitiveUsers count and manifest HMAC a summary must match.
            binding = binding_from_config(blk.get(BINDING_KEY))
    return _phish_core(policy_id, sp, sections, cfg, cfg_bad, binding)


def phish_exists(policy_id: str, row: dict, sections: dict) -> dict:
    return _phish(policy_id, {**row["params"], "sections": row["sections"]}, sections)


KINDS = {"phish_exists": phish_exists}
