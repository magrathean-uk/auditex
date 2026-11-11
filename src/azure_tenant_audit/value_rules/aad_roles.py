"""AAD 7.4-7.9 privileged-role rules, from v3.9.1 FINAL.

P2 is checked before assignment/rule values. Explicit null dates and absent
keys remain distinct; labelled violations win over unreadable peer records.
Only closed rule/config names can enter the constant reason templates.
"""
from __future__ import annotations

from .helpers import _p2_gate
from .record import _A, BAD_SECTION_LIST, EMPTY_SECTION, ITEM_LABEL, ITEM_VALUE, _rec


def _roles_cfg(sections, key):
    """(users, groups) RoleExclusions of scuba_config.Aad[key]; undefined is empty (as the Rego); None when the config shape cannot be read."""
    cfg = sections["scuba_config"]
    if not isinstance(cfg, dict):
        return None
    cur = cfg.get("Aad")
    for k in (key, "RoleExclusions"):
        if cur is None:
            break
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    if cur is None:
        return set(), set()
    if not isinstance(cur, dict):
        return None
    out = []
    for k in ("Users", "Groups"):
        x = cur.get(k)
        if x is None:
            out.append(set())
        elif isinstance(x, list) and all(y is None or type(y) is str for y in x):
            out.append({y for y in x if y is not None})
        else:
            return None
    return out[0], out[1]


def _rule_label(rule):
    return type(rule.get("RuleSource")) is str and type(rule.get("RuleSourceType")) is str


def _rules_of(role):
    r = role.get("Rules")
    return r if isinstance(r, list) and all(isinstance(x, dict) for x in r) else None


def _priv_roles(policy_id, sp, sections):
    name = "privileged_roles"
    lst = sections[name]
    if not isinstance(lst, list):
        return _A(policy_id, BAD_SECTION_LIST, "Data unusable: privileged_roles is not a list of objects; the policy was not assessed.", "section_not_a_list", [name])
    p2 = _p2_gate(policy_id, sections)
    if p2:
        return p2
    roles = [r for r in lst if isinstance(r, dict)]
    if not roles:
        return _A(policy_id, EMPTY_SECTION, "Data unavailable: privileged_roles holds no objects; the policy was not assessed.", "no_usable_items", [name])
    leaf = sp["leaf"]
    what = sp["what"]
    if leaf == "permanent":
        cfg = _roles_cfg(sections, "MS.AAD.7.4v1")
        excluded = cfg[0] | cfg[1] if cfg is not None else None
        bad = unl = unusable = 0
        for r in roles:
            a = r.get("Assignments")
            if not isinstance(a, list) or any(not isinstance(x, dict) for x in a):
                unusable += 1
                continue
            perm = []
            for x in a:
                if "EndDateTime" not in x:
                    unusable += 1
                elif x["EndDateTime"] is None:
                    if type(x.get("PrincipalId")) is str:
                        perm.append(x["PrincipalId"])
                    else:
                        unl += 1
            if perm:
                if cfg is None:
                    unusable += 1
                elif set(perm) - excluded:
                    if type(r.get("DisplayName")) is str:
                        bad += 1
                    else:
                        unl += 1
        if bad:
            return _rec(policy_id, "not_met", "violation_found", "Requirement not met: a role has a permanent active assignment that the configuration does not allow.", "role_flagged", None)
        if unl:
            return _A(policy_id, ITEM_LABEL, "Data unusable: a role or assignment that shows a permanent assignment carries no name or principal; the policy was not assessed.",
                      "role_unlabelled", [name])
        if unusable:
            return _A(policy_id, ITEM_VALUE, "Data unusable: a role has no usable assignment list, an assignment lacks its end date, or the role exclusions cannot be read; the policy was not assessed.",
                      "role_field_unusable", [name, "scuba_config"])
        return _rec(policy_id, "met", "no_violation_found", "Requirement met: no role has a permanent active assignment beyond the configured exclusions.", "all_clear", None)
    if leaf == "outside_pim":
        bad = unl = unusable = 0
        for r in roles:
            a = r.get("Assignments")
            if not isinstance(a, list) or any(not isinstance(x, dict) for x in a):
                unusable += 1
                continue
            for x in a:
                if "StartDateTime" not in x:
                    unusable += 1
                elif x["StartDateTime"] is None:
                    if type(r.get("DisplayName")) is str:
                        bad += 1
                    else:
                        unl += 1
        if bad:
            return _rec(policy_id, "not_met", "violation_found", "Requirement not met: a role has an assignment without a start date, so it was made outside PIM.", "role_flagged", None)
        if unl:
            return _A(policy_id, ITEM_LABEL, "Data unusable: a role without a name shows an assignment without a start date; the policy was not assessed.", "role_unlabelled", [name])
        if unusable:
            return _A(policy_id, ITEM_VALUE, "Data unusable: a role has no usable assignment list or an assignment lacks its start date key; the policy was not assessed.",
                      "role_field_unusable", [name])
        return _rec(policy_id, "met", "no_violation_found", "Requirement met: every assignment of every role has a start date.", "all_clear", None)
    # rule scans
    ids = {"ga_approval": ("Approval_EndUser_Assignment",), "assignment_alert": ("Notification_Admin_Admin_Assignment", "Notification_Admin_Admin_Eligibility"),
           "ga_activation_alert": ("Notification_Admin_EndUser_Assignment",), "other_activation_alert": ("Notification_Admin_EndUser_Assignment",)}[leaf]
    bad = unl = unusable = seen = short = 0
    for r in roles:
        dn = r.get("DisplayName")
        if leaf in ("ga_approval", "ga_activation_alert", "other_activation_alert"):
            if type(dn) is not str:
                unusable += 1                              # the role cannot be told apart from Global Administrator
                continue
            is_ga = dn == "Global Administrator"
            if is_ga != (leaf != "other_activation_alert"):
                continue
        rules = _rules_of(r)
        if rules is None:
            unusable += 1
            continue
        rule_ids = {ru["Id"] for ru in rules if isinstance(ru.get("Id"), str)}
        short += 1 if any(i not in rule_ids for i in ids) else 0      # v3.7 (lens B AAD-B2, D106): a considered role that lacks a rule the policy reads
        for ru in rules:
            if ru.get("Id") not in ids:
                continue
            seen += 1
            if leaf == "ga_approval":
                s = ru.get("Setting")
                v = s.get("IsApprovalRequired") if isinstance(s, dict) else None
                st = "unusable" if type(v) is not bool else ("clear" if v else "bad")
            else:
                if leaf != "assignment_alert":
                    if ru.get("NotificationType") != "Email" or type(ru.get("NotificationType")) is not str:
                        unusable += 1
                        continue
                n = ru.get("NotificationRecipients", "absent")
                n = [] if n is None else n                    # null is the empty list (the Rego's Count(null)); an absent key is unusable
                st = "unusable" if not isinstance(n, list) else ("bad" if not n else "clear")
            if st == "bad":
                if _rule_label(ru):
                    bad += 1
                else:
                    unl += 1
            elif st == "unusable":
                unusable += 1
    if bad:
        return _rec(policy_id, "not_met", "violation_found", f"Requirement not met: {what}.", "role_flagged", None)
    if unl:
        return _A(policy_id, ITEM_LABEL, "Data unusable: a rule that shows the condition the policy looks for carries no source name or type; the policy was not assessed.", "role_unlabelled", [name])
    if unusable:
        return _A(policy_id, ITEM_VALUE, "Data unusable: a role or rule the policy reads lacks a usable value; the policy was not assessed.", "role_field_unusable", [name])
    if not seen:
        return _A(policy_id, "data_unavailable_rule_absent", "Data unavailable: no role carries the rule the policy reads (for Global Administrator, no such role); the policy was not assessed.",
                  "rule_absent", [name])
    if short:
        return _A(policy_id, "data_unavailable_rule_absent", "Data unavailable: a role lacks a rule the policy reads (a missing eligibility or assignment rule, or a role with no rules), so not every part of the requirement is shown; the policy was not assessed.",
                  "rule_absent", [name])
    return _rec(policy_id, "met", "no_violation_found", "Requirement met: every rule the policy reads is set as required.", "all_clear", None)


def privileged_roles(policy_id, row, sections):
    return _priv_roles(policy_id, row["params"], sections)


KINDS = {"priv_roles": privileged_roles}
