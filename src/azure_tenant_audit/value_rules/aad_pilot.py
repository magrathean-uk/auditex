"""Eight AAD pilot policies, v3.9.1 section 3.6.

Rule views use the ScubaGear field casing. Identity values and reference-only
provenance never enter records; every emitted reason is a catalogue constant.
Authenticator context has no Conditional Access exemption in this baseline.
"""
from __future__ import annotations

import re

from .catalogue import cell_entry, row_for
from .record import _rec

AM = "authentication_method"
LOW3 = ("Sms", "Voice", "Email")
ZERO_GUID = "00000000-0000-0000-0000-000000000000"
INT_MAX = 2147483647
G_SELF = "ManagePermissionGrantsForSelf."
G_OWNED = "ManagePermissionGrantsForOwnedResource."
G_LOW = G_SELF + "microsoft-user-default-low"
G_REC = G_SELF + "microsoft-user-default-recommended"
G_LEG = G_SELF + "microsoft-user-default-legacy"
ALL_APPS = ("/Date(-62135596800000)/", "0001-01-01T00:00:00Z")
_DATED = re.compile(r"^(\d{4}-\d{2}-\d{2}T[0-9:.]+Z|/Date\(-?\d+\)/)$")
_DAYS = re.compile(r"^P(\d+)D$")
APP_SCOPES = ("ApplicationRestrictions", "ServicePrincipalRestrictions")
DEFAULT_POLICY = "default_app_management_policy"
CUSTOM_POLICIES = "app_management_policies"


def _answer(policy_id: str, cell: str, *, text: str | None = None,
            cited: list[str] | None = None, code: str | None = None) -> dict:
    """Emit only catalogue constants; variable phrases come from closed spec lists."""
    entry = cell_entry(policy_id, cell, row_for(policy_id))
    selected = entry["reason_texts"][0] if text is None else text
    constant = next((item for item in entry["reason_texts"] if item == selected), None)
    if constant is None:
        raise ValueError("AAD pilot reason is not a catalogue constant")
    return _rec(policy_id, entry["verdict"], code or entry["reason_code"], constant, cell, cited)


def _not_one_text(name, count):
    if count in (0, 2):
        return f"Data unusable: {name} holds {count} objects, not one; the policy was not assessed."
    return f"Data unusable: {name} does not hold exactly one object; the policy was not assessed."


def _am_configs(policy_id, sections):
    """Require a singleton policy and a list of method configurations."""
    sec, cite = (sections[AM], [AM])
    if not isinstance(sec, list):
        return (_answer(policy_id, 'section_shape_unusable', text=f'Data unusable: {AM} is not a list holding one policy object; the policy was not assessed.', cited=cite), None)
    if len(sec) != 1:
        return (_answer(policy_id, 'section_not_singleton', text=_not_one_text(AM, len(sec)), cited=cite), None)
    item = sec[0]
    fs = item.get('authentication_method_feature_settings') if isinstance(item, dict) else None
    if not isinstance(fs, list):
        return (_answer(policy_id, 'settings_not_a_list', text=f'Data unusable: {AM} has no list of authentication method configurations; the policy was not assessed.', cited=cite), None)
    return (None, [c for c in fs if isinstance(c, dict)])


def _am_low(policy_id: str, row: dict, sections: dict) -> dict:
    rec, cfgs = _am_configs(policy_id, sections)
    if rec:
        return rec
    seen = {k: [] for k in LOW3}
    for c in cfgs:
        i = c.get('Id')
        if type(i) is str and i in seen:
            seen[i].append(c.get('State'))
    on = [k for k in LOW3 if 'enabled' in seen[k]]
    if on:
        return _answer(policy_id, 'method_enabled', text=f"Requirement not met: {', '.join(on)} authentication is enabled.")
    odd = [k for k in LOW3 if any(s not in ('enabled', 'disabled') for s in seen[k])]
    if odd:
        return _answer(policy_id, 'method_state_unusable', text=f"Data unusable: the state of {', '.join(odd)} authentication is not enabled or disabled; the policy was not assessed.", cited=[AM])
    miss = [k for k in LOW3 if not seen[k]]
    if miss:
        return _answer(policy_id, 'method_entry_missing', text=f"Data unavailable: the export has no {', '.join(miss)} authentication method configuration; the policy was not assessed.", cited=[AM])
    return _answer(policy_id, 'all_disabled')


def _authenticator(policy_id, sections):
    rec, cfgs = _am_configs(policy_id, sections)
    if rec:
        return (rec, None)
    ents = [c for c in cfgs if c.get('Id') == 'MicrosoftAuthenticator']
    if not ents:
        return (_answer(policy_id, 'authenticator_entry_absent', text=f'Data unavailable: {AM} has no Microsoft Authenticator configuration, so whether the policy applies is unknown; the policy was not assessed.', cited=[AM]), None)
    if len(ents) > 1:
        return (_answer(policy_id, 'authenticator_duplicated', cited=[AM]), None)
    return (None, ents[0])


def _auth_cfg(a):
    """Closed reasons for bad, unreadable or excluded context configuration."""
    bad, un, excl = ([], [], [])
    o = a.get('IsSoftwareOathEnabled')
    if o is True:
        bad.append('software OATH is enabled')
    elif o is not False:
        un.append(('IsSoftwareOathEnabled absent, null or not a boolean', 'D70'))
    fs = a.get('FeatureSettings')
    for key, nm in (('DisplayAppInformationRequiredState', 'application'), ('DisplayLocationInformationRequiredState', 'location')):
        blk = fs.get(key) if isinstance(fs, dict) else None
        if not isinstance(blk, dict):
            un.append((f'the {nm} context setting is absent', 'D70'))
            continue
        s = blk.get('State')
        if s == 'disabled':
            bad.append(f'{nm} context is disabled')
        elif s != 'enabled':
            un.append((f'the {nm} context state is not enabled or disabled', 'D67'))
        inc = blk.get('IncludeTarget')
        iid = inc.get('Id') if isinstance(inc, dict) else None
        if type(iid) is not str:
            un.append((f'the {nm} context target is absent', 'D70'))
        elif iid != 'all_users':
            bad.append(f'{nm} context is not shown to all users')
        ex = blk.get('ExcludeTarget')
        if ex is None:
            continue
        eid = ex.get('Id') if isinstance(ex, dict) else 0
        if eid is None or eid == '' or eid == ZERO_GUID:
            continue
        if type(eid) is str:
            excl.append(nm)
        else:
            un.append((f'the {nm} context exclusion is unreadable', 'D70'))
    return (bad, un, excl)


def _am_context(policy_id: str, row: dict, sections: dict) -> dict:
    rec, a = _authenticator(policy_id, sections)
    if rec:
        return rec
    st = a.get('State')
    if st == 'disabled':
        return _answer(policy_id, 'closed_gate')
    if st != 'enabled':
        return _answer(policy_id, 'authenticator_state_unusable', cited=[AM])
    bad, un, excl = _auth_cfg(a)
    if bad:
        return _answer(policy_id, 'config_not_met', text='Requirement not met: ' + '; '.join(bad) + '.')
    if un:
        return _answer(policy_id, 'config_unusable', text=f'Data unusable: {un[0][0]}; the policy was not assessed.', cited=[AM])
    if excl:
        return _answer(policy_id, 'config_exclusion_target', cited=[AM])
    return _answer(policy_id, 'config_met')


def _risky_items(cl):
    """(risky, odd, null_only): readings of the classification list."""
    risky = odd = False
    items = [x for x in cl if x is not None]
    for x in items:
        n = x.get('RiskyPermClassifications') if isinstance(x, dict) else None
        if isinstance(n, str) and n or (isinstance(n, list) and n and all(type(e) is str and e for e in n)):
            risky = True
        else:
            odd = True
    return (risky, odd, bool(cl) and (not items))


def _consent(policy_id: str, row: dict, sections: dict) -> dict:
    ap, cl = (sections['authorization_policies'], sections['risky_delegated_permission_classifications'])
    if not isinstance(ap, list):
        return _answer(policy_id, 'section_not_a_list', cited=['authorization_policies'])
    objs = [p for p in ap if isinstance(p, dict)]
    if not objs:
        return _answer(policy_id, 'no_usable_items', cited=['authorization_policies'])
    per, grants_bad = ([], False)
    for p in objs:
        g = p.get('PermissionGrantPolicyIdsAssignedToDefaultUserRole')
        if not (isinstance(g, list) and all(type(x) is str for x in g)):
            grants_bad = True
            continue
        per.append((type(p.get('Id')) is str, g))
    if any((lab and G_REC in g for lab, g in per)):
        return _answer(policy_id, 'recommended_granted')
    low = [lab for lab, g in per if G_LOW in g]
    shape_bad = odd = null_only = risky = False
    if low:
        if not isinstance(cl, list):
            shape_bad = True
        else:
            risky, odd, null_only = _risky_items(cl)
    if risky and any(low):
        return _answer(policy_id, 'low_with_risky')
    if any((not lab and G_REC in g for lab, g in per)) or (risky and low):
        return _answer(policy_id, 'flag_bad_unlabelled', cited=['authorization_policies'])
    if grants_bad:
        return _answer(policy_id, 'grants_unusable', cited=['authorization_policies'])
    if shape_bad or odd or null_only:
        return _answer(policy_id, 'classifications_unusable', cited=['risky_delegated_permission_classifications'])
    other = [x for lab, g in per for x in g if not x.startswith(G_OWNED) and x != G_LOW]
    if other:
        return _answer(policy_id, 'grant_not_evaluable', text='Data unusable: users may consent under a grant policy (' + ('legacy' if other == [G_LEG] else 'custom or unrecognised') + ') whose terms the export does not show; the policy was not assessed.', cited=['authorization_policies'])
    if low:
        return _answer(policy_id, 'met_low_no_risk')
    return _answer(policy_id, 'met_no_self_grant')


def _admin_consent(policy_id: str, row: dict, sections: dict) -> dict:
    sec = sections['directory_settings']
    if not isinstance(sec, list):
        return _answer(policy_id, 'section_not_a_list', cited=['directory_settings'])
    vals = []
    for g in sec:
        for s in g.get('Values') if isinstance(g, dict) and isinstance(g.get('Values'), list) else []:
            if isinstance(s, dict) and s.get('Name') == 'EnableAdminConsentRequests':
                vals.append(s.get('Value'))
    low = [v.lower() if isinstance(v, str) else None for v in vals]
    if 'false' in low and 'true' not in low:
        return _answer(policy_id, 'admin_consent_off')
    if 'false' in low:
        return _answer(policy_id, 'value_conflict', cited=['directory_settings'])
    if not vals:
        return _answer(policy_id, 'no_setting', cited=['directory_settings'])
    if any(x not in ('true', 'false') for x in low):
        return _answer(policy_id, 'value_unusable', cited=['directory_settings'])
    return _answer(policy_id, 'admin_consent_on')


def _scope_entries(pol, cred, rtype):
    """Entries per scope: absent lists hold none; wrongly typed lists are unusable."""
    out, un = ({}, False)
    for sc in APP_SCOPES:
        o = pol.get(sc)
        if o is not None and (not isinstance(o, dict)):
            un = True
            o = {}
        lst = (o or {}).get(cred)
        if lst is not None and (not isinstance(lst, list)):
            un = True
            lst = []
        out[sc] = [e for e in lst or [] if isinstance(e, dict) and e.get('RestrictionType') == rtype]
    return (out, un)


def _eval_entry(e: dict, maxd: int | None) -> tuple[str, str]:
    st = e.get('State')
    if st == 'disabled':
        return ('bad', 'the restriction is not enabled')
    if st != 'enabled':
        return ('un', 'a restriction state is not enabled or disabled')
    d = e.get('RestrictForAppsCreatedAfterDateTime')
    if type(d) is str and d not in ALL_APPS:
        if _DATED.match(d):
            return ('bad', 'the restriction applies only to apps created after a date')
        return ('un', 'a restriction date cannot be read')
    if type(d) is not str:
        return ('un', 'a restriction date cannot be read')
    if maxd:
        m = _DAYS.match(e.get('MaxLifetime')) if type(e.get('MaxLifetime')) is str else None
        if not m:
            return ('un', 'a lifetime is not a whole number of days')
        if int(m.group(1)) > maxd:
            return ('bad', 'a lifetime exceeds the limit')
    return ('ok', '')


def _eval_app(pol, custom, cred, rtype, maxd, scopes=APP_SCOPES):
    """Read one restriction in default scopes and every custom policy.

    A scope made moot by blocked password addition is omitted from the default
    check. Custom policies still apply and can weaken either scope.
    """
    ents, un_shape = _scope_entries(pol, cred, rtype)
    bad, un = ([], ['a credential list is not a list'] if un_shape else [])
    for sc in scopes:
        for e in ents[sc]:
            k, why = _eval_entry(e, maxd)
            (bad if k == 'bad' else un if k == 'un' else []).append(why)
    for p in custom:
        if not isinstance(p, dict):
            un.append('a custom app management policy is not an object')
            continue
        r = p.get('Restrictions')
        lst = r.get(cred) if isinstance(r, dict) else None
        mine = [x for x in lst if isinstance(x, dict) and x.get('RestrictionType') == rtype] if isinstance(lst, list) else []
        if not mine and r is not None and (not isinstance(r, dict)) and (p.get('IsEnabled') is True):
            un.append('custom policy restrictions are unreadable')
        if p.get('IsEnabled') is False or not mine:
            continue
        if p.get('IsEnabled') is not True:
            un.append('a custom policy has no boolean IsEnabled')
            continue
        for x in mine:
            if x.get('State') == 'disabled':
                ap = x.get('AppliesTo')
                if not isinstance(ap, list):
                    un.append('a custom policy exemption lists no readable apps')
                elif ap:
                    bad.append('a custom policy exempts apps from the restriction')
            elif x.get('State') != 'enabled':
                un.append('a custom policy restriction state is not enabled or disabled')
            else:
                k, why = _eval_entry(x, maxd)
                if k == 'ok':
                    continue
                ap = x.get('AppliesTo')
                if not isinstance(ap, list):
                    un.append('a custom policy restriction lists no readable apps')
                elif ap:
                    (bad if k == 'bad' else un).append('a custom policy applies a weaker restriction to some apps: ' + why if k == 'bad' else 'a custom policy restriction cannot be read: ' + why)
    return (bad, un, [sc for sc in scopes if not ents[sc]], ents)


def _app_restriction(policy_id: str, row: dict, sections: dict) -> dict:
    sp = row['params']
    a = sp['app']
    dp, cp = (sections[DEFAULT_POLICY], sections[CUSTOM_POLICIES])
    if not isinstance(dp, list) or any(not isinstance(e, dict) for e in dp):
        return _answer(policy_id, 'section_shape_unusable', text=f'Data unusable: {DEFAULT_POLICY} is not a list of objects; the policy was not assessed.', cited=[DEFAULT_POLICY])
    if not isinstance(cp, list):
        return _answer(policy_id, 'section_shape_unusable', text=f'Data unusable: {CUSTOM_POLICIES} is not a list; the policy was not assessed.', cited=[CUSTOM_POLICIES])
    if not dp:
        return _answer(policy_id, 'no_default_policy', text=f'Data unavailable: {DEFAULT_POLICY} is empty, so no default restriction is shown; the policy was not assessed.', cited=[DEFAULT_POLICY])
    if len(dp) > 1:
        return _answer(policy_id, 'default_not_singleton', text=_not_one_text(DEFAULT_POLICY, len(dp)), cited=[DEFAULT_POLICY])
    pol = dp[0]
    scopes = APP_SCOPES
    # Password lifetimes apply only in scopes where password addition is permitted.
    if a['moot']:
        ab, au, _, ae = _eval_app(pol, cp, 'PasswordCredentials', 'passwordAddition', None)
        if not ab and (not au) and all(ae[sc] for sc in APP_SCOPES):
            return _answer(policy_id, 'moot_addition_blocked')
        cb, cu, _, _ = _eval_app(pol, cp, 'PasswordCredentials', 'passwordAddition', None, scopes=())
        if not cb and (not cu):
            st = {}
            for sc in APP_SCOPES:
                ks = [_eval_entry(e, None)[0] for e in ae[sc]]
                st[sc] = 'blocked' if ks and all(k == 'ok' for k in ks) else 'open' if 'bad' in ks else 'unknown'
            if 'blocked' in st.values():
                if 'unknown' in st.values():
                    return _answer(policy_id, 'moot_scope_unknown', cited=[DEFAULT_POLICY])
                scopes = tuple(sc for sc in APP_SCOPES if st[sc] == 'open')
    bad, un, missing, _ = _eval_app(pol, cp, a['cred'], a['rtype'], a['maxd'], scopes=scopes)
    if bad:
        return _answer(policy_id, 'restriction_not_met', text='Requirement not met: ' + sorted(set(bad))[0] + f" ({sp['what']}).")
    if un:
        return _answer(policy_id, 'restriction_unusable', text=f'Data unusable: {sorted(set(un))[0]}; the policy was not assessed.', cited=[CUSTOM_POLICIES, DEFAULT_POLICY])
    if missing:
        return _answer(policy_id, 'entry_missing', text=f"Data unavailable: the default policy shows no {a['rtype']} restriction for {' or '.join(m.replace('Restrictions', '') for m in missing)}; the policy was not assessed.", cited=[DEFAULT_POLICY])
    return _answer(policy_id, 'restrictions_compliant', text=f"Requirement met: the {a['rtype']} restriction is enabled for every app in " + ('both scopes' if scopes == APP_SCOPES else 'the scope where password addition is permitted') + (f" within {a['maxd']} days." if a['maxd'] else '.'))


class _DomainRoots:
    """Reversed character trie; lookup cost depends on the name, not root count.

    Terminals keep the first exported root for stable ties. Checking the next
    character enforces a dot boundary without normalising case or DNS labels.
    The same index also supports the reference's bare-suffix collision check.
    """

    def __init__(self, roots: list[dict], *, lower: bool = False):
        self._trie = {}
        for root in roots:
            name = root['Id'].lower() if lower else root['Id']
            node = self._trie
            for char in reversed(name):
                node = node.setdefault(char, {})
            node.setdefault(None, root)

    def longest(self, name: str, *, boundary: bool = True) -> dict | None:
        node = self._trie
        match = node.get(None) if not boundary or not name or name.endswith('.') else None
        for length, char in enumerate(reversed(name), 1):
            node = node.get(char)
            if node is None:
                break
            if None in node and (not boundary or length == len(name) or name[-length - 1] == '.'):
                match = node[None]
        return match


def _domain_validity(policy_id: str, row: dict, sections: dict) -> dict:
    sp = row['params']
    sec = sections['domain_settings']
    if not isinstance(sec, list):
        return _answer(policy_id, 'section_not_a_list', cited=['domain_settings'])
    doms = [d for d in sec if isinstance(d, dict)]
    if not doms:
        return _answer(policy_id, 'no_usable_items', cited=['domain_settings'])
    scope, unusable = ([], False)
    for d in doms:
        ver, auth, i = (d.get('IsVerified'), d.get('AuthenticationType'), d.get('Id'))
        if ver is False or (type(auth) is str and auth != 'Managed'):
            continue
        if ver is not True or type(auth) is not str or type(i) is not str or (type(d.get('IsRoot')) is not bool):
            unusable = True
            continue
        scope.append(d)
    roots = [d for d in scope if d['IsRoot']]
    root_index = _DomainRoots(roots)
    lower_root_index = _DomainRoots(roots, lower=True)

    def never(d):
        if 'PasswordValidityPeriodInDays' not in d:
            return None
        v = d['PasswordValidityPeriodInDays']
        if v is None or (type(v) is int and v == INT_MAX):
            return True
        return False if type(v) is int else None
    valid, invalid, orphan, collision, case_only = ([], [], False, False, False)
    for d in scope:
        if d['IsRoot']:
            r = never(d)
        else:
            root = root_index.longest(d['Id'])
            if root is None:
                orphan = True
                collision = collision or root_index.longest(d['Id'], boundary=False) is not None
                case_only = case_only or lower_root_index.longest(d['Id'].lower()) is not None
                continue
            # Inherit from the longest case-sensitive, dot-boundary root.
            r = never(root)
        if r is None:
            unusable = True
        (valid if r else invalid).append(d['Id']) if r is not None else None
    # An observed expiring domain decides before any unreadable or orphan entry.
    if invalid:
        how_many = '1 managed domain' if len(invalid) == 1 else '2 managed domains' if len(invalid) == 2 else 'more than two managed domains'
        return _answer(policy_id, 'password_expiry_set', text=f"Requirement not met: passwords expire for {how_many} ({sp['what']}).")
    if unusable:
        return _answer(policy_id, 'domain_unusable', cited=['domain_settings'])
    if orphan:
        if case_only and (not collision):
            return _answer(policy_id, 'orphan_sub_domain', text='Data unusable: a managed sub-domain matches a managed verified root domain only when letter case is ignored, so the export does not establish that it is under that root and its password policy is unknown; the policy was not assessed.', cited=['domain_settings'], code='data_unusable_sub_domain_root_case')
        return _answer(policy_id, 'orphan_sub_domain', text='Data unusable: a managed sub-domain has no managed verified root domain in the export, so its password policy is unknown; the policy was not assessed.', cited=['domain_settings'], code='data_unusable_sub_domain_without_root')
    if not valid:
        return _answer(policy_id, 'no_managed_domain', cited=['domain_settings'])
    return _answer(policy_id, 'passwords_never_expire')


KINDS = {"am_context": _am_context, "am_low": _am_low, "consent": _consent,
         "admin_consent": _admin_consent, "app_restriction": _app_restriction,
         "domain_validity": _domain_validity}
