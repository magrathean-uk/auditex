"""Conditional Access existence rules from v3.9.1 FINAL.

Each object must carry every conjunct; objects are never merged into a pass.
An unreadable authentication strength remains unknown (F1); all recognised
Conditions restrictions are checked independently of projection (N1/F2).
"""
from __future__ import annotations

from .aad_roles import _p2_gate
from .helpers import _lst
from .record import _A, BAD_SECTION_LIST, EMPTY_SECTION, ITEM_VALUE, _rec

CA_ID = "conditional_access_policies"
AAD_91 = "MS.AAD.9.1v1"


def _env_cell91(policy_id, sections):
    """v3.7 (lens A F8, main-approved): AAD 9.1 is closed only in gcchigh and dod (closed_gate); it is judged in commercial and gcc (Q36); an absent, null, mistyped, case-variant
    or unrecognised environment leaves it unknown, as for the Teams gates (D19)."""
    cfg = sections["scuba_config"]
    env = cfg.get("M365Environment") if isinstance(cfg, dict) else None
    if type(env) is str and env in ("commercial", "gcc"):
        return None
    return _A(policy_id, "data_unusable_environment_field",
              "Data unusable: scuba_config does not state the M365 environment as commercial, gcc, gcchigh or dod, so whether the policy applies is unknown; the policy was not assessed.",
              "environment_unknown", ["scuba_config"])


MFA_COMBOS = {"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor", "deviceBasedPush", "temporaryAccessPassOneTime", "temporaryAccessPassMultiUse",
              "password,microsoftAuthenticatorPush", "password,softwareOath", "password,hardwareOath", "password,sms", "password,voice", "federatedMultiFactor",
              "microsoftAuthenticatorPush,federatedSingleFactor", "softwareOath,federatedSingleFactor", "hardwareOath,federatedSingleFactor",
              "sms,federatedSingleFactor", "voice,federatedSingleFactor"}


PR_COMBOS = {"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"}


STATES = {"enabled": "t", "disabled": "f", "enabledForReportingButNotEnforced": "f"}


def _in(lst, x):
    return "u" if lst is None else ("t" if x in lst else "f")


def _combos(p):
    """AllowedCombinations as a set of strings; None when unusable. GrantControls or AuthenticationStrength null: no strength (empty set)."""
    gc = p.get("GrantControls", "absent")
    if gc is None:
        return set()
    if not isinstance(gc, dict):
        return None
    if "AuthenticationStrength" not in gc:
        return None
    s = gc["AuthenticationStrength"]
    if s is None:
        return set()
    if not isinstance(s, dict) or "AllowedCombinations" not in s:
        return None
    v = s["AllowedCombinations"]
    if v is None:
        return set()
    return set(v) if isinstance(v, list) and all(type(x) is str for x in v) else None


def _builtin(p):
    """The built-in controls as a list of strings; None when unusable. v3.9 (N5, D111): a list that names the same control twice is unusable (Entra stores a set; a duplicate
    cannot come from the export, so the shape is not read as a set and the grant is not decided)."""
    gc = p.get("GrantControls", "absent")
    if gc is None:
        return []
    b = _lst(p, "GrantControls", "BuiltInControls") if isinstance(gc, dict) else None
    if b is not None and len(set(b)) != len(b):
        return None
    return b


def _dup_controls(p):
    """True when BuiltInControls is a list of strings that names a control twice (the D111 shape)."""
    gc = p.get("GrantControls")
    b = _lst(p, "GrantControls", "BuiltInControls") if isinstance(gc, dict) else None
    return b is not None and len(set(b)) != len(b)


DEVICE_CONTROLS = ("compliantDevice", "domainJoinedDevice")


def _grant_managed(p):
    """AAD 3.7 grant (conjuncts `grant_devices` and `operator_or`): does the policy require a managed device? t / f / u plus the divergence id the verdict leans on.
    The Rego wants exactly compliantDevice and domainJoinedDevice with operator OR. v3.6 keeps that (no id) and adds two readings that are stricter than the baseline's
    "either hybrid joined or compliant" and so are met with a baseline-correct tag: operator AND with at least one device control, every control being required
    (D87, main Q27; extra controls under AND only add requirements), and a single device control (D89, main's standing rule). Operator OR with an extra control stays
    not met (any one control then passes, so a device is not required); an operator that is not a string leaves the object unusable, as before.
    v3.7 (lens B CA-2): a non-empty authentication strength is one more control. Under OR it grants access without a device, so a device control OR a strength is not met
    (D92; for two device controls beside a strength the Rego says met); under AND the device control is still required (D87); with no usable operator the object is unusable.
    D89 now means a single device control and no strength. v3.9.1 (F1, D112): "no strength" is a readable null or empty strength; an absent or unreadable one is unknown (see the first branch)."""
    b = _builtin(p)
    if b is None:
        return "u", ("D111" if _dup_controls(p) else None)
    gc = p.get("GrantControls")
    op = gc.get("Operator") if isinstance(gc, dict) else None
    s = _combos(p)
    has_dev = any(x in b for x in DEVICE_CONTROLS)
    if s is None and b and all(x in DEVICE_CONTROLS for x in b):
        # v3.9.1 (F1, D112): the strength is absent, not an object or without a readable AllowedCombinations list: unknown, not "no strength". Beside controls that are all device controls
        # it may be a second way in that needs no device, so OR does not meet the baseline; AND still requires the device control (D87); with no usable operator OR and AND differ (D109).
        # Where another control already sits beside the device control the status does not depend on the strength (OR: not met, AND: met, D87), so the branches below stand.
        if op == "AND":
            return "t", "D87"
        if op == "OR":
            return "u", "D112"
        return "u", "D109"
    if s and has_dev:
        if op == "AND":
            return "t", "D87"
        if op == "OR":
            return "f", "D92"
        return "u", "D109"            # v3.9 (N7b): OR says not met, AND says met, no usable operator: the one id for an operator-ambiguous grant in every Conditional Access policy
    if op not in ("OR", "AND"):      # v3.9 (N7b): an operator that is absent, null, mistyped or neither OR nor AND is unusable, the same in all ten policies (`_paths` already read it so)
        exactly_two = "compliantDevice" in b and "domainJoinedDevice" in b and len(b) == 2
        if len(b) == 1 and b[0] in DEVICE_CONTROLS:
            return "t", "D110"        # v3.9 (N4, Q46's reading): one control, so OR and AND agree (the operator is irrelevant): stricter than the baseline's "either", met with a baseline-correct tag (v3.8: unknown)
        if len(b) >= 2 and has_dev and not exactly_two:
            return "u", "D109"        # v3.8 (main's Q46, D109): two or more controls with a device control among them and no usable operator: AND says met (D87), OR says not met, so the evidence is ambiguous
        if exactly_two:
            return "t", "D110"        # v3.9 (N4): OR meets the baseline exactly, AND is stricter (D87): both met, so the status stands (v3.8: unknown, because the conjunct `operator_or` needed a string)
        return "f", None
    if len(b) == 1 and b[0] in DEVICE_CONTROLS:
        return "t", "D89"
    if op == "AND" and any(x in b for x in DEVICE_CONTROLS):
        return "t", "D87"
    return ("t" if op == "OR" and "compliantDevice" in b and "domainJoinedDevice" in b and len(b) == 2 else "f"), None


def _paths(p, sat_b, sat_s, strength):
    """v3.7 (lens A F3, lens B CA-3): t / f / u plus the divergence id for 'every way the grant can be satisfied meets the requirement'. The built-in controls and a non-empty
    authentication strength are alternatives under operator OR (any one grants access, so each must qualify alone) and all required under AND (one qualifying control is
    enough). With one control the operator is irrelevant. `sat_b(x)` and `sat_s(combos)` say whether a built-in control or the strength qualifies; `strength` says what an
    unreadable strength means: 'u' (always unknown), 'u_if_none' (unknown only when no built-in control qualifies) or 'ignore'. OR beside a control that does not qualify is
    f with D92 (the Rego never reads the operator); an operator that is absent or not a string beside such a control is u."""
    b = _builtin(p)
    s = _combos(p)
    if b is None:
        return "u", ("D111" if _dup_controls(p) else None)
    if s is None and strength == "u":
        return "u", None
    alts = [bool(sat_b(x)) for x in b] + ([bool(sat_s(s))] if s else [])
    if "block" in b:
        return ("t" if any(alts) else "f"), None      # block is a deny and cannot be combined with other controls: nothing else is an alternative way in (the pack's fixtures attach a strength to every policy); as v3.6 (Q44 stands)
    if s is None and strength == "u_if_none" and not any(alts):
        return "u", None
    if not any(alts):
        return "f", None
    gc = p.get("GrantControls")
    op = gc.get("Operator") if isinstance(gc, dict) else None
    if s is None and strength in ("ignore", "u_if_none") and all(alts):
        # v3.9.1 (F1, D112): an absent or unreadable strength is unknown, not "no strength". Beside controls that all qualify it may be a second way in that does not qualify: OR is then
        # unknown (D112), AND still requires the qualifying control (met), no usable operator: OR and AND differ (D109). A non-qualifying control already beside them decides below.
        if op == "AND":
            return "t", None
        if op == "OR":
            return "u", "D112"
        return "u", "D109"
    if len(alts) == 1 or all(alts):
        return "t", None
    if op == "AND":
        return "t", None
    if op == "OR":
        return "f", "D92"
    return "u", "D109"      # v3.9 (N7b): OR and AND disagree and the operator is absent or not a string: the operator-ambiguous id (v3.8: D16)


def _role_inventory(sections):
    """Known exact string IDs and whether the inventory is complete; once per assessment."""
    roles = sections.get("privileged_roles")
    if not isinstance(roles, list):
        return set(), False
    ids = [r.get("RoleTemplateId") for r in roles if isinstance(r, dict)]
    return {i for i in ids if type(i) is str}, bool(ids) and all(type(i) is str for i in ids)


def _roles_cover(p, sections, inventory=None):
    known, complete = _role_inventory(sections) if inventory is None else inventory
    inc = _lst(p, "Conditions", "Users", "IncludeRoles")
    if inc is None:
        return "u", None
    # _lst validates every element before hashing; case, whitespace and duplicate
    # semantics are unchanged. A known missing role wins over unreadable peers.
    if not known <= set(inc):
        return "f", None
    return ("t" if complete else "u"), None


_BUILTIN_CONJ = ("block", "strength_pr", "mfa_general", "grant_devices", "grant_any_device", "operator_or")


def _conj(name, p, sections, inventory=None):
    """v3.9: `_conj0` plus the D111 tag on an unknown conjunct that rests on a duplicated BuiltInControls list."""
    v, d = _conj0(name, p, sections, inventory)
    if v == "u" and d is None and name in _BUILTIN_CONJ and _dup_controls(p) and (name != "strength_pr" or _combos(p) is not None):
        d = "D111"
    return v, d


def _conj0(name, p, sections, inventory=None):
    """t / f / u for one conjunct of one policy object, plus an optional divergence id the verdict leans on (t only; f carries D92 for the operator-OR reading)."""
    if name == "users_all":
        return _in(_lst(p, "Conditions", "Users", "IncludeUsers"), "All"), None
    if name == "apps_all":
        return _in(_lst(p, "Conditions", "Applications", "IncludeApplications"), "All"), None
    if name == "no_role_excl":
        v = _lst(p, "Conditions", "Users", "ExcludeRoles")
        return ("u" if v is None else "t" if not v else "f"), None
    if name == "enabled":
        s = p.get("State")
        return (STATES.get(s, "u") if type(s) is str else "u"), None
    if name == "block":
        b = _builtin(p)
        if b is None:
            return "u", None
        return _paths(p, lambda x: x == "block", lambda s: False, "ignore")      # block beside another control is decided by block: met per Q44 (`_paths` returns before the operator is read); D92 does not apply to it (v3.9, N7a)
    if name == "client_legacy":
        v = _lst(p, "Conditions", "ClientAppTypes")
        return ("u" if v is None else "t" if "other" in v and "exchangeActiveSync" in v else "f"), None
    if name == "client_all":
        return _in(_lst(p, "Conditions", "ClientAppTypes"), "all"), None
    if name == "user_risk_high":
        return _in(_lst(p, "Conditions", "UserRiskLevels"), "high"), None
    if name == "signin_risk_high":
        return _in(_lst(p, "Conditions", "SignInRiskLevels"), "high"), None
    if name == "agent_risk_high":
        c = p.get("Conditions")
        if not isinstance(c, dict) or "AgentIdRiskLevels" not in c:
            return "u", None
        v = c["AgentIdRiskLevels"]
        if v is None:
            return "f", None
        if isinstance(v, str):
            return ("t" if "high" in [x.strip() for x in v.split(",")] else "f"), None
        if isinstance(v, list) and all(type(x) is str for x in v):
            return ("t" if "high" in v else "f"), None
        return "u", None
    if name == "agent_sp_all":
        return _in(_lst(p, "Conditions", "ClientApplications", "IncludeAgentIdServicePrincipals", null_parent_empty=True), "All"), None
    if name == "strength_pr":
        s = _combos(p)
        if s is None:
            return "u", None
        if not s or not s <= PR_COMBOS:
            return "f", None
        return _paths(p, lambda x: False, lambda c: bool(c) and c <= PR_COMBOS, "u")      # v3.7 (F3): a PR strength OR another control is not met (D92)
    if name == "mfa_general":
        b = _builtin(p)
        s = _combos(p)
        v, d = _paths(p, lambda x: x == "mfa", lambda c: bool(c) and c <= MFA_COMBOS, "u_if_none")
        if v == "t" and d is None and b is not None and "mfa" not in b and s and s <= PR_COMBOS:
            d = "D58"      # ruling 3: a phishing-resistant-only strength is MFA (the Rego's IsGeneralMFA needs a non-PR combination)
        return v, d
    if name == "grant_devices":
        return _grant_managed(p)
    if name == "grant_any_device":
        return _paths(p, lambda x: x in DEVICE_CONTROLS, lambda c: False, "ignore")      # v3.7 (F3): a device control OR another control is not met (D92)
    if name == "operator_or":
        gc = p.get("GrantControls", "absent")
        if not isinstance(gc, dict):
            return "u", None
        if gc.get("Operator") not in ("OR", "AND"):
            return _grant_managed(p)      # v3.9 (N4): no usable operator: the status stands where OR and AND agree (met, D110; or not met), and is unknown (D109) where they differ
        if gc["Operator"] == "OR":
            return "t", None
        gm = _grant_managed(p)      # v3.6 (Q27): a managed-device grant under AND is read by _grant_managed (D87), not failed here
        return ("u", gm[1]) if gm[0] == "u" else (("t" if gm[0] == "t" else "f"), None)      # v3.9 (N5): an unusable grant (a duplicated control, an unreadable list) stays unknown under AND (v3.8: not met)
    if name == "no_user_actions":
        v = _lst(p, "Conditions", "Applications", "IncludeUserActions")
        return ("u" if v is None else "t" if not v else "f"), None
    if name == "action_register":
        return _in(_lst(p, "Conditions", "Applications", "IncludeUserActions"), "urn:user:registersecurityinfo"), None
    if name == "flow_device_code":
        c = p.get("Conditions")
        if not isinstance(c, dict) or "AuthenticationFlows" not in c:
            return "u", None
        af = c["AuthenticationFlows"]
        if af is None:
            return "f", None
        if not isinstance(af, dict) or "TransferMethods" not in af:
            return "u", None
        tm = af["TransferMethods"]
        if tm is None:
            return "f", None
        if type(tm) is not str:
            return "u", None
        toks = tm.split(",")
        if any(t not in ("deviceCodeFlow", "authenticationTransfer") for t in toks):
            return "u", None
        if "deviceCodeFlow" not in toks:
            return "f", None
        return "t", ("D59" if len(toks) > 1 else None)         # ruling 3: the combined value counts (the Rego compares the exact string)
    if name == "roles_cover":
        v, d = _roles_cover(p, sections, inventory)
        if v != "t" and _in(_lst(p, "Conditions", "Users", "IncludeUsers"), "All") == "t":
            return "t", "D93"     # v3.7 (lens B CA-4, standing rule 1): a policy that includes all users covers every privileged role, plainly stricter than the requirement
        return v, d
    raise KeyError(name)


def _exempt(kind, p, sections, key, allowed_sets=None):
    """t / f / u: every excluded id of this kind is on the configured exemption list (the Rego's four *FullyExempt tests)."""
    if kind == "guests":
        u = p.get("Conditions", {}).get("Users") if isinstance(p.get("Conditions"), dict) else None
        if not isinstance(u, dict) or "ExcludeGuestsOrExternalUsers" not in u:
            return "u"
        g = u["ExcludeGuestsOrExternalUsers"]
        if g is None:
            return "t"
        if not isinstance(g, dict) or type(g.get("GuestOrExternalUserTypes")) is not str:
            return "u"
        x = g["GuestOrExternalUserTypes"].split(",")
        if any(t != t.strip() or not t for t in x):
            return "u"
        cfgkey = "GuestUserTypes"
    else:
        path, cfgkey = {"users": (("Conditions", "Users", "ExcludeUsers"), "Users"), "groups": (("Conditions", "Users", "ExcludeGroups"), "Groups"),
                        "apps": (("Conditions", "Applications", "ExcludeApplications"), "Applications")}[kind]
        x = _lst(p, *path)
        if x is None:
            return "u"
        if not x:
            return "t"
    if allowed_sets is None:
        allowed_sets = {}
    if kind not in allowed_sets:
        allowed_sets[kind] = _allowed_exemptions(sections, key, cfgkey)
    allowed = allowed_sets[kind]
    return "u" if allowed is None else "t" if set(x) <= allowed else "f"


def _allowed_exemptions(sections, key, cfgkey):
    """Validate and prepare a configured exemption list once, when first needed."""
    cfg = sections.get("scuba_config")
    cur = cfg.get("Aad") if isinstance(cfg, dict) else "bad"
    for k in (key, "CapExclusions"):
        if cur is None:
            break
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    if cur is None:
        return set()
    if isinstance(cur, dict):
        a = cur.get(cfgkey)
        if a is None:
            return set()
        if isinstance(a, list) and all(type(y) is str for y in a):
            return set(a)
    return None


def _ca_obj(c, p, sections, inventory=None, allowed_sets=None):
    """One policy object: (status, flags). status: pass, near_miss, fail, unknown; `ctl` = every C conjunct true and the S ones not all false-or-unknown
    irrelevant: a controlling object carries the control (union candidate)."""
    res = [(n, k, *_conj(n, p, sections, inventory)) for n, k in c["conj"]]
    vals = [r[2] for r in res]
    rst = _restricted(c, p)      # v3.9 (N1): True, False or None (unknown)
    ctl = all(r[2] == "t" for r in res if r[1] == "C") and rst is False
    divs = [r[3] for r in res if r[3]]
    uids = [r[3] for r in res if r[2] == "u"]      # v3.9 (N7b): the divergence ids of the unknown conjuncts (None where an unknown conjunct names none)
    if "f" in vals:
        return "fail", ctl, divs, rst, uids
    if "u" in vals:
        return "unknown", ctl, divs, rst, uids
    ex = [_exempt(k, p, sections, c["key"], allowed_sets) for k in c["ex"]]
    excl = any(_exclusions_present(k, p) for k in c["ex"])
    if "f" in ex:
        return "near_miss", True, divs, rst, uids
    if "u" in ex:
        return "unknown", True, divs, rst, uids + [None]
    if rst is None:
        return "unknown", False, divs, rst, uids + [None]      # v3.9 (N1): an unreadable restriction field: the object cannot count as a pass
    return ("pass_excl" if excl else "pass"), True, divs, rst, uids


FOREIGN = {"user_risk_high": "UserRiskLevels", "signin_risk_high": "SignInRiskLevels", "agent_risk_high": "AgentIdRiskLevels", "client_legacy": "ClientAppTypes",
           "client_all": "ClientAppTypes", "no_user_actions": "IncludeUserActions", "action_register": "IncludeUserActions", "flow_device_code": "TransferMethods"}


def _present(v):
    """True when a Conditions value carries something: not null, not an empty or blank string, not a list without a present element, not an object whose values are all absent
    (an exported `{"Mode": null, "Rule": null}` filter is absent). A number or boolean counts as present."""
    if v is None:
        return False
    if isinstance(v, str):
        return v.strip() != ""
    if isinstance(v, (list, tuple)):
        return any(_present(x) for x in v)
    if isinstance(v, dict):
        return any(_present(x) for x in v.values())
    return True


def _restricted(c, p):
    """v3.9 (N1; v3.7 D91 extended): True, False or None (unknown). True when the policy object carries an applicability condition that its own conjuncts do not read and
    that narrows who or what the policy applies to: a risk level, a client app type other than `all`, a user action, an authentication flow (D91, v3.7) and, new in v3.9, a device
    platform other than `all` included or any excluded, a location other than `All` included or any excluded, a device filter or any other device condition, a device state, a workload
    identity or agent identity target, a service principal risk level, an insider risk level, an application filter and an authentication context. Such an object covers only part of the
    sign-ins in a way no other policy can complete, so it is not a union candidate and a pass through it does not count (`restricted_policy_only`). None: a condition that is present
    but not readable (a non-list `ClientAppTypes`, a non-object container; v3.9.1, F2: an `AuthenticationFlows` that is a string, number, boolean or list) leaves the restriction unknown, so the object cannot count as a pass (unusable, not unrestricted).
    The rule does not rely on the product's projection withholding the section (spec R22). Absent, null, empty and exported-empty values are not restrictions (the Graph export
    renders an unset condition that way). Include lists of users, groups, roles and guests are not restrictions: with `All` included they only repeat what All covers; the exclusions
    of users, groups, guests and applications are read by `_exempt`, and the excluded roles by the `no_role_excl` conjunct."""
    own = {FOREIGN[n] for n, _ in c["conj"] if n in FOREIGN}
    own_agent_sp = any(n == "agent_sp_all" for n, _ in c["conj"])
    cond = p.get("Conditions")
    if not isinstance(cond, dict):
        return False
    unknown = False
    for f in ("UserRiskLevels", "SignInRiskLevels"):
        if f not in own and cond.get(f):
            return True
    if "AgentIdRiskLevels" not in own and cond.get("AgentIdRiskLevels"):
        return True
    for f in ("ServicePrincipalRiskLevels", "InsiderRiskLevels"):
        if _present(cond.get(f)):
            return True
    cat = cond.get("ClientAppTypes")
    if "ClientAppTypes" not in own:
        if isinstance(cat, list):
            if cat and "all" not in cat:
                return True
        elif cat is not None:
            unknown = True                       # a string, number or object where a list is required: unreadable, so unknown (not unrestricted)
    apps = cond.get("Applications")
    if "IncludeUserActions" not in own and isinstance(apps, dict) and apps.get("IncludeUserActions"):
        return True
    if isinstance(apps, dict):
        for f in ("ApplicationFilter", "IncludeAuthenticationContextClassReferences"):
            if _present(apps.get(f)):
                return True
    af = cond.get("AuthenticationFlows")
    if isinstance(af, dict):
        if "TransferMethods" not in own and af.get("TransferMethods"):
            return True
    elif _present(af):
        unknown = True                           # v3.9.1 (F2): a string, number or list where an object is required: unreadable, so unknown (not unrestricted), as Platforms, Locations and the rest
    pl = cond.get("Platforms")
    if isinstance(pl, dict):
        inc, exc = pl.get("IncludePlatforms"), pl.get("ExcludePlatforms")
        for x in (inc, exc):
            if x is not None and not isinstance(x, list):
                unknown = True
        if isinstance(inc, list) and _present(inc) and "all" not in inc:
            return True
        if isinstance(exc, list) and _present(exc):
            return True
        if any(_present(v) for k, v in pl.items() if k not in ("IncludePlatforms", "ExcludePlatforms")):
            return True
    elif _present(pl):
        unknown = True
    lo = cond.get("Locations")
    if isinstance(lo, dict):
        inc, exc = lo.get("IncludeLocations"), lo.get("ExcludeLocations")
        for x in (inc, exc):
            if x is not None and not isinstance(x, list):
                unknown = True
        if isinstance(inc, list) and _present(inc) and "All" not in inc:
            return True
        if isinstance(exc, list) and _present(exc):
            return True
        if any(_present(v) for k, v in lo.items() if k not in ("IncludeLocations", "ExcludeLocations")):
            return True
    elif _present(lo):
        unknown = True
    for f in ("Devices", "DeviceStates"):
        dv = cond.get(f)
        if isinstance(dv, dict):
            if any(_present(v) for v in dv.values()):
                return True
        elif _present(dv):
            unknown = True
    ca = cond.get("ClientApplications")
    if isinstance(ca, dict):
        if any(_present(v) for k, v in ca.items() if not (own_agent_sp and k == "IncludeAgentIdServicePrincipals")):
            return True
    elif _present(ca):
        unknown = True
    return None if unknown else False


def _exclusions_present(kind, p):
    if kind == "guests":
        return isinstance(p.get("Conditions"), dict) and isinstance(p["Conditions"].get("Users"), dict) and p["Conditions"]["Users"].get("ExcludeGuestsOrExternalUsers") is not None
    path = {"users": ("Conditions", "Users", "ExcludeUsers"), "groups": ("Conditions", "Users", "ExcludeGroups"), "apps": ("Conditions", "Applications", "ExcludeApplications")}[kind]
    return bool(_lst(p, *path))


def _ca_exists(policy_id, sp, sections):
    c = sp["ca"]
    lst = sections[CA_ID]
    if not isinstance(lst, list):
        return _A(policy_id, BAD_SECTION_LIST, f"Data unusable: {CA_ID} is not a list of objects; the policy was not assessed.", "section_not_a_list", [CA_ID])
    if "privileged_roles" in sp["sections"] and not isinstance(sections["privileged_roles"], list):
        return _A(policy_id, BAD_SECTION_LIST, "Data unusable: privileged_roles is not a list of objects; the policy was not assessed.", "section_not_a_list", ["privileged_roles"])
    objs = [p for p in lst if isinstance(p, dict)]
    if not lst:
        return _rec(policy_id, "not_met", "no_policies_configured", f"Requirement not met: {CA_ID} is empty, so no Conditional Access policy exists.", "no_policies", None)
    if not objs:
        return _A(policy_id, EMPTY_SECTION, f"Data unavailable: {CA_ID} holds no objects; the policy was not assessed.", "no_usable_items", [CA_ID])
    if c["p2"]:
        g = _p2_gate(policy_id, sections)
        if g:
            return g
    inventory = _role_inventory(sections) if any(n == "roles_cover" for n, _ in c["conj"]) else None
    allowed_sets = {}
    res = [_ca_obj(c, p, sections, inventory, allowed_sets) for p in objs]
    passing = [r for r in res if r[0] in ("pass", "pass_excl") and not r[3]]      # v3.7 (F1, F2): a passing object restricted by a condition the policy does not read never counts (v3.9, N1: platforms, locations, devices and the rest of `_restricted`)
    restricted_pass = [r for r in res if r[0] in ("pass", "pass_excl") and r[3]]
    if passing:
        clean = any(r[0] == "pass" for r in passing)
        return _rec(policy_id, "met", "policy_meets_requirement" if clean else "policy_meets_with_declared_exclusions",
                    "Requirement met: a Conditional Access policy meets every condition" + ("." if clean else ", its exclusions all on the configured exemption list."),
                    "met_policy_clean" if clean else "met_policy_declared_exclusions", None)
    if any(r[0] == "unknown" for r in res):
        return _A(policy_id, ITEM_VALUE, "Data unusable: a Conditional Access policy lacks a usable value for a field the policy reads, or its exclusions cannot be read; the policy was not assessed.",
                  "policy_field_unusable", [s for s in sp["sections"] if s != "service_plans"])
    near = [r for r in res if r[0] == "near_miss"]
    if policy_id == "MS.AAD.3.2v2" and near and _v2_key(sections):
        return _A(policy_id, ITEM_VALUE, "Data unusable: the exemption entry is written under MS.AAD.3.2v2, which ScubaGear ignores (it reads MS.AAD.3.2v1); the policy was not assessed.",
                  "exemption_key_ambiguous", ["scuba_config"])
    ctl = [r for r in res if r[1]]
    if len(ctl) >= 2:
        return _A(policy_id, "data_unusable_policy_set", "Data unusable: no single Conditional Access policy carries every condition, but more than one policy carries the control, so the evidence does not show whether they cover the requirement together; the policy was not assessed.",
                  "union_possible", [CA_ID])
    if restricted_pass:
        return _A(policy_id, "data_unusable_policy_set", "Data unusable: the only Conditional Access policy whose controls match the requirement applies to part of the sign-ins only (limited by risk level, client app type, user action, authentication flow or context, application filter, device platform, location, device or workload identity), so the evidence does not show whether it covers the requirement on its own; the policy was not assessed.",
                  "restricted_policy_only", [CA_ID])
    if near:
        return _rec(policy_id, "not_met", "exclusions_not_configured", "Requirement not met: a policy would meet the condition, but its exclusions are not on the configured exemption list.",
                    "near_miss_exclusions", None)
    return _rec(policy_id, "not_met", "no_policy_meets_requirement", f"Requirement not met: no Conditional Access policy meets every condition ({sp['what']}).", "no_policy_meets", None)


def _v2_key(sections):
    cfg = sections.get("scuba_config")
    a = cfg.get("Aad") if isinstance(cfg, dict) else None
    return isinstance(a, dict) and "MS.AAD.3.2v2" in a


def conditional_access(policy_id, row, sections):
    if policy_id == AAD_91:
        environment = _env_cell91(policy_id, sections)
        if environment:
            return environment
    return _ca_exists(policy_id, {**row["params"], "sections": row["sections"]}, sections)


KINDS = {"ca_exists": conditional_access}
