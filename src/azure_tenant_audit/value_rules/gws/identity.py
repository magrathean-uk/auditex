"""Identity kinds for Google Workspace: ``twosv``, ``super_admin_count`` and ``admin_sso`` (design M13 8.2, lane L10).

- ``twosv`` answers COMMONCONTROLS.1.1 to 1.5 as SG:scubagoggles/rego/Commoncontrols.rego:106-469 does. Per unit:
  (a) its own ``allowEnrollment`` is false; (b) enrolment is on (effective) and its own ``enforcedFrom`` is not in
  force; (c) enrolment is on and enforced (effective) and its own value of the policy's third setting breaks the
  policy. ``enforcedFrom`` is in force when it is not the Unix epoch and not after ``gws_tenant.as_of`` (D8, in
  place of the wall clock). Durations are ``<n>[smhd]`` (SG:scubagoggles/rego/Utils.rego:655). CC.1.4 fails a grace
  period below one day or above seven days (D5; ScubaGoggles fails only zero or above seven days). The 2SV defaults
  come from ``section_semantics`` through ``effective_units``.
- ``super_admin_count`` answers COMMONCONTROLS.6.2: met when two to eight super admins are read (design 8.2, D9: no
  break-glass exclusion input).
- ``admin_sso`` answers COMMONCONTROLS.6.1 as SG:scubagoggles/rego/Commoncontrols.rego:941-1073: for each privileged
  user, the modes of the SSO assignments on the groups the user is in decide; with none, the assignment on the
  nearest organisational unit of the user's parent chain decides; with neither, the user signs in with Google.

Unknown is not safe (design 8.4): a malformed value, an unknown enum, a cut read, a group assignment met with
incomplete memberships or an unresolved parent chain never answers met. A positively read violation still wins over
unknowns elsewhere (design 8.2, step 4). Texts are constant; no input value enters an answer.
"""
from __future__ import annotations

import calendar
import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from ..record import _A, _rec
from .reduce import (
    _OU,
    MISSING,
    UNUSABLE,
    Units,
    Unusable,
    _topology,
    effective,
    effective_units,
)

# Outcomes, ordered so the strongest wins under ``max``: a positively read violation wins over any unknown. Ints, not
# words, so no outcome name becomes a product field name.
_FINE, _LINEAGE, _MEMBERSHIP, _UNKNOWN, _VIOLATES = range(5)
_DAY = 86_400
_GROUP = re.compile(r"group:[^/\s]+")
_DURATION = re.compile(r"(\d+)([dhms])", re.ASCII | re.IGNORECASE)
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
                      re.ASCII)

_SHAPE_TEXT = "Data unusable: an evidence section this policy reads has the wrong shape; the policy was not assessed."


# --- shared parsers ---------------------------------------------------------------------------------------------


def duration_seconds(value: Any) -> int | None:
    """``<n>[smhd]`` in seconds (``DurationToSeconds``, SG:scubagoggles/rego/Utils.rego:655-665); None otherwise."""
    if not isinstance(value, str):
        return None
    match = _DURATION.fullmatch(value)
    if match is None:
        return None
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": _DAY}[match.group(2).lower()]


def instant_ns(value: Any) -> int | None:
    """An RFC 3339 date and time (``time.parse_ns`` with Go's RFC3339 layout) in nanoseconds since the Unix epoch;
    None for anything else, including an impossible date."""
    if not isinstance(value, str):
        return None
    match = _RFC3339.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    zone = match.group(8)
    try:
        offset = UTC if zone == "Z" else timezone(
            (1 if zone[0] == "+" else -1) * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
        moment = datetime(year, month, day, hour, minute, second, tzinfo=offset)
    except ValueError:
        return None
    seconds = calendar.timegm(moment.astimezone(UTC).timetuple())
    return seconds * 1_000_000_000 + int((match.group(7) or "").ljust(9, "0"))


# --- twosv (COMMONCONTROLS.1.1 to 1.5) ----------------------------------------------------------------------------


def _twosv_sections() -> tuple[str, str]:
    return "security_two_step_verification_enrollment", "security_two_step_verification_enforcement"


def _factor_sets() -> frozenset[str]:
    """The ``allowedSignInFactorSet`` values ScubaGoggles names (SG:scubagoggles/rego/Commoncontrols.rego:110-118)."""
    return frozenset(("ALL", "NO_TELEPHONY", "PASSKEY_ONLY", "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE",
                      "PASSKEY_PLUS_SECURITY_CODE"))


def _third(check: str) -> tuple[str, str] | None:
    """The section and field of the policy's own third test, by its ``params.check``; None for CC.1.2."""
    if check == "enrolled_and_enforced":
        return None
    if check in {"passkey_only", "no_telephony"}:
        return "security_two_step_verification_enforcement_factor", "allowedSignInFactorSet"
    if check == "grace_period_one_to_seven_days":
        return "security_two_step_verification_grace_period", "enrollmentGracePeriod"
    if check == "device_trust_off":
        return "security_two_step_verification_device_trust", "allowTrustingDevice"
    raise ValueError("Unknown twosv check")


def _breaks(check: str, value: Any) -> int:
    """Whether the unit's own value of the third setting breaks the policy: violates, fine or unknown."""
    if check in {"passkey_only", "no_telephony"}:
        if not isinstance(value, str) or value not in _factor_sets():
            return _UNKNOWN
        bad = value != "PASSKEY_ONLY" if check == "passkey_only" else value == "ALL"
    elif check == "grace_period_one_to_seven_days":
        seconds = duration_seconds(value)
        if seconds is None:
            return _UNKNOWN
        bad = seconds < _DAY or seconds > 7 * _DAY  # D5: the baseline's "at least one day"
    else:
        if not isinstance(value, bool):
            return _UNKNOWN
        bad = value
    return _VIOLATES if bad else _FINE


def _own(units: Units, unit: str, section: str, field: str) -> Any:
    """The unit's own value, defaults included on the top unit (ScubaGoggles' ``settings.<section>.<field>``)."""
    value = units.values.get(unit, {}).get(section, MISSING)
    if value is MISSING or value is UNUSABLE:
        return value
    if not isinstance(value, dict):
        return UNUSABLE
    return value.get(field, MISSING)


def _enforced(value: Any, as_of: int) -> bool | None:
    """``Is2SVEnforced`` against ``as_of`` (D8): not the epoch and not after ``as_of``; None when unreadable."""
    moment = instant_ns(value)
    if moment is None:
        return None
    return moment != 0 and moment <= as_of


def _enrolled(units: Units, unit: str) -> bool | None:
    enrollment, _ = _twosv_sections()
    value = effective(units, unit, enrollment, "allowEnrollment")
    return value if isinstance(value, bool) else None


def _twosv_unit(units: Units, unit: str, check: str, as_of: int) -> int:
    enrollment, enforcement = _twosv_sections()
    outcomes = {_FINE}
    own_enrol = _own(units, unit, enrollment, "allowEnrollment")
    if own_enrol is not MISSING:  # (a)
        outcomes.add(_UNKNOWN if not isinstance(own_enrol, bool) else _VIOLATES if own_enrol is False else _FINE)
    own_from = _own(units, unit, enforcement, "enforcedFrom")
    if own_from is not MISSING:  # (b)
        in_force = None if own_from is UNUSABLE else _enforced(own_from, as_of)
        if in_force is not True:
            enrolled = _enrolled(units, unit)
            outcomes.add(_FINE if enrolled is False else
                         _UNKNOWN if enrolled is None or in_force is None else _VIOLATES)
    third = _third(check)
    if third is not None:  # (c)
        own_value = _own(units, unit, *third)
        if own_value is not MISSING:
            verdict = _UNKNOWN if own_value is UNUSABLE else _breaks(check, own_value)
            if verdict == _VIOLATES:
                enrolled = _enrolled(units, unit)
                in_force = _enforced(effective(units, unit, enforcement, "enforcedFrom"), as_of)
                verdict = (_FINE if enrolled is False or in_force is False else
                           _UNKNOWN if enrolled is None or in_force is None else _VIOLATES)
            outcomes.add(verdict)
    return max(outcomes)


def twosv(policy_id: str, row: dict, sections: dict) -> dict:
    check = row["params"]["check"]
    third = _third(check)
    keys = list(_twosv_sections()) + ([third[0]] if third else [])
    try:
        units = effective_units(sections, keys)
    except Unusable:
        units = None
    as_of = instant_ns(sections["gws_tenant"].get("as_of")) if units is not None else None
    if units is None or as_of is None:
        return _A(policy_id, "data_unusable_section_shape", _SHAPE_TEXT, "section_shape_unusable", row["sections"])
    if not units.complete:
        return _A(policy_id, "data_unavailable_policy_read_incomplete",
                  "Data unavailable: the Google Workspace policy read or the organisational unit read is incomplete; "
                  "the policy was not assessed.", "policy_read_incomplete", row["sections"])
    outcome = max(_twosv_unit(units, unit, check, as_of) for unit in units.values)
    if outcome == _VIOLATES:
        return _rec(policy_id, "not_met", "unit_violates",
                    "Requirement not met: at least one organisational unit or group has a 2-Step Verification "
                    "setting that breaks this policy.", "unit_violates", row["sections"])
    if outcome == _UNKNOWN:
        return _A(policy_id, "data_unusable_setting_value",
                  "Data unusable: a 2-Step Verification setting that applies has an unreadable value, a value of the "
                  "wrong type or an unknown option; the policy was not assessed.", "setting_value_unusable",
                  row["sections"])
    return _rec(policy_id, "met", "no_unit_violates",
                "Requirement met: no organisational unit or group has a 2-Step Verification setting that breaks "
                "this policy.", "no_unit_violates", row["sections"])


# --- super_admin_count (COMMONCONTROLS.6.2) -----------------------------------------------------------------------


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def super_admin_count(policy_id: str, row: dict, sections: dict) -> dict:
    admins = sections["gws_admins"]
    count = _count(admins.get("super_admin_count")) if isinstance(admins, dict) else None
    if count is None:
        return _A(policy_id, "data_unusable_section_shape", _SHAPE_TEXT, "section_shape_unusable", row["sections"])
    if admins.get("complete") is not True:
        return _A(policy_id, "data_unavailable_user_read_incomplete",
                  "Data unavailable: the Google Workspace user or admin role read is incomplete; the policy was not "
                  "assessed.", "user_read_incomplete", row["sections"])
    if count == 0:
        return _A(policy_id, "data_unusable_super_admin_count",
                  "Data unusable: the read reports no super admin, which a Google Workspace tenant cannot have; the "
                  "policy was not assessed.", "count_unusable", row["sections"])
    if 2 <= count <= 8:
        return _rec(policy_id, "met", "count_in_range",
                    "Requirement met: two to eight super admin accounts are configured.", "count_in_range",
                    row["sections"])
    return _rec(policy_id, "not_met", "count_out_of_range",
                "Requirement not met: fewer than two or more than eight super admin accounts are configured.",
                "count_out_of_range", row["sections"])


# --- admin_sso (COMMONCONTROLS.6.1) -------------------------------------------------------------------------------


def _sso_modes() -> tuple[frozenset[str], frozenset[str]]:
    """Google-only modes (``SsoModeRepresentsGoogleAuthOnly``, SG:scubagoggles/rego/Commoncontrols.rego:1031-1044)
    and the external-SSO modes of the Cloud Identity ``InboundSsoAssignment.SsoMode`` enum; any other value is
    unknown."""
    return frozenset(("SSO_OFF", "SSO_MODE_UNSPECIFIED", "")), frozenset(("SAML_SSO", "DOMAIN_WIDE_SAML_IF_ENABLED"))


def _mode(modes: set[str]) -> int:
    """The modes of the groups a user is in: any external one violates, else any unknown one is unknown."""
    google, external = _sso_modes()
    if modes & external:
        return _VIOLATES
    return _FINE if modes <= google else _UNKNOWN


def _privileged(admins: Any) -> list[tuple[str, frozenset[str]]] | None:
    """``[(org unit, groups)]`` per privileged user; None when any entry has the wrong shape."""
    users = admins.get("privileged") if isinstance(admins, dict) else None
    if not isinstance(users, list):
        return None
    out = []
    for user in users:
        if (not isinstance(user, dict) or not isinstance(user.get("user"), str) or not user["user"]
                or not isinstance(user.get("org_unit"), str) or not _OU.fullmatch(user["org_unit"])
                or not isinstance(user.get("groups"), list)
                or any(not isinstance(group, str) or not _GROUP.fullmatch(group) for group in user["groups"])):
            return None
        out.append((user["org_unit"], frozenset(user["groups"])))
    return out


def _assignments(sso: Any) -> dict[str, set[str]] | None:
    """``{target: {upper-cased modes}}``; None when any assignment has the wrong shape."""
    entries = sso.get("assignments") if isinstance(sso, dict) else None
    if not isinstance(entries, list):
        return None
    out: dict[str, set[str]] = {}
    for entry in entries:
        target = entry.get("target") if isinstance(entry, dict) else None
        if (not isinstance(target, str) or not (_OU.fullmatch(target) or _GROUP.fullmatch(target))
                or not isinstance(entry.get("sso_mode"), str)):
            return None
        out.setdefault(target, set()).add(entry["sso_mode"].upper())
    return out


def _lineage(org_units: dict[str, str | None], unit: str) -> list[str]:
    """The unit and its ancestors, nearest first; the topology is complete and sound, so the walk ends."""
    chain = []
    while unit is not None:
        chain.append(unit)
        unit = org_units[unit]
    return chain


def _admin_user(org_unit: str, groups: frozenset[str], assigned: dict[str, set[str]], members_known: bool,
                org_units: dict[str, str | None] | None) -> int:
    """One privileged user (SG:scubagoggles/rego/Commoncontrols.rego:1015-1029): group assignments first, else the
    nearest assignment on the user's OU chain, else SSO_OFF (:1006)."""
    group_modes = set().union(*(assigned.get(group, set()) for group in groups))
    outcome = _mode(group_modes) if group_modes else _FINE
    if outcome == _VIOLATES:
        return _VIOLATES
    if not members_known:
        # An unseen membership may add an external-SSO group, or a Google-only group that overrides the OU.
        return _MEMBERSHIP
    if group_modes:
        return outcome
    if org_units is None or org_unit not in org_units:
        return _LINEAGE
    for unit in _lineage(org_units, org_unit):
        if unit in assigned:
            # One OU holds one assignment; two different modes on it are ambiguous, not a choice.
            return _UNKNOWN if len(assigned[unit]) > 1 else _mode(assigned[unit])
    return _FINE


def admin_sso(policy_id: str, row: dict, sections: dict) -> dict:
    admins, sso = sections["gws_admins"], sections["gws_sso"]
    users, assigned = _privileged(admins), _assignments(sso)
    try:
        _, topology_sound, _ = _topology(sections["gws_tenant"])
    except Unusable:
        users = None
    if users is None or assigned is None or not isinstance(admins.get("memberships_complete"), bool):
        return _A(policy_id, "data_unusable_section_shape", _SHAPE_TEXT, "section_shape_unusable", row["sections"])
    if admins.get("complete") is not True:
        return _A(policy_id, "data_unavailable_user_read_incomplete",
                  "Data unavailable: the Google Workspace user or admin role read is incomplete; the policy was not "
                  "assessed.", "user_read_incomplete", ["gws_admins"])
    if sso.get("complete") is not True:
        return _A(policy_id, "data_unavailable_sso_read_incomplete",
                  "Data unavailable: the inbound SSO assignment read is incomplete; the policy was not assessed.",
                  "sso_read_incomplete", ["gws_sso"])
    if not users:
        return _A(policy_id, "data_unusable_no_privileged_users",
                  "Data unusable: the read reports no privileged account, which a Google Workspace tenant cannot "
                  "have; the policy was not assessed.", "no_privileged_users", ["gws_admins"])
    members_known = admins["memberships_complete"] or not any(_GROUP.fullmatch(target) for target in assigned)
    org_units = sections["gws_tenant"]["org_units"] if topology_sound else None
    outcome = max(_admin_user(org_unit, groups, assigned, members_known, org_units) for org_unit, groups in users)
    if outcome == _VIOLATES:
        return _rec(policy_id, "not_met", "admin_uses_external_sso",
                    "Requirement not met: at least one privileged account is assigned to sign in through an external "
                    "identity provider.", "admin_uses_external_sso", row["sections"])
    if outcome == _UNKNOWN:
        return _A(policy_id, "data_unusable_sso_assignment",
                  "Data unusable: an inbound SSO assignment that applies to a privileged account has an unknown mode, "
                  "or one target holds disagreeing assignments; the policy was not assessed.", "assignment_unusable",
                  ["gws_sso"])
    if outcome == _MEMBERSHIP:
        return _A(policy_id, "data_unavailable_membership_incomplete",
                  "Data unavailable: an inbound SSO assignment targets a group and the group membership read is "
                  "incomplete; the policy was not assessed.", "membership_incomplete", ["gws_admins", "gws_sso"])
    if outcome == _LINEAGE:
        return _A(policy_id, "data_unavailable_org_unit_lineage",
                  "Data unavailable: the organisational unit read is incomplete or inconsistent, so the nearest SSO "
                  "assignment of a privileged account cannot be found; the policy was not assessed.",
                  "lineage_unresolved", ["gws_tenant", "gws_admins"])
    return _rec(policy_id, "met", "admins_use_google_sign_in",
                "Requirement met: every privileged account signs in with Google, not through an external identity "
                "provider.", "admins_use_google_sign_in", row["sections"])


KINDS = {"twosv": twosv, "super_admin_count": super_admin_count, "admin_sso": admin_sso}
