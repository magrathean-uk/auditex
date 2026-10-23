"""Tenant-level identity control verdicts: is MFA enforced, is legacy authentication blocked,
can users consent to apps.

Registration reports say who *could* use MFA, never whether it is *required*. These verdicts
read the configuration that enforces or blocks instead: Microsoft Entra security defaults,
enabled Conditional Access policies, and the authorization policy's user consent settings.

Each verdict never guesses:

* ``effective_mfa``: ``enforced`` | ``enforced_with_exclusions`` | ``not_enforced`` | ``unknown``
* ``administrator_mfa``: the same values, for the effective administrator set only
* ``legacy_authentication_block``: ``blocked`` | ``blocked_with_exclusions`` | ``not_blocked`` | ``unknown``
* ``user_consent``: ``restricted`` | ``limited`` | ``unrestricted`` | ``unknown``

A negative verdict needs complete evidence. A policy list that was blocked, truncated or never
collected can hide the one policy that changes the answer, so those states give ``unknown``.
A positive verdict needs positive evidence of its own: security defaults reported on, or at
least one qualifying enabled Conditional Access policy.

A policy that targets everyone but excludes principals does not enforce for them. ``enforced`` and
``blocked`` therefore need every principal excluded from all of the qualifying policies to be an
emergency-access account the operator listed (``--break-glass-accounts``, ``break_glass.py``); an
excluded role, a guest type or any other user or group reads ``*_with_exclusions``, which baselines
treat as a gap, never a pass. Exclusions are compared by principal as well as by id: a user excluded by
id from one policy, through a role-assignable group from a second and through a role they hold from a
third is outside all three, and counts as excluded. Nothing here performs I/O.

Security defaults are the basis of a verdict (``basis``) but not of a Conditional Access benchmark
control: baselines read ``basis`` and leave CIS 5.2.2.x and the SCuBA Conditional Access controls
``not_assessed`` when no qualifying policy backs the verdict.
"""
from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

KIND = "identity_control_verdict"
SECTION = "identity_control_verdicts"

CONTROL_EFFECTIVE_MFA = "effective_mfa"
CONTROL_LEGACY_AUTH = "legacy_authentication_block"
CONTROL_USER_CONSENT = "user_consent"
CONTROL_ADMIN_MFA = "administrator_mfa"

VERDICT_ENFORCED = "enforced"
VERDICT_ENFORCED_WITH_EXCLUSIONS = "enforced_with_exclusions"
VERDICT_NOT_ENFORCED = "not_enforced"
VERDICT_BLOCKED = "blocked"
VERDICT_BLOCKED_WITH_EXCLUSIONS = "blocked_with_exclusions"
VERDICT_NOT_BLOCKED = "not_blocked"
VERDICT_UNKNOWN = "unknown"

EVIDENCE_COLLECTED = "collected"
EVIDENCE_BLOCKED = "blocked"
EVIDENCE_TRUNCATED = "truncated"
EVIDENCE_ABSENT = "absent"

# The built-in phishing-resistant MFA strength, and the modes a custom strength may allow and stay
# phishing-resistant (Microsoft Learn: authentication strengths).
_PHISHING_RESISTANT_STRENGTH_ID = "00000000-0000-0000-0000-000000000004"
_PHISHING_RESISTANT_MODES = frozenset({"fido2", "windowshelloforbusiness", "x509certificatemultifactor"})
# Built-in authentication strengths that require MFA (Microsoft Learn: authentication strengths).
_BUILT_IN_MFA_STRENGTH_IDS = frozenset(
    {
        "00000000-0000-0000-0000-000000000002",  # Multifactor authentication
        "00000000-0000-0000-0000-000000000003",  # Passwordless MFA
        "00000000-0000-0000-0000-000000000004",  # Phishing-resistant MFA
    }
)
# authenticationMethodModes (Microsoft Graph). An allowed combination of two or more modes is
# multi-factor. A single-entry combination is judged by its one mode: known single-factor modes
# weaken the strength, known multi-factor modes keep it, and any other mode cannot be rated.
_SINGLE_FACTOR_MODES = frozenset(
    {
        "password",
        "sms",
        "voice",
        "email",
        "softwareoath",
        "hardwareoath",
        "x509certificatesinglefactor",
        "federatedsinglefactor",
    }
)
_MULTI_FACTOR_MODES = frozenset(
    {
        "fido2",
        "windowshelloforbusiness",
        "x509certificatemultifactor",
        "devicebasedpush",
        "temporaryaccesspassonetime",
        "temporaryaccesspassmultiuse",
        "federatedmultifactor",
    }
)
_LEGACY_CLIENT_APP_TYPES = ("exchangeactivesync", "other")
_MODERN_CLIENT_APP_TYPES = ("browser", "mobileanddesktopclients")
_ENFORCING_STATES = ("enabled", "enabledforreportingbutnotenforced")

# The directory roles a benchmark asks an administrator MFA policy to include, by role template id (the id of a
# built-in role definition). These are static lists, not the roles held today: a policy that covers the roles
# the current administrators hold leaves the next person given another privileged role without MFA.
# CIS Microsoft 365 Foundations 5.2.2.1 ("at minimum" these roles; the same list is Prowler's AdminRoles).
CIS_ADMINISTRATOR_ROLES: Mapping[str, str] = {
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451": "Global Reader",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}
# ScubaGear's DefaultPrivilegedRoles (MS.AAD.3.6v1 needs every one included and none excluded).
SCUBA_PRIVILEGED_ROLES: Mapping[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
}

_SELF_CONSENT_PREFIX = "ManagePermissionGrantsForSelf."
_OWNED_RESOURCE_CONSENT_PREFIX = "ManagePermissionGrantsForOwnedResource."
# Microsoft built-in permission grant policies for user consent (Microsoft Learn:
# configure user consent settings).
_CONSENT_UNRESTRICTED_POLICIES = frozenset({"microsoft-user-default-legacy"})
# Policies that let users consent, within limits. CIS 5.1.5.1 asks for no user consent at all and
# ScubaGear fails the recommended (Microsoft-managed) assignment, so none of these reads ``restricted``.
# ``-allow-consent-apps`` is the companion policy of the Microsoft-managed setting: it grants named
# permissions to named first-party clients only.
_CONSENT_LIMITED_POLICIES = {
    "microsoft-user-default-low": "verified_publishers_low_risk_permissions",
    "microsoft-user-default-recommended": "microsoft_managed",
    "microsoft-user-default-allow-consent-apps": "microsoft_managed",
}
_BUILT_IN_CONSENT_PREFIX = "microsoft-"

_MFA_SCOPE = (
    "Microsoft Entra security defaults and Conditional Access policies. Registration reports, "
    "per-user MFA states and legacy MFA settings are not evaluated."
)
_ADMIN_MFA_SCOPE = (
    "Microsoft Entra security defaults and Conditional Access policies, read against the effective "
    "administrator set. Registration reports, per-user MFA states and legacy MFA settings are not evaluated."
)
_PER_USER_MFA_LIMITATION = (
    "Per-user (legacy) MFA states are not read, so a tenant that enforces MFA only through per-user MFA, "
    "without security defaults or Conditional Access, reads not_enforced."
)
_ROLE_CATALOG_SCOPE = (
    "role_catalog_verdict: every role of the CIS 5.2.2.1 administrator list (15 roles) included by a policy that requires "
    "MFA and none excluded, whoever holds it now. phishing_resistant_role_catalog_verdict: the same over ScubaGear's "
    "default privileged roles (8 roles, MS.AAD.3.6v1) for phishing-resistant policies. Both are static lists by role "
    "template id; the verdict itself reads the roles administrators hold today."
)
_LEGACY_LIMITATION = "Exchange Online protocol settings (for example SMTP AUTH) are not evaluated."
_LEGACY_SCOPE = (
    "Microsoft Entra security defaults and Conditional Access policies. Exchange Online protocol "
    "settings (for example SMTP AUTH) are not evaluated."
)
_CONSENT_SCOPE = (
    "The authorization policy's default user role permissions. Custom permission grant policies "
    "and group-owner (resource-specific) consent are not evaluated."
)


@dataclass(frozen=True)
class AdminScope:
    """What the administrator MFA verdict needs to know about the effective administrator set.

    Built from ``normalized/effective_admin_set.json`` by ``effective_admins.admin_scope``. Every id is
    lower-case. ``complete`` is the set's own state: only a complete set can show that a role-targeted
    policy covers every role an administrator holds, or that an exclusion does not reach one.
    """

    complete: bool = False
    privileged_role_ids: frozenset[str] = frozenset()
    held_role_ids: frozenset[str] = frozenset()
    admin_principal_ids: frozenset[str] = frozenset()
    guest_admin_count: int | None = None
    # Principal id -> the administrator roles that principal holds, by any route the set read. Empty for a scope
    # that was built by hand with only the flat sets above: the verdicts then assume the worst split of roles.
    principal_roles: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # Group id -> ids of the members the run read (role-assignable groups, nested groups included as members).
    group_members: Mapping[str, frozenset[str]] = field(default_factory=dict)
    guest_principal_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Evidence:
    """One collected endpoint as the verdicts see it.

    ``state`` is ``collected``, ``blocked`` (the read failed), ``truncated`` (the rows are
    known to be incomplete) or ``absent`` (never collected).
    """

    state: str = EVIDENCE_ABSENT
    rows: tuple[Mapping[str, Any], ...] = ()
    detail: str | None = None

    @property
    def usable(self) -> bool:
        return self.state == EVIDENCE_COLLECTED

    def summary(self) -> dict[str, Any]:
        result: dict[str, Any] = {"state": self.state, "row_count": len(self.rows)}
        if self.detail:
            result["detail"] = self.detail
        return result


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item not in (None, "")]
    return []


def _lower(values: Iterable[str]) -> list[str]:
    return [item.lower() for item in values]


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _has_all(values: Iterable[str]) -> bool:
    return "all" in _lower(values)


def _guest_scope(value: Any) -> dict[str, Any] | None:
    scope = _mapping(value)
    types = _strings(scope.get("guestOrExternalUserTypes"))
    tenants = _mapping(scope.get("externalTenants"))
    membership = tenants.get("membershipKind")
    if not types and not membership:
        return None
    result: dict[str, Any] = {"types": types}
    if membership:
        result["tenants"] = str(membership)
    return result


def _strength_reference(grant: Mapping[str, Any]) -> dict[str, Any] | None:
    strength = grant.get("authenticationStrength")
    if not isinstance(strength, Mapping) or not strength.get("id"):
        return None
    reference: dict[str, Any] = {"id": str(strength["id"]), "display_name": strength.get("displayName")}
    if strength.get("requirementsSatisfied"):
        reference["requirements_satisfied"] = str(strength["requirementsSatisfied"])
    combinations = _strings(strength.get("allowedCombinations"))
    if combinations:
        reference["allowed_combinations"] = combinations
    return reference


def policy_targeting(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Who, what and how a Conditional Access policy applies, with raw include and exclude values.

    ``clientAppTypes`` defaults to ``["all"]``, the Graph default, when a fixture omits it.
    """
    conditions = _mapping(policy.get("conditions"))
    users = _mapping(conditions.get("users"))
    applications = _mapping(conditions.get("applications"))
    locations = _mapping(conditions.get("locations"))
    platforms = _mapping(conditions.get("platforms"))
    devices = _mapping(conditions.get("devices"))
    flows = _mapping(conditions.get("authenticationFlows"))
    grant = _mapping(policy.get("grantControls"))
    device_filter = _mapping(devices.get("deviceFilter"))
    return {
        "state": str(policy.get("state") or ""),
        "include_users": _strings(users.get("includeUsers")),
        "exclude_users": _strings(users.get("excludeUsers")),
        "include_groups": _strings(users.get("includeGroups")),
        "exclude_groups": _strings(users.get("excludeGroups")),
        "include_roles": _strings(users.get("includeRoles")),
        "exclude_roles": _strings(users.get("excludeRoles")),
        "include_guests_or_external_users": _guest_scope(users.get("includeGuestsOrExternalUsers")),
        "exclude_guests_or_external_users": _guest_scope(users.get("excludeGuestsOrExternalUsers")),
        "include_applications": _strings(applications.get("includeApplications")),
        "exclude_applications": _strings(applications.get("excludeApplications")),
        "include_user_actions": _strings(applications.get("includeUserActions")),
        "include_authentication_contexts": _strings(applications.get("includeAuthenticationContextClassReferences")),
        "client_app_types": _strings(conditions.get("clientAppTypes")) or ["all"],
        "include_platforms": _strings(platforms.get("includePlatforms")),
        "exclude_platforms": _strings(platforms.get("excludePlatforms")),
        "include_locations": _strings(locations.get("includeLocations")),
        "exclude_locations": _strings(locations.get("excludeLocations")),
        "sign_in_risk_levels": _strings(conditions.get("signInRiskLevels")),
        "user_risk_levels": _strings(conditions.get("userRiskLevels")),
        "service_principal_risk_levels": _strings(conditions.get("servicePrincipalRiskLevels")),
        "insider_risk_levels": _strings(conditions.get("insiderRiskLevels")),
        "device_filter_mode": str(device_filter["mode"]).lower() if device_filter.get("mode") else None,
        "device_filter_rule": str(device_filter["rule"]) if device_filter.get("rule") else None,
        "authentication_flows": _strings(flows.get("transferMethods")),
        "grant": {
            "operator": str(grant["operator"]) if grant.get("operator") else None,
            "built_in_controls": _lower(_strings(grant.get("builtInControls"))),
            "authentication_strength": _strength_reference(grant),
            "custom_authentication_factors": _strings(grant.get("customAuthenticationFactors")),
            "terms_of_use": _strings(grant.get("termsOfUse")),
        },
    }


def compact_targeting(targeting: Mapping[str, Any]) -> dict[str, Any]:
    """The targeting block without empty values, for the normalized policy record."""
    result: dict[str, Any] = {}
    for key, value in targeting.items():
        if key == "grant":
            grant = {name: item for name, item in _mapping(value).items() if item not in (None, [], {}, "")}
            if grant:
                result["grant"] = grant
        elif value not in (None, [], {}, ""):
            result[key] = value
    return result


def _narrowing_reasons(targeting: Mapping[str, Any]) -> list[str]:
    """Conditions that shrink a policy's reach: narrower includes, and exclusions of platforms, devices or apps.

    Excluded principals and excluded locations are not here: they are listed on the verdict as the
    exceptions to a qualifying policy.
    """
    reasons: list[str] = []
    platforms = targeting["include_platforms"]
    if platforms and "all" not in _lower(platforms):
        reasons.append("narrowed_by_platform")
    if targeting["exclude_platforms"]:
        reasons.append("excludes_platforms")
    locations = targeting["include_locations"]
    if locations and not _has_all(locations):
        reasons.append("narrowed_by_location")
    if any(
        targeting[key]
        for key in ("sign_in_risk_levels", "user_risk_levels", "service_principal_risk_levels", "insider_risk_levels")
    ):
        reasons.append("narrowed_by_risk_condition")
    if targeting["device_filter_mode"] == "include":
        reasons.append("narrowed_by_device_filter")
    if targeting["device_filter_mode"] == "exclude":
        reasons.append("device_filter_excludes_devices")
    if targeting["exclude_applications"]:
        reasons.append("excludes_applications")
    if targeting["authentication_flows"]:
        reasons.append("narrowed_by_authentication_flow")
    return reasons


def _scope_reasons(targeting: Mapping[str, Any], *, client_types_cover: bool) -> list[str]:
    reasons: list[str] = []
    if not _has_all(targeting["include_users"]):
        reasons.append("not_all_users")
    if (
        not _has_all(targeting["include_applications"])
        or targeting["include_user_actions"]
        or targeting["include_authentication_contexts"]
    ):
        reasons.append("not_all_cloud_apps")
    if not client_types_cover:
        reasons.append("client_app_types_not_covered")
    return reasons


def _client_types_cover(client_types: Iterable[str], required: tuple[str, ...]) -> bool:
    lowered = set(_lower(client_types))
    return "all" in lowered or set(required) <= lowered


def _combinations_class(combinations: Iterable[str]) -> str:
    """``weak`` if any allowed combination is a known single factor, ``unverified`` if one cannot be rated."""
    result = "mfa"
    for combination in combinations:
        modes = [mode.strip().lower() for mode in combination.split(",") if mode.strip()]
        if len(modes) != 1:
            continue
        if modes[0] in _SINGLE_FACTOR_MODES:
            return "weak"
        if modes[0] not in _MULTI_FACTOR_MODES:
            result = "unverified"
    return result


def _strength_class(strength: Mapping[str, Any], strengths: Evidence) -> str:
    """``mfa``, ``weak`` (can be met by a single factor) or ``unverified``."""
    satisfied = str(strength.get("requirements_satisfied") or "").lower()
    combinations = list(strength.get("allowed_combinations") or [])
    strength_id = str(strength.get("id") or "")
    if not satisfied and not combinations and strengths.usable:
        for row in strengths.rows:
            if str(row.get("id") or "") == strength_id:
                satisfied = str(row.get("requirementsSatisfied") or "").lower()
                combinations = _strings(row.get("allowedCombinations"))
                break
    if satisfied == "mfa":
        return "mfa"
    if satisfied == "none":
        return "weak"
    if combinations:
        return _combinations_class(combinations)
    if strength_id in _BUILT_IN_MFA_STRENGTH_IDS:
        return "mfa"
    return "unverified"


def _phishing_resistant(targeting: Mapping[str, Any], strengths: Evidence) -> bool:
    """Whether the policy's grant requires an authentication strength that only phishing-resistant methods meet.

    A built-in control such as ``mfa`` accepts SMS and push, so only an authentication strength counts: the
    built-in phishing-resistant one, or a strength whose every allowed combination is FIDO2, Windows Hello for
    Business or a certificate-based multi-factor credential.
    """
    grant = targeting["grant"]
    strength = grant["authentication_strength"]
    if not strength or "block" in grant["built_in_controls"]:
        return False
    if str(grant["operator"] or "").upper() != "AND" and grant["built_in_controls"]:
        # "Require one of": the user may pick the built-in control, so the strength is not the only way in.
        return False
    strength_id = str(strength.get("id") or "")
    combinations = list(strength.get("allowed_combinations") or [])
    if not combinations and strengths.usable:
        for row in strengths.rows:
            if str(row.get("id") or "") == strength_id:
                combinations = _strings(row.get("allowedCombinations"))
                break
    if combinations:
        modes = [mode.strip().lower() for combination in combinations for mode in combination.split(",") if mode.strip()]
        return bool(modes) and all(mode in _PHISHING_RESISTANT_MODES for mode in modes)
    return strength_id == _PHISHING_RESISTANT_STRENGTH_ID


def _mfa_grant(targeting: Mapping[str, Any], strengths: Evidence) -> tuple[str, str | None]:
    """Classify a policy's grant: ``mfa``, ``not_mfa`` (no MFA alternative), or a reason it falls short.

    With "require all" every selected control applies, so one MFA-class control is enough. With
    "require one" the user picks, so every alternative must itself be MFA-class.
    """
    grant = targeting["grant"]
    controls = list(grant["built_in_controls"])
    if "block" in controls:
        return "not_mfa", None
    alternatives = ["mfa" if control == "mfa" else "other" for control in controls]
    strength = grant["authentication_strength"]
    if strength:
        alternatives.append(_strength_class(strength, strengths))
    if not any(item in ("mfa", "weak", "unverified") for item in alternatives):
        return "not_mfa", None
    if str(grant["operator"] or "").upper() == "AND":
        if "mfa" in alternatives:
            return "mfa", None
        satisfied = [item for item in alternatives if item in ("weak", "unverified")]
        alternatives = satisfied
    elif all(item == "mfa" for item in alternatives):
        return "mfa", None
    if "other" in alternatives:
        return "short", "grant_operator_or_with_other_controls"
    if "weak" in alternatives:
        return "short", "authentication_strength_allows_single_factor"
    return "unverified", "authentication_strength_unverified"


def _resolve(lookups: Mapping[str, Mapping[str, str]], kind: str, object_id: str) -> str | None:
    return (lookups.get(kind) or {}).get(object_id) or (lookups.get(kind) or {}).get(object_id.lower())


def _exclusions(
    targeting: Mapping[str, Any],
    lookups: Mapping[str, Mapping[str, str]],
    sanctioned: Collection[str] = frozenset(),
) -> list[dict[str, Any]]:
    """The principals a policy excludes. ``sanctioned`` marks the emergency-access users and groups the operator listed.

    Only a user or a group can be sanctioned. An excluded role or guest type is never an emergency-access
    account, so it always reads as a gap in the policy.
    """
    rows: list[dict[str, Any]] = []
    for kind, key in (("user", "exclude_users"), ("group", "exclude_groups"), ("role", "exclude_roles")):
        for object_id in targeting[key]:
            name = _resolve(lookups, kind, object_id)
            row: dict[str, Any] = {
                "type": kind,
                "id": object_id,
                "resolved": name is not None,
                "sanctioned": kind != "role" and object_id.lower() in sanctioned,
            }
            if name:
                row["display_name"] = name
            rows.append(row)
    guests = targeting["exclude_guests_or_external_users"]
    if guests:
        rows.append(
            {
                "type": "guests_or_external_users",
                "id": ",".join(guests["types"]) or str(guests.get("tenants") or "all"),
                "resolved": False,
                "sanctioned": False,
            }
        )
    return sorted(rows, key=lambda row: (row["type"], row["id"]))


def _policy_summary(
    policy: Mapping[str, Any],
    targeting: Mapping[str, Any],
    lookups: Mapping[str, Mapping[str, str]],
    reasons: list[str],
    sanctioned: Collection[str] = frozenset(),
) -> dict[str, Any]:
    policy_id = str(policy.get("id") or "")
    grant = targeting["grant"]
    strength = grant["authentication_strength"]
    grant_summary: dict[str, Any] = {"built_in_controls": list(grant["built_in_controls"])}
    if grant["operator"]:
        grant_summary["operator"] = grant["operator"]
    if strength:
        grant_summary["authentication_strength"] = strength.get("display_name") or strength.get("id")
    summary: dict[str, Any] = {
        "id": policy_id,
        "display_name": policy.get("displayName"),
        "state": targeting["state"],
        "grant": grant_summary,
        "exclusions": _exclusions(targeting, lookups, sanctioned),
        "excluded_applications": list(targeting["exclude_applications"]),
        "excluded_locations": list(targeting["exclude_locations"]),
        "excluded_platforms": list(targeting["exclude_platforms"]),
    }
    if targeting["device_filter_mode"]:
        summary["device_filter"] = {
            key: value
            for key, value in (("mode", targeting["device_filter_mode"]), ("rule", targeting["device_filter_rule"]))
            if value
        }
    if policy_id:
        summary["key"] = f"conditional_access_policy:{policy_id}"
    if reasons:
        summary["reasons"] = list(reasons)
    return summary


class _Directory:
    """Who holds which administrator role and who belongs to which group, as far as the run read it.

    Roles are known for administrators only (the effective administrator set) and group members for the
    role-assignable groups the run expanded, so a role or group outside that reads as having no known members.
    ``members`` follows nested groups.
    """

    def __init__(self, scope: AdminScope | None, principals: Mapping[str, frozenset[str]] | None = None) -> None:
        self._roles: dict[str, frozenset[str]] = dict(principals if principals is not None else (scope.principal_roles if scope else {}))
        self._holders: dict[str, set[str]] = {}
        for principal, roles in self._roles.items():
            for role in roles:
                self._holders.setdefault(role, set()).add(principal)
        self._direct: dict[str, frozenset[str]] = dict(scope.group_members) if scope is not None else {}
        self._closure: dict[str, frozenset[str]] = {}
        self.guests: frozenset[str] = scope.guest_principal_ids if scope is not None else frozenset()
        # Whether the set says what each administrator holds and whether they are a guest, or only the flat sets.
        self._itemised = bool(scope is not None and scope.principal_roles)

    def roles(self, principal: str) -> frozenset[str]:
        return self._roles.get(principal, frozenset())

    def knows_principal(self, principal: str) -> bool:
        """Whether the set lists the principal as an administrator (so its roles are known)."""
        return principal in self._roles

    def is_guest(self, principal: str) -> bool | None:
        if principal in self.guests:
            return True
        return False if self._itemised and principal in self._roles else None

    def holders(self, role_id: str) -> set[str]:
        return set(self._holders.get(role_id, ()))

    def knows_group(self, group_id: str) -> bool:
        return group_id in self._direct

    def members(self, group_id: str) -> frozenset[str]:
        if group_id not in self._closure:
            seen: set[str] = set()
            queue = [group_id]
            while queue:
                current = queue.pop()
                for member in self._direct.get(current, ()):
                    if member not in seen:
                        seen.add(member)
                        queue.append(member)
            self._closure[group_id] = frozenset(seen)
        return self._closure[group_id]


def _excluded_principals(exclusions: Iterable[Mapping[str, Any]], directory: _Directory) -> dict[str, list[Mapping[str, Any]]]:
    """Principal id (lower-case) -> the exclusion rows that leave it out: itself, a group it is in, a role it holds."""
    reached: dict[str, list[Mapping[str, Any]]] = {}
    for row in exclusions:
        kind, row_id = row["type"], str(row["id"]).lower()
        if kind == "user" and row_id != _LEGACY_GUEST_EXCLUSION:
            targets: Iterable[str] = (row_id,)
        elif kind == "group":
            targets = directory.members(row_id)
        elif kind == "role":
            targets = directory.holders(row_id)
        else:
            continue
        for target in targets:
            reached.setdefault(target, []).append(row)
    return reached


def _common_exclusions(
    policies: list[dict[str, Any]],
    directory: _Directory | None = None,
    *,
    sanctioned: Collection[str] = frozenset(),
    lookups: Mapping[str, Mapping[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Principals excluded from every qualifying policy; those are the ones the basis does not cover.

    First the exclusions every policy lists by the same type and id. With a ``directory`` the comparison also runs
    by principal: a user excluded by id from one policy, through a group the run read the members of from a second
    and through a role they hold from a third is outside all three, though no single exclusion is common to them.
    Those principals are added as ``user`` rows with the route each policy excludes them by (``via``).

    A group whose members the run did not read, and the operator did not list as emergency access, might contain
    any principal. A principal that some policies exclude by a route the run can see, and every other policy only
    through such a group, is added as a ``possible`` row: it may well be outside all of them.
    """
    if not policies:
        return []
    common = {(row["type"], row["id"]) for row in policies[0]["exclusions"]}
    for policy in policies[1:]:
        common &= {(row["type"], row["id"]) for row in policy["exclusions"]}
    policy_ids = [policy["id"] for policy in policies if policy["id"]]
    result = []
    for row in policies[0]["exclusions"]:
        if (row["type"], row["id"]) in common:
            result.append({**row, "policy_ids": policy_ids})
    if directory is None or len(policies) < 2:
        return result
    sanctioned_ids = {str(item).lower() for item in sanctioned}
    per_policy = [_excluded_principals(policy["exclusions"], directory) for policy in policies]
    unread_groups = [
        sorted(
            str(row["id"])
            for row in policy["exclusions"]
            if row["type"] == "group"
            and not directory.knows_group(str(row["id"]).lower())
            and str(row["id"]).lower() not in sanctioned_ids
        )
        for policy in policies
    ]
    shared = set(per_policy[0]).intersection(*per_policy[1:])
    possible = {
        principal
        for principal in set().union(*per_policy)
        if all(principal in routes or groups for routes, groups in zip(per_policy, unread_groups))
    } - shared
    if not shared and not possible:
        return result
    implied: set[str] = set()
    for row in result:
        implied |= set(_excluded_principals([row], directory))
    sanctioned_members = {member for item in sanctioned_ids for member in directory.members(item)}
    names = {key.lower(): value for key, value in ((lookups or {}).get("user") or {}).items()}
    for principal in sorted((shared | possible) - implied):
        is_sanctioned = principal in sanctioned_ids or principal in sanctioned_members
        if principal in possible and is_sanctioned:
            continue
        via = [
            (
                {"policy_id": policy["id"], "type": routes[principal][0]["type"], "id": routes[principal][0]["id"]}
                if principal in routes
                else {"policy_id": policy["id"], "type": "group", "id": groups[0], "members_read": False}
            )
            for policy, routes, groups in zip(policies, per_policy, unread_groups)
        ]
        row = {
            "type": "user",
            "id": principal,
            "resolved": principal in names,
            "sanctioned": is_sanctioned,
            "via": via,
            "policy_ids": policy_ids,
        }
        if principal in possible:
            row["possible"] = True
        if principal in names:
            row["display_name"] = names[principal]
        result.append(row)
    return result


def _common_values(policies: list[dict[str, Any]], key: str) -> list[str]:
    if not policies:
        return []
    common = set(policies[0][key])
    for policy in policies[1:]:
        common &= set(policy[key])
    return sorted(common)


def _security_defaults_view(evidence: Evidence) -> tuple[dict[str, Any], bool | None]:
    row = evidence.rows[0] if evidence.usable and evidence.rows else None
    enabled = row.get("isEnabled") if row is not None and isinstance(row.get("isEnabled"), bool) else None
    view = evidence.summary()
    if evidence.usable and enabled is None:
        view = {"state": EVIDENCE_ABSENT, "row_count": len(evidence.rows), "detail": "is_enabled_missing"}
    if enabled is not None:
        view["enabled"] = enabled
    if row is not None and row.get("id"):
        view["policy_id"] = str(row["id"])
    return view, enabled


def _policy_view(evidence: Evidence, policies: list[Mapping[str, Any]]) -> dict[str, Any]:
    view = evidence.summary()
    if evidence.usable:
        view["enabled_policy_count"] = sum(
            1 for policy in policies if str(policy.get("state") or "").lower() == "enabled"
        )
    return view


def _evidence_reasons(prefix: str, view: Mapping[str, Any]) -> list[str]:
    return [] if view["state"] == EVIDENCE_COLLECTED else [f"{prefix}_{view['state']}"]


def _plural_principals(count: int) -> str:
    return "1 principal" if count == 1 else f"{count} principals"


def _unsanctioned(exclusions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Exclusions that are a gap: not an emergency-access account the operator listed, and not covered by another policy."""
    return [row for row in exclusions if not row.get("sanctioned") and not row.get("covered_by_policy_ids")]


def _exclusion_fields(
    common: list[dict[str, Any]], sanctioned: Collection[str], unresolved: Sequence[str] = ()
) -> dict[str, Any]:
    """Record fields for the principals excluded from every qualifying policy and the part that is a gap.

    ``unresolved`` lists the emergency-access entries the operator gave that matched no collected user or group (or
    matched more than one); the verdict is judged without them.
    """
    gap = _unsanctioned(common)
    return {
        "excluded_principals": common,
        "excluded_principal_count": len(common),
        "unsanctioned_exclusions": gap,
        "unsanctioned_exclusion_count": len(gap),
        "sanctioned_exclusion_source": "operator" if sanctioned else "none",
        "unresolved_operator_accounts": list(unresolved),
    }


_MFA_BASIS_SUMMARY = {
    ("security_defaults",): "Security defaults are enabled.",
    ("conditional_access_policy",): (
        "At least one enabled Conditional Access policy requires MFA for all users on all cloud apps."
    ),
    ("security_defaults", "conditional_access_policy"): (
        "Security defaults are enabled and an enabled Conditional Access policy requires MFA for all users on all cloud apps."
    ),
}


def evaluate_effective_mfa(
    *,
    policies: Evidence,
    security_defaults: Evidence,
    authentication_strengths: Evidence,
    lookups: Mapping[str, Mapping[str, str]],
    registration: Mapping[str, Any] | None = None,
    sanctioned: Collection[str] = frozenset(),
    admin_scope: AdminScope | None = None,
    unresolved_accounts: Sequence[str] = (),
) -> dict[str, Any]:
    """``enforced`` when security defaults or an all-users, all-apps MFA policy with only sanctioned exclusions applies.

    ``sanctioned`` is the lower-case object ids of the emergency-access users and groups the operator listed. A
    qualifying policy that excludes anything else (a role, a guest type, another user or group) gives
    ``enforced_with_exclusions``: MFA is required, but not of everyone. ``admin_scope`` lets the comparison run by
    principal (who holds an excluded role, who is in an excluded group the run read); ``unresolved_accounts`` are
    operator entries that matched no account, recorded on the verdict.

    The verdict is the reading Cyber Essentials takes: an administrator role or administrator that every all-users
    policy excludes, but a role-targeted MFA policy requires MFA of, is covered (the row is marked
    ``covered_by_policy_ids`` and the policy listed in ``supplementary_policies``). ``single_policy_verdict`` is the
    reading CIS 5.2.2.2 and SCuBA MS.AAD.3.2v1 take, which look for one policy that leaves nobody out, and does not
    credit that cover.
    """
    defaults_view, defaults_enabled = _security_defaults_view(security_defaults)
    policy_rows = [row for row in policies.rows if isinstance(row, Mapping)] if policies.usable else []
    qualifying: list[dict[str, Any]] = []
    near_miss: list[dict[str, Any]] = []
    report_only: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    coverers: list[_Coverer] = []
    for policy in policy_rows:
        targeting = policy_targeting(policy)
        if targeting["state"].lower() not in _ENFORCING_STATES:
            continue
        grant_class, grant_reason = _mfa_grant(targeting, authentication_strengths)
        if grant_class == "not_mfa":
            continue
        reasons = _scope_reasons(
            targeting, client_types_cover=_client_types_cover(targeting["client_app_types"], _MODERN_CLIENT_APP_TYPES)
        )
        reasons.extend(_narrowing_reasons(targeting))
        if grant_reason:
            reasons.append(grant_reason)
        if targeting["state"].lower() == "enabledforreportingbutnotenforced":
            report_only.append(_policy_summary(policy, targeting, lookups, ["report_only", *reasons], sanctioned))
        elif grant_class == "unverified" and reasons == [grant_reason]:
            # Would qualify if its authentication strength could be shown to require MFA.
            unverified.append(_policy_summary(policy, targeting, lookups, reasons, sanctioned))
        elif reasons:
            summary = _policy_summary(policy, targeting, lookups, reasons, sanctioned)
            near_miss.append(summary)
            if targeting["include_roles"] and set(reasons) <= _MFA_ROLE_POLICY_REASONS:
                # Requires MFA of the roles it names, so it covers an administrator an all-users policy excludes.
                coverers.append(
                    _Coverer(
                        targeting=targeting,
                        summary=summary,
                        strength_unverified="authentication_strength_unverified" in reasons,
                        phishing_resistant=False,
                        full_reach=False,
                    )
                )
        else:
            qualifying.append(_policy_summary(policy, targeting, lookups, [], sanctioned))

    policy_view = _policy_view(policies, policy_rows)
    directory = _Directory(admin_scope)
    excluded_all = _common_exclusions(qualifying, directory, sanctioned=sanctioned, lookups=lookups)
    excluded, relied_on = _rescue_exclusions(
        excluded_all, coverers, directory, known=admin_scope is not None and admin_scope.complete, sanctioned=sanctioned
    )
    gap = _unsanctioned(excluded)
    single_gap = _unsanctioned(excluded_all)
    # The policies back a positive verdict only when they alone leave nobody out. Security defaults that are on beside
    # a policy with gaps establish the verdict, and that policy is not a basis for a Conditional Access benchmark
    # control, so it is not listed.
    ca_backs = bool(qualifying) and not gap
    basis = [name for name, present in (
        ("security_defaults", defaults_enabled is True),
        ("conditional_access_policy", bool(qualifying) and (not gap or defaults_enabled is not True)),
    ) if present]
    reasons = [*_evidence_reasons("policy_collection", policy_view), *_evidence_reasons("security_defaults", defaults_view)]
    if defaults_enabled is True or ca_backs:
        verdict, reasons = VERDICT_ENFORCED, []
        basis_summary = _MFA_BASIS_SUMMARY[tuple(basis)]
    elif qualifying:
        verdict, reasons = VERDICT_ENFORCED_WITH_EXCLUSIONS, []
        basis_summary = (
            "An enabled Conditional Access policy requires MFA for all users on all cloud apps, but every qualifying "
            f"policy excludes {_plural_principals(len(gap))} that {'is' if len(gap) == 1 else 'are'} not an emergency "
            "access account the operator listed."
        )
    elif not reasons and defaults_enabled is False and not unverified:
        verdict = VERDICT_NOT_ENFORCED
        basis_summary = (
            "Security defaults are off and no enabled Conditional Access policy requires MFA for all users on all cloud apps."
        )
    else:
        verdict = VERDICT_UNKNOWN
        basis_summary = "The evidence does not establish whether MFA is enforced."
        if unverified:
            reasons.append("authentication_strength_unverified")

    record: dict[str, Any] = {
        "control": CONTROL_EFFECTIVE_MFA,
        "title": "Effective MFA enforcement",
        "verdict": verdict,
        "basis": basis,
        "basis_summary": basis_summary,
        "reasons": sorted(set(reasons)),
        "evaluated_scope": _MFA_SCOPE,
        "limitations": [] if verdict == VERDICT_ENFORCED else [_PER_USER_MFA_LIMITATION],
        "security_defaults": defaults_view,
        "policy_collection": policy_view,
        "authentication_strength_collection": authentication_strengths.summary(),
        "single_policy_verdict": (
            VERDICT_ENFORCED
            if defaults_enabled is True or (qualifying and not single_gap)
            else VERDICT_ENFORCED_WITH_EXCLUSIONS
            if qualifying
            else verdict
        ),
        "qualifying_policies": qualifying,
        "supplementary_policies": list({id(coverer): coverer.summary for coverer in relied_on}.values()),
        **_exclusion_fields(excluded, sanctioned, unresolved_accounts),
        "excluded_locations": _common_values(qualifying, "excluded_locations"),
        "non_qualifying_mfa_policies": near_miss,
        "report_only_mfa_policies": report_only,
        "unverified_policies": unverified,
    }
    if registration:
        record["registration_context"] = {
            "sampled_users": registration.get("sampled_users"),
            "mfa_registered": registration.get("mfa_registered"),
            "mfa_not_registered": registration.get("mfa_not_registered"),
            "note": "Registration shows who can use MFA, not whether it is required. It never establishes enforcement.",
        }
    return record


_LEGACY_BASIS_SUMMARY = {
    ("security_defaults",): "Security defaults are enabled, which block legacy authentication.",
    ("conditional_access_policy",): (
        "At least one enabled Conditional Access policy blocks legacy authentication clients for all users on all cloud apps."
    ),
    ("security_defaults", "conditional_access_policy"): (
        "Security defaults are enabled and an enabled Conditional Access policy blocks legacy authentication clients."
    ),
}


def evaluate_legacy_authentication_block(
    *,
    policies: Evidence,
    security_defaults: Evidence,
    lookups: Mapping[str, Mapping[str, str]],
    sanctioned: Collection[str] = frozenset(),
    admin_scope: AdminScope | None = None,
    unresolved_accounts: Sequence[str] = (),
) -> dict[str, Any]:
    """``blocked`` when security defaults or an all-users, all-apps block policy with only sanctioned exclusions covers legacy clients.

    A block policy that excludes anything but the operator's emergency-access accounts gives ``blocked_with_exclusions``.
    A policy counts only when it names both legacy client app types (Exchange ActiveSync clients and Other clients),
    as ScubaGear and the CIS audit do, and no location condition limits it: a block of every client type that
    exempts the trusted countries (``all`` client types, locations excluded) leaves legacy protocols open from
    them, and a legacy block that exempts a network leaves them open from that network. Two block policies that
    each name one legacy client type, and are otherwise the same, do block both, but neither is the one policy the
    benchmarks look for: the verdict stays ``not_blocked`` and records ``legacy_block_split_across_policies`` with the
    policies in ``block_split_across_policies``.
    """
    defaults_view, defaults_enabled = _security_defaults_view(security_defaults)
    policy_rows = [row for row in policies.rows if isinstance(row, Mapping)] if policies.usable else []
    blocking: list[dict[str, Any]] = []
    near_miss: list[dict[str, Any]] = []
    report_only: list[dict[str, Any]] = []
    split_candidates: list[tuple[dict[str, Any], set[str]]] = []
    for policy in policy_rows:
        targeting = policy_targeting(policy)
        if targeting["state"].lower() not in _ENFORCING_STATES:
            continue
        if "block" not in targeting["grant"]["built_in_controls"]:
            continue
        lowered_types = set(_lower(targeting["client_app_types"]))
        if "all" not in lowered_types and not lowered_types & set(_LEGACY_CLIENT_APP_TYPES):
            continue
        # ``all`` is every client type, not a statement about legacy ones: only a policy that lists both counts.
        reasons = _scope_reasons(
            targeting, client_types_cover=set(_LEGACY_CLIENT_APP_TYPES) <= lowered_types
        )
        reasons = [
            (
                "legacy_client_app_types_not_targeted"
                if "all" in lowered_types
                else "legacy_client_app_types_incomplete"
            )
            if reason == "client_app_types_not_covered"
            else reason
            for reason in reasons
        ]
        reasons.extend(_narrowing_reasons(targeting))
        if targeting["exclude_locations"]:
            reasons.append("excludes_locations")
        if targeting["state"].lower() == "enabledforreportingbutnotenforced":
            report_only.append(_policy_summary(policy, targeting, lookups, ["report_only", *reasons], sanctioned))
        elif reasons:
            summary = _policy_summary(policy, targeting, lookups, reasons, sanctioned)
            near_miss.append(summary)
            if reasons == ["legacy_client_app_types_incomplete"]:
                split_candidates.append((summary, lowered_types & set(_LEGACY_CLIENT_APP_TYPES)))
        else:
            blocking.append(_policy_summary(policy, targeting, lookups, [], sanctioned))

    policy_view = _policy_view(policies, policy_rows)
    excluded = _common_exclusions(blocking, _Directory(admin_scope), sanctioned=sanctioned, lookups=lookups)
    gap = _unsanctioned(excluded)
    # As for MFA: security defaults beside a block policy with gaps establish the verdict, and the policy is not listed
    # as a basis for a Conditional Access benchmark control.
    ca_backs = bool(blocking) and not gap
    basis = [name for name, present in (
        ("security_defaults", defaults_enabled is True),
        ("conditional_access_policy", bool(blocking) and (not gap or defaults_enabled is not True)),
    ) if present]
    reasons = [*_evidence_reasons("policy_collection", policy_view), *_evidence_reasons("security_defaults", defaults_view)]
    if defaults_enabled is True or ca_backs:
        verdict, reasons = VERDICT_BLOCKED, []
        basis_summary = _LEGACY_BASIS_SUMMARY[tuple(basis)]
    elif blocking:
        verdict, reasons = VERDICT_BLOCKED_WITH_EXCLUSIONS, []
        basis_summary = (
            "An enabled Conditional Access policy blocks legacy authentication clients for all users on all cloud apps, "
            f"but every qualifying policy excludes {_plural_principals(len(gap))} that "
            f"{'is' if len(gap) == 1 else 'are'} not an emergency access account the operator listed."
        )
    elif not reasons and defaults_enabled is False:
        verdict = VERDICT_NOT_BLOCKED
        basis_summary = (
            "Security defaults are off and no enabled Conditional Access policy blocks the Exchange ActiveSync and "
            "other legacy client types, named explicitly and without a location limit, for all users on all cloud apps."
        )
    else:
        verdict = VERDICT_UNKNOWN
        basis_summary = "The evidence does not establish whether legacy authentication is blocked."

    split: list[dict[str, Any]] = []
    if verdict == VERDICT_NOT_BLOCKED and len(split_candidates) > 1:
        covered = set().union(*(types for _, types in split_candidates))
        if set(_LEGACY_CLIENT_APP_TYPES) <= covered:
            split = [summary for summary, _types in split_candidates]
            reasons.append("legacy_block_split_across_policies")

    return {
        "control": CONTROL_LEGACY_AUTH,
        "title": "Legacy authentication block",
        "verdict": verdict,
        "basis": basis,
        "basis_summary": basis_summary,
        "reasons": sorted(set(reasons)),
        "evaluated_scope": _LEGACY_SCOPE,
        "limitations": [] if verdict == VERDICT_BLOCKED else [_LEGACY_LIMITATION],
        "security_defaults": defaults_view,
        "policy_collection": policy_view,
        "blocking_policies": blocking,
        "block_split_across_policies": [summary["id"] for summary in split if summary.get("id")],
        **_exclusion_fields(excluded, sanctioned, unresolved_accounts),
        "excluded_locations": _common_values(blocking, "excluded_locations"),
        "non_qualifying_block_policies": near_miss,
        "report_only_block_policies": report_only,
    }


_ADMIN_UNVERIFIED_REASONS = frozenset({"authentication_strength_unverified", "administrator_set_unknown"})
# An MFA policy that is only a near miss for "all users" for these reasons still requires MFA of the roles it names.
_MFA_ROLE_POLICY_REASONS = frozenset({"not_all_users", "authentication_strength_unverified"})
# A policy that carries only these reasons still requires MFA of the administrators it reaches: it names some of the
# roles an administrator holds, or the set is not known well enough to say who it reaches, or its authentication
# strength cannot be rated. Each such policy counts for the administrators it does reach (see ``_coverage``).
_ADMIN_COVERAGE_REASONS = frozenset(
    {"covers_only_some_administrator_roles", "administrator_set_unknown", "authentication_strength_unverified"}
)
_LEGACY_GUEST_EXCLUSION = "guestsorexternalusers"


def _administrator_reach(targeting: Mapping[str, Any], scope: AdminScope | None) -> tuple[str | None, list[str]]:
    """How a policy reaches the administrators: ``all_users``, ``administrator_roles``, or ``None`` and why not.

    A role-targeted policy reaches every administrator on its own only when it includes every role an administrator
    holds, which needs a complete administrator set. A policy for named groups or users is not judged: who is in
    them is not known. A role-targeted policy that falls short still counts for the administrators it does reach,
    once every enabled policy is combined per administrator.
    """
    if _has_all(targeting["include_users"]):
        return "all_users", []
    include_roles = set(_lower(targeting["include_roles"]))
    if not include_roles:
        return None, ["not_all_administrators"]
    if scope is None or not scope.complete:
        return None, ["administrator_set_unknown"]
    if scope.held_role_ids - include_roles:
        return None, ["covers_only_some_administrator_roles"]
    return "administrator_roles", []


def _admin_principals(scope: AdminScope | None) -> dict[str, frozenset[str]]:
    """The administrators the verdict judges one by one: principal id -> the administrator roles it holds.

    A scope built from the flat sets alone says which roles are held and by whom, not who holds which. The verdict
    then assumes the worst split: each administrator holds no role that can be shown, and each held role has a
    holder that holds only that role.
    """
    if scope is None:
        return {}
    if scope.principal_roles:
        return dict(scope.principal_roles)
    principals: dict[str, frozenset[str]] = {principal: frozenset() for principal in scope.admin_principal_ids}
    for role in scope.held_role_ids:
        principals[f"role:{role}"] = frozenset({role})
    return principals


@dataclass(frozen=True, eq=False)
class _Coverer:
    """An enabled policy that requires MFA of the administrators it reaches, whether or not that is all of them."""

    targeting: Mapping[str, Any]
    summary: dict[str, Any]
    strength_unverified: bool
    phishing_resistant: bool
    full_reach: bool


def _principal_excluded(
    targeting: Mapping[str, Any], principal: str, directory: _Directory, sanctioned: Collection[str]
) -> bool | None:
    """Whether a policy leaves ``principal`` out: ``True``, ``False``, or ``None`` when an exclusion might.

    A principal is excluded as a user, as a member of an excluded group the run read, or as a holder of an excluded
    role. A group whose members were not read, or a guest type, might reach it. An exclusion of an emergency-access
    user or group the operator listed does not count as one that might.
    """
    users = set(_lower(targeting["exclude_users"]))
    if principal in users or directory.roles(principal) & set(_lower(targeting["exclude_roles"])):
        return True
    unsure = False
    for group in _lower(targeting["exclude_groups"]):
        if principal in directory.members(group):
            return True
        if not directory.knows_group(group) and group not in sanctioned:
            unsure = True
    if (targeting["exclude_guests_or_external_users"] or _LEGACY_GUEST_EXCLUSION in users) and directory.is_guest(principal) is not False:
        unsure = True
    return None if unsure else False


def _reaches(targeting: Mapping[str, Any], principal: str, directory: _Directory) -> bool:
    """Whether a policy includes ``principal``: all users, or a role the principal holds."""
    if _has_all(targeting["include_users"]):
        return True
    return bool(set(_lower(targeting["include_roles"])) & directory.roles(principal))


def _coverage(
    coverers: Iterable[_Coverer], principal: str, directory: _Directory, sanctioned: Collection[str]
) -> tuple[str, list[_Coverer], list[str]]:
    """``yes`` when a verified policy requires MFA of ``principal``, ``maybe`` when one might, else ``no``.

    The policies are combined: Conditional Access applies every policy that includes a principal and does not
    exclude it, so a principal one policy excludes is still covered by another that reaches it.
    """
    maybe: list[_Coverer] = []
    reasons: list[str] = []
    for coverer in coverers:
        if not _reaches(coverer.targeting, principal, directory):
            continue
        excluded = _principal_excluded(coverer.targeting, principal, directory, sanctioned)
        if excluded is True:
            continue
        if excluded is None:
            maybe.append(coverer)
            reasons.append("administrator_exclusion_unresolved")
        elif coverer.strength_unverified:
            maybe.append(coverer)
            reasons.append("authentication_strength_unverified")
        else:
            return "yes", [coverer], []
    return ("maybe" if maybe else "no"), maybe, reasons


def _role_coverage(
    role_id: str, coverers: Iterable[_Coverer], sanctioned: Collection[str]
) -> tuple[str, list[_Coverer], list[str]]:
    """The same for the holders of a role when none is known: a policy that includes the role and leaves nobody out covers them all."""
    maybe: list[_Coverer] = []
    reasons: list[str] = []
    for coverer in coverers:
        targeting = coverer.targeting
        if not (_has_all(targeting["include_users"]) or role_id in set(_lower(targeting["include_roles"]))):
            continue
        if role_id in set(_lower(targeting["exclude_roles"])):
            continue
        others = [
            item
            for item in (*_lower(targeting["exclude_users"]), *_lower(targeting["exclude_groups"]))
            if item not in sanctioned
        ]
        if others or targeting["exclude_guests_or_external_users"]:
            maybe.append(coverer)
            reasons.append("administrator_exclusion_unresolved")
        elif coverer.strength_unverified:
            maybe.append(coverer)
            reasons.append("authentication_strength_unverified")
        else:
            return "yes", [coverer], []
    return ("maybe" if maybe else "no"), maybe, reasons


def _exclusion_coverage(
    row: Mapping[str, Any],
    coverers: Iterable[_Coverer],
    directory: _Directory,
    *,
    known: bool,
    sanctioned: Collection[str],
) -> list[tuple[str, list[_Coverer], list[str]]] | None:
    """Whether other policies require MFA of the administrators an excluded role or user row leaves out.

    One outcome per administrator the row reaches (``yes``, ``maybe`` or ``no``, see ``_coverage``). A role is also
    judged as a whole when the administrator set is not complete or nobody is known to hold it: the set may be missing
    a holder (a PIM-eligible user, say), and a policy that includes the role but excludes a user cannot be shown to
    reach him. ``None`` when the row is not an administrator role or user.
    """
    row_id = str(row["id"]).lower()
    if row["type"] == "role":
        holders = sorted(directory.holders(row_id))
        outcomes = [_coverage(coverers, principal, directory, sanctioned) for principal in holders]
        if not known or not holders:
            outcomes.append(_role_coverage(row_id, coverers, sanctioned))
        return outcomes
    if row["type"] == "user" and directory.knows_principal(row_id):
        return [_coverage(coverers, row_id, directory, sanctioned)]
    return None


def _rescue_exclusions(
    rows: list[dict[str, Any]],
    coverers: list[_Coverer],
    directory: _Directory,
    *,
    known: bool,
    sanctioned: Collection[str],
) -> tuple[list[dict[str, Any]], list[_Coverer]]:
    """The exclusion rows, each marked ``covered_by_policy_ids`` when other enabled policies require MFA of everyone it leaves out.

    Used by the all-users verdicts: an all-users policy that excludes the Global Administrator role, and a policy for
    that role, still require MFA of everyone. Only a policy that verifiably requires MFA counts; a row that is not an
    administrator role or user, an emergency-access account, or one that is only possibly excluded stays as it is.
    """
    sanctioned_ids = {str(item).lower() for item in sanctioned}
    result: list[dict[str, Any]] = []
    relied: list[_Coverer] = []
    for row in rows:
        outcomes = None if row.get("sanctioned") or row.get("possible") else _exclusion_coverage(
            row, coverers, directory, known=known, sanctioned=sanctioned_ids
        )
        if outcomes and all(state == "yes" for state, _, _ in outcomes):
            used = [coverer for _, items, _ in outcomes for coverer in items]
            relied.extend(used)
            result.append({**row, "covered_by_policy_ids": sorted({str(item.summary["id"]) for item in used if item.summary.get("id")}) or ["unnamed"]})
        else:
            result.append(row)
    return result, relied


def _administrator_outcome(
    qualifying: list[dict[str, Any]],
    coverers: list[_Coverer],
    scope: AdminScope | None,
    directory: _Directory,
    principals: Mapping[str, frozenset[str]],
    *,
    sanctioned: Collection[str],
    lookups: Mapping[str, Mapping[str, str]],
) -> tuple[str | None, list[dict[str, Any]], list[_Coverer], list[str]]:
    """How completely the enabled policies cover the administrators: the verdict kind, exclusions, policies relied on, reasons.

    ``not_enforced``: an administrator is excluded from every qualifying policy (an excluded privileged role someone
    holds, an excluded user who is an administrator, or a user left out by a different route in each policy) and no
    other policy requires MFA of that administrator. ``enforced_with_exclusions``: a group or guest type is excluded
    and its administrators cannot be told apart. ``enforced``: nothing that reaches an administrator is excluded,
    other than the operator's emergency-access accounts, or every administrator it excludes is covered by another
    policy. ``unknown``: the only policy that could cover an excluded administrator cannot be verified. ``None``: no
    policy reaches every administrator, and the policies together do not cover them either.
    """
    known = scope is not None and scope.complete
    sanctioned_ids = {str(item).lower() for item in sanctioned}
    used: list[_Coverer] = []
    if not qualifying:
        if not (known and principals and coverers):
            return None, [], [], []
        outcomes = [_coverage(coverers, principal, directory, sanctioned_ids) for principal in sorted(principals)]
        if any(state == "no" for state, _, _ in outcomes):
            return None, [], [], []
        used = [coverer for _, items, _ in outcomes for coverer in items]
        if all(state == "yes" for state, _, _ in outcomes):
            return VERDICT_ENFORCED, [], used, []
        return VERDICT_UNKNOWN, [], [], sorted({reason for _, _, items in outcomes for reason in items})
    relevant_roles = (scope.held_role_ids if known else scope.privileged_role_ids) if scope is not None else frozenset()
    definite: list[dict[str, Any]] = []
    possible: list[dict[str, Any]] = []
    undecided: list[str] = []
    for row in _unsanctioned(_common_exclusions(qualifying, directory, sanctioned=sanctioned, lookups=lookups)):
        row_id = str(row["id"]).lower()
        if row["type"] == "user" and row_id == _LEGACY_GUEST_EXCLUSION:
            # The older way to exclude every guest and external user: the same as a guest type.
            row = {**row, "type": "guests_or_external_users"}
        if row["type"] == "role":
            if row_id not in relevant_roles:
                if not known:
                    possible.append(row)
                continue
        elif row["type"] == "user":
            if not (scope is not None and row_id in scope.admin_principal_ids):
                if not known:
                    possible.append(row)
                continue
        elif row["type"] == "group" or not (known and scope.guest_admin_count == 0):
            possible.append(row)
            continue
        else:
            continue
        outcomes = _exclusion_coverage(row, coverers, directory, known=known, sanctioned=sanctioned_ids) or []
        if row["type"] == "role" and not known and not directory.holders(row_id):
            # Nobody known holds the role, but the set is not complete: a holder may be missing from it.
            state, items, why = outcomes[0]
            if state == "yes":
                used.extend(items)
            else:
                undecided.extend(["administrator_set_unknown", *why])
        elif all(state == "yes" for state, _, _ in outcomes):
            used.extend(coverer for _, items, _ in outcomes for coverer in items)
        elif any(state == "no" for state, _, _ in outcomes) and not row.get("possible"):
            definite.append(row)
        elif any(state == "no" for state, _, _ in outcomes):
            # A group the run did not read might contain the administrator, and might not.
            undecided.append("administrator_exclusion_unresolved")
        else:
            undecided.extend(reason for _, _, items in outcomes for reason in items)
    if definite:
        return VERDICT_NOT_ENFORCED, [*definite, *possible], used, []
    if undecided:
        return VERDICT_UNKNOWN, [], used, sorted(set(undecided))
    if possible:
        return VERDICT_ENFORCED_WITH_EXCLUSIONS, possible, used, []
    return VERDICT_ENFORCED, [], used, []


def _role_catalog(coverers: Iterable[_Coverer], roles: Mapping[str, str]) -> tuple[str, list[dict[str, Any]]]:
    """Whether the policies cover every role of a benchmark's list: ``enforced``, ``not_enforced`` or ``unknown``.

    A role is covered when a verified policy includes it (all users, or the role itself) and does not exclude it. A
    role no policy includes, or one every policy that reaches it excludes, is uncovered, whoever holds it today.
    """
    coverers = list(coverers)
    uncovered: list[dict[str, Any]] = []
    undecided = False
    for role_id, name in roles.items():
        state, why = "no", "not_included"
        for coverer in coverers:
            targeting = coverer.targeting
            if not (_has_all(targeting["include_users"]) or role_id in set(_lower(targeting["include_roles"]))):
                continue
            if role_id in set(_lower(targeting["exclude_roles"])):
                why = "excluded"
                continue
            if coverer.strength_unverified:
                state = "maybe"
                continue
            state = "yes"
            break
        if state == "no":
            uncovered.append({"id": role_id, "name": name, "reason": why})
        elif state == "maybe":
            undecided = True
    if uncovered:
        return VERDICT_NOT_ENFORCED, uncovered
    return (VERDICT_UNKNOWN if undecided else VERDICT_ENFORCED), []


def evaluate_administrator_mfa(
    *,
    policies: Evidence,
    security_defaults: Evidence,
    authentication_strengths: Evidence,
    lookups: Mapping[str, Mapping[str, str]],
    admin_scope: AdminScope | None = None,
    sanctioned: Collection[str] = frozenset(),
    unresolved_accounts: Sequence[str] = (),
) -> dict[str, Any]:
    """Whether MFA is required of the administrators: security defaults, or policies that reach every administrator.

    Registration reports say who could use MFA. This reads what requires it, for the effective administrator set only.
    A policy qualifies when it requires MFA on all cloud apps for all users, or for every role an administrator holds,
    and is not narrowed. The exclusions that every qualifying policy shares then decide the verdict: an excluded
    administrator role (or administrator) gives ``not_enforced`` because those administrators are not required to
    use MFA, unless another enabled policy that reaches them (a role-targeted policy that does not cover every
    administrator on its own) requires it; an excluded group or guest type gives ``enforced_with_exclusions``. Policies
    are combined per administrator, and a principal left out of every qualifying policy by a different route in each
    (user, group, role) counts as excluded. ``phishing_resistant_verdict`` is the same reading over the policies that
    require a phishing-resistant authentication strength. Security defaults require MFA of administrators but not a
    phishing-resistant method.

    The verdict reads the roles administrators hold today. ``role_catalog_verdict`` is the stricter reading the
    benchmarks make (CIS 5.2.2.1): every role of the CIS administrator list included, none excluded, whoever holds
    it now; ``phishing_resistant_role_catalog_verdict`` does the same over ScubaGear's privileged roles for the
    phishing-resistant policies (MS.AAD.3.6v1). Neither changes ``verdict``, which Cyber Essentials reads.
    """
    defaults_view, defaults_enabled = _security_defaults_view(security_defaults)
    policy_rows = [row for row in policies.rows if isinstance(row, Mapping)] if policies.usable else []
    qualifying: list[dict[str, Any]] = []
    near_miss: list[dict[str, Any]] = []
    report_only: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    coverers: list[_Coverer] = []
    for policy in policy_rows:
        targeting = policy_targeting(policy)
        if targeting["state"].lower() not in _ENFORCING_STATES:
            continue
        grant_class, grant_reason = _mfa_grant(targeting, authentication_strengths)
        if grant_class == "not_mfa":
            continue
        reach, reasons = _administrator_reach(targeting, admin_scope)
        if (
            not _has_all(targeting["include_applications"])
            or targeting["include_user_actions"]
            or targeting["include_authentication_contexts"]
        ):
            reasons.append("not_all_cloud_apps")
        if not _client_types_cover(targeting["client_app_types"], _MODERN_CLIENT_APP_TYPES):
            reasons.append("client_app_types_not_covered")
        reasons.extend(_narrowing_reasons(targeting))
        if grant_reason:
            reasons.append(grant_reason)
        if targeting["state"].lower() == "enabledforreportingbutnotenforced":
            report_only.append(_policy_summary(policy, targeting, lookups, ["report_only", *reasons], sanctioned))
            continue
        if reasons and set(reasons) <= _ADMIN_UNVERIFIED_REASONS:
            summary = _policy_summary(policy, targeting, lookups, reasons, sanctioned)
            unverified.append(summary)
        elif reasons:
            summary = _policy_summary(policy, targeting, lookups, reasons, sanctioned)
            near_miss.append(summary)
        else:
            summary = _policy_summary(policy, targeting, lookups, [], sanctioned)
            summary["reach"] = reach
            summary["phishing_resistant"] = _phishing_resistant(targeting, authentication_strengths)
            qualifying.append(summary)
        if set(reasons) <= _ADMIN_COVERAGE_REASONS:
            coverers.append(
                _Coverer(
                    targeting=targeting,
                    summary=summary,
                    strength_unverified="authentication_strength_unverified" in reasons,
                    phishing_resistant=_phishing_resistant(targeting, authentication_strengths),
                    full_reach=not reasons,
                )
            )

    policy_view = _policy_view(policies, policy_rows)
    principals = _admin_principals(admin_scope)
    directory = _Directory(admin_scope, principals)
    outcome_kwargs: dict[str, Any] = {"sanctioned": sanctioned, "lookups": lookups}
    kind, exclusions, relied_on, outcome_reasons = _administrator_outcome(
        qualifying, coverers, admin_scope, directory, principals, **outcome_kwargs
    )
    resistant = [policy for policy in qualifying if policy["phishing_resistant"]]
    resistant_coverers = [coverer for coverer in coverers if coverer.phishing_resistant]
    resistant_kind, _resistant_exclusions, _resistant_relied_on, _resistant_reasons = _administrator_outcome(
        resistant, resistant_coverers, admin_scope, directory, principals, **outcome_kwargs
    )
    supplementary = {id(coverer): coverer.summary for coverer in relied_on if not coverer.full_reach}
    # Policies back the verdict only when they alone enforce it; security defaults that are on beside policies with
    # gaps establish the verdict, and those policies are not a basis for a Conditional Access benchmark control.
    ca_backs = kind == VERDICT_ENFORCED and bool(qualifying or relied_on)
    basis = [name for name, present in (
        ("security_defaults", defaults_enabled is True),
        ("conditional_access_policy", ca_backs or (bool(qualifying) and defaults_enabled is not True)),
    ) if present]
    reasons = [*_evidence_reasons("policy_collection", policy_view), *_evidence_reasons("security_defaults", defaults_view)]
    if defaults_enabled is True or kind == VERDICT_ENFORCED:
        verdict, reasons = VERDICT_ENFORCED, []
        basis_summary = (
            "An enabled Conditional Access policy requires MFA of every administrator, or security defaults are enabled."
            if ca_backs
            else "Security defaults are enabled, which require MFA of administrator roles."
        )
    elif kind == VERDICT_ENFORCED_WITH_EXCLUSIONS:
        verdict, reasons = VERDICT_ENFORCED_WITH_EXCLUSIONS, []
        basis_summary = (
            "An enabled Conditional Access policy requires MFA of administrators, but every qualifying policy excludes "
            f"{_plural_principals(len(exclusions))} that may include administrators and "
            f"{'is' if len(exclusions) == 1 else 'are'} not an emergency access account the operator listed."
        )
    elif kind == VERDICT_NOT_ENFORCED and defaults_enabled is False:
        verdict, reasons = VERDICT_NOT_ENFORCED, []
        basis_summary = (
            "Security defaults are off and every Conditional Access policy that requires MFA of administrators excludes "
            "an administrator role or an administrator that no other policy covers, so those administrators are not "
            "required to use MFA."
        )
    elif kind is None and not reasons and defaults_enabled is False and not unverified:
        verdict = VERDICT_NOT_ENFORCED
        basis_summary = (
            "Security defaults are off and no enabled Conditional Access policy requires MFA of all users, or of every "
            "administrator role, on all cloud apps."
        )
    else:
        verdict = VERDICT_UNKNOWN
        basis_summary = "The evidence does not establish whether MFA is enforced for administrators."
        reasons.extend(
            reason for policy in unverified for reason in policy.get("reasons", []) if reason in _ADMIN_UNVERIFIED_REASONS
        )
        reasons.extend(outcome_reasons)
    if verdict == VERDICT_UNKNOWN:
        resistant_verdict = VERDICT_UNKNOWN
        catalog_verdict, catalog_uncovered = VERDICT_UNKNOWN, []
        resistant_catalog_verdict, resistant_catalog_uncovered = VERDICT_UNKNOWN, []
    else:
        resistant_verdict = VERDICT_UNKNOWN if resistant_kind == VERDICT_UNKNOWN else resistant_kind or VERDICT_NOT_ENFORCED
        if defaults_enabled is True:
            # Security defaults require MFA of every administrator role, but not a phishing-resistant method.
            catalog_verdict, catalog_uncovered = VERDICT_ENFORCED, []
        else:
            catalog_verdict, catalog_uncovered = _role_catalog(coverers, CIS_ADMINISTRATOR_ROLES)
        resistant_catalog_verdict, resistant_catalog_uncovered = _role_catalog(resistant_coverers, SCUBA_PRIVILEGED_ROLES)

    excluded = _common_exclusions(qualifying, directory, sanctioned=sanctioned, lookups=lookups)
    return {
        "control": CONTROL_ADMIN_MFA,
        "title": "Administrator MFA enforcement",
        "verdict": verdict,
        "basis": basis,
        "basis_summary": basis_summary,
        "reasons": sorted(set(reasons)),
        "evaluated_scope": _ADMIN_MFA_SCOPE,
        "limitations": [] if verdict == VERDICT_ENFORCED else [_PER_USER_MFA_LIMITATION],
        "administrator_set": (
            {
                "state": "complete" if admin_scope.complete else "unknown",
                "role_count": len(admin_scope.held_role_ids),
                "administrator_count": len(admin_scope.admin_principal_ids),
            }
            if admin_scope is not None
            else {"state": EVIDENCE_ABSENT}
        ),
        "phishing_resistant_verdict": resistant_verdict,
        "phishing_resistant_policy_ids": sorted(policy["id"] for policy in resistant if policy["id"]),
        "role_catalog_verdict": catalog_verdict,
        "role_catalog_uncovered_roles": catalog_uncovered,
        "phishing_resistant_role_catalog_verdict": resistant_catalog_verdict,
        "phishing_resistant_role_catalog_uncovered_roles": resistant_catalog_uncovered,
        "role_catalog_scope": _ROLE_CATALOG_SCOPE,
        "security_defaults": defaults_view,
        "policy_collection": policy_view,
        "authentication_strength_collection": authentication_strengths.summary(),
        "qualifying_policies": qualifying,
        "supplementary_policies": list(supplementary.values()),
        **_exclusion_fields(excluded, sanctioned, unresolved_accounts),
        "administrator_exclusions": exclusions,
        "non_qualifying_mfa_policies": near_miss,
        "report_only_mfa_policies": report_only,
        "unverified_policies": unverified,
    }


def evaluate_user_consent(*, authorization_policy: Evidence, permission_grant_policies: Evidence) -> dict[str, Any]:
    """``unrestricted`` when users may consent to any app (the legacy consent policy is assigned).

    ``limited`` means users can still consent, to verified publishers or low-risk permissions or under the
    Microsoft-managed policy. Only a tenant that assigns no self-service consent policy reads ``restricted``,
    which is what CIS 5.1.5.1 and ScubaGear ``MS.AAD.5.2v1`` ask for.
    """
    view = authorization_policy.summary()
    row = authorization_policy.rows[0] if authorization_policy.usable and authorization_policy.rows else None
    defaults = _mapping(row.get("defaultUserRolePermissions")) if row is not None else {}
    assigned_raw = defaults.get("permissionGrantPoliciesAssigned")
    reasons = _evidence_reasons("authorization_policy", view)
    record: dict[str, Any] = {
        "control": CONTROL_USER_CONSENT,
        "title": "User consent to applications",
        "evaluated_scope": _CONSENT_SCOPE,
        "authorization_policy": view,
        "permission_grant_policy_collection": permission_grant_policies.summary(),
    }
    if row is None or not isinstance(assigned_raw, list):
        if row is not None:
            reasons.append("permission_grant_policies_assigned_missing")
        elif not reasons:
            reasons.append("authorization_policy_empty")
        record.update({"verdict": "unknown", "reasons": sorted(set(reasons)), "consent_mode": "unknown"})
        return record

    assigned = [str(item) for item in assigned_raw if item not in (None, "")]
    definitions = {
        str(item.get("id")): item.get("displayName")
        for item in permission_grant_policies.rows
        if isinstance(item, Mapping) and item.get("id")
    }
    unrestricted: list[str] = []
    limited: dict[str, str] = {}
    custom: list[dict[str, Any]] = []
    built_in: list[dict[str, Any]] = []
    for item in assigned:
        if not item.startswith(_SELF_CONSENT_PREFIX):
            continue
        policy_id = item[len(_SELF_CONSENT_PREFIX):]
        if policy_id in _CONSENT_UNRESTRICTED_POLICIES:
            unrestricted.append(item)
        elif policy_id in _CONSENT_LIMITED_POLICIES:
            limited[item] = _CONSENT_LIMITED_POLICIES[policy_id]
        elif policy_id.startswith(_BUILT_IN_CONSENT_PREFIX):
            built_in.append({"id": item, "display_name": definitions.get(policy_id)})
        else:
            custom.append({"id": item, "display_name": definitions.get(policy_id)})
    if unrestricted:
        verdict, mode = "unrestricted", "unrestricted"
    elif custom or built_in:
        verdict, mode = "unknown", "custom" if custom else "built_in"
        if custom:
            reasons.append("custom_permission_grant_policy_not_evaluated")
        if built_in:
            reasons.append("built_in_permission_grant_policy_not_evaluated")
    elif limited:
        # Users can still consent: CIS 5.1.5.1 asks for no user consent, so this is not ``restricted``.
        verdict, mode = "limited", sorted(set(limited.values()))[0]
    else:
        verdict, mode = "restricted", "none"
    record.update(
        {
            "verdict": verdict,
            "consent_mode": mode,
            "reasons": sorted(set(reasons)),
            "permission_grant_policies_assigned": assigned,
            "unrestricted_policies": unrestricted,
            "limited_policies": [{"id": key, "mode": value} for key, value in sorted(limited.items())],
            "custom_policies": custom,
            "built_in_policies": built_in,
            "owned_resource_policies": [item for item in assigned if item.startswith(_OWNED_RESOURCE_CONSENT_PREFIX)],
        }
    )
    return record
