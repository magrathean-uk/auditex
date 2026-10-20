"""Tenant-level identity control verdicts: is MFA enforced, is legacy authentication blocked,
can users consent to apps.

Registration reports say who *could* use MFA, never whether it is *required*. These verdicts
read the configuration that enforces or blocks instead: Microsoft Entra security defaults,
enabled Conditional Access policies, and the authorization policy's user consent settings.

Each verdict is three-valued and never guesses:

* ``effective_mfa``: ``enforced`` | ``not_enforced`` | ``unknown``
* ``legacy_authentication_block``: ``blocked`` | ``not_blocked`` | ``unknown``
* ``user_consent``: ``restricted`` | ``unrestricted`` | ``unknown``

A negative verdict needs complete evidence. A policy list that was blocked, truncated or never
collected can hide the one policy that changes the answer, so those states give ``unknown``.
A positive verdict needs positive evidence of its own: security defaults reported on, or at
least one qualifying enabled Conditional Access policy. Nothing here performs I/O.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

KIND = "identity_control_verdict"
SECTION = "identity_control_verdicts"

CONTROL_EFFECTIVE_MFA = "effective_mfa"
CONTROL_LEGACY_AUTH = "legacy_authentication_block"
CONTROL_USER_CONSENT = "user_consent"

EVIDENCE_COLLECTED = "collected"
EVIDENCE_BLOCKED = "blocked"
EVIDENCE_TRUNCATED = "truncated"
EVIDENCE_ABSENT = "absent"

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

_SELF_CONSENT_PREFIX = "ManagePermissionGrantsForSelf."
_OWNED_RESOURCE_CONSENT_PREFIX = "ManagePermissionGrantsForOwnedResource."
# Microsoft built-in permission grant policies for user consent (Microsoft Learn:
# configure user consent settings).
_CONSENT_UNRESTRICTED_POLICIES = frozenset({"microsoft-user-default-legacy"})
_CONSENT_LIMITED_POLICIES = {
    "microsoft-user-default-low": "verified_publishers_low_risk_permissions",
    "microsoft-user-default-recommended": "microsoft_managed",
}

_MFA_SCOPE = (
    "Microsoft Entra security defaults and Conditional Access policies. Registration reports, "
    "per-user MFA states and legacy MFA settings are not evaluated."
)
_LEGACY_SCOPE = (
    "Microsoft Entra security defaults and Conditional Access policies. Exchange Online protocol "
    "settings (for example SMTP AUTH) are not evaluated."
)
_CONSENT_SCOPE = (
    "The authorization policy's default user role permissions. Custom permission grant policies "
    "and group-owner (resource-specific) consent are not evaluated."
)


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


def _exclusions(targeting: Mapping[str, Any], lookups: Mapping[str, Mapping[str, str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kind, key in (("user", "exclude_users"), ("group", "exclude_groups"), ("role", "exclude_roles")):
        for object_id in targeting[key]:
            name = _resolve(lookups, kind, object_id)
            row: dict[str, Any] = {"type": kind, "id": object_id, "resolved": name is not None}
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
            }
        )
    return sorted(rows, key=lambda row: (row["type"], row["id"]))


def _policy_summary(
    policy: Mapping[str, Any],
    targeting: Mapping[str, Any],
    lookups: Mapping[str, Mapping[str, str]],
    reasons: list[str],
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
        "exclusions": _exclusions(targeting, lookups),
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


def _common_exclusions(policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Principals excluded from every qualifying policy; those are the ones the basis does not cover."""
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
) -> dict[str, Any]:
    """``enforced`` when security defaults or an enabled all-users, all-apps MFA policy applies."""
    defaults_view, defaults_enabled = _security_defaults_view(security_defaults)
    policy_rows = [row for row in policies.rows if isinstance(row, Mapping)] if policies.usable else []
    qualifying: list[dict[str, Any]] = []
    near_miss: list[dict[str, Any]] = []
    report_only: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
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
            report_only.append(_policy_summary(policy, targeting, lookups, ["report_only", *reasons]))
        elif grant_class == "unverified" and reasons == [grant_reason]:
            # Would qualify if its authentication strength could be shown to require MFA.
            unverified.append(_policy_summary(policy, targeting, lookups, reasons))
        elif reasons:
            near_miss.append(_policy_summary(policy, targeting, lookups, reasons))
        else:
            qualifying.append(_policy_summary(policy, targeting, lookups, []))

    policy_view = _policy_view(policies, policy_rows)
    basis = [name for name, present in (
        ("security_defaults", defaults_enabled is True),
        ("conditional_access_policy", bool(qualifying)),
    ) if present]
    reasons = [*_evidence_reasons("policy_collection", policy_view), *_evidence_reasons("security_defaults", defaults_view)]
    if basis:
        verdict, reasons = "enforced", []
        basis_summary = _MFA_BASIS_SUMMARY[tuple(basis)]
    elif not reasons and defaults_enabled is False and not unverified:
        verdict = "not_enforced"
        basis_summary = (
            "Security defaults are off and no enabled Conditional Access policy requires MFA for all users on all cloud apps."
        )
    else:
        verdict = "unknown"
        basis_summary = "The evidence does not establish whether MFA is enforced."
        if unverified:
            reasons.append("authentication_strength_unverified")

    excluded = _common_exclusions(qualifying)
    record: dict[str, Any] = {
        "control": CONTROL_EFFECTIVE_MFA,
        "title": "Effective MFA enforcement",
        "verdict": verdict,
        "basis": basis,
        "basis_summary": basis_summary,
        "reasons": sorted(set(reasons)),
        "evaluated_scope": _MFA_SCOPE,
        "security_defaults": defaults_view,
        "policy_collection": policy_view,
        "authentication_strength_collection": authentication_strengths.summary(),
        "qualifying_policies": qualifying,
        "excluded_principals": excluded,
        "excluded_principal_count": len(excluded),
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
) -> dict[str, Any]:
    """``blocked`` when security defaults or an enabled all-users, all-apps block policy covers legacy clients."""
    defaults_view, defaults_enabled = _security_defaults_view(security_defaults)
    policy_rows = [row for row in policies.rows if isinstance(row, Mapping)] if policies.usable else []
    blocking: list[dict[str, Any]] = []
    near_miss: list[dict[str, Any]] = []
    report_only: list[dict[str, Any]] = []
    for policy in policy_rows:
        targeting = policy_targeting(policy)
        if targeting["state"].lower() not in _ENFORCING_STATES:
            continue
        if "block" not in targeting["grant"]["built_in_controls"]:
            continue
        lowered_types = set(_lower(targeting["client_app_types"]))
        if "all" not in lowered_types and not lowered_types & set(_LEGACY_CLIENT_APP_TYPES):
            continue
        reasons = _scope_reasons(
            targeting,
            client_types_cover=_client_types_cover(targeting["client_app_types"], _LEGACY_CLIENT_APP_TYPES),
        )
        reasons = [
            "legacy_client_app_types_incomplete" if reason == "client_app_types_not_covered" else reason
            for reason in reasons
        ]
        reasons.extend(_narrowing_reasons(targeting))
        if targeting["state"].lower() == "enabledforreportingbutnotenforced":
            report_only.append(_policy_summary(policy, targeting, lookups, ["report_only", *reasons]))
        elif reasons:
            near_miss.append(_policy_summary(policy, targeting, lookups, reasons))
        else:
            blocking.append(_policy_summary(policy, targeting, lookups, []))

    policy_view = _policy_view(policies, policy_rows)
    basis = [name for name, present in (
        ("security_defaults", defaults_enabled is True),
        ("conditional_access_policy", bool(blocking)),
    ) if present]
    reasons = [*_evidence_reasons("policy_collection", policy_view), *_evidence_reasons("security_defaults", defaults_view)]
    if basis:
        verdict, reasons = "blocked", []
        basis_summary = _LEGACY_BASIS_SUMMARY[tuple(basis)]
    elif not reasons and defaults_enabled is False:
        verdict = "not_blocked"
        basis_summary = (
            "Security defaults are off and no enabled Conditional Access policy blocks the Exchange ActiveSync and "
            "other legacy client types for all users on all cloud apps."
        )
    else:
        verdict = "unknown"
        basis_summary = "The evidence does not establish whether legacy authentication is blocked."

    excluded = _common_exclusions(blocking)
    return {
        "control": CONTROL_LEGACY_AUTH,
        "title": "Legacy authentication block",
        "verdict": verdict,
        "basis": basis,
        "basis_summary": basis_summary,
        "reasons": sorted(set(reasons)),
        "evaluated_scope": _LEGACY_SCOPE,
        "security_defaults": defaults_view,
        "policy_collection": policy_view,
        "blocking_policies": blocking,
        "excluded_principals": excluded,
        "excluded_principal_count": len(excluded),
        "excluded_locations": _common_values(blocking, "excluded_locations"),
        "non_qualifying_block_policies": near_miss,
        "report_only_block_policies": report_only,
    }


def evaluate_user_consent(*, authorization_policy: Evidence, permission_grant_policies: Evidence) -> dict[str, Any]:
    """``unrestricted`` when users may consent to any app (the legacy consent policy is assigned)."""
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
    for item in assigned:
        if not item.startswith(_SELF_CONSENT_PREFIX):
            continue
        policy_id = item[len(_SELF_CONSENT_PREFIX):]
        if policy_id in _CONSENT_UNRESTRICTED_POLICIES:
            unrestricted.append(item)
        elif policy_id in _CONSENT_LIMITED_POLICIES:
            limited[item] = _CONSENT_LIMITED_POLICIES[policy_id]
        else:
            custom.append({"id": item, "display_name": definitions.get(policy_id)})
    if unrestricted:
        verdict, mode = "unrestricted", "unrestricted"
    elif custom:
        verdict, mode = "unknown", "custom"
        reasons.append("custom_permission_grant_policy_not_evaluated")
    elif limited:
        verdict, mode = "restricted", sorted(set(limited.values()))[0]
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
            "owned_resource_policies": [item for item in assigned if item.startswith(_OWNED_RESOURCE_CONSENT_PREFIX)],
        }
    )
    return record
