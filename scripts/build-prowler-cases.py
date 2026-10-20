#!/usr/bin/env python3
"""Second labelling oracle: run Prowler's Microsoft 365 checks offline over ScubaGear tenant variants and compare verdicts.

Offline only: nothing here contacts a tenant. The ScubaGear miner (`build-oracle-cases.py`) writes one tenant variant per unit
test as `variants-<product>/variant-NNNN.json` plus `cases-<product>.jsonl`. This script

1. loads `configs/oracle-policy-map.json` (ScubaGear policy id -> Prowler M365 check id, `exact` or `partial`),
2. imports Prowler's own pydantic service models from a checkout supplied with `--prowler-root` (imports only, nothing is
   copied) and builds, for every variant, the service objects each mapped check reads, on a stub client that has no
   Graph, PowerShell or network access,
3. runs each mapped check's `execute()` and writes one verdict row per (variant, policy, check) to `verdicts.jsonl`
   (`PASS`, `FAIL` or `MANUAL`; `UNMAPPED` with a `reason` when the evidence cannot be expressed or the check has no finding),
4. compares those verdicts with each ScubaGear case label and writes `consensus.jsonl` (`agree`, `disagree` or `unmapped`
   with both verdicts), `unmapped-evidence.json` (why rows were not compared, by reason and check) and `summary.json`.

Rows that share a ScubaGear policy are conjunctive parts: a `FAIL` part makes the policy `FAIL`, otherwise any unmapped part
leaves it unmapped, otherwise any `MANUAL` part makes it `MANUAL`, otherwise it is `PASS`. A case whose ScubaGear label is
`unknown` (evidence section deliberately not collected) is never compared.

Prowler needs its own dependencies (pydantic, msgraph-sdk, microsoft-kiota-abstractions, azure-identity, msal, colorama,
dnspython, python-dateutil, pyyaml, jsonschema); run this script with an interpreter that has them. See
docs/guides/model-development.md for the exact setup. Builders exist for every mapped check: Entra and the Admin Center
(AAD), Exchange, Defender, Purview (SecuritySuite and EXO), SharePoint and Teams. A check with no builder is reported as
`no_builder`.

Evidence rules, shared by every builder. A setting the check reads and the variant carries is passed through unchanged. A
setting the check reads and the variant lacks is central (UNMAPPED, `evidence_missing:<section>.<key>`) or peripheral, meaning
ScubaGear never exports it: it is then assumed compliant, so the verdict can fail only on exported evidence, and the
assumption is written on every row. A check whose evidence ScubaGear does not export at all is UNMAPPED with
`not_exported:<what>`. Policies that ScubaGear skips in a US Government region are UNMAPPED with
`scubagear_not_applicable:us_government_region`, with Prowler's own verdict kept as `prowler_status`.

The output directory is new; an existing one is refused.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import importlib
import json
import logging
import re
import subprocess
import sys
import types
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
DEFAULT_MAP = REPO / "configs" / "oracle-policy-map.json"
M365_SERVICES = "prowler.providers.m365.services"
PROVENANCE_RE = re.compile(r"\.rego (MS\.[A-Z0-9]+\.\d+\.\d+v\d+); variant=(.*?); opa=[^;]*; input_sha256=([0-9a-f]{64})")
SUBPROCESS_TIMEOUT = 60  # seconds per `git` call
EXTENDED_LIMIT = 400  # characters of status_extended kept per verdict row

# Built-in authentication strengths (Microsoft Entra documentation), keyed by the display name Prowler compares against.
_PHISHING_RESISTANT = frozenset({"windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"})
_PASSWORDLESS = _PHISHING_RESISTANT | {"deviceBasedPush"}
_MULTIFACTOR = _PASSWORDLESS | {
    "temporaryAccessPassOneTime", "temporaryAccessPassMultiUse", "password,microsoftAuthenticatorPush", "password,softwareOath",
    "password,hardwareOath", "password,sms", "password,voice", "federatedMultiFactor", "microsoftAuthenticatorPush,federatedSingleFactor",
    "softwareOath,federatedSingleFactor", "hardwareOath,federatedSingleFactor", "sms,federatedSingleFactor", "voice,federatedSingleFactor",
}
BUILT_IN_STRENGTHS = {
    "Phishing-resistant MFA": _PHISHING_RESISTANT,
    "Passwordless MFA": _PASSWORDLESS,
    "Multifactor authentication": _MULTIFACTOR,
}
CUSTOM_STRENGTH = "Custom authentication strength"


class EvidenceGap(Exception):
    """The variant cannot be expressed as the objects a Prowler check reads; `reason` is a short stable code."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --------------------------------------------------------------------------------------------------------------------
# Policy map and case parsing (pure; no Prowler needed)
# --------------------------------------------------------------------------------------------------------------------

def load_policy_map(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_policy_map(doc: dict, known_policies: dict[str, str] | set[str] | None = None, known_checks: set[str] | None = None) -> list[str]:
    """Return every problem found in the map: ids, duplicates, confidence values. An empty list means valid.

    `known_policies` is the miner's policy list; given as a policy -> product mapping it also checks each row's product."""
    errors: list[str] = []
    rows = doc.get("rows")
    if not isinstance(rows, list) or not rows:
        return ["rows must be a non-empty list"]
    seen_pairs: set[tuple[Any, str]] = set()
    seen_prowler_only: set[str] = set()
    confidences = set(doc.get("confidence", {}))
    for index, row in enumerate(rows):
        where = f"rows[{index}]"
        policy, check = row.get("scubagear_policy"), row.get("prowler_check")
        if not isinstance(check, str) or not re.fullmatch(r"[a-z0-9]+(_[a-z0-9]+)+", check):
            errors.append(f"{where}: invalid prowler_check {check!r}")
            continue
        if known_checks is not None and check not in known_checks:
            errors.append(f"{where}: {check} is not a Prowler M365 check")
        if not isinstance(row.get("note"), str) or not row["note"].strip() or "\n" in row["note"]:
            errors.append(f"{where}: note must be one non-empty line")
        if row.get("confidence") not in confidences:
            errors.append(f"{where}: unknown confidence {row.get('confidence')!r}")
        if policy is None:
            if row.get("confidence") != "none":
                errors.append(f"{where}: a Prowler-only row must have confidence 'none'")
            if check in seen_prowler_only:
                errors.append(f"{where}: duplicate Prowler-only row {check}")
            seen_prowler_only.add(check)
            continue
        if row.get("confidence") not in ("exact", "partial"):
            errors.append(f"{where}: a mapped row must be exact or partial")
        if not isinstance(policy, str) or not re.fullmatch(r"MS\.[A-Z0-9]+\.\d+\.\d+v\d+", policy):
            errors.append(f"{where}: invalid scubagear_policy {policy!r}")
        if known_policies is not None and policy not in known_policies:
            errors.append(f"{where}: {policy} is not in the miner's policy list")
        elif isinstance(known_policies, dict) and policy in known_policies and row.get("product") != known_policies[policy]:
            errors.append(f"{where}: product {row.get('product')!r} does not match the miner's {known_policies[policy]!r} for {policy}")
        if (policy, check) in seen_pairs:
            errors.append(f"{where}: duplicate pair {policy} / {check}")
        seen_pairs.add((policy, check))
    mapped_checks = {check for _, check in seen_pairs}
    for check in sorted(seen_prowler_only & mapped_checks):
        errors.append(f"{check} is both mapped and listed as Prowler-only")
    return errors


def policy_rows(doc: dict) -> dict[str, list[dict]]:
    """Mapped rows grouped by ScubaGear policy id, in file order."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in doc["rows"]:
        if row.get("scubagear_policy"):
            grouped[row["scubagear_policy"]].append(row)
    return dict(grouped)


def known_policies_from_summary(summary: dict) -> dict[str, str]:
    """ScubaGear policy id -> miner product name, from the kit's summary.json."""
    return {policy: product for product, info in summary["products"].items() for policy in info["sections_per_policy"]}


def parse_case(case: dict) -> dict:
    """Policy id, variant name, input hash and ScubaGear verdict (met, not_met or unknown) of one mined case."""
    match = PROVENANCE_RE.search(case["provenance"]["source"])
    if not match:
        raise ValueError(f"case {case.get('id')}: provenance does not name a policy, variant and input hash")
    verdict = "unknown"
    for claim in case["expected"]["claims"]:
        if claim["id"] == "requirement_met" and claim["status"] == "confirmed" and isinstance(claim["value"], bool):
            verdict = "met" if claim["value"] else "not_met"
    return {"case_id": case["id"], "policy": match.group(1), "variant_name": match.group(2), "input_sha256": match.group(3),
            "scubagear_verdict": verdict}


def variant_hashes(variants_dir: Path) -> dict[Path, str]:
    """sha256 of every variant file's bytes, the hash each case records in `input_sha256`."""
    return {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(Path(variants_dir).glob("variant-*.json"))}


def first_variant_by_hash(hashes: dict[Path, str]) -> dict[str, Path]:
    """The lowest-numbered file for each distinct input; identical variants from different unit tests share a hash."""
    first: dict[str, Path] = {}
    for path, sha in hashes.items():
        first.setdefault(sha, path)
    return first


def combine_statuses(rows: list[dict]) -> tuple[str, str | None]:
    """Policy-level Prowler verdict from its conjunctive check rows, plus the reason when unmapped."""
    if any(r["status"] == "FAIL" for r in rows):
        return "FAIL", None
    unmapped = [r for r in rows if r["status"] == "UNMAPPED"]
    if unmapped:
        return "UNMAPPED", unmapped[0].get("reason", "unmapped")
    if any(r["status"] == "MANUAL" for r in rows):
        return "MANUAL", None
    return "PASS", None


def consensus_row(facts: dict, mapped: list[dict], verdict_rows: list[dict] | None) -> dict:
    """Compare one ScubaGear case with Prowler's verdict rows for the same variant and policy."""
    out = {"case_id": facts["case_id"], "scubagear_policy": facts["policy"], "variant": facts["variant_name"],
           "scubagear_verdict": facts["scubagear_verdict"], "prowler_checks": [], "prowler_verdict": None,
           "confidence": None, "consensus": "unmapped", "reason": None}
    if not mapped:
        out["reason"] = "policy_not_mapped"
        return out
    out["confidence"] = "exact" if all(row["confidence"] == "exact" for row in mapped) else "partial"
    if facts["scubagear_verdict"] == "unknown":
        out["reason"] = "scubagear_label_unknown"
        return out
    if verdict_rows is None:
        out["reason"] = "variant_not_found"
        return out
    out["prowler_checks"] = [{k: r.get(k) for k in ("prowler_check", "status", "prowler_status", "status_extended", "reason", "assumptions") if r.get(k)}
                             for r in verdict_rows]
    status, reason = combine_statuses(verdict_rows)
    out["prowler_verdict"] = status
    if status == "UNMAPPED":
        out["reason"] = reason
    elif status == "MANUAL":
        out["reason"] = "prowler_manual"
    else:
        out["consensus"] = "agree" if (status == "PASS") == (facts["scubagear_verdict"] == "met") else "disagree"
    return out


# --------------------------------------------------------------------------------------------------------------------
# Evidence builders: ScubaGear variant -> the objects Prowler's services hold (needs Prowler imported)
# --------------------------------------------------------------------------------------------------------------------

def _section(inp: dict, name: str, kind: type) -> Any:
    value = inp.get(name)
    if value is None:
        raise EvidenceGap(f"evidence_missing:{name}")
    if not isinstance(value, kind):
        raise EvidenceGap(f"shape:{name} is {type(value).__name__}")
    return value


def _enum(enum_cls: type, value: Any, where: str) -> Any:
    try:
        return enum_cls(value)
    except ValueError:
        raise EvidenceGap(f"shape:{where}={value!r}") from None


def _enums(enum_cls: type, values: Any, where: str) -> list:
    return [_enum(enum_cls, v, where) for v in (values or [])]


def authentication_strength_name(strength: dict | None) -> str | None:
    """Display name Prowler compares: the built-in strength whose combinations equal the export, else a custom name."""
    combinations = (strength or {}).get("AllowedCombinations")
    if not combinations:
        return None
    for name, built_in in BUILT_IN_STRENGTHS.items():
        if set(combinations) == built_in:
            return name
    return CUSTOM_STRENGTH


def _guests(entra: Any, value: dict | None) -> Any:
    if not value:
        return None
    raw = value.get("GuestOrExternalUserTypes") or ""
    types_ = [_enum(entra.GuestOrExternalUserType, t.strip(), "guest_or_external_user_type") for t in raw.split(",") if t.strip()]
    kind = (value.get("ExternalTenants") or {}).get("MembershipKind")
    return entra.GuestsOrExternalUsers(
        guest_or_external_user_types=types_,
        external_tenants_membership_kind=_enum(entra.ExternalTenantsMembershipKind, kind, "external_tenants_membership_kind") if kind else None)


def build_conditional_access(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    policies = {}
    for index, raw in enumerate(_section(inp, "conditional_access_policies", list)):
        cond, users, apps = raw["Conditions"], raw["Conditions"]["Users"], raw["Conditions"]["Applications"]
        grant = raw.get("GrantControls") or {}
        pid = f"scubagear-cap-{index}"
        policies[pid] = entra.ConditionalAccessPolicy(
            id=pid,
            display_name=raw["DisplayName"],
            conditions=entra.Conditions(
                application_conditions=entra.ApplicationsConditions(
                    included_applications=list(apps.get("IncludeApplications") or []),
                    excluded_applications=list(apps.get("ExcludeApplications") or []),
                    included_user_actions=_enums(entra.UserAction, apps.get("IncludeUserActions"), "user_action")),
                user_conditions=entra.UsersConditions(
                    included_groups=list(users.get("IncludeGroups") or []), excluded_groups=list(users.get("ExcludeGroups") or []),
                    included_users=list(users.get("IncludeUsers") or []), excluded_users=list(users.get("ExcludeUsers") or []),
                    included_roles=list(users.get("IncludeRoles") or []), excluded_roles=list(users.get("ExcludeRoles") or []),
                    included_guests_or_external_users=_guests(entra, users.get("IncludeGuestsOrExternalUsers")),
                    excluded_guests_or_external_users=_guests(entra, users.get("ExcludeGuestsOrExternalUsers"))),
                client_app_types=_enums(entra.ClientAppType, cond.get("ClientAppTypes"), "client_app_type"),
                user_risk_levels=_enums(entra.RiskLevel, cond.get("UserRiskLevels"), "user_risk_level"),
                sign_in_risk_levels=_enums(entra.RiskLevel, cond.get("SignInRiskLevels"), "sign_in_risk_level"),
                authentication_flows=entra.Entra._parse_authentication_flows(
                    {"transferMethods": methods} if (methods := (cond.get("AuthenticationFlows") or {}).get("TransferMethods")) else None)),
            grant_controls=entra.GrantControls(
                built_in_controls=_enums(entra.ConditionalAccessGrantControl, grant.get("BuiltInControls"), "built_in_control"),
                operator=_enum(entra.GrantControlOperator, grant.get("Operator", "AND"), "grant_control_operator"),
                authentication_strength=authentication_strength_name(grant.get("AuthenticationStrength"))),
            session_controls=entra.SessionControls(
                persistent_browser=entra.PersistentBrowser(is_enabled=False, mode="always"),
                sign_in_frequency=entra.SignInFrequency(is_enabled=False, frequency=None, type=None, interval=None)),
            state=_enum(entra.ConditionalAccessPolicyState, raw["State"], "policy_state"))
    return {"conditional_access_policies": policies}, ["session controls are not exported by ScubaGear and are left at their defaults"]


def build_authentication_methods(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    configurations, settings = {}, None
    for item in _section(inp, "authentication_method", list):
        for config in item.get("authentication_method_feature_settings") or []:
            if not config.get("Id"):
                raise EvidenceGap("shape:authentication method without Id")
            configurations[config["Id"]] = entra.AuthenticationMethodConfiguration(id=config["Id"], state=config.get("State") or "disabled")
            if config["Id"] == "MicrosoftAuthenticator":
                features = config.get("FeatureSettings") or {}
                settings = entra.AuthenticationMethodsPolicySettings(
                    authenticator_state=config.get("State"),
                    authenticator_display_app_information_state=(features.get("DisplayAppInformationRequiredState") or {}).get("State"),
                    authenticator_display_location_information_state=(features.get("DisplayLocationInformationRequiredState") or {}).get("State"))
    return {"authentication_method_configurations": configurations, "authentication_methods_policy_settings": settings}, []


def build_authorization_policy(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    policies = _section(inp, "authorization_policies", list)
    if len(policies) != 1:
        raise EvidenceGap(f"shape:authorization_policies has {len(policies)} entries; Prowler holds one")
    raw = policies[0]
    perms = raw.get("DefaultUserRolePermissions") or {}
    try:
        policy = entra.AuthorizationPolicy(
            id=raw.get("Id") or "authorizationPolicy", name="Authorization Policy", description="",
            default_user_role_permissions=entra.DefaultUserRolePermissions(
                allowed_to_create_apps=perms.get("AllowedToCreateApps"), allowed_to_create_security_groups=perms.get("AllowedToCreateSecurityGroups"),
                allowed_to_create_tenants=perms.get("AllowedToCreateTenants"),
                allowed_to_read_bitlocker_keys_for_owned_device=perms.get("AllowedToReadBitlockerKeysForOwnedDevice"),
                allowed_to_read_other_users=perms.get("AllowedToReadOtherUsers"), odata_type=None,
                permission_grant_policies_assigned=list(raw.get("PermissionGrantPolicyIdsAssignedToDefaultUserRole") or [])),
            guest_invite_settings=raw.get("AllowInvitesFrom"), guest_user_role_id=raw.get("GuestUserRoleId"))
    except ValueError as error:
        raise EvidenceGap(f"shape:authorization policy: {str(error).splitlines()[0]}") from None
    return {"authorization_policy": policy}, []


def build_admin_consent(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    values = [str(v.get("Value", "")).lower() for group in _section(inp, "directory_settings", list)
              for v in group.get("Values") or [] if v.get("Name") == "EnableAdminConsentRequests"]
    policy = None
    if values:
        policy = entra.AdminConsentPolicy(admin_consent_enabled=all(v == "true" for v in values), notify_reviewers=False,
                                          email_reminders_to_reviewers=False, duration_in_days=30)
    return {"admin_consent_policy": policy}, ["admin consent state is taken from the EnableAdminConsentRequests directory setting; "
                                              "reviewer notification and duration are not exported"]


def build_app_management(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    policies = _section(inp, "default_app_management_policy", list)
    if len(policies) != 1:
        raise EvidenceGap(f"shape:default_app_management_policy has {len(policies)} entries; Prowler holds one")

    def restrictions(raw: dict | None) -> Any:
        ns = types.SimpleNamespace
        return entra.Entra._parse_app_management_restrictions(ns(
            password_credentials=[ns(restriction_type=r.get("RestrictionType"), state=r.get("State"), max_lifetime=r.get("MaxLifetime"))
                                  for r in (raw or {}).get("PasswordCredentials") or []],
            key_credentials=[ns(restriction_type=r.get("RestrictionType"), state=r.get("State"), max_lifetime=r.get("MaxLifetime"))
                             for r in (raw or {}).get("KeyCredentials") or []]))

    raw = policies[0]
    policy = entra.DefaultAppManagementPolicy(
        id="default-app-management-policy", name="Default app management policy", description=None, is_enabled=True,
        application_restrictions=restrictions(raw.get("ApplicationRestrictions")),
        service_principal_restrictions=restrictions(raw.get("ServicePrincipalRestrictions")))
    return {"default_app_management_policy": policy}, ["the policy is assumed enabled; ScubaGear does not export the enabled flag"]


def _admin_role_ids(entra: Any) -> dict[str, str]:
    return {member.name.replace("_", " ").title(): member.value for member in entra.AdminRoles}


def build_privileged_users(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    role_ids, ignored, users = _admin_role_ids(entra), set(), {}
    for key, raw in _section(inp, "privileged_users", dict).items():
        roles = raw.get("roles") or []
        ignored |= {r for r in roles if r not in role_ids}
        users[key] = entra.User(id=key, name=raw.get("DisplayName") or key, on_premises_sync_enabled=raw.get("OnPremisesImmutableId") is not None,
                                directory_roles_ids=[role_ids[r] for r in roles if r in role_ids])
    notes = ["on-premises sync is inferred from a non-null OnPremisesImmutableId"]
    if ignored:
        notes.append(f"roles outside Prowler's administrator role list are ignored: {', '.join(sorted(ignored))}")
    return {"users": users}, notes


def build_pim_approval(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    entra = rt.module("entra")
    settings = {}
    for role in _section(inp, "privileged_roles", list):
        if role.get("DisplayName") != "Global Administrator":
            continue
        for rule in role.get("Rules") or []:
            if rule.get("Id") == "Approval_EndUser_Assignment":
                settings[entra.GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID] = entra.PimRoleApprovalSetting(
                    role_definition_id=entra.GLOBAL_ADMINISTRATOR_ROLE_TEMPLATE_ID,
                    is_approval_required=bool((rule.get("Setting") or {}).get("IsApprovalRequired")), has_approvers=True)
    return {"pim_role_approval_settings": settings}, ["approvers are not exported by ScubaGear and are assumed configured"]


def build_directory_roles(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    admincenter = rt.module("admincenter")
    members = [admincenter.User(id=key, name=raw.get("DisplayName") or key, directory_roles=list(raw.get("roles") or []))
               for key, raw in _section(inp, "privileged_users", dict).items() if "Global Administrator" in (raw.get("roles") or [])]
    role = admincenter.DirectoryRole(id="global-administrator", name="Global Administrator", members=members)
    return {"directory_roles": {"Global Administrator": role}}, []


# ---- Exchange, Defender, Purview, SharePoint and Teams ---------------------------------------------------------------
#
# Rules shared by these builders. A setting a check reads and the variant carries is passed through unchanged. A setting
# the check reads and the variant does not carry is either central (the check cannot say anything without it: the
# builder raises `evidence_missing:<section>.<key>`) or peripheral (ScubaGear never exports it: it is assumed compliant,
# so the verdict can only fail on exported evidence, and the assumption is returned and recorded on every row).
# A check whose evidence ScubaGear does not export at all raises `not_exported:<what>`.

def _entries(inp: dict, name: str) -> list[dict]:
    """The objects in a list section. Prowler skips the empty entries PowerShell leaves for "nothing found", so this does too."""
    values = [v for v in _section(inp, name, list) if v not in (None, {}, [])]
    if not all(isinstance(v, dict) for v in values):
        raise EvidenceGap(f"shape:{name} holds entries that are not objects")
    return values


def _single(inp: dict, name: str) -> dict:
    """The one entry of a section Prowler holds as a single object."""
    values = _entries(inp, name)
    if not values:
        raise EvidenceGap(f"evidence_missing:{name}")
    if len(values) > 1:
        raise EvidenceGap(f"shape:{name} has {len(values)} entries; Prowler holds one")
    return values[0]


def _global_entry(inp: dict, name: str, notes: list[str]) -> dict:
    """The Global entry of a policy list; Prowler reads only the tenant-wide Global policy, ScubaGear may read every entry."""
    values = _entries(inp, name)
    chosen = [v for v in values if v.get("Identity") == "Global"]
    if not chosen:
        raise EvidenceGap(f"evidence_missing:{name}.Global")
    if len(values) > len(chosen):
        notes.append(f"Prowler reads only the Global entry of {name}; {len(values) - len(chosen)} other entries are not read")
    return chosen[0]


def _need(raw: dict, key: str, where: str) -> Any:
    if raw.get(key) is None:
        raise EvidenceGap(f"evidence_missing:{where}.{key}")
    return raw[key]


def _flag(raw: dict, key: str, where: str) -> bool:
    value = _need(raw, key, where)
    if not isinstance(value, bool):
        raise EvidenceGap(f"shape:{where}.{key} is {type(value).__name__}, not a boolean")
    return value


def _as_list(value: Any) -> list[str] | None:
    if value is None:
        return None
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def _not_exported(what: str) -> Callable:
    def build(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
        raise EvidenceGap(f"not_exported:{what}")
    return build


def build_transport_config(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    exchange = rt.module("exchange")
    raw = _single(inp, "transport_config")
    return {"transport_config": exchange.TransportConfig(smtp_auth_disabled=_flag(raw, "SmtpClientAuthenticationDisabled", "transport_config"))}, []


def build_organization_config(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    exchange = rt.module("exchange")
    raw = _single(inp, "org_config")
    org = exchange.Organization(
        name=str(raw.get("Name") or ""), guid=str(raw.get("Identity") or ""), audit_disabled=_flag(raw, "AuditDisabled", "org_config"),
        oauth_enabled=True, mailtips_enabled=True, mailtips_external_recipient_enabled=False, mailtips_group_metrics_enabled=True,
        mailtips_large_audience_threshold=25)
    return {"organization_config": org}, []


def build_dkim(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    configs = [defender.DkimConfig(dkim_signing_enabled=_flag(raw, "Enabled", "dkim_config"), id=str(_need(raw, "Domain", "dkim_config")))
               for raw in _entries(inp, "dkim_config")]
    return {"dkim_configurations": configs}, []


class _TxtAnswer:
    """A TXT answer as dnspython hands it to Prowler: `strings` is a tuple of bytes."""

    def __init__(self, text: str):
        self.strings = (text.encode("utf-8"),)


@contextlib.contextmanager
def _dmarc_answers(defender: Any, records: dict[str, list[str]]):
    """Answer Prowler's `_dmarc.<domain>` TXT lookups from the variant, so its own record parsing runs and nothing touches the network."""
    resolver = defender.dns.asyncresolver
    original = resolver.resolve

    async def resolve(qname: str, rdtype: str = "A", *args: Any, **kwargs: Any) -> list:
        domain = str(qname).removeprefix("_dmarc.")
        if rdtype != "TXT" or domain == str(qname) or domain not in records:
            raise defender.dns.resolver.NXDOMAIN()
        if not records[domain]:
            raise defender.dns.resolver.NoAnswer()
        return [_TxtAnswer(text) for text in records[domain]]

    resolver.resolve = resolve
    try:
        yield
    finally:
        resolver.resolve = original


def build_dmarc(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    records: dict[str, list[str]] = {}
    for raw in _entries(inp, "dmarc_records"):
        rdata = raw.get("rdata")
        if rdata is not None and not isinstance(rdata, list):
            raise EvidenceGap("shape:dmarc_records.rdata is not a list")
        records[str(_need(raw, "domain", "dmarc_records"))] = [str(text) for text in rdata or []]

    async def lookup() -> list[tuple[Any, bool]]:
        return await asyncio.gather(*(defender.Defender._get_dmarc_txt_record(domain) for domain in records))

    with _dmarc_answers(defender, records):
        results = asyncio.run(lookup())
    configurations = {domain: defender.DomainDmarcConfiguration(domain=domain, dmarc_record=record, lookup_failed=failed)
                      for domain, (record, failed) in zip(records, results)}
    return ({"domain_dmarc_configurations": configurations, "domain_discovery_failed": False},
            ["a domain with no TXT data is read as a confirmed absence of a DMARC record; ScubaGear does not distinguish a failed DNS lookup"])


def _connection_filter(ip_allow_list: bool) -> Callable:
    def build(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
        defender = rt.module("defender")
        raw = _single(inp, "conn_filter")
        allow = raw.get("IPAllowList")
        if ip_allow_list and allow is None:
            raise EvidenceGap("evidence_missing:conn_filter.IPAllowList")
        safe = _flag(raw, "EnableSafeList", "conn_filter") if not ip_allow_list else False
        policy = defender.ConnectionFilterPolicy(ip_allow_list=list(allow or []), identity=str(raw.get("Name") or "Default"), enable_safe_list=safe)
        return {"connection_filter_policy": policy}, []
    return build


def _filter_rules(inp: dict, section: str, policy_key: str, model: Any, notes: list[str]) -> dict:
    """Policy name -> rule, the shape Prowler keeps for every Defender filter-rule section."""
    rules = {}
    for raw in _entries(inp, section):
        if raw.get("Priority") is None:
            notes.append(f"{section} priority is not exported and is reported as 0")
        rules[str(_need(raw, policy_key, section))] = model(
            state=str(_need(raw, "State", section)), priority=int(raw.get("Priority") or 0), users=_as_list(raw.get("SentTo")),
            groups=_as_list(raw.get("SentToMemberOf")), domains=_as_list(raw.get("RecipientDomainIs")))
    return rules


def build_malware(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    notes = ["the default anti-malware policy is identified by the identity 'Default'; ScubaGear does not export IsDefault"]
    policies = []
    for raw in _entries(inp, "anti_malware_policies"):
        identity = str(_need(raw, "Identity", "anti_malware_policies"))
        file_types = raw.get("FileTypes")
        if not isinstance(file_types, list):
            raise EvidenceGap("evidence_missing:anti_malware_policies.FileTypes")
        policies.append(defender.MalwarePolicy(
            enable_file_filter=_flag(raw, "EnableFileFilter", "anti_malware_policies"), identity=identity,
            enable_internal_sender_admin_notifications=False, internal_sender_admin_address="", file_types=[str(t) for t in file_types],
            is_default=identity == "Default"))
    policies.sort(key=lambda p: p.is_default, reverse=True)  # Prowler keeps the default policy first
    rules = _filter_rules(inp, "anti_malware_rules", "MalwareFilterPolicy", defender.MalwareRule, notes)
    return {"malware_policies": policies, "malware_rules": rules}, notes


def build_inbound_spam(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    notes: list[str] = []
    policies = []
    for raw in _entries(inp, "hosted_content_filter_policies"):
        domains = raw.get("AllowedSenderDomains")
        if not isinstance(domains, list):
            raise EvidenceGap("evidence_missing:hosted_content_filter_policies.AllowedSenderDomains")
        policies.append(defender.DefenderInboundSpamPolicy(
            identity=str(_need(raw, "Identity", "hosted_content_filter_policies")), allowed_sender_domains=[str(d) for d in domains],
            default=_flag(raw, "IsDefault", "hosted_content_filter_policies")))
    policies.sort(key=lambda p: p.default, reverse=True)
    rules = _filter_rules(inp, "hosted_content_filter_rules", "HostedContentFilterPolicy", defender.InboundSpamRule, notes)
    return {"inbound_spam_policies": policies, "inbound_spam_rules": rules}, notes


def build_safe_attachments(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    notes: list[str] = []
    policies = {}
    for raw in _entries(inp, "safe_attachment_policies"):
        name = str(_need(raw, "Identity", "safe_attachment_policies"))
        if raw.get("Enable") is None or raw.get("QuarantineTag") is None:
            notes.append("Safe Attachments Enable and QuarantineTag are not exported and are assumed enabled and AdminOnlyAccessPolicy")
        policies[name] = defender.SafeAttachmentsPolicy(
            name=name, identity=name, enable=True if raw.get("Enable") is None else bool(raw["Enable"]),
            action=str(_need(raw, "Action", "safe_attachment_policies")),
            quarantine_tag="AdminOnlyAccessPolicy" if raw.get("QuarantineTag") is None else str(raw["QuarantineTag"]),
            redirect=False, redirect_address="", is_built_in_protection=name == "Built-In Protection Policy")
    rules = _filter_rules(inp, "safe_attachment_rules", "SafeAttachmentPolicy", defender.SafeAttachmentsRule, notes)
    return {"safe_attachments_policies": policies, "safe_attachments_rules": rules}, notes


def build_atp_policy(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    raw = _single(inp, "atp_policy_for_o365")
    policy = defender.AdvancedThreatProtectionPolicy(
        identity=str(raw.get("Identity") or "Default"), enable_atp_for_spo_teams_odb=_flag(raw, "EnableATPForSPOTeamsODB", "atp_policy_for_o365"),
        enable_safe_docs=True, allow_safe_docs_open=False)
    return {"advanced_threat_protection_policy": policy}, [
        "Safe Documents (EnableSafeDocs, AllowSafeDocsOpen) is not exported and is assumed enabled with click-through blocked"]


def build_anti_phishing(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    notes = ["spoof intelligence, DMARC honouring and the quarantine actions are not exported and are assumed enabled and Quarantine"]
    policies = {}
    for raw in _entries(inp, "anti_phish_policies"):
        name = str(raw.get("Name") or _need(raw, "Identity", "anti_phish_policies"))
        policies[name] = defender.AntiphishingPolicy(
            name=name, spoof_intelligence=True, spoof_intelligence_action="Quarantine", dmarc_reject_action="Quarantine",
            dmarc_quarantine_action="Quarantine", safety_tips=_flag(raw, "EnableFirstContactSafetyTips", "anti_phish_policies"),
            unauthenticated_sender_action=_flag(raw, "EnableUnauthenticatedSender", "anti_phish_policies"),
            show_tag=_flag(raw, "EnableViaTag", "anti_phish_policies"), honor_dmarc_policy=True, default=bool(raw.get("IsDefault")))
    policies = dict(sorted(policies.items(), key=lambda item: item[1].default, reverse=True))
    rules = _filter_rules(inp, "anti_phish_rules", "AntiPhishPolicy", defender.AntiphishingRule, notes)
    return {"antiphishing_policies": policies, "antiphishing_rules": rules}, notes


SAFE_LINKS_FLAGS = {"EnableSafeLinksForEmail": "enable_safe_links_for_email", "EnableSafeLinksForTeams": "enable_safe_links_for_teams",
                    "EnableSafeLinksForOffice": "enable_safe_links_for_office", "TrackClicks": "track_clicks", "ScanUrls": "scan_urls",
                    "EnableForInternalSenders": "enable_for_internal_senders", "DeliverMessageAfterScan": "deliver_message_after_scan"}


def build_safe_links(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    defender = rt.module("defender")
    notes = ["Safe Links AllowClickThrough and DisableUrlRewrite are not exported and are assumed off"]
    policies = {}
    for raw in _entries(inp, "safe_links_policies"):
        name = str(_need(raw, "Identity", "safe_links_policies"))
        flags = {field: _flag(raw, key, "safe_links_policies") for key, field in SAFE_LINKS_FLAGS.items()}
        policies[name] = defender.SafeLinksPolicy(
            name=name, identity=name, allow_click_through=False, disable_url_rewrite=False, is_built_in_protection=name == "Built-In Protection Policy",
            is_default=False, **flags)
    rules = _filter_rules(inp, "safe_links_rules", "SafeLinksPolicy", defender.SafeLinksRule, notes)
    return {"safe_links_policies": policies, "safe_links_rules": rules}, notes


def build_audit_log(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    purview = rt.module("purview")
    raw = _single(inp, "admin_audit_log_config")
    return {"audit_log_config": purview.AuditLogConfig(audit_log_search=_flag(raw, "UnifiedAuditLogIngestionEnabled", "admin_audit_log_config"))}, []


def build_password_policy(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    admincenter = rt.module("admincenter")
    settings = inp.get("domain_settings")
    entries = settings if isinstance(settings, list) else [settings] if isinstance(settings, dict) and settings else []
    if not entries:
        raise EvidenceGap("evidence_missing:domain_settings")
    period = _need(entries[0], "PasswordValidityPeriodInDays", "domain_settings")
    return {"password_policy": admincenter.PasswordPolicy(password_validity_period=period)}, []


SHARING_CAPABILITY = {0: "Disabled", 1: "ExternalUserSharingOnly", 2: "ExternalUserAndGuestSharing", 3: "ExistingExternalUserSharingOnly"}
SHARING_DOMAIN_MODE = {0: "none", 1: "allowList", 2: "blockList"}


def _sharepoint_settings(domain_restriction: bool) -> Callable:
    def build(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
        sharepoint = rt.module("sharepoint")
        raw = _single(inp, "SPO_tenant")
        capability = _need(raw, "SharingCapability", "SPO_tenant")
        if capability not in SHARING_CAPABILITY:
            raise EvidenceGap(f"shape:SPO_tenant.SharingCapability={capability!r}")
        mode, allowed, blocked, notes = "none", None, None, []
        if domain_restriction:
            code = _need(raw, "SharingDomainRestrictionMode", "SPO_tenant")
            if code not in SHARING_DOMAIN_MODE:
                raise EvidenceGap(f"shape:SPO_tenant.SharingDomainRestrictionMode={code!r}")
            mode = SHARING_DOMAIN_MODE[code]
            if mode != "none":
                notes.append("the SharePoint allowed and blocked domain lists are not exported and the list for the selected mode is assumed non-empty")
                allowed = ["assumed.invalid"] if mode == "allowList" else None
                blocked = ["assumed.invalid"] if mode == "blockList" else None
        settings = sharepoint.SharePointSettings(
            sharingCapability=SHARING_CAPABILITY[capability], sharingAllowedDomainList=allowed, sharingBlockedDomainList=blocked,
            sharingDomainRestrictionMode=mode, resharingEnabled=False, legacyAuth=False, allowedDomainGuidsForSyncApp=[])
        return {"settings": settings}, notes
    return build


def _teams_meeting_policy(key: str, field: str) -> Callable:
    def build(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
        teams, notes = rt.module("teams"), []
        raw = _global_entry(inp, "meeting_policies", notes)
        return {"global_meeting_policy": teams.GlobalMeetingPolicy(**{field: _need(raw, key, "meeting_policies")})}, notes
    return build


def _teams_user_settings(key: str, field: str) -> Callable:
    def build(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
        teams, notes = rt.module("teams"), []
        raw = _global_entry(inp, "federation_configuration", notes)
        return {"user_settings": teams.UserSettings(**{field: _need(raw, key, "federation_configuration")})}, notes
    return build


def build_teams_settings(inp: dict, rt: "ProwlerRuntime") -> tuple[dict, list[str]]:
    teams, notes = rt.module("teams"), []
    raw = _global_entry(inp, "client_configuration", notes)
    storage = teams.CloudStorageSettings(allow_box=True, allow_drop_box=True, allow_egnyte=True, allow_google_drive=True, allow_share_file=True)
    return {"teams_settings": teams.TeamsSettings(cloud_storage_settings=storage, allow_email_into_channel=_flag(raw, "AllowEmailIntoChannel", "client_configuration"))}, notes


# Teams check -> (ScubaGear key, Prowler model field) for the settings each reads.
TEAMS_MEETING_SETTINGS = {
    "teams_meeting_external_control_disabled": ("AllowExternalParticipantGiveRequestControl", "allow_external_participant_give_request_control"),
    "teams_meeting_anonymous_user_start_disabled": ("AllowAnonymousUsersToStartMeeting", "allow_anonymous_users_to_start_meeting"),
    "teams_meeting_external_lobby_bypass_disabled": ("AutoAdmittedUsers", "allow_external_users_to_bypass_lobby"),
    "teams_meeting_dial_in_lobby_bypass_disabled": ("AllowPSTNUsersToBypassLobby", "allow_pstn_users_to_bypass_lobby"),
    "teams_meeting_recording_disabled": ("AllowCloudRecording", "allow_cloud_recording"),
}
TEAMS_USER_SETTINGS = {
    "teams_external_domains_restricted": ("AllowFederatedUsers", "allow_external_access"),
    "teams_external_users_cannot_start_conversations": ("AllowTeamsConsumerInbound", "allow_teams_consumer_inbound"),
    "teams_unmanaged_communication_disabled": ("AllowTeamsConsumer", "allow_teams_consumer"),
}


ATTRIBUTE_BUILDERS: dict[str, tuple[str, Callable]] = {
    "conditional_access": ("entra", build_conditional_access),
    "authentication_methods": ("entra", build_authentication_methods),
    "authorization_policy": ("entra", build_authorization_policy),
    "admin_consent": ("entra", build_admin_consent),
    "app_management": ("entra", build_app_management),
    "privileged_users": ("entra", build_privileged_users),
    "pim_approval": ("entra", build_pim_approval),
    "directory_roles": ("admincenter", build_directory_roles),
    "password_policy": ("admincenter", build_password_policy),
    "transport_config": ("exchange", build_transport_config),
    "organization_config": ("exchange", build_organization_config),
    "external_in_outlook": ("exchange", _not_exported("external_in_outlook")),
    "outbound_spam_policy": ("defender", _not_exported("outbound_spam_policy")),
    "sharing_policy_state": ("admincenter", _not_exported("sharing_policy_enabled")),
    "dkim": ("defender", build_dkim),
    "dmarc": ("defender", build_dmarc),
    "connection_filter_ip_allow_list": ("defender", _connection_filter(True)),
    "connection_filter_safe_list": ("defender", _connection_filter(False)),
    "inbound_spam": ("defender", build_inbound_spam),
    "malware": ("defender", build_malware),
    "safe_attachments": ("defender", build_safe_attachments),
    "atp_policy": ("defender", build_atp_policy),
    "anti_phishing": ("defender", build_anti_phishing),
    "safe_links": ("defender", build_safe_links),
    "audit_log": ("purview", build_audit_log),
    "sharepoint_sharing_capability": ("sharepoint", _sharepoint_settings(False)),
    "sharepoint_domain_restriction": ("sharepoint", _sharepoint_settings(True)),
    "teams_settings": ("teams", build_teams_settings),
    **{f"teams_meeting:{check}": ("teams", _teams_meeting_policy(*fields)) for check, fields in TEAMS_MEETING_SETTINGS.items()},
    **{f"teams_user:{check}": ("teams", _teams_user_settings(*fields)) for check, fields in TEAMS_USER_SETTINGS.items()},
}
CHECK_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "entra_legacy_authentication_blocked": ("conditional_access",),
    "entra_identity_protection_user_risk_enabled": ("conditional_access",),
    "entra_conditional_access_policy_block_high_medium_sign_in_risk": ("conditional_access",),
    "entra_users_mfa_enabled": ("conditional_access",),
    "entra_admin_users_phishing_resistant_mfa_enabled": ("conditional_access",),
    "entra_managed_device_required_for_authentication": ("conditional_access",),
    "entra_managed_device_required_for_mfa_registration": ("conditional_access",),
    "entra_conditional_access_policy_device_code_flow_blocked": ("conditional_access",),
    "entra_authentication_method_authenticator_show_context": ("authentication_methods",),
    "entra_authentication_method_sms_voice_disabled": ("authentication_methods",),
    "entra_authentication_method_email_otp_disabled": ("authentication_methods",),
    "entra_thirdparty_integrated_apps_not_allowed": ("authorization_policy",),
    "entra_policy_restricts_user_consent_for_apps": ("authorization_policy",),
    "entra_policy_guest_users_access_restrictions": ("authorization_policy",),
    "entra_policy_guest_invite_only_for_admin_roles": ("authorization_policy",),
    "entra_admin_consent_workflow_enabled": ("admin_consent",),
    "entra_default_app_management_policy_enabled": ("app_management",),
    "entra_admin_users_cloud_only": ("privileged_users",),
    "entra_pim_global_administrator_approval_required": ("pim_approval",),
    "admincenter_users_between_two_and_four_global_admins": ("directory_roles",),
    "admincenter_settings_password_never_expire": ("password_policy",),
    "admincenter_external_calendar_sharing_disabled": ("sharing_policy_state",),
    "exchange_transport_config_smtp_auth_disabled": ("transport_config",),
    "exchange_organization_mailbox_auditing_enabled": ("organization_config",),
    "exchange_external_email_tagging_enabled": ("external_in_outlook",),
    "defender_antispam_outbound_policy_forwarding_disabled": ("outbound_spam_policy",),
    "defender_domain_dkim_enabled": ("dkim",),
    "defender_domain_dmarc_records_published": ("dmarc",),
    "defender_antispam_connection_filter_policy_empty_ip_allowlist": ("connection_filter_ip_allow_list",),
    "defender_antispam_connection_filter_policy_safe_list_off": ("connection_filter_safe_list",),
    "defender_antispam_policy_inbound_no_allowed_domains": ("inbound_spam",),
    "defender_malware_policy_comprehensive_attachments_filter_applied": ("malware",),
    "defender_malware_policy_common_attachments_filter_enabled": ("malware",),
    "defender_safe_attachments_policy_enabled": ("safe_attachments",),
    "defender_atp_safe_attachments_and_docs_configured": ("atp_policy",),
    "defender_antiphishing_policy_configured": ("anti_phishing",),
    "defender_safelinks_policy_enabled": ("safe_links",),
    "purview_audit_log_search_enabled": ("audit_log",),
    "sharepoint_external_sharing_restricted": ("sharepoint_sharing_capability",),
    "sharepoint_external_sharing_managed": ("sharepoint_domain_restriction",),
    "teams_email_sending_to_channel_disabled": ("teams_settings",),
    **{check: (f"teams_meeting:{check}",) for check in TEAMS_MEETING_SETTINGS},
    **{check: (f"teams_user:{check}",) for check in TEAMS_USER_SETTINGS},
}

# Prowler audit_config values applied to one check, with the assumption recorded on every row of that check. Prowler's own
# list of recommended blocked file types has 53 entries and every ScubaGear fixture blocks exactly the baseline's three, so
# without this the check would fail every fixture and say nothing about the filter, rule state or default-policy logic.
CHECK_AUDIT_CONFIG: dict[str, tuple[dict, str]] = {
    "defender_malware_policy_comprehensive_attachments_filter_applied": (
        {"recommended_blocked_file_types": ["exe", "cmd", "vbe"]},
        "Prowler's recommended_blocked_file_types is set to the baseline's three types (exe, cmd, vbe); its default list has 53"),
}

# ScubaGear counts these policies as met, without testing them, in a US Government region, so the label says nothing to compare.
US_GOVERNMENT_REGIONS = frozenset({"gcc", "gcchigh", "dod"})
NOT_APPLICABLE_POLICIES = {policy: "us_government_region" for policy in ("MS.TEAMS.2.2v2", "MS.TEAMS.2.3v2", "MS.TEAMS.4.1v1")}


def scubagear_not_applicable(policy: str, inp: dict) -> str | None:
    """Reason ScubaGear skips `policy` for this variant (and records it as met), or None."""
    scuba = inp.get("scuba_config")
    if policy in NOT_APPLICABLE_POLICIES and isinstance(scuba, dict) and scuba.get("M365Environment") in US_GOVERNMENT_REGIONS:
        return NOT_APPLICABLE_POLICIES[policy]
    return None


# --------------------------------------------------------------------------------------------------------------------
# Prowler runtime: imports, stub clients, check execution
# --------------------------------------------------------------------------------------------------------------------

class ProwlerRuntime:
    """Imports Prowler from `root` and runs M365 checks against stub service clients (no Graph, PowerShell or network)."""

    SERVICES = {"entra": "Entra", "admincenter": "AdminCenter", "exchange": "Exchange", "defender": "Defender", "purview": "Purview",
                "sharepoint": "SharePoint", "teams": "Teams"}
    BASE_ATTRIBUTES = {"tenant_domain": "oracle.invalid", "tenant_id": "oracle", "audited_tenant": "oracle", "audited_domain": "oracle.invalid"}

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        if not (self.root / "prowler/providers/m365/services").is_dir():
            raise SystemExit(
                f"{self.root}/prowler/providers/m365/services is missing. A sparse checkout limited to mcp_server omits the provider; "
                "clone a copy with the prowler directory checked out (see docs/guides/model-development.md, Second oracle).")
        if str(self.root) not in sys.path:
            sys.path.append(str(self.root))  # appended, so Prowler's top-level `tests` package cannot shadow Auditex's
        logging.getLogger("prowler").setLevel(logging.CRITICAL)
        self._modules: dict[str, Any] = {}
        self._clients: dict[str, Any] = {}
        self._checks: dict[str, Any] = {}
        for service in self.SERVICES:
            self._install_client(service)
        prowler_file = Path(sys.modules[f"{M365_SERVICES}.entra.entra_service"].__file__).resolve()
        if self.root not in prowler_file.parents:
            raise SystemExit(f"Prowler was imported from {prowler_file}, not from --prowler-root {self.root}")

    def module(self, service: str) -> Any:
        if service not in self._modules:
            try:
                self._modules[service] = importlib.import_module(f"{M365_SERVICES}.{service}.{service}_service")
            except ModuleNotFoundError as error:
                raise SystemExit(f"Prowler needs {error.name!r}, which this interpreter lacks; use the oracle environment "
                                 "described in docs/guides/model-development.md") from None
        return self._modules[service]

    def _install_client(self, service: str) -> None:
        """Make `from ...<service>_client import <service>_client` return a stub instance of the real service class.

        An earlier runtime in the same process may already have installed the stub, and check modules imported since then
        hold that very object, so it is reused rather than replaced."""
        name = f"{M365_SERVICES}.{service}.{service}_client"
        existing = sys.modules.get(name)
        if existing is not None and getattr(existing, "AUDITEX_STUB", False):
            self._clients[service] = getattr(existing, f"{service}_client")
            return
        stub = types.ModuleType(name)
        stub.AUDITEX_STUB = True
        client = object.__new__(getattr(self.module(service), self.SERVICES[service]))
        setattr(stub, f"{service}_client", client)
        sys.modules[name] = stub
        self._clients[service] = client

    def execute(self, check_id: str, service: str, attributes: dict, audit_config: dict | None = None) -> list[tuple[str, str]]:
        """Run one check on a stub client holding exactly `attributes`; return (status, status_extended) per finding."""
        client = self._clients[service]
        client.__dict__.clear()
        client.__dict__.update(self.BASE_ATTRIBUTES)
        client.__dict__.update(audit_config=dict(audit_config or {}), fixer_config={})
        client.__dict__.update(attributes)
        if check_id not in self._checks:
            module = importlib.import_module(f"{M365_SERVICES}.{service}.{check_id}.{check_id}")
            self._checks[check_id] = getattr(module, check_id)
        return [(str(f.status), str(f.status_extended)) for f in self._checks[check_id]().execute()]


def prowler_commit(root: Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def _verdict(findings: list[tuple[str, str]]) -> tuple[str, str]:
    statuses = {status for status, _ in findings}
    status = "FAIL" if "FAIL" in statuses else "MANUAL" if "MANUAL" in statuses or not statuses <= {"PASS"} else "PASS"
    return status, " | ".join(text for _, text in findings)[:EXTENDED_LIMIT]


def run_variant(rt: ProwlerRuntime | None, inp: dict, rows: list[dict]) -> list[dict]:
    """One verdict row per mapped (policy, check) row for a variant; checks and attribute groups run once and are shared."""
    groups: dict[str, tuple[dict, list[str]] | EvidenceGap] = {}
    results: dict[str, tuple[str, str, str | None, list[str]]] = {}

    def group(name: str) -> tuple[dict, list[str]]:
        if name not in groups:
            try:
                groups[name] = ATTRIBUTE_BUILDERS[name][1](inp, rt)
            except EvidenceGap as gap:
                groups[name] = gap
            except (KeyError, TypeError, AttributeError, ValueError) as error:
                groups[name] = EvidenceGap(f"shape:{name}: {error.__class__.__name__} {str(error)[:80]}")
        if isinstance(groups[name], EvidenceGap):
            raise groups[name]
        return groups[name]

    def evaluate(check_id: str, service: str) -> tuple[str, str, str | None, list[str]]:
        needs = CHECK_ATTRIBUTES.get(check_id)
        if needs is None or rt is None:
            return "UNMAPPED", "", "no_builder", []
        attributes, assumptions = {}, []
        audit_config, audit_note = CHECK_AUDIT_CONFIG.get(check_id, (None, None))
        try:
            for name in needs:
                built, notes = group(name)
                attributes.update(built)
                assumptions += notes
            if audit_note:
                assumptions.append(audit_note)
            findings = rt.execute(check_id, service, attributes, audit_config)
        except EvidenceGap as gap:
            return "UNMAPPED", "", gap.reason, []
        except Exception as error:  # noqa: BLE001 - one broken check must not stop the run; it is reported per row
            if isinstance(error, AttributeError) and str(error).startswith(f"'{rt.SERVICES[service]}' object has no attribute"):
                return "UNMAPPED", "", f"missing_attribute:{str(error).rsplit(' ', 1)[-1].strip(chr(39))}", []
            return "UNMAPPED", "", f"check_error:{error.__class__.__name__}: {str(error)[:80]}", []
        if not findings:
            return "UNMAPPED", "", "no_finding", assumptions
        status, text = _verdict(findings)
        return status, text, None, assumptions

    out = []
    for row in rows:
        key = row["prowler_check"]
        if key not in results:
            results[key] = evaluate(key, row["prowler_service"])
        status, text, reason, assumptions = results[key]
        item = {"scubagear_policy": row["scubagear_policy"], "prowler_check": key, "confidence": row["confidence"],
                "status": status, "status_extended": text}
        skipped = scubagear_not_applicable(row["scubagear_policy"], inp)
        if skipped and status != "UNMAPPED":
            item.update(status="UNMAPPED", prowler_status=status)  # Prowler's own verdict stays visible, but is not compared
            reason = f"scubagear_not_applicable:{skipped}"
        if reason:
            item["reason"] = reason
        if assumptions:
            item["assumptions"] = sorted(set(assumptions))
        out.append(item)
    return out


# --------------------------------------------------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------------------------------------------------

def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


# Unmapped reasons that carry a detail after the colon; the summary counts the family, `unmapped-evidence.json` keeps the detail.
REASON_FAMILIES = ("check_error", "shape", "evidence_missing", "not_exported", "missing_attribute")


def summarise(consensus: list[dict], verdicts: list[dict]) -> dict:
    by_policy: dict[str, Counter] = defaultdict(Counter)
    reasons: Counter = Counter()
    for row in consensus:
        by_policy[row["scubagear_policy"]][row["consensus"]] += 1
        if row["reason"]:
            reasons[row["reason"].split(":")[0] if row["reason"].startswith(REASON_FAMILIES) else row["reason"]] += 1
    compared = [r for r in consensus if r["consensus"] in ("agree", "disagree")]
    return {
        "cases": len(consensus),
        "consensus": dict(Counter(r["consensus"] for r in consensus)),
        "compared_by_confidence": {c: dict(Counter(r["consensus"] for r in compared if r["confidence"] == c)) for c in ("exact", "partial")},
        "unmapped_reasons": dict(reasons.most_common()),
        "by_policy": {p: dict(c) for p, c in sorted(by_policy.items())},
        "verdict_rows": dict(Counter(v["status"] for v in verdicts)),
    }


def unmapped_report(verdicts: list[dict]) -> dict:
    by_reason: Counter = Counter()
    by_check: dict[str, Counter] = defaultdict(Counter)
    examples: dict[str, list[str]] = defaultdict(list)
    for row in verdicts:
        if row["status"] != "UNMAPPED":
            continue
        by_reason[row["reason"]] += 1
        by_check[row["prowler_check"]][row["reason"]] += 1
        if len(examples[row["reason"]]) < 3 and row["variant"] not in examples[row["reason"]]:
            examples[row["reason"]].append(row["variant"])
    return {"by_reason": dict(by_reason.most_common()), "by_check": {c: dict(r.most_common()) for c, r in sorted(by_check.items())},
            "example_variants": dict(examples)}


def check_outcomes(verdicts: list[dict]) -> dict:
    """Which checks produced a Prowler verdict, and for the rest why none could be produced (reasons by row count)."""
    ran: set[str] = set()
    blocked: dict[str, Counter] = defaultdict(Counter)
    for row in verdicts:
        if row["status"] != "UNMAPPED" or "prowler_status" in row:
            ran.add(row["prowler_check"])
        else:
            blocked[row["prowler_check"]][row["reason"]] += 1
    return {"checks_executed": sorted(ran), "checks_not_evaluated": {c: dict(r.most_common()) for c, r in sorted(blocked.items()) if c not in ran}}


def run(args: argparse.Namespace) -> int:
    kit, out_dir = Path(args.kit_dir).resolve(), Path(args.output_dir)
    if out_dir.exists():
        print(f"refusing to replace existing output directory {out_dir}", file=sys.stderr)
        return 2
    doc = load_policy_map(args.map)
    summary = json.loads((kit / "summary.json").read_text(encoding="utf-8"))
    policies = known_policies_from_summary(summary)
    products = args.products or ["AAD"]
    unknown = [p for p in products if p not in summary["products"]]
    if unknown:
        print(f"unknown product(s) {unknown}; the kit has {sorted(summary['products'])}", file=sys.stderr)
        return 2
    selected = {**doc, "rows": [row for row in doc["rows"] if row.get("product") in products or not row.get("scubagear_policy")]}
    problems = validate_policy_map(selected, known_policies=policies)
    if problems:
        print("invalid policy map:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 2
    by_policy = policy_rows(selected)
    rt = ProwlerRuntime(Path(args.prowler_root))
    out_dir.mkdir(parents=True)
    all_verdicts: list[dict] = []
    all_consensus: list[dict] = []
    per_product: dict[str, dict] = {}
    for product in products:
        package = summary["products"][product]["package"]
        hashes = variant_hashes(kit / f"variants-{package}")
        variants = first_variant_by_hash(hashes)
        rows = [row for policy, group in by_policy.items() if policies[policy] == product for row in group]
        verdicts_by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
        verdicts: list[dict] = []
        for path, sha in hashes.items():
            for item in run_variant(rt, json.loads(path.read_text(encoding="utf-8")), rows):
                item.update(variant=path.stem, product=product, input_sha256=sha)
                verdicts.append(item)
                verdicts_by_key[(path.stem, item["scubagear_policy"])].append(item)
        consensus = []
        for case in read_jsonl(kit / f"cases-{package}.jsonl"):
            facts = parse_case(case)
            path = variants.get(facts["input_sha256"])
            rows_for_case = verdicts_by_key.get((path.stem, facts["policy"])) if path else None
            row = consensus_row(facts, by_policy.get(facts["policy"], []), rows_for_case)
            row.update(product=product, variant_name=row["variant"], variant=path.stem if path else None)
            consensus.append(row)
        all_verdicts += verdicts
        all_consensus += consensus
        per_product[product] = {"variants": len(hashes), "distinct_inputs": len(variants), **summarise(consensus, verdicts), **check_outcomes(verdicts)}
    write_jsonl(out_dir / "verdicts.jsonl", all_verdicts)
    write_jsonl(out_dir / "consensus.jsonl", all_consensus)
    (out_dir / "unmapped-evidence.json").write_text(json.dumps(unmapped_report(all_verdicts), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checks_run = check_outcomes(all_verdicts)["checks_executed"]
    meta = {"kit": str(kit), "map": str(Path(args.map).resolve()), "prowler_root": str(rt.root), "prowler_commit": prowler_commit(rt.root),
            "scubagear_commit": doc["scubagear"]["commit"], "python": sys.version.split()[0], "products": per_product,
            "checks_with_builders": sorted(CHECK_ATTRIBUTES), "checks_executed": checks_run}
    (out_dir / "summary.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for product, info in per_product.items():
        print(f"{product}: {info['cases']} cases, {info['variants']} variants ({info['distinct_inputs']} distinct); consensus {info['consensus']}; "
              f"compared by confidence {info['compared_by_confidence']}; unmapped reasons {info['unmapped_reasons']}")
    print(f"wrote {out_dir}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--kit-dir", required=True, help="oracle-case kit written by build-oracle-cases.py (summary.json, cases-*.jsonl, variants-*)")
    parser.add_argument("--prowler-root", required=True, help="Prowler checkout whose prowler/providers/m365 is on disk; added to sys.path")
    parser.add_argument("--output-dir", required=True, help="new directory for verdicts.jsonl, consensus.jsonl, unmapped-evidence.json, summary.json")
    parser.add_argument("--map", default=str(DEFAULT_MAP), help="policy map (default: configs/oracle-policy-map.json)")
    parser.add_argument("--products", nargs="+", help="miner product names, e.g. AAD EXO (default: AAD)")
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
