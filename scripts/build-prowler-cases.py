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
docs/guides/model-development.md for the exact setup. Builders exist for the Entra (AAD) checks and the Global Administrator
count; other mapped checks are reported as `no_builder`.

The output directory is new; an existing one is refused.
"""
from __future__ import annotations

import argparse
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
    out["prowler_checks"] = [{k: r.get(k) for k in ("prowler_check", "status", "status_extended", "reason", "assumptions") if r.get(k)}
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


ATTRIBUTE_BUILDERS: dict[str, tuple[str, Callable]] = {
    "conditional_access": ("entra", build_conditional_access),
    "authentication_methods": ("entra", build_authentication_methods),
    "authorization_policy": ("entra", build_authorization_policy),
    "admin_consent": ("entra", build_admin_consent),
    "app_management": ("entra", build_app_management),
    "privileged_users": ("entra", build_privileged_users),
    "pim_approval": ("entra", build_pim_approval),
    "directory_roles": ("admincenter", build_directory_roles),
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
}


# --------------------------------------------------------------------------------------------------------------------
# Prowler runtime: imports, stub clients, check execution
# --------------------------------------------------------------------------------------------------------------------

class ProwlerRuntime:
    """Imports Prowler from `root` and runs M365 checks against stub service clients (no Graph, PowerShell or network)."""

    SERVICES = {"entra": "Entra", "admincenter": "AdminCenter"}
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

    def execute(self, check_id: str, service: str, attributes: dict) -> list[tuple[str, str]]:
        """Run one check on a stub client holding exactly `attributes`; return (status, status_extended) per finding."""
        client = self._clients[service]
        client.__dict__.clear()
        client.__dict__.update(self.BASE_ATTRIBUTES)
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
        try:
            for name in needs:
                built, notes = group(name)
                attributes.update(built)
                assumptions += notes
            findings = rt.execute(check_id, service, attributes)
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


def summarise(consensus: list[dict], verdicts: list[dict]) -> dict:
    by_policy: dict[str, Counter] = defaultdict(Counter)
    reasons: Counter = Counter()
    for row in consensus:
        by_policy[row["scubagear_policy"]][row["consensus"]] += 1
        if row["reason"]:
            reasons[row["reason"].split(":")[0] if row["reason"].startswith(("check_error", "shape")) else row["reason"]] += 1
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
        per_product[product] = {"variants": len(hashes), "distinct_inputs": len(variants), **summarise(consensus, verdicts)}
    write_jsonl(out_dir / "verdicts.jsonl", all_verdicts)
    write_jsonl(out_dir / "consensus.jsonl", all_consensus)
    (out_dir / "unmapped-evidence.json").write_text(json.dumps(unmapped_report(all_verdicts), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checks_run = sorted({r["prowler_check"] for r in all_verdicts if r["status"] != "UNMAPPED" or r.get("reason") != "no_builder"})
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
