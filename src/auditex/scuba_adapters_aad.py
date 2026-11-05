"""Read-only AAD adapters and private rule-view variants.

Only selected configuration fields leave an operation envelope. Rule variants
never change the model adapter's diagnostics or its shape-gated evidence.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS
from azure_tenant_audit.resources import load_json_resource
from auditex.scuba_projection import (
    Bundle, Unavailable, _require, _strings, _text, _nullable_text,
    _blank, _annotation, _enum,
)


def _pascal(value: Any) -> Any:
    """Copy Graph containers, capitalising keys and discarding OData metadata."""
    if isinstance(value, dict):
        _require(all(isinstance(k, str) and k for k in value), kind="invalid_type")
        return {k[0].upper() + k[1:]: _pascal(v) for k, v in value.items() if not _annotation(k)}
    if isinstance(value, list):
        return [_pascal(v) for v in value]
    return value


def _select(row: Any, keys: tuple[str, ...]) -> dict[str, Any]:
    """Missing and null are distinct; never manufacture a field."""
    _require(isinstance(row, dict), kind="invalid_type")
    return _pascal({k: row[k] for k in keys if k in row})


def _authentication_method(bundle: Bundle) -> Any:
    rows = bundle.operation("auth_methods", "authenticationMethodsPolicy")
    _require(len(rows) == 1)
    policy = rows[0]
    _require(_text(policy.get("policyMigrationState")), "PolicyMigrationState", "invalid_type")
    try:
        configs = bundle.operation("auth_methods", "authenticationMethodConfigurations")
    except Unavailable as exc:
        if exc.reason != "missing_artifact":
            raise
        # A missing operation must not conceal a failed fan-out coverage row.
        bundle.coverage("auth_methods", "authenticationMethodConfigurations")
        if "authenticationMethodConfigurations" not in policy:
            # Older runs collected only migration state. Keep that evidence for
            # AAD 3.4 without asserting an empty configurations inventory for 3.3/3.5.
            return [{"authentication_method_policy": {"PolicyMigrationState": policy["policyMigrationState"]}}]
        configs = policy["authenticationMethodConfigurations"]
        _require(isinstance(configs, list), "authenticationMethodConfigurations", "invalid_type")
    result = []
    for config in configs:
        _require(isinstance(config, dict), "authenticationMethodConfigurations", "invalid_type")
        if not isinstance(config.get("id"), str):
            continue
        item = _select(config, ("id", "state"))
        if config["id"] == "MicrosoftAuthenticator":
            item.update(_select(config, ("isSoftwareOathEnabled",)))
            if "featureSettings" in config:
                settings = config["featureSettings"]
                if settings is None:
                    item["FeatureSettings"] = None
                else:
                    _require(isinstance(settings, dict), "FeatureSettings", "invalid_type")
                    features = {}
                    for key in ("displayAppInformationRequiredState", "displayLocationInformationRequiredState"):
                        if key not in settings:
                            continue
                        block = settings[key]
                        if block is None:
                            features[key] = None
                            continue
                        trimmed = {"state": block["state"]} if isinstance(block, dict) and "state" in block else {}
                        _require(isinstance(block, dict), key, "invalid_type")
                        for target in ("includeTarget", "excludeTarget"):
                            if target in block:
                                trimmed[target] = None if block[target] is None else _target(block[target])
                        features[key] = trimmed
                    item["FeatureSettings"] = _pascal(features)
        result.append(item)
    return [{"authentication_method_policy": {"PolicyMigrationState": policy["policyMigrationState"]},
             "authentication_method_feature_settings": result}]


def _target(row: Any) -> dict[str, Any]:
    _require(isinstance(row, dict), kind="invalid_type")
    return {"id": row["id"]} if "id" in row else {}


def _directory_settings(bundle: Bundle) -> Any:
    result = []
    for row in bundle.operation("consent_policy", "directorySettings"):
        item = _select(row, ("id", "displayName", "templateId"))
        _require(isinstance(row.get("values"), list), "Values", "invalid_type")
        item["Values"] = [_select(v, ("name", "value")) for v in row["values"]
                          if isinstance(v, dict) and v.get("name") == "EnableAdminConsentRequests"]
        result.append(item)
    return result


def _domain_settings(bundle: Bundle) -> Any:
    return [_select(row, ("id", "isVerified", "authenticationType", "isRoot", "passwordValidityPeriodInDays"))
            for row in bundle.operation("identity", "domains")]


_ENTRY_KEYS = ("restrictionType", "state", "restrictForAppsCreatedAfterDateTime", "maxLifetime")


def _scope(value: Any, applies_to: list[dict[str, str]] | None = None) -> Any:
    if value is None:
        return None
    _require(isinstance(value, dict), kind="invalid_type")
    result = {}
    for key in ("passwordCredentials", "keyCredentials"):
        if key not in value:
            continue
        entries = value[key]
        if entries is None:
            result[key] = None
            continue
        _require(isinstance(entries, list), key, "invalid_type")
        result[key] = []
        for entry in entries:
            item = _select(entry, _ENTRY_KEYS)
            if applies_to is not None:
                item["AppliesTo"] = _pascal(applies_to)
            result[key].append(item)
    return _pascal(result)


def _default_app_policy(bundle: Bundle) -> Any:
    rows = bundle.operation("consent_policy", "defaultAppManagementPolicy")
    _require(len(rows) == 1)
    row = rows[0]
    item = _select(row, ("id", "displayName", "isEnabled"))
    for key in ("applicationRestrictions", "servicePrincipalRestrictions"):
        if key in row:
            item[key[0].upper() + key[1:]] = _scope(row[key])
    return [item]


def _app_policies(bundle: Bundle) -> Any:
    policies = bundle.operation("consent_policy", "appManagementPolicies")
    if not policies:
        return []
    fanout = bundle.operation("consent_policy", "appManagementPolicyAppliesTo")
    targets = {}
    for row in fanout:
        policy_id = row.get("policyId")
        _require(_text(policy_id) and policy_id not in targets, "policyId")
        _require(row.get("appliesToTruncated") is False, "appliesToTruncated")
        _require(isinstance(row.get("appliesTo"), list), "AppliesTo", "invalid_type")
        ids = []
        for target in row["appliesTo"]:
            _require(isinstance(target, dict) and _text(target.get("id")), "AppliesTo.Id", "invalid_type")
            ids.append({"id": target["id"]})
        targets[policy_id] = ids
    result = []
    for row in policies:
        _require(_text(row.get("id")) and row["id"] in targets, "AppliesTo", "missing_field")
        item = _select(row, ("id", "displayName", "isEnabled"))
        if "restrictions" in row:
            item["Restrictions"] = _scope(row["restrictions"], targets[row["id"]])
        result.append(item)
    return result


def _risky_classifications(bundle: Bundle) -> Any:
    data = load_json_resource("configs/risky-delegated-permissions.json", default=None)
    _require(isinstance(data, dict) and isinstance(data.get("resources"), dict)
             and isinstance(data.get("permissions"), dict))
    rows = bundle.operation("app_consent", "delegatedPermissionClassifications")
    result = []
    for row in rows:
        app_id = row.get("appId")
        _require(_text(app_id) and app_id in data["resources"], "AppId")
        resource = data["resources"][app_id]
        permissions = data["permissions"].get(resource)
        _require(isinstance(permissions, dict) and isinstance(permissions.get("Delegated"), dict))
        delegated = permissions["Delegated"]
        _require(isinstance(row.get("classifications"), list), "classifications", "invalid_type")
        names = []
        for classification in row["classifications"]:
            _require(isinstance(classification, dict), "classifications", "invalid_type")
            permission_id = classification.get("permissionId")
            if classification.get("classification") == "low" and isinstance(permission_id, str) and permission_id in delegated:
                _require(_text(classification.get("permissionName")), "permissionName", "invalid_type")
                names.append(classification["permissionName"])
        if names:
            _require(_text(row.get("servicePrincipalId")), "ObjectId", "invalid_type")
            item = _select(row, ("appId", "displayName"))
            item.update(ObjectId=row["servicePrincipalId"], RiskyPermClassifications=names)
            result.append(item)
    return result


def _ca_rule(bundle: Bundle) -> Any:
    # Matches _ca's selected fields, State guard and null-list semantics.
    # Extra restriction containers are copied only into the private rule view.
    spec = {
        "DisplayName": _text, "State": _text,
        "Conditions": {
            "Applications": {k: _strings for k in ("IncludeApplications", "ExcludeApplications", "IncludeUserActions")},
            "AuthenticationFlows": {"TransferMethods": _nullable_text},
            "ClientAppTypes": _strings, "SignInRiskLevels": _strings, "UserRiskLevels": _strings,
            "AgentIdRiskLevels": _nullable_text,
            "ClientApplications": {"IncludeAgentIdServicePrincipals": _strings},
            "Users": {**{k: _strings for k in ("IncludeUsers", "ExcludeUsers", "IncludeRoles", "ExcludeRoles", "ExcludeGroups")},
                      "ExcludeGuestsOrExternalUsers": {"GuestOrExternalUserTypes": _text,
                                                       "ExternalTenants": {"MembershipKind": _text}}}},
        "GrantControls": {"BuiltInControls": _strings, "Operator": _nullable_text,
                          "AuthenticationStrength": {"AllowedCombinations": lambda v: v is None or _strings(v)}}}

    extensions = {
        "conditions.": {"Locations": {k: _strings for k in ("IncludeLocations", "ExcludeLocations")},
                        "Platforms": {k: _strings for k in ("IncludePlatforms", "ExcludePlatforms")},
                        "Devices": _pascal, "DeviceStates": _pascal,
                        "ServicePrincipalRiskLevels": _strings, "InsiderRiskLevels": _strings},
        "conditions.applications.": {"ApplicationFilter": _pascal,
                                    "IncludeAuthenticationContextClassReferences": _strings},
    }
    restriction_names = {"locations", "devices", "platforms", "sessionControls", "includeGroups",
                         "includeGuestsOrExternalUsers", "authenticationContextClassReferences",
                         "servicePrincipalRiskLevels", "customAuthenticationFactors", "termsOfUse",
                         "applicationFilter", "includeServicePrincipals", "excludeServicePrincipals",
                         "servicePrincipalFilter", "id", "displayName"}
    found = False

    def restriction(value: Any) -> Any:
        if isinstance(value, dict):
            return _pascal({k: restriction(v) for k, v in value.items()
                            if k not in {"id", "displayName"} and not _annotation(k)})
        if isinstance(value, list):
            return [restriction(v) for v in value]
        return value

    def convert(row: Any, fields: dict, path: str = "", *, variant: bool = False) -> dict:
        nonlocal found
        _require(isinstance(row, dict), kind="invalid_type")
        output = {}
        for key, value in row.items():
            if _annotation(key):
                continue
            target = key[0].upper() + key[1:] if key else ""
            if target not in fields:
                restricted = key in restriction_names and (path or key != "id")
                if (restricted and not _blank(value)
                        or not restricted and path and value not in (None, [], {}, "")):
                    found = True
                if not variant:
                    continue
                check = extensions.get(path, {}).get(target)
                if path == "conditions.clientApplications." and key not in {"id", "displayName"}:
                    check = _pascal
                if check is None:
                    # _restricted also reads unknown keys inside these two
                    # containers. Dropping a populated one could broaden a pass.
                    if path in {"conditions.locations.", "conditions.platforms."} and key not in {"id", "displayName"}:
                        _require(_blank(value), kind="unexpected_field")
                    continue
            else:
                check = fields[target]
            _require(key == target[0].lower() + target[1:] and target not in output, target, "unexpected_field")
            if isinstance(check, dict):
                output[target] = None if value is None else convert(value, check, path + key + ".", variant=variant)
            elif check is _pascal:
                output[target] = restriction(value)
            else:
                if value is None and check is _strings:
                    value = []
                _require(check(value), target, "invalid_type")
                if target == "State":
                    _enum(value, {"enabled", "disabled", "enabledForReportingButNotEnforced"}, "State")
                output[target] = _pascal(value)
        return output

    rows = bundle.operation("conditional_access", "conditionalAccessPolicies")
    base, model_safe = [], True
    for row in rows:
        found = False
        base.append(convert(row, spec))
        if found and base[-1].get("State") not in {"disabled", "enabledForReportingButNotEnforced"}:
            model_safe = False
    # On every shape the model adapter can represent, return precisely its value,
    # including its omission of empty restrictions and disabled-policy extras.
    return base if model_safe else [convert(row, spec, variant=True) for row in rows]


def _spo_rule(bundle: Bundle) -> Any:
    rows = bundle.alternatives([("sharepoint_access", "sharePointSettings"), ("onedrive_posture", "sharePointSettings")])
    _require(len(rows) == 1)
    raw, result = rows[0], {}
    for key, names in ENUM_NAME_KEYS.items():
        aliases = [key, key[0].lower() + key[1:]]
        if key == "ODBSharingCapability":
            aliases += ["oneDriveSharingCapability", "odbSharingCapability"]
        values = [raw[k] for k in aliases if k in raw]
        if not values:
            continue
        reverse = {str(v).split(" (")[0]: n for n, v in names.items()}
        numbers = [v if type(v) is int else reverse.get(v) if isinstance(v, str) else None for v in values]
        if all(type(n) is int and n in names and n == numbers[0] for n in numbers):
            result[key] = numbers[0]
    for key in ("RequireAnonymousLinksExpireInDays", "EmailAttestationRequired", "EmailAttestationReAuthDays"):
        values = [raw[k] for k in (key, key[0].lower() + key[1:]) if k in raw]
        check = (lambda v: type(v) is bool) if key == "EmailAttestationRequired" else (
            lambda v: type(v) is int and v >= (-1 if key == "RequireAnonymousLinksExpireInDays" else 0))
        if values and all(check(v) and v == values[0] for v in values):
            result[key] = values[0]
    _require("SharingCapability" in result, "SharingCapability", "missing_field")
    return [result]


ADAPTERS: dict[str, Callable[[Bundle], Any]] = {
    "authentication_method": _authentication_method,
    "directory_settings": _directory_settings,
    "domain_settings": _domain_settings,
    "default_app_management_policy": _default_app_policy,
    "app_management_policies": _app_policies,
    "risky_delegated_permission_classifications": _risky_classifications,
}

RULE_VARIANTS: dict[str, Callable[[Bundle], Any]] = {
    "conditional_access_policies": _ca_rule,
    "SPO_tenant": _spo_rule,
}
