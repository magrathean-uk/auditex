"""Synthetic bundle tests; no tenant calls, shell providers or held-out data."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import lzma
import os
from pathlib import Path

import pytest

from auditex import scuba_adapters_aad as aad
from auditex import scuba_projection as projection
from azure_tenant_audit.external_sharing import ENUM_NAME_KEYS
from azure_tenant_audit.scuba_assessment import validate_explainer, value_rule_verdict
from azure_tenant_audit.collection_markers import NOT_COLLECTED
from azure_tenant_audit.run_files import UnsafeRunFileError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/scuba-adapters-aad"
SCUBA = Path(os.environ["AUDITEX_TEST_SCUBAGEAR"]) if os.environ.get("AUDITEX_TEST_SCUBAGEAR") else None
RISK_PATH = "schemas/RiskyAppPermissions.json"
TENANT = "11111111-1111-4111-8111-111111111111"

# Pack-only fields deliberately omitted at every round trip, including nested
# free text and target display names. Everything else is selected explicitly.
PACK_ONLY_DROPPED = {
    "authentication_method": "policy metadata; configuration fields except Id/State; Authenticator fields except IsSoftwareOathEnabled and the two context blocks; target fields except Id",
    "directory_settings": "group fields except Id/DisplayName/TemplateId/Values; values other than EnableAdminConsentRequests; value fields except Name/Value",
    "domain_settings": "IsDefault, IsInitial, PasswordNotificationWindowInDays, SupportedServices and all fields outside the five rule fields",
    "default_app_management_policy": "IsOverridden and other policy metadata; scope fields except PasswordCredentials/KeyCredentials; entry fields except RestrictionType/State/RestrictForAppsCreatedAfterDateTime/MaxLifetime",
    "app_management_policies": "Description and other policy metadata; entry metadata; AppliesTo fields except Id",
    "risky_delegated_permission_classifications": "all fields except ObjectId/AppId/DisplayName/RiskyPermClassifications; classification metadata and non-risky or non-low entries",
    "conditional_access_policies": "policy Id and metadata; Users.IncludeGroups/IncludeGuestsOrExternalUsers; SessionControls; GrantControls.CustomAuthenticationFactors/TermsOfUse; nested id/displayName; unrecognised fields",
    "SPO_tenant": "all fields outside the ten validated settings; absent and invalid settings are omitted",
}


def write(root, path, payload):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload) + "\n")


def graph(value):
    if isinstance(value, dict):
        return {k[0].lower() + k[1:]: graph(v) for k, v in value.items()}
    if isinstance(value, list):
        return [graph(v) for v in value]
    return value


def operation(root, collector, name, rows, *, singleton=False, **metadata):
    path = root / f"raw/{collector}.json"
    payload = json.loads(path.read_text()) if path.exists() else {}
    payload[name] = {**(rows if singleton else {"value": rows}), "status": "ok", **metadata}
    write(root, f"raw/{collector}.json", payload)


def bundle(root):
    result = projection.Bundle(root, 250_000, 256 * 1024 * 1024, 10_000)
    result.manifest = json.loads((root / "run-manifest.json").read_text())
    return result


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setattr(projection, "AREA_ADAPTER_MODULES", ("auditex.scuba_adapters_aad",))
    write(tmp_path, "run-manifest.json", {"run_id": "synthetic-run", "platform": "m365", "tenant_id": TENANT})
    return tmp_path


def pick(row, fields):
    if not isinstance(row, dict):
        raise ValueError("object required")
    return {k: deepcopy(row[k]) for k in fields if k in row}


ENTRY = ("RestrictionType", "State", "RestrictForAppsCreatedAfterDateTime", "MaxLifetime")


def expected_scope(scope, custom=False):
    if scope is None:
        return None
    result = {}
    for key, entries in pick(scope, ("PasswordCredentials", "KeyCredentials")).items():
        if entries is None:
            result[key] = None
            continue
        if not isinstance(entries, list):
            raise ValueError("credential list required")
        result[key] = []
        for entry in entries:
            item = pick(entry, ENTRY)
            if custom:
                targets = entry["AppliesTo"]
                if not isinstance(targets, list) or any(not isinstance(t, dict) or not isinstance(t.get("Id"), str) for t in targets):
                    raise ValueError("target ids required")
                item["AppliesTo"] = [pick(t, ("Id",)) for t in targets]
            result[key].append(item)
    return result


def expected(section, value):
    if not isinstance(value, list) or any(not isinstance(r, dict) for r in value):
        raise ValueError("list of objects required")
    if section == "authentication_method":
        if len(value) != 1:
            raise ValueError("singleton required")
        row = value[0]
        policy = pick(row["authentication_method_policy"], ("PolicyMigrationState",))
        if not isinstance(policy.get("PolicyMigrationState"), str):
            raise ValueError("migration state required")
        configs = row["authentication_method_feature_settings"]
        if not isinstance(configs, list) or any(not isinstance(c, dict) for c in configs):
            raise ValueError("configuration list required")
        items = []
        for c in configs:
            if not isinstance(c.get("Id"), str):
                continue
            item = pick(c, ("Id", "State"))
            if c["Id"] == "MicrosoftAuthenticator":
                item.update(pick(c, ("IsSoftwareOathEnabled",)))
                if "FeatureSettings" in c:
                    fs = c["FeatureSettings"]
                    if fs is None:
                        item["FeatureSettings"] = None
                    else:
                        fields = pick(fs, ("DisplayAppInformationRequiredState", "DisplayLocationInformationRequiredState"))
                        for k, block in fields.items():
                            if block is None:
                                continue
                            fields[k] = pick(block, ("State", "IncludeTarget", "ExcludeTarget"))
                            for target in ("IncludeTarget", "ExcludeTarget"):
                                if target in fields[k] and fields[k][target] is not None:
                                    fields[k][target] = pick(fields[k][target], ("Id",))
                        item["FeatureSettings"] = fields
            items.append(item)
        return [{"authentication_method_policy": policy, "authentication_method_feature_settings": items}]
    if section == "directory_settings":
        result = []
        for row in value:
            if not isinstance(row.get("Values"), list):
                raise ValueError("settings list required")
            item = pick(row, ("Id", "DisplayName", "TemplateId"))
            item["Values"] = [pick(v, ("Name", "Value")) for v in row["Values"]
                              if isinstance(v, dict) and v.get("Name") == "EnableAdminConsentRequests"]
            result.append(item)
        return result
    if section == "domain_settings":
        return [pick(row, ("Id", "IsVerified", "AuthenticationType", "IsRoot", "PasswordValidityPeriodInDays")) for row in value]
    if section in {"default_app_management_policy", "app_management_policies"}:
        custom = section == "app_management_policies"
        if not custom and len(value) != 1:
            raise ValueError("singleton required")
        result = []
        for row in value:
            item = pick(row, ("Id", "DisplayName", "IsEnabled"))
            if custom and not isinstance(item.get("Id"), str):
                raise ValueError("policy id required")
            for key in (("Restrictions",) if custom else ("ApplicationRestrictions", "ServicePrincipalRestrictions")):
                if key in row:
                    item[key] = expected_scope(row[key], custom)
            result.append(item)
        return result
    if section == "risky_delegated_permission_classifications":
        return [pick(row, ("ObjectId", "AppId", "DisplayName", "RiskyPermClassifications")) for row in value]
    if section == "SPO_tenant":
        if len(value) != 1:
            raise ValueError("singleton required")
        item = pick(value[0], ("SharingCapability", "SharingDomainRestrictionMode", "ODBSharingCapability"))
        if "SharingCapability" not in item or any(type(v) is not int or v not in ENUM_NAME_KEYS[k] for k, v in item.items()):
            raise ValueError("Graph capability required")
        return [item]
    if section == "conditional_access_policies":
        return expected_ca(value)
    raise ValueError(section)


CA_LISTS = {"IncludeApplications", "ExcludeApplications", "IncludeUserActions", "ClientAppTypes", "SignInRiskLevels",
            "UserRiskLevels", "IncludeAgentIdServicePrincipals", "IncludeUsers", "ExcludeUsers", "IncludeRoles", "ExcludeRoles",
            "ExcludeGroups", "BuiltInControls", "IncludeAuthenticationContextClassReferences", "IncludeLocations", "ExcludeLocations",
            "IncludePlatforms", "ExcludePlatforms", "ServicePrincipalRiskLevels", "InsiderRiskLevels"}
CA_FIELDS = {"DisplayName": None, "State": None,
             "Conditions": {"Applications": {k: None for k in ("IncludeApplications", "ExcludeApplications", "IncludeUserActions", "ApplicationFilter", "IncludeAuthenticationContextClassReferences")},
                            "AuthenticationFlows": {"TransferMethods": None}, "ClientApplications": None,
                            "Users": {**{k: None for k in ("IncludeUsers", "ExcludeUsers", "IncludeRoles", "ExcludeRoles", "ExcludeGroups")},
                                      "ExcludeGuestsOrExternalUsers": {"GuestOrExternalUserTypes": None, "ExternalTenants": {"MembershipKind": None}}},
                            **{k: None for k in ("ClientAppTypes", "SignInRiskLevels", "UserRiskLevels", "AgentIdRiskLevels", "Devices", "DeviceStates", "ServicePrincipalRiskLevels", "InsiderRiskLevels")},
                            "Locations": {"IncludeLocations": None, "ExcludeLocations": None},
                            "Platforms": {"IncludePlatforms": None, "ExcludePlatforms": None}},
             "GrantControls": {"BuiltInControls": None, "Operator": None, "AuthenticationStrength": {"AllowedCombinations": None}}}


def expected_ca(value):
    def select(row, fields):
        if not isinstance(row, dict):
            raise ValueError("CA object required")
        result = {}
        for key, child in fields.items():
            if key not in row:
                continue
            val = row[key]
            result[key] = select(val, child) if child is not None and val is not None else deepcopy(val)
            if key in CA_LISTS and val is None:
                result[key] = []
        return result
    return [select(row, CA_FIELDS) for row in value]


def raw_contract(section, value):
    """Invert only fields a correct collector can produce, without inventing ids."""
    clean = expected(section, value)
    if section == "authentication_method":
        item = value[0]
        return [("auth_methods", "authenticationMethodsPolicy", graph(item["authentication_method_policy"]), True),
                ("auth_methods", "authenticationMethodConfigurations", graph(item["authentication_method_feature_settings"]), False)]
    if section == "directory_settings":
        return [("consent_policy", "directorySettings", graph(value), False)]
    if section == "domain_settings":
        return [("identity", "domains", graph(value), False)]
    if section == "default_app_management_policy":
        return [("consent_policy", "defaultAppManagementPolicy", graph(value[0]), True)]
    if section == "app_management_policies":
        policies, fanout = [], []
        for policy in value:
            raw = graph(policy)
            targets = None
            for entries in (raw.get("restrictions") or {}).values():
                for entry in entries or []:
                    mine = entry.pop("appliesTo")
                    if targets is not None and mine != targets:
                        raise ValueError("fan-out must be the same in every entry")
                    targets = mine
            if targets is None:
                raise ValueError("no exported fan-out to invert")
            policies.append(raw)
            fanout.append({"policyId": raw["id"], "appliesTo": targets, "appliesToTruncated": False})
        return [("consent_policy", "appManagementPolicies", policies, False),
                ("consent_policy", "appManagementPolicyAppliesTo", fanout, False)]
    if section == "risky_delegated_permission_classifications":
        data = json.loads((ROOT / "configs/risky-delegated-permissions.json").read_text())
        rows = []
        for row in clean:
            resource = data["resources"][row["AppId"]]
            by_name = {v["Name"]: k for k, v in data["permissions"][resource]["Delegated"].items()}
            names = row["RiskyPermClassifications"]
            if not isinstance(names, list) or not names:
                raise ValueError("classification names required")
            rows.append({"servicePrincipalId": row["ObjectId"], "appId": row["AppId"], "displayName": row["DisplayName"],
                         "classifications": [{"permissionId": by_name[n], "permissionName": n, "classification": "low"} for n in names]})
        return [("app_consent", "delegatedPermissionClassifications", rows, False)]
    if section == "SPO_tenant":
        return [("sharepoint_access", "sharePointSettings", graph(clean), False)]
    if section == "conditional_access_policies":
        return [("conditional_access", "conditionalAccessPolicies", graph(value), False)]
    raise ValueError(section)


def vectors():
    path = FIXTURES / "vectors-aad.jsonl.xz"
    if not path.exists():
        path = FIXTURES / "vectors-aad.jsonl"
    if not path.exists():
        return []
    text = lzma.decompress(path.read_bytes()).decode() if path.suffix == ".xz" else path.read_text()
    return [json.loads(line) for line in text.splitlines()]


@pytest.mark.parametrize("vector", vectors(), ids=lambda r: r["vector_id"])
def test_vector_round_trip(run, vector):
    for section, pack in vector["sections"].items():
        for collector, name, raw, singleton in raw_contract(section, pack):
            operation(run, collector, name, raw, singleton=singleton)
        # PD-1 permits retries only for incomplete_shape. An explicitly complete
        # empty normalised summary gets the legacy adapter to that shape gate.
        if section == "SPO_tenant":
            write(run, "normalized/sharepoint_tenant_settings.json", {"records": [], "status": "ok"})
    result = projection.project_run(run)
    for section, pack in vector["sections"].items():
        assert result.rule_sections[section] == expected(section, pack)
        if section in aad.ADAPTERS:
            assert result[section] == NOT_COLLECTED
            assert result.report["sections"][section]["reason"] == "incomplete_shape"


def test_fixture_origins_and_selection():
    rows = vectors()
    assert rows
    assert len({r["vector_id"] for r in rows}) == len(rows)
    assert all(r["source_kind"] in {"constructed", "pack-train", "pack-validation", "packlic-train"} for r in rows)
    assert all(r["split"] in {None, "train", "validation"} for r in rows)
    assert max(Counter((r["policy"], r["rule_cell"]) for r in rows).values()) <= 6
    assert all("@" not in json.dumps(r["sections"]) and "example.com" not in json.dumps(r).lower()
               and "contoso" not in json.dumps(r).lower() for r in rows)
    assert all(isinstance(d.get("Id"), str) and d["Id"].endswith(".invalid")
               for r in rows for d in r["sections"].get("domain_settings", []))
    meta = json.loads((FIXTURES / "README.md").read_text().split("```json\n")[1].split("```", 1)[0])
    path = next(FIXTURES.glob("vectors-aad.jsonl*"))
    assert sha256(path.read_bytes()).hexdigest() == meta["fixture_sha256"]
    assert len(rows) == meta["rows"]
    assert all(r["source_file"].startswith("constructed by ") if r["source_kind"] == "constructed"
               else r["source_file"].startswith("20261030-oracle-pack-v10/") for r in rows)


RAW = {
    "authentication_method": [("auth_methods", "authenticationMethodsPolicy", {"policyMigrationState": "migrationComplete"}, True),
                              ("auth_methods", "authenticationMethodConfigurations", [{"id": "Sms", "state": "disabled"}], False)],
    "directory_settings": [("consent_policy", "directorySettings", [{"id": "settings", "values": [{"name": "EnableAdminConsentRequests", "value": "true"}]}], False)],
    "domain_settings": [("identity", "domains", [{"id": "example.invalid", "isVerified": True, "authenticationType": "Managed", "isRoot": True}], False)],
    "default_app_management_policy": [("consent_policy", "defaultAppManagementPolicy", {"id": "default", "applicationRestrictions": None}, True)],
    "app_management_policies": [("consent_policy", "appManagementPolicies", [{"id": "policy1", "restrictions": {"passwordCredentials": [{"restrictionType": "passwordLifetime", "maxLifetime": None}]}}], False),
                                ("consent_policy", "appManagementPolicyAppliesTo", [{"policyId": "policy1", "appliesTo": [{"id": "app1", "displayName": "discarded"}], "appliesToTruncated": False}], False)],
    "risky_delegated_permission_classifications": [("app_consent", "delegatedPermissionClassifications", [], False)],
}


def seed(run, section):
    for collector, name, raw, singleton in RAW[section]:
        operation(run, collector, name, deepcopy(raw), singleton=singleton)


@pytest.mark.parametrize("section", RAW)
def test_stage_a_projects_to_rules_only(run, section):
    seed(run, section)
    result = projection.project_run(run)
    assert result.rule_sections[section] != NOT_COLLECTED
    assert result[section] == NOT_COLLECTED


@pytest.mark.parametrize("section,collector,name", [(s, c, n) for s, ops in RAW.items() for c, n, _, _ in ops])
@pytest.mark.parametrize("failure", ["coverage", "ledger", "partial", "item_count", "truncation"])
def test_each_source_failure_withholds(run, section, collector, name, failure):
    seed(run, section)
    if failure in {"coverage", "ledger"}:
        write(run, "coverage.json" if failure == "coverage" else "normalized/coverage_ledger.json", {"records": [
            {"collector": collector, "name": name, "status": "failed", "error_class": "permission_denied", "error": "synthetic failure"}]})
    else:
        payload = json.loads((run / f"raw/{collector}.json").read_text())
        payload[name][{"partial": "partial", "item_count": "item_count", "truncation": "sample_truncated"}[failure]] = 999 if failure == "item_count" else True
        write(run, f"raw/{collector}.json", payload)
    assert projection.project_run(run).rule_sections[section] == NOT_COLLECTED


@pytest.mark.parametrize("collector,name,section", [("identity", "domains", "domain_settings"), ("consent_policy", "directorySettings", "directory_settings"), ("consent_policy", "appManagementPolicies", "app_management_policies"), ("app_consent", "delegatedPermissionClassifications", "risky_delegated_permission_classifications")])
def test_empty_needs_complete(run, collector, name, section):
    operation(run, collector, name, [])
    assert projection.project_run(run).rule_sections[section] == []
    write(run, f"raw/{collector}.json", {name: {"value": []}})
    assert projection.project_run(run).rule_sections[section] == NOT_COLLECTED


def test_absence_null_and_minimisation(run):
    operation(run, "identity", "domains", [{"id": "example.invalid"}, {"id": "mocktenant.invalid", "passwordValidityPeriodInDays": None}])
    operation(run, "consent_policy", "directorySettings", [{"values": [{"name": "Other", "value": "private synthetic text"}, {"name": "EnableAdminConsentRequests", "value": "false", "extra": "discarded"}]}])
    operation(run, "consent_policy", "defaultAppManagementPolicy", {"applicationRestrictions": {"passwordCredentials": [{"maxLifetime": None}, {}]}, "servicePrincipalRestrictions": None}, singleton=True)
    seed(run, "app_management_policies")
    result = projection.project_run(run).rule_sections
    assert result["domain_settings"] == [{"Id": "example.invalid"}, {"Id": "mocktenant.invalid", "PasswordValidityPeriodInDays": None}]
    assert result["directory_settings"] == [{"Values": [{"Name": "EnableAdminConsentRequests", "Value": "false"}]}]
    assert result["default_app_management_policy"] == [{"ApplicationRestrictions": {"PasswordCredentials": [{"MaxLifetime": None}, {}]}, "ServicePrincipalRestrictions": None}]
    assert result["app_management_policies"][0]["Restrictions"]["PasswordCredentials"][0]["AppliesTo"] == [{"Id": "app1"}]


@pytest.mark.parametrize("bad", ["missing", "truncated", "duplicate", "null", "no_policy_row"])
def test_app_fanout_must_be_complete(run, bad):
    seed(run, "app_management_policies")
    raw = json.loads((run / "raw/consent_policy.json").read_text())
    fan = raw["appManagementPolicyAppliesTo"]["value"]
    if bad == "missing":
        del raw["appManagementPolicyAppliesTo"]
    elif bad == "truncated":
        fan[0]["appliesToTruncated"] = True
    elif bad == "duplicate":
        fan.append(deepcopy(fan[0]))
    elif bad == "null":
        fan[0]["appliesTo"] = None
    else:
        fan.clear()
    write(run, "raw/consent_policy.json", raw)
    assert projection.project_run(run).rule_sections["app_management_policies"] == NOT_COLLECTED


def test_inline_configurations_only_when_operation_missing(run):
    policy = {"policyMigrationState": "migrationComplete", "authenticationMethodConfigurations": [{"id": "Sms", "state": "disabled"}]}
    operation(run, "auth_methods", "authenticationMethodsPolicy", policy, singleton=True)
    want = [{"authentication_method_policy": {"PolicyMigrationState": "migrationComplete"}, "authentication_method_feature_settings": [{"Id": "Sms", "State": "disabled"}]}]
    assert projection.project_run(run).rule_sections["authentication_method"] == want
    operation(run, "auth_methods", "authenticationMethodConfigurations", [], status="failed")
    assert projection.project_run(run).rule_sections["authentication_method"] == NOT_COLLECTED
    raw = json.loads((run / "raw/auth_methods.json").read_text())
    del raw["authenticationMethodConfigurations"]
    write(run, "raw/auth_methods.json", raw)
    write(run, "coverage.json", {"records": [{"collector": "auth_methods", "name": "authenticationMethodConfigurations", "status": "failed"}]})
    assert projection.project_run(run).rule_sections["authentication_method"] == NOT_COLLECTED


def test_authenticator_minimisation_and_null_targets(run):
    seed(run, "authentication_method")
    block = {"state": "enabled", "includeTarget": {"id": "all_users", "targetType": "group", "extra": "discarded"}, "excludeTarget": None, "other": True}
    operation(run, "auth_methods", "authenticationMethodConfigurations", [
        {"state": "enabled"}, {"id": None}, {"id": "Sms", "state": "disabled", "includeTargets": ["discarded"]},
        {"id": "MicrosoftAuthenticator", "state": "enabled", "isSoftwareOathEnabled": False,
         "featureSettings": {"displayAppInformationRequiredState": block, "displayLocationInformationRequiredState": block, "other": "discarded"}, "extra": True}])
    result = projection.project_run(run).rule_sections["authentication_method"][0]["authentication_method_feature_settings"]
    assert result[0] == {"Id": "Sms", "State": "disabled"}
    assert len(result) == 2
    assert result[1]["FeatureSettings"] == {k: {"State": "enabled", "IncludeTarget": {"Id": "all_users"}, "ExcludeTarget": None} for k in ("DisplayAppInformationRequiredState", "DisplayLocationInformationRequiredState")}


def test_legacy_policy_only_preserves_migration_without_inventing_configs(run):
    operation(run, "auth_methods", "authenticationMethodsPolicy", {"policyMigrationState": "migrationComplete"}, singleton=True)
    assert projection.project_run(run).rule_sections["authentication_method"] == [
        {"authentication_method_policy": {"PolicyMigrationState": "migrationComplete"}}]


def risk_row():
    data = json.loads((ROOT / "configs/risky-delegated-permissions.json").read_text())
    app_id = next(iter(data["resources"]))
    permissions = data["permissions"][data["resources"][app_id]]["Delegated"]
    pid = next(iter(permissions))
    return {"servicePrincipalId": "mock-sp", "appId": app_id, "displayName": "Mock resource", "classifications": [
        {"permissionId": pid, "permissionName": permissions[pid]["Name"], "classification": "low"},
        {"permissionId": pid, "permissionName": "ignored-medium", "classification": "medium"},
        {"permissionId": "not-in-list", "permissionName": "ignored-unknown", "classification": "low"}]}


def test_risky_filter_and_unknown_resource(run):
    row = risk_row()
    operation(run, "app_consent", "delegatedPermissionClassifications", [row])
    result = projection.project_run(run).rule_sections["risky_delegated_permission_classifications"]
    assert result == [{"ObjectId": "mock-sp", "AppId": row["appId"], "DisplayName": "Mock resource", "RiskyPermClassifications": [row["classifications"][0]["permissionName"]]}]
    row["appId"] = "unknown-resource"
    operation(run, "app_consent", "delegatedPermissionClassifications", [row])
    assert projection.project_run(run).rule_sections["risky_delegated_permission_classifications"] == NOT_COLLECTED


def test_missing_per_sp_read_and_failed_coverage_withholds(run):
    operation(run, "app_consent", "delegatedPermissionClassifications", [])
    write(run, "coverage.json", {"records": [{"collector": "app_consent", "name": "delegatedPermissionClassifications", "status": "failed", "error_class": "permission_denied"}]})
    assert projection.project_run(run).rule_sections["risky_delegated_permission_classifications"] == NOT_COLLECTED


def test_unreadable_vendored_data_withholds(run, monkeypatch):
    seed(run, "risky_delegated_permission_classifications")
    monkeypatch.setattr(aad, "load_json_resource", lambda *a, **k: None)
    assert projection.project_run(run).rule_sections["risky_delegated_permission_classifications"] == NOT_COLLECTED


def test_vendored_subset_equals_pinned_file():
    if SCUBA is None:
        pytest.skip("set AUDITEX_TEST_SCUBAGEAR for pinned offline comparison")
    path = SCUBA / RISK_PATH
    if not path.exists():
        pytest.skip("pinned local ScubaGear checkout absent")
    original = json.loads(path.read_text())
    vendored = json.loads((ROOT / "configs/risky-delegated-permissions.json").read_text())
    assert vendored["resources"] == original["resources"]
    assert vendored["permissions"] == {k: {"Delegated": v["Delegated"]} for k, v in original["permissions"].items()}
    assert vendored["source"]["commit"] == "2446ad723b7f55031cc02c8aca244d731d468cba"
    assert vendored["source"]["licence"] == "CC0 1.0"


def test_risky_resource_ids_match_collector_when_available():
    from azure_tenant_audit.collectors import app_consent
    if not hasattr(app_consent, "RISKY_RESOURCE_APP_IDS"):
        pytest.skip("aadsp-1 resource constant not merged")
    data = json.loads((ROOT / "configs/risky-delegated-permissions.json").read_text())
    assert set(data["resources"]) == set(app_consent.RISKY_RESOURCE_APP_IDS)


CA = {"displayName": "Mock CA", "state": "enabled", "conditions": {"applications": {"includeApplications": ["All"], "excludeApplications": [], "includeUserActions": []}, "users": {"includeUsers": ["All"], "excludeUsers": [], "excludeGroups": []}, "clientAppTypes": ["all"]}, "grantControls": {"builtInControls": ["block"], "operator": "OR", "authenticationStrength": None}}
SPO = {"SharingCapability": 2, "ODBSharingCapability": 3, "DefaultLinkPermission": 1, "DefaultSharingLinkType": 1,
       "FileAnonymousLinkType": 1, "FolderAnonymousLinkType": 1, "SharingDomainRestrictionMode": 1,
       "RequireAnonymousLinksExpireInDays": -1, "EmailAttestationRequired": True, "EmailAttestationReAuthDays": 30}
RESTRICTIONS = [{"locations": {"includeLocations": ["mock-location"], "excludeLocations": []}},
                {"platforms": {"includePlatforms": ["android"]}}, {"devices": {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq true"}}},
                {"deviceStates": {"includeStates": ["mock-state"]}}, {"clientApplications": {"excludeServicePrincipals": ["mock-sp"]}},
                {"servicePrincipalRiskLevels": ["high"]}, {"insiderRiskLevels": ["high"]},
                {"applications": {"applicationFilter": {"mode": "include", "rule": "mock-filter"}}},
                {"applications": {"includeAuthenticationContextClassReferences": ["c1"]}}]


def with_restriction(extra):
    row = deepcopy(CA)
    for key, value in extra.items():
        if key == "applications":
            row["conditions"][key].update(value)
        else:
            row["conditions"][key] = deepcopy(value)
    return row


def public_projection_bytes(result):
    """Only public model evidence, policy views and diagnostics may persist."""
    return {name: projection._json(value).encode("utf-8") for name, value in (
        ("model.json", dict(result)), ("views.json", result.views), ("report.json", result.report))}


@pytest.mark.parametrize("extra", RESTRICTIONS)
def test_ca_variant_changes_only_rules(run, monkeypatch, extra):
    row = with_restriction(extra)
    operation(run, "conditional_access", "conditionalAccessPolicies", [row])
    with_variant = projection.project_run(run)
    monkeypatch.setattr(aad, "RULE_VARIANTS", {})
    without = projection.project_run(run)
    assert dict(with_variant) == dict(without)
    assert with_variant.report == without.report
    assert public_projection_bytes(with_variant) == public_projection_bytes(without)
    assert with_variant.rule_sections["conditional_access_policies"] == expected_ca([aad._pascal(row)])
    assert without.rule_sections["conditional_access_policies"] == NOT_COLLECTED
    assert with_variant.report["sections"]["conditional_access_policies"]["unsupported_conditions"]


@pytest.mark.parametrize("section,policy,cell,reason_code", [
    ("conditional_access_policies", "MS.AAD.1.1v1", "no_policy_meets", "no_policy_meets_requirement"),
    ("SPO_tenant", "MS.SHAREPOINT.1.1v1", "value_noncompliant", "setting_noncompliant"),
], ids=["conditional_access_policies", "SPO_tenant"])
def test_variant_model_serialisation_and_written_sidecars_are_byte_identical(
        run, monkeypatch, capsys, caplog, section, policy, cell, reason_code):
    import auditex.model_serving as serving
    import auditex.rule_assessment as rule_assessment

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 5, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(serving, "datetime", FixedDatetime)
    monkeypatch.setattr(rule_assessment, "datetime", FixedDatetime)
    monkeypatch.setattr(serving.ModelClient, "assess", lambda *a, **k: pytest.fail("unexpected model call"))
    caplog.set_level("DEBUG")
    # A recorded empty emergency-access list makes the CA config usable; an
    # unrecorded list would mask the variant's answer as section_not_collected.
    manifest = json.loads((run / "run-manifest.json").read_text())
    write(run, "run-manifest.json", {**manifest, "rule_parameters": {"break_glass_accounts": []}})
    canary = "PRIVATE CA display-name canary"
    email = "private-ca-canary@example.invalid"
    row = with_restriction(RESTRICTIONS[0])
    row["displayName"] = canary
    row["conditions"]["users"]["excludeUsers"] = [email]
    operation(run, "conditional_access", "conditionalAccessPolicies", [row])
    operation(run, "sharepoint_access", "sharePointSettings", [{**SPO, "DefaultSharingLinkType": 3}])
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [{
        "read_state": "collected", "sharing_capability": "externalUserAndGuestSharing",
        "onedrive_sharing_capability": "existingExternalUserSharingOnly"}]})
    enabled = projection.project_run(run)
    assert canary in json.dumps(enabled.rule_sections["conditional_access_policies"])
    assert email in json.dumps(enabled.rule_sections["conditional_access_policies"])
    assert all(canary not in json.dumps(value) and email not in json.dumps(value)
               for key, value in enabled.rule_sections.items() if key != "conditional_access_policies")

    def outputs(result):
        public = public_projection_bytes(result)
        # Exercise the real prompt writer for both affected policy families.
        serving.assess_run(run, dry_run=True,
                           policies=["MS.AAD.1.1v1", "MS.SHAREPOINT.1.1v1"])
        serving.assess_run(run,
                           policies=["MS.AAD.1.1v1", "MS.SHAREPOINT.1.1v1"])
        public.update({name: (run / name).read_bytes() for name in (
            "model_assessment_prompts.jsonl", "model_assessment.json")})
        return public

    with_variant = outputs(enabled)
    # Toggle one private adapter at a time; the other policy is an unchanged control.
    monkeypatch.setattr(aad, "RULE_VARIANTS", {k: v for k, v in aad.RULE_VARIANTS.items() if k != section})
    disabled = projection.project_run(run)
    assert disabled.rule_sections[section] == NOT_COLLECTED
    assert enabled.rule_sections[section] != NOT_COLLECTED
    without = outputs(disabled)
    assessment_name = "model_assessment.json"
    assert {k: v for k, v in with_variant.items() if k != assessment_name} == {
        k: v for k, v in without.items() if k != assessment_name}
    on, off = (json.loads(files[assessment_name]) for files in (with_variant, without))
    # Every envelope field and unaffected row must remain identical, including order.
    assert {k: v for k, v in on.items() if k not in {"policies", "totals"}} == {
        k: v for k, v in off.items() if k not in {"policies", "totals"}}
    assert [r["policy_id"] for r in on["policies"]] == [r["policy_id"] for r in off["policies"]]
    assert [r for r in on["policies"] if r["policy_id"] != policy] == [
        r for r in off["policies"] if r["policy_id"] != policy]
    on_row, off_row = (next(r for r in result["policies"] if r["policy_id"] == policy) for result in (on, off))
    # The explainer is rendered from the rule answer, so it changes with the verdict like the other answer fields.
    answer_fields = {"claims", "limitations", "recommendations", "rule_precheck", "comparison", "explainer"}
    assert {k: v for k, v in on_row.items() if k not in answer_fields} == {
        k: v for k, v in off_row.items() if k not in answer_fields}
    assert value_rule_verdict(on_row) == "not_met"
    assert value_rule_verdict(off_row) == "not_assessed"
    assert on_row.get("explainer") != off_row.get("explainer")
    if "explainer" in on_row:
        validate_explainer(on_row, on_row["explainer"])  # selected explainer matches its changed rule verdict
    on_detail, off_detail = on_row["rule_precheck"], off_row["rule_precheck"]
    assert (on_detail["cell"], on_detail["reason_code"]) == (cell, reason_code)
    assert (off_detail["cell"], off_detail["reason_code"]) == (
        "section_not_collected", "required_evidence_section_not_collected")
    changed_detail = {"cell", "reason_code", "reason_text", "section"}
    assert {k: v for k, v in on_detail.items() if k not in changed_detail} == {
        k: v for k, v in off_detail.items() if k not in changed_detail}
    on_claim = next(c for c in on_row["claims"] if c["id"] == "requirement_met")
    off_claim = next(c for c in off_row["claims"] if c["id"] == "requirement_met")
    assert (on_claim["status"], on_claim["value"]) == ("confirmed", False)
    assert (off_claim["status"], off_claim["value"]) == ("unknown", None)
    assert on_row["comparison"] == {**off_row["comparison"], "model_status": "fail"}
    assert off_row["comparison"]["model_status"] is None
    assert on["totals"] == {"answered": 2, "unknown": 0, "invalid": 0, "skipped": 0,
                            "rule_answered": 2, "scope_narrowed": 0}
    assert off["totals"] == {**on["totals"], "answered": 1, "unknown": 1}
    for mode, files in (("enabled", with_variant), ("disabled", without)):
        for name, content in files.items():
            target = run / "serialisation" / mode / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            assert target.read_bytes() == content
            if name != assessment_name:
                assert target.read_bytes() == (run / "serialisation" / "enabled" / name).read_bytes()
            assert canary.encode() not in content and email.encode() not in content
    captured = capsys.readouterr()
    for text in (captured.out, captured.err, caplog.text):
        assert canary not in text and email not in text


@pytest.mark.parametrize("state", ["enabled", "disabled", "enabledForReportingButNotEnforced"])
@pytest.mark.parametrize("extra", [{}, {"locations": {"includeLocations": [], "excludeLocations": None}}, RESTRICTIONS[0]])
def test_ca_model_success_invariant(run, state, extra):
    row = with_restriction(extra)
    row["state"] = state
    row["conditions"]["clientAppTypes"] = None
    operation(run, "conditional_access", "conditionalAccessPolicies", [row])
    try:
        model = projection._ca(bundle(run))
    except projection.Unavailable:
        assert state == "enabled" and extra == RESTRICTIONS[0]
        return
    before = bundle(run)
    assert aad._ca_rule(before) == model
    assert not before.dropped_conditions and not before.null_lists and not before.ignored_fields


def test_ca_drops_unread_fields_and_annotations(run):
    row = with_restriction(RESTRICTIONS[0])
    row.update(sessionControls={"persistentBrowser": {"mode": "always"}}, **{"@odata.context": "discarded"})
    row["conditions"]["users"].update(includeGroups=["mock-group"], includeGuestsOrExternalUsers={"guestOrExternalUserTypes": "all"})
    row["grantControls"].update(customAuthenticationFactors=["mock-factor"], termsOfUse=["mock-terms"], id="discarded", displayName="discarded")
    operation(run, "conditional_access", "conditionalAccessPolicies", [row])
    b = bundle(run)
    assert aad._ca_rule(b) == expected_ca([aad._pascal(row)])
    assert not b.dropped_conditions and not b.null_lists and not b.ignored_fields


@pytest.mark.parametrize("key", ["locations", "platforms"])
def test_unknown_restriction_leaf_cannot_become_unrestricted(run, key):
    row = with_restriction({key: {"futureQualifier": "mock-restriction"}})
    operation(run, "conditional_access", "conditionalAccessPolicies", [row])
    assert projection.project_run(run).rule_sections["conditional_access_policies"] == NOT_COLLECTED


def test_nested_restriction_metadata_is_dropped(run):
    row = with_restriction({"devices": {"deviceFilter": {"mode": "include", "rule": "mock-rule", "id": "discarded", "displayName": "discarded"}}})
    operation(run, "conditional_access", "conditionalAccessPolicies", [row])
    value = aad._ca_rule(bundle(run))[0]["Conditions"]["Devices"]
    assert value == {"DeviceFilter": {"Mode": "include", "Rule": "mock-rule"}}


@pytest.mark.parametrize("field,value", [("DefaultSharingLinkType", 0), ("DefaultSharingLinkType", 3), ("DefaultLinkPermission", 0), ("SharingDomainRestrictionMode", 2)])
def test_sp_closed_values_and_model_report_unchanged(run, monkeypatch, field, value):
    raw = {**SPO, field: value}
    operation(run, "sharepoint_access", "sharePointSettings", [raw])
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [{"read_state": "collected", "sharing_capability": "externalUserAndGuestSharing", "onedrive_sharing_capability": "existingExternalUserSharingOnly"}]})
    with_variant = projection.project_run(run)
    monkeypatch.setattr(aad, "RULE_VARIANTS", {})
    without = projection.project_run(run)
    assert with_variant.rule_sections["SPO_tenant"] == [raw]
    assert dict(with_variant) == dict(without)
    assert with_variant.report == without.report


def test_sp_graph_only_full_shell_and_model_success_invariant(run):
    graph_only = {"sharingCapability": "externalUserAndGuestSharing", "sharingDomainRestrictionMode": "blockList"}
    operation(run, "sharepoint_access", "sharePointSettings", [graph_only])
    assert aad._spo_rule(bundle(run)) == [{"SharingCapability": 2, "SharingDomainRestrictionMode": 2}]
    graph_only["oneDriveSharingCapability"] = "existingExternalUserSharingOnly"
    operation(run, "sharepoint_access", "sharePointSettings", [graph_only])
    assert aad._spo_rule(bundle(run)) == [{"SharingCapability": 2, "SharingDomainRestrictionMode": 2, "ODBSharingCapability": 3}]
    operation(run, "sharepoint_access", "sharePointSettings", [SPO])
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [{"read_state": "collected", "sharing_capability": "externalUserAndGuestSharing", "onedrive_sharing_capability": "existingExternalUserSharingOnly"}]})
    assert aad._spo_rule(bundle(run)) == projection._spo(bundle(run)) == [SPO]


@pytest.mark.parametrize("raw", [{}, {"SharingCapability": None}, {"SharingCapability": True}, {"SharingCapability": 4}, {"SharingCapability": "unknown"}])
def test_sp_gate_missing_or_invalid_withholds(run, raw):
    operation(run, "sharepoint_access", "sharePointSettings", [raw])
    with pytest.raises(projection.Unavailable):
        aad._spo_rule(bundle(run))


def test_sp_invalid_optional_fields_are_omitted(run):
    raw = {"SharingCapability": 0, "DefaultLinkPermission": True, "EmailAttestationRequired": 1,
           "RequireAnonymousLinksExpireInDays": -2, "EmailAttestationReAuthDays": -1}
    operation(run, "sharepoint_access", "sharePointSettings", [raw])
    assert aad._spo_rule(bundle(run)) == [{"SharingCapability": 0}]


def test_sp_raw_requirement_exposes_legacy_normalised_synthesis_invariant_limit(run):
    raw = {k: v for k, v in SPO.items() if k not in {"SharingCapability", "ODBSharingCapability"}}
    operation(run, "sharepoint_access", "sharePointSettings", [raw])
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [{"read_state": "collected", "sharing_capability": "externalUserAndGuestSharing", "onedrive_sharing_capability": "existingExternalUserSharingOnly"}]})
    assert projection._spo(bundle(run)) == [SPO]
    with pytest.raises(projection.Unavailable):
        aad._spo_rule(bundle(run))
    # The approved hook runs only after a legacy model withhold. A successful
    # legacy model projection still retains its normalised-derived value.
    assert projection.project_run(run).rule_sections["SPO_tenant"] == [SPO]


@pytest.mark.parametrize("metadata", [
    {"status": "failed"}, {"read_state": "failed"}, {"collection_status": "failed"}, {"complete": False},
    {"partial": True}, {"error_class": "permission_denied"}, {"resolver_error": True}, {"incomplete": True},
    {"bounded_sample": True}, {"collection_truncated": True}, {"truncation_reason": "row_limit"},
    {"@odata.nextLink": "https://example.invalid/next"},
], ids=lambda metadata: next(iter(metadata)))
def test_normalised_sp_health_failure_cannot_become_raw_rule_evidence(run, monkeypatch, metadata):
    operation(run, "sharepoint_access", "sharePointSettings", [SPO])
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [], **metadata})
    monkeypatch.setitem(aad.RULE_VARIANTS, "SPO_tenant", lambda b: pytest.fail("health failure retried"))
    result = projection.project_run(run)
    assert result.rule_sections["SPO_tenant"] == NOT_COLLECTED
    if "resolver_error" in metadata:
        assert result.report["sections"]["SPO_tenant"]["detail"] == {"field": "resolver_error", "kind": "unseen_shape"}


@pytest.mark.parametrize("section", ["conditional_access_policies", "SPO_tenant"])
@pytest.mark.parametrize("reason", ["collector_error", "ledger", "qualifier_check", "missing_artifact", "manifest_error", "platform",
                                   "bounded_sample", "collection_truncated", "sample_truncated", "manifest_coverage_gaps"])
def test_variant_never_bypasses_nonshape_failure(run, monkeypatch, section, reason):
    collector, name = ("conditional_access", "conditionalAccessPolicies") if section == "conditional_access_policies" else ("sharepoint_access", "sharePointSettings")
    operation(run, collector, name, [with_restriction(RESTRICTIONS[0]) if section == "conditional_access_policies" else SPO])
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [], "status": "ok"})
    if reason == "manifest_error":
        (run / "run-manifest.json").write_text("invalid-json")
    elif reason == "platform":
        write(run, "run-manifest.json", {"platform": "google_workspace"})
    elif reason == "missing_artifact":
        (run / f"raw/{collector}.json").unlink()
    elif reason == "manifest_coverage_gaps":
        write(run, "run-manifest.json", {"platform": "m365", "coverage_gaps": [f"{collector}.{name}"]})
    elif reason == "collector_error":
        write(run, "coverage.json", {"records": [{"collector": collector, "name": name, "status": "failed", "error_class": "permission_denied", "error": "synthetic failure"}]})
    elif reason == "ledger":
        write(run, "normalized/coverage_ledger.json", {"records": [{"collector": collector, "coverage_status": "partial",
              "diagnostics": [{"item": name}]}]})
    elif reason in {"qualifier_check", "bounded_sample", "collection_truncated", "sample_truncated"}:
        raw = json.loads((run / f"raw/{collector}.json").read_text())
        raw[name]["partial" if reason == "qualifier_check" else reason] = True
        write(run, f"raw/{collector}.json", raw)
    monkeypatch.setitem(aad.RULE_VARIANTS, section, lambda b: pytest.fail("nonshape failure retried"))
    if reason == "manifest_error":
        # A required run manifest that is not a valid root-trusted document is a fixed refusal, not an
        # optional omission that would surface as NOT_COLLECTED; the variant is never consulted.
        with pytest.raises(UnsafeRunFileError):
            projection.project_run(run)
        monkeypatch.setattr(aad, "RULE_VARIANTS", {})
        with pytest.raises(UnsafeRunFileError):
            projection.project_run(run)
        return
    enabled = projection.project_run(run)
    monkeypatch.setattr(aad, "RULE_VARIANTS", {})
    disabled = projection.project_run(run)
    assert enabled.rule_sections[section] == NOT_COLLECTED
    assert public_projection_bytes(enabled) == public_projection_bytes(disabled)
    entry = enabled.report["sections"][section]
    expected_reason = {"collector_error": "collector_error", "missing_artifact": "missing_artifact",
                       "platform": "not_applicable_to_platform"}.get(reason, "incomplete_shape")
    assert entry["reason"] == expected_reason
    fields = {"ledger": "coverage_status", "qualifier_check": "partial", "bounded_sample": "bounded_sample",
              "collection_truncated": "collection_truncated", "sample_truncated": "sample_truncated",
              "manifest_coverage_gaps": "coverage_gaps"}
    if reason in fields:
        assert entry["detail"] == {"field": fields[reason], "kind": "unseen_shape"}


@pytest.mark.parametrize("section", ["conditional_access_policies", "SPO_tenant"])
@pytest.mark.parametrize("bound", ["scan_max_bytes", "scan_max_rows", "scan_max_chunks"])
def test_variant_never_bypasses_source_scan_bounds(run, monkeypatch, section, bound):
    collector, name = (("conditional_access", "conditionalAccessPolicies") if section == "conditional_access_policies"
                       else ("sharepoint_access", "sharePointSettings"))
    row = with_restriction(RESTRICTIONS[0]) if section == "conditional_access_policies" else SPO
    write(run, "normalized/sharepoint_tenant_settings.json", {"records": [], "status": "ok"})
    limit = 1024 if bound == "scan_max_bytes" else 1
    if bound == "scan_max_chunks":
        chunks = [f"chunks/{collector}/{index}.jsonl" for index in range(2)]
        for path in chunks:
            write(run, path, row)
        operation(run, collector, name, [], chunk_files=chunks, chunk_count=2, item_count=2)
    elif bound == "scan_max_bytes":
        operation(run, collector, name, [row], **{"@odata.context": "x" * (limit * 2)})
        assert (run / "run-manifest.json").stat().st_size < limit < (run / f"raw/{collector}.json").stat().st_size
        assert (run / "normalized/sharepoint_tenant_settings.json").stat().st_size < limit
    else:
        operation(run, collector, name, [row, row])
    monkeypatch.setitem(aad.RULE_VARIANTS, section, lambda b: pytest.fail("scan failure retried"))
    enabled = projection.project_run(run, **{bound: limit})
    monkeypatch.setattr(aad, "RULE_VARIANTS", {})
    disabled = projection.project_run(run, **{bound: limit})
    assert enabled.rule_sections[section] == NOT_COLLECTED
    assert public_projection_bytes(enabled) == public_projection_bytes(disabled)
    entry = enabled.report["sections"][section]
    assert entry["reason"] == "oversize"
    assert entry["detail"] == {"field": bound, "kind": "scan_bound"}
    # The manifest parsed successfully: this failure belongs to section evidence.
    assert enabled["tenant_id"] == TENANT
    if bound == "scan_max_rows":
        assert entry["scan"]["rows"] == limit


@pytest.mark.parametrize("section", ["conditional_access_policies", "SPO_tenant"])
@pytest.mark.parametrize("detail", [
    {"field": "$", "kind": "unseen_shape"}, {"field": "future_health_marker", "kind": "unseen_shape"},
    {"field": "SharingCapability", "kind": "invalid_type"}, {"field": "SharingCapability", "kind": "unseen_shape"},
    {"field": "conditions.locations", "kind": "unexpected_field"},
])
def test_unidentified_incomplete_shape_never_retries(run, monkeypatch, section, detail):
    def refused(b):
        raise projection.Unavailable(field=detail["field"], kind=detail["kind"])

    monkeypatch.setattr(projection, "_ca" if section == "conditional_access_policies" else "_spo", refused)
    monkeypatch.setitem(aad.RULE_VARIANTS, section, lambda b: pytest.fail("unidentified shape retried"))
    result = projection.project_run(run)
    assert result.rule_sections[section] == NOT_COLLECTED
    assert result.report["sections"][section]["detail"] == detail


def test_sp_first_failed_read_does_not_fall_back(run):
    operation(run, "sharepoint_access", "sharePointSettings", [SPO], status="failed")
    operation(run, "onedrive_posture", "sharePointSettings", [SPO])
    with pytest.raises(projection.Unavailable):
        aad._spo_rule(bundle(run))


def test_missing_normalised_sp_file_keeps_approved_missing_artifact_gate(run):
    operation(run, "sharepoint_access", "sharePointSettings", [{"sharingCapability": 2, "sharingDomainRestrictionMode": 0}])
    result = projection.project_run(run)
    assert result.rule_sections["SPO_tenant"] == NOT_COLLECTED
    assert result.report["sections"]["SPO_tenant"]["reason"] == "missing_artifact"


def test_pascal_drops_annotations_and_copies_containers():
    value = {"outer": [{"id": "mock-id", "@odata.type": "discarded"}], "extra@odata.context": "discarded"}
    result = aad._pascal(value)
    assert result == {"Outer": [{"Id": "mock-id"}]}
    result["Outer"].append({})
    assert len(value["outer"]) == 1
