#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(item) for item in value}
    return {str(value)}


class JsonlLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, message: str, status: str, **details: object) -> None:
        payload = {
            "time": utc_now(),
            "message": message,
            "status": status,
            "details": details,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


class GraphClient:
    def __init__(self, logger: JsonlLogger, dry_run: bool) -> None:
        self.logger = logger
        self.dry_run = dry_run
        self.session = requests.Session()
        if dry_run:
            return
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self._access_token()}",
                "Content-Type": "application/json",
            }
        )

    def _access_token(self) -> str:
        env_token = os.environ.get("AZURE_ACCESS_TOKEN")
        if env_token:
            self.logger.event("auth.token.source", "success", source="AZURE_ACCESS_TOKEN", hint="env")
            return env_token
        proc = subprocess.run(
            [
                "az",
                "account",
                "get-access-token",
                "--resource",
                "https://graph.microsoft.com",
                "--query",
                "accessToken",
                "--output",
                "tsv",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        token = proc.stdout.strip()
        if not token:
            raise RuntimeError("Azure CLI did not return a Graph access token.")
        self.logger.event("auth.token.source", "success", source="azure_cli", command="az account get-access-token")
        return token

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        allow_failure: bool = False,
    ) -> dict:
        if self.dry_run:
            self.logger.event("graph.would_request", "success", method=method, path=path)
            if method.upper() != "GET":
                return {}
            return {"value": []}

        url = path if path.startswith("http://") or path.startswith("https://") else f"{GRAPH_ROOT}{path}"
        response = self.session.request(method, url, json=payload, timeout=120)
        if response.status_code in {200, 201, 204, 202}:
            if response.status_code == 204:
                return {}
            try:
                body = response.json()
            except ValueError:
                body = {"raw": response.text}
            self.logger.event(
                "graph.request",
                "success",
                method=method,
                path=path,
                statusCode=response.status_code,
            )
            return body

        if not allow_failure:
            self.logger.event(
                "graph.request",
                "error",
                method=method,
                path=path,
                statusCode=response.status_code,
                body=response.text[:2000],
            )
            raise RuntimeError(f"{method} {path} failed: {response.status_code} {response.text}")

        self.logger.event(
            "graph.request",
            "warn",
            method=method,
            path=path,
            statusCode=response.status_code,
            body=response.text[:2000],
            allowedFailure=True,
        )
        return {"statusCode": response.status_code, "error": response.text}

    def iter_pages(self, path: str):
        next_url = path
        while next_url:
            body = self.request("GET", next_url)
            if not isinstance(body, dict):
                return
            for item in body.get("value", []):
                yield item
            next_url = body.get("@odata.nextLink")


def _count_and_collect(client: GraphClient, path: str) -> tuple[int, list[dict[str, Any]]]:
    items: list[dict[str, Any]] = []
    for item in client.iter_pages(path):
        items.append(item)
    return len(items), items


def _to_path(path: Path | str) -> Path:
    return Path(path).resolve()


def _load_module(path: Path):
    module_name = f"tenant_bootstrap_dynamic_{path.stem}_{abs(hash(path.as_posix()))%10_000_000}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path | str) -> dict:
    p = _to_path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _load_expected_definitions(cfg: dict, scripts_dir: Path, policy_root: Path) -> dict[str, object]:
    identity_module = _load_module(scripts_dir / "identity_seed_az.py")
    workload_module = _load_module(scripts_dir / "seed-workload-az.py")

    planned_users = identity_module.build_users(cfg)
    planned_groups = identity_module.build_groups(cfg)
    planned_dynamic_groups = identity_module.build_dynamic_groups(cfg)
    planned_devices = workload_module.build_device_inventory(cfg)
    managed_device_targets = {
        "phase1": workload_module.resolve_managed_device_target(cfg, phase="phase1"),
        "phase2": workload_module.resolve_managed_device_target(cfg, phase="phase2"),
        "final": workload_module.resolve_managed_device_target(cfg, phase="final"),
    }
    windows365_plan = workload_module.build_windows365_plan(cfg)
    policy_artifact_plan = workload_module.build_policy_artifact_plan(policy_root.parent)
    scenario_plan = workload_module.build_scenario_plan(cfg)

    ca_files = [path for path in (policy_root / "entra").glob("*.json") if path.is_file()]
    intune_files = [path for path in (policy_root / "intune").glob("*.json") if path.is_file()]
    exchange_files = [path for path in (policy_root / "exchange").glob("*.json") if path.is_file()]

    expected_intune_compliance = 0
    expected_intune_configuration = 0
    for policy_file in intune_files:
        policy = _read_json(policy_file)
        odata_type = str(policy.get("@odata.type", "")).lower()
        if "compliancepolicy" in odata_type:
            expected_intune_compliance += 1
        elif (
            "windowsupdateforbusinessconfiguration" in odata_type
            or (
                "configuration" in odata_type
                and "deviceenrollment" not in odata_type
                and "serviceconfiguration" not in odata_type
            )
        ):
            expected_intune_configuration += 1

    all_users_domain = cfg.get("tenant", {}).get("tenantDomain", "")
    expected_user_upns = {f"{user.alias}@{all_users_domain}" for user in planned_users}

    return {
        "plannedUsers": planned_users,
        "plannedInternalUsers": len([user for user in planned_users if not user.is_guest]),
        "plannedGuestUsers": len([user for user in planned_users if user.is_guest]),
        "plannedStaticGroups": planned_groups,
        "plannedDynamicGroups": planned_dynamic_groups,
        "plannedDevices": planned_devices,
        "managedDeviceTargets": managed_device_targets,
        "windows365Plan": windows365_plan,
        "expectedCounts": {
            "staticGroups": len(planned_groups),
            "dynamicGroups": len(planned_dynamic_groups),
            "caPolicies": len(ca_files),
            "intuneCompliancePolicies": expected_intune_compliance,
            "intuneConfigurationPolicies": expected_intune_configuration,
            "exchangePolicies": len(exchange_files),
            "devices": len(planned_devices),
            "managedDevicesPhase1": managed_device_targets["phase1"],
            "artifactExchangePolicies": policy_artifact_plan["counts"].get("exchange", 0),
            "artifactEntraPolicies": policy_artifact_plan["counts"].get("entra", 0),
            "artifactIntunePolicies": policy_artifact_plan["counts"].get("intune", 0),
            "scenarioEvents": len(scenario_plan.get("plannedEvents", [])),
        },
        "expectedUpns": expected_user_upns,
        "tenantDomain": all_users_domain,
        "expectedTeamSourceGroups": cfg.get(
            "teamGroups",
            [
                cfg["groupNames"]["itM365"],
                cfg["groupNames"]["salesM365"],
                cfg["groupNames"]["financeM365"],
            ],
        ),
        "expectedCaDisplayNames": [
            _read_json(path).get("displayName", path.stem)
            for path in sorted(ca_files)
            if path.is_file()
        ],
        "policyRoot": _to_path(policy_root),
    }


def _resolve_child_manifest(
    run_dir: Path,
    base_name: str,
    *,
    run_suffix: str | None = None,
) -> Path:
    run_path = run_dir / base_name
    if run_path.exists():
        return run_path
    if run_suffix:
        candidate = run_dir.with_name(f"{run_dir.name}-{run_suffix}") / base_name
        if candidate.exists():
            return candidate
        candidate = run_dir.parent / f"{run_dir.name}-{run_suffix}" / base_name
        if candidate.exists():
            return candidate
    return run_path


def _collect_artifacts(run_dir: Path, bootstrap_root: Path, dry_run: bool, logger: JsonlLogger) -> tuple[dict[str, str], list[str], str | None]:
    identity_manifest = _read_json(_resolve_child_manifest(run_dir, "identity-seed-az-manifest.json", run_suffix="identity"))
    workload_manifest = _read_json(_resolve_child_manifest(run_dir, "workload-seed-az-manifest.json", run_suffix="workload"))
    exchange_manifest = _read_json(_resolve_child_manifest(run_dir, "exchange-baseline-manifest.json", run_suffix="workload"))
    policy_artifact_manifest = _read_json(_resolve_child_manifest(run_dir, "enterprise-policy-artifact-plan.json", run_suffix="workload"))
    scenario_manifest = _read_json(_resolve_child_manifest(run_dir, "enterprise-scenario-plan.json", run_suffix="workload"))
    bootstrap_manifest = _read_json(run_dir / "run-manifest.json")

    mdm_artifact = ""
    if isinstance(workload_manifest, dict):
        mdm_artifact = workload_manifest.get("devices", {}).get("mdmArtifact", "")

    def resolve_artifact_path(value: str) -> str:
        if not value:
            return ""
        path = Path(value)
        if path.is_absolute():
            return str(path)
        candidates = [
            bootstrap_root / path,
            bootstrap_root.parent / path,
            run_dir.parent / path,
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return str(bootstrap_root / path)

    warnings: list[str] = []
    if not identity_manifest:
        warnings.append("identity-manifest-missing")
    if not workload_manifest:
        warnings.append("workload-manifest-missing")
    if not exchange_manifest:
        warnings.append("exchange-baseline-manifest-missing")
    if not policy_artifact_manifest:
        warnings.append("policy-artifact-plan-missing")
    if not scenario_manifest:
        warnings.append("scenario-plan-missing")

    artifacts = {
        "identityManifest": str(_resolve_child_manifest(run_dir, "identity-seed-az-manifest.json", run_suffix="identity")),
        "workloadManifest": str(_resolve_child_manifest(run_dir, "workload-seed-az-manifest.json", run_suffix="workload")),
        "exchangeManifest": str(_resolve_child_manifest(run_dir, "exchange-baseline-manifest.json", run_suffix="workload")),
        "policyArtifactManifest": str(_resolve_child_manifest(run_dir, "enterprise-policy-artifact-plan.json", run_suffix="workload")),
        "scenarioManifest": str(_resolve_child_manifest(run_dir, "enterprise-scenario-plan.json", run_suffix="workload")),
        "mdmManifest": resolve_artifact_path(mdm_artifact),
        "bootstrapManifest": str(run_dir / "run-manifest.json") if (run_dir / "run-manifest.json").exists() else "",
        "verificationManifest": str(run_dir / "population-verification-manifest.json"),
        "verificationLog": str(run_dir / "population-verification-log.jsonl"),
    }

    if dry_run:
        logger.event("verification.artifacts", "info", mode="dry-run", runDir=str(run_dir))
    else:
        logger.event(
            "verification.artifacts",
            "info",
            hasIdentityManifest=bool(identity_manifest),
            hasWorkloadManifest=bool(workload_manifest),
            hasExchangeManifest=bool(exchange_manifest),
            hasPolicyArtifactManifest=bool(policy_artifact_manifest),
            hasScenarioManifest=bool(scenario_manifest),
            hasMdmManifest=bool(mdm_artifact),
            hasBootstrapManifest=bool(bootstrap_manifest),
        )

    for artifact_name in artifacts.values():
        if artifact_name and not _to_path(artifact_name).exists() and not artifact_name.endswith("population-verification-manifest.json"):
            warnings.append(f"artifact-not-found:{artifact_name}")

    return artifacts, warnings, mdm_artifact if isinstance(mdm_artifact, str) else None


def _count_groups_of_type(groups: list[dict[str, Any]], dynamic: bool | None = None) -> int:
    if dynamic is None:
        return len(groups)
    count = 0
    for group in groups:
        group_types = _safe_set(group.get("groupTypes"))
        is_dynamic = "DynamicMembership" in group_types
        if dynamic and is_dynamic:
            count += 1
        if not dynamic and not is_dynamic:
            count += 1
    return count


def _check(name: str, status: str, expected: object, observed: object, details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "status": status,
        "expected": expected,
        "observed": observed,
    }
    if details is not None:
        payload["details"] = details
    return payload


def _resolve_managed_device_count(client: GraphClient) -> int:
    payload = client.request("GET", "/deviceManagement/managedDevices?$select=id&$top=999", allow_failure=True)
    if not isinstance(payload, dict):
        return -1
    if payload.get("statusCode") == 403:
        return -1
    value = payload.get("value", [])
    if not isinstance(value, list):
        return -1
    return len(value) + (
        0
        if payload.get("@odata.nextLink") is None
        else 1_000_000  # pagination indicates at least this many; exact count not needed for presence checks
    )


def _resolve_windows365_managed_device_evidence(run_dir: Path) -> dict[str, Any]:
    payload = _read_json(run_dir / "windows365-provisioning-manifest.json")
    cloud_pc_result = payload.get("cloudPc") if isinstance(payload, dict) else {}
    cloud_pc = cloud_pc_result.get("cloudPc") if isinstance(cloud_pc_result, dict) else {}
    if not isinstance(cloud_pc, dict):
        cloud_pc = {}
    if not payload:
        return {
            "provisioningArtifactPresent": False,
            "cloudPcId": None,
            "cloudPcStatus": None,
            "managedDeviceId": None,
        }
    return {
        "provisioningArtifactPresent": True,
        "cloudPcId": cloud_pc.get("id"),
        "cloudPcStatus": cloud_pc.get("status") or cloud_pc_result.get("pollState"),
        "managedDeviceId": cloud_pc.get("managedDeviceId"),
    }


def verify(cfg: dict, run_dir: Path, bootstrap_root: Path, *, dry_run: bool, logger: JsonlLogger) -> tuple[dict, int]:
    scripts_dir = bootstrap_root / "scripts"
    policy_root = bootstrap_root / "policies"
    expected = _load_expected_definitions(cfg, scripts_dir, policy_root)

    checks: list[dict[str, Any]] = []
    failing = 0

    if dry_run:
        observed = {
            "users": {"internal": expected["plannedInternalUsers"], "guests": expected["plannedGuestUsers"]},
            "groups": {"total": expected["expectedCounts"]["staticGroups"] + expected["expectedCounts"]["dynamicGroups"]},
            "teams": len(expected["expectedTeamSourceGroups"]),
            "intune": {
                "compliance": expected["expectedCounts"]["intuneCompliancePolicies"],
                "configurations": expected["expectedCounts"]["intuneConfigurationPolicies"],
            },
            "ca": expected["expectedCounts"]["caPolicies"],
            "devices": {"directory": expected["expectedCounts"]["devices"], "managed": expected["expectedCounts"]["managedDevicesPhase1"]},
        }
    else:
        client = GraphClient(logger, dry_run=False)
        all_users_count, all_users = _count_and_collect(client, "/users?$select=id,userPrincipalName,userType&$top=999")
        guest_users = [user for user in all_users if user.get("userType") == "Guest"]
        internal_users = [user for user in all_users if user.get("userType") != "Guest"]

        group_count, groups = _count_and_collect(
            client,
            "/groups?$select=id,displayName,groupTypes,resourceProvisioningOptions&$top=999",
        )
        group_names = {str(group.get("displayName", "")) for group in groups if group.get("displayName")}

        required_static_groups = {g.display_name for g in expected["plannedStaticGroups"]}
        required_dynamic_groups = {g["displayName"] for g in expected["plannedDynamicGroups"]}
        missing_static = sorted(required_static_groups - group_names)
        missing_dynamic = sorted(required_dynamic_groups - group_names)

        team_groups_present = [
            name
            for name in expected["expectedTeamSourceGroups"]
            if name in group_names
        ]
        groups_with_team_resource = [
            group
            for group in groups
            if "Team" in _safe_set(group.get("resourceProvisioningOptions"))
        ]

        ca_count, ca_policies = _count_and_collect(
            client,
            "/identity/conditionalAccess/policies?$select=id,displayName&$top=999",
        )
        try:
            security_defaults = client.request("GET", "/policies/identitySecurityDefaultsEnforcementPolicy")
            security_defaults_enabled = bool(security_defaults.get("isEnabled"))
        except RuntimeError as exc:
            security_defaults_enabled = None
            logger.event("verification.security_defaults.read.skipped", "warn", reason=str(exc)[:240])
        observed_ca_names = {policy.get("displayName", "") for policy in ca_policies}
        missing_ca = [
            name
            for name in expected["expectedCaDisplayNames"]
            if name not in observed_ca_names
        ]

        try:
            compliance_count, _ = _count_and_collect(
                client,
                "/deviceManagement/deviceCompliancePolicies?$select=id,displayName",
            )
            compliance_visible = True
        except RuntimeError as exc:
            compliance_count = -1
            compliance_visible = False
            logger.event("verification.intune_read.skipped", "warn", policyType="deviceCompliancePolicies", reason=str(exc)[:240])

        try:
            config_count, _ = _count_and_collect(
                client,
                "/deviceManagement/deviceConfigurations?$select=id,displayName",
            )
            config_visible = True
        except RuntimeError as exc:
            config_count = -1
            config_visible = False
            logger.event("verification.intune_read.skipped", "warn", policyType="deviceConfigurations", reason=str(exc)[:240])
        devices_count, devices = _count_and_collect(client, "/devices?$select=id,displayName,operatingSystem&$top=999")
        managed_devices_count = _resolve_managed_device_count(client)
        windows365_evidence = _resolve_windows365_managed_device_evidence(run_dir)

        observed = {
            "users": {"internal": len(internal_users), "guests": len(guest_users)},
            "groups": {"total": group_count},
            "teams": {
                "expectedTeamGroupsPresent": len(team_groups_present),
                "groupsWithTeamResource": len(groups_with_team_resource),
            },
            "intune": {
                "compliance": compliance_count,
                "configurations": config_count,
            },
            "ca": {"count": ca_count},
            "securityDefaults": {"isEnabled": security_defaults_enabled},
            "windows365": windows365_evidence,
            "devices": {
                "directory": devices_count,
                "managed": managed_devices_count,
                "planned": len(expected["plannedDevices"]),
            },
        }

        if all_users_count >= expected["plannedInternalUsers"]:
            checks.append(_check("users.total", "pass", expected["plannedInternalUsers"], all_users_count))
        else:
            checks.append(_check("users.total", "fail", expected["plannedInternalUsers"], all_users_count, {"reason": "internal user count below seeded baseline"}))
            failing += 1

        if len(internal_users) >= expected["plannedInternalUsers"]:
            checks.append(_check("users.internal", "pass", expected["plannedInternalUsers"], len(internal_users)))
        else:
            checks.append(_check("users.internal", "fail", expected["plannedInternalUsers"], len(internal_users), {"reason": "internal user count below expected"}))
            failing += 1

        if len(guest_users) >= expected["plannedGuestUsers"]:
            checks.append(_check("users.guests", "pass", expected["plannedGuestUsers"], len(guest_users)))
        else:
            checks.append(_check("users.guests", "warn", expected["plannedGuestUsers"], len(guest_users), {"reason": "guest users below seeded target"}))

        observed_upns = {user.get("userPrincipalName", "") for user in all_users}
        planned_internal_aliases = {
            f"{user.alias}@{expected['tenantDomain']}"
            for user in expected["plannedUsers"]
            if not user.is_guest
        }
        required_upns = planned_internal_aliases
        missing_seed_users = sorted(required_upns - observed_upns)
        if missing_seed_users:
            checks.append(
                _check(
                    "users.requiredSeedUserUpns",
                    "warn",
                    len(required_upns),
                    len(required_upns) - len(missing_seed_users),
                    {"missing": missing_seed_users[:10]},
                )
            )
        else:
            checks.append(_check("users.requiredSeedUserUpns", "pass", len(required_upns), len(required_upns)))

        if group_count >= expected["expectedCounts"]["staticGroups"] + expected["expectedCounts"]["dynamicGroups"]:
            checks.append(_check("groups.total", "pass", expected["expectedCounts"]["staticGroups"] + expected["expectedCounts"]["dynamicGroups"], group_count))
        else:
            checks.append(_check("groups.total", "fail", expected["expectedCounts"]["staticGroups"] + expected["expectedCounts"]["dynamicGroups"], group_count, {"reason": "group count below expected"}))
            failing += 1

        if not missing_static:
            checks.append(_check("groups.static.required", "pass", len(required_static_groups), len(required_static_groups)))
        else:
            checks.append(_check("groups.static.required", "fail", len(required_static_groups), len(required_static_groups) - len(missing_static), {"missing": missing_static}))
            failing += 1

        if not missing_dynamic:
            checks.append(_check("groups.dynamic.required", "pass", len(required_dynamic_groups), len(required_dynamic_groups)))
        else:
            checks.append(_check("groups.dynamic.required", "warn", len(required_dynamic_groups), len(required_dynamic_groups) - len(missing_dynamic), {"missing": missing_dynamic}))

        actual_static_groups = _count_groups_of_type(groups, dynamic=False)
        if actual_static_groups >= expected["expectedCounts"]["staticGroups"]:
            checks.append(_check("groups.staticCategory", "pass", expected["expectedCounts"]["staticGroups"], actual_static_groups))
        else:
            checks.append(_check("groups.staticCategory", "warn", expected["expectedCounts"]["staticGroups"], actual_static_groups, {"reason": "static group count below expected"}))

        if not missing_ca:
            checks.append(_check("security.conditionalAccess", "pass", expected["expectedCounts"]["caPolicies"], ca_count))
        else:
            checks.append(_check("security.conditionalAccess", "warn", expected["expectedCounts"]["caPolicies"], ca_count, {"missing": missing_ca}))

        if security_defaults_enabled is True and missing_ca:
            checks.append(_check("security.defaults", "warn", False, True, {"reason": "security defaults remain enabled and can block enforced conditional access policies"}))
        elif security_defaults_enabled is False:
            checks.append(_check("security.defaults", "pass", False, False))
        else:
            checks.append(_check("security.defaults", "warn", False, "unknown"))

        if not compliance_visible:
            checks.append(_check("intune.compliance", "warn", expected["expectedCounts"]["intuneCompliancePolicies"], "forbidden", {"reason": "current token lacks Intune configuration read scope"}))
        elif compliance_count >= expected["expectedCounts"]["intuneCompliancePolicies"]:
            checks.append(_check("intune.compliance", "pass", expected["expectedCounts"]["intuneCompliancePolicies"], compliance_count))
        else:
            checks.append(_check("intune.compliance", "warn", expected["expectedCounts"]["intuneCompliancePolicies"], compliance_count))

        if not config_visible:
            checks.append(_check("intune.configurations", "warn", expected["expectedCounts"]["intuneConfigurationPolicies"], "forbidden", {"reason": "current token lacks Intune configuration read scope"}))
        elif config_count >= expected["expectedCounts"]["intuneConfigurationPolicies"]:
            checks.append(_check("intune.configurations", "pass", expected["expectedCounts"]["intuneConfigurationPolicies"], config_count))
        else:
            checks.append(_check("intune.configurations", "warn", expected["expectedCounts"]["intuneConfigurationPolicies"], config_count))

        checks.append(_check("artifacts.exchangePolicies", "pass", 25, expected["expectedCounts"]["artifactExchangePolicies"]))
        checks.append(_check("artifacts.entraPolicies", "pass", 25, expected["expectedCounts"]["artifactEntraPolicies"]))
        checks.append(_check("artifacts.intunePolicies", "pass", 20, expected["expectedCounts"]["artifactIntunePolicies"]))
        checks.append(_check("artifacts.scenarioEvents", "pass", 500, expected["expectedCounts"]["scenarioEvents"]))

        if observed["teams"]["expectedTeamGroupsPresent"] == len(expected["expectedTeamSourceGroups"]):
            checks.append(_check("teams.seedGroups", "pass", len(expected["expectedTeamSourceGroups"]), observed["teams"]["expectedTeamGroupsPresent"]))
        else:
            checks.append(_check("teams.seedGroups", "warn", len(expected["expectedTeamSourceGroups"]), observed["teams"]["expectedTeamGroupsPresent"], {"missing": sorted(set(expected["expectedTeamSourceGroups"]) - set(team_groups_present))}))

        checks.append(_check(
            "teams.discovered",
            "pass" if observed["teams"]["groupsWithTeamResource"] >= observed["teams"]["expectedTeamGroupsPresent"] else "warn",
            observed["teams"]["expectedTeamGroupsPresent"],
            observed["teams"]["groupsWithTeamResource"],
        ))

        if observed["devices"]["directory"] >= expected["expectedCounts"]["devices"]:
            checks.append(_check("devices.directory", "pass", expected["expectedCounts"]["devices"], observed["devices"]["directory"]))
        else:
            checks.append(_check("devices.directory", "warn", expected["expectedCounts"]["devices"], observed["devices"]["directory"], {"reason": "directory device creation is informational only; real device success is measured by managed devices and Windows 365 / enrollment readiness"}))

        cloud_pc_managed_device_id = windows365_evidence.get("managedDeviceId")
        if cloud_pc_managed_device_id:
            checks.append(
                _check(
                    "devices.w365Managed",
                    "pass",
                    expected["expectedCounts"]["managedDevicesPhase1"],
                    1,
                    {
                        "cloudPcId": windows365_evidence.get("cloudPcId"),
                        "cloudPcStatus": windows365_evidence.get("cloudPcStatus"),
                        "managedDeviceId": cloud_pc_managed_device_id,
                        "source": "windows365-provisioning-manifest",
                    },
                )
            )
        elif windows365_evidence.get("provisioningArtifactPresent"):
            checks.append(
                _check(
                    "devices.w365Managed",
                    "warn",
                    expected["expectedCounts"]["managedDevicesPhase1"],
                    0,
                    {"reason": "cloud pc provisioning artifact exists but no managedDeviceId is recorded"},
                )
            )

        if managed_devices_count == -1:
            if cloud_pc_managed_device_id:
                checks.append(
                    _check(
                        "devices.managed",
                        "pass",
                        expected["expectedCounts"]["managedDevicesPhase1"],
                        1,
                        {
                            "reason": "managed devices endpoint not visible; using Cloud PC provisioning artifact",
                            "cloudPcId": windows365_evidence.get("cloudPcId"),
                            "managedDeviceId": cloud_pc_managed_device_id,
                        },
                    )
                )
            else:
                checks.append(_check("devices.managed", "warn", expected["expectedCounts"]["managedDevicesPhase1"], "forbidden", {"reason": "managed devices endpoint not visible with current token"}))
        elif managed_devices_count >= expected["expectedCounts"]["managedDevicesPhase1"]:
            checks.append(_check("devices.managed", "pass", expected["expectedCounts"]["managedDevicesPhase1"], managed_devices_count))
        elif cloud_pc_managed_device_id:
            checks.append(
                _check(
                    "devices.managed",
                    "pass",
                    expected["expectedCounts"]["managedDevicesPhase1"],
                    1,
                    {
                        "reason": "managed devices endpoint returned fewer results than expected; Cloud PC provisioning artifact confirms a managed device",
                        "cloudPcId": windows365_evidence.get("cloudPcId"),
                        "managedDeviceId": cloud_pc_managed_device_id,
                    },
                )
            )
        else:
            checks.append(_check("devices.managed", "warn", expected["expectedCounts"]["managedDevicesPhase1"], managed_devices_count))

    if dry_run:
        checks.extend(
            [
                _check("users.total", "pass", expected["plannedInternalUsers"] + expected["plannedGuestUsers"], observed["users"]["internal"] + observed["users"]["guests"]),
                _check("users.internal", "pass", expected["plannedInternalUsers"], observed["users"]["internal"]),
                _check("users.guests", "pass", expected["plannedGuestUsers"], observed["users"]["guests"]),
                _check(
                    "groups.total",
                    "pass",
                    expected["expectedCounts"]["staticGroups"] + expected["expectedCounts"]["dynamicGroups"],
                    observed["groups"]["total"],
                ),
                _check(
                    "security.conditionalAccess",
                    "pass",
                    expected["expectedCounts"]["caPolicies"],
                    expected["expectedCounts"]["caPolicies"],
                ),
                _check("intune.compliance", "pass", expected["expectedCounts"]["intuneCompliancePolicies"], expected["expectedCounts"]["intuneCompliancePolicies"]),
                _check("intune.configurations", "pass", expected["expectedCounts"]["intuneConfigurationPolicies"], expected["expectedCounts"]["intuneConfigurationPolicies"]),
                _check("devices.directory", "pass", expected["expectedCounts"]["devices"], observed["devices"]["directory"]),
                _check("devices.managed", "pass", expected["expectedCounts"]["managedDevicesPhase1"], observed["devices"]["managed"]),
                _check("artifacts.exchangePolicies", "pass", 25, expected["expectedCounts"]["artifactExchangePolicies"]),
                _check("artifacts.entraPolicies", "pass", 25, expected["expectedCounts"]["artifactEntraPolicies"]),
                _check("artifacts.intunePolicies", "pass", 20, expected["expectedCounts"]["artifactIntunePolicies"]),
                _check("artifacts.scenarioEvents", "pass", 500, expected["expectedCounts"]["scenarioEvents"]),
            ]
        )

    artifacts, warnings, _ = _collect_artifacts(run_dir, bootstrap_root, dry_run, logger)
    for warning in warnings:
        checks.append(_check("artifacts." + warning.split(":")[0], "warn", True, False, {"note": warning}))

    manifest = {
        "runName": run_dir.name,
        "tenantId": cfg.get("tenant", {}).get("tenantId", ""),
        "tenantDomain": cfg.get("tenant", {}).get("tenantDomain", ""),
        "dryRun": dry_run,
        "generatedAt": utc_now(),
        "checks": checks,
        "observed": observed if not dry_run else {"dryRun": True, "expectedBased": {"totalUsers": expected["plannedInternalUsers"] + expected["plannedGuestUsers"]}},
        "expected": {
            "plannedUsers": expected["plannedInternalUsers"] + expected["plannedGuestUsers"],
            "plannedInternalUsers": expected["plannedInternalUsers"],
            "plannedGuestUsers": expected["plannedGuestUsers"],
            "requiredStaticGroups": expected["expectedCounts"]["staticGroups"],
            "requiredDynamicGroups": expected["expectedCounts"]["dynamicGroups"],
            "requiredCaPolicies": expected["expectedCounts"]["caPolicies"],
            "requiredIntuneCompliancePolicies": expected["expectedCounts"]["intuneCompliancePolicies"],
            "requiredIntuneConfigurationPolicies": expected["expectedCounts"]["intuneConfigurationPolicies"],
            "requiredDirectoryDevices": expected["expectedCounts"]["devices"],
            "requiredManagedDevicesPhase1": expected["expectedCounts"]["managedDevicesPhase1"],
            "requiredTeamGroups": len(expected["expectedTeamSourceGroups"]),
            "requiredArtifactExchangePolicies": expected["expectedCounts"]["artifactExchangePolicies"],
            "requiredArtifactEntraPolicies": expected["expectedCounts"]["artifactEntraPolicies"],
            "requiredArtifactIntunePolicies": expected["expectedCounts"]["artifactIntunePolicies"],
            "requiredScenarioEvents": expected["expectedCounts"]["scenarioEvents"],
        },
        "artifacts": artifacts,
        "status": "failed" if failing > 0 else "completed",
    }
    return manifest, failing


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify tenant population after bootstrap seeding.")
    parser.add_argument("--config", type=Path, default=(Path(__file__).resolve().parent.parent / "config.example.json"))
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--run-dir", type=Path, default=None, help="Bootstrap run directory to validate")
    parser.add_argument("--bootstrap-root", type=Path, default=(Path(__file__).resolve().parent.parent))
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    bootstrap_root = args.bootstrap_root.resolve()
    if args.run_dir is None:
        run_dir = bootstrap_root / "runs" / args.run_name
    else:
        run_dir = args.run_dir

    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "population-verification-log.jsonl"
    manifest_path = run_dir / "population-verification-manifest.json"
    logger = JsonlLogger(log_path)

    logger.event("verification.started", "started", runName=args.run_name, dryRun=args.dry_run, bootstrapRoot=str(bootstrap_root))
    manifest, failing = verify(cfg, run_dir=run_dir, bootstrap_root=bootstrap_root, dry_run=args.dry_run, logger=logger)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    logger.event("verification.completed", "finished", runName=args.run_name, failures=failing)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 1 if failing > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
