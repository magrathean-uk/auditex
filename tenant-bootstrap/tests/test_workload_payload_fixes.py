from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_team_body_targets_group_binding_flow():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    body = workload.build_team_body("12345678-1234-1234-1234-1234567890ab")

    assert body == {}


def test_ca_policy_normalizer_removes_empty_controls_and_placeholders():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    payload = {
        "displayName": "CA-ReportOnly-01-Legacy-First",
        "state": "reportOnly",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeGroups": [""]},
            "applications": {"includeApplications": ["All"]},
            "platforms": {"includePlatforms": ["all"]},
            "clientAppTypes": ["all"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        "sessionControls": {},
    }

    normalized = workload._normalize_ca_policy(payload)

    assert "sessionControls" not in normalized
    assert "excludeGroups" not in normalized["conditions"]["users"]
    assert normalized["state"] == "enabledForReportingButNotEnforced"
    assert normalized["conditions"]["users"]["includeUsers"] == ["All"]


def test_intune_sanitizer_adds_required_scheduled_action_and_drops_invalid_fields():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    compliance = {
        "@odata.type": "#microsoft.graph.windows10CompliancePolicy",
        "displayName": "Seed-Windows-11-Compliance-Strict",
        "passwordRequired": True,
        "earlyLaunchAntimalwareDriverEnabled": True,
    }
    configuration = {
        "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
        "displayName": "Seed-Windows-11-DeviceConfig",
        "edgeSearchEngine": "bing",
        "passwordBlockSimple": True,
        "passwordMinimumLength": 12,
    }

    cleaned_compliance = workload._sanitize_intune_policy(compliance)
    cleaned_configuration = workload._sanitize_intune_policy(configuration)

    scheduled = cleaned_compliance["scheduledActionsForRule"]
    assert len(scheduled) == 1
    assert scheduled[0]["scheduledActionConfigurations"][0]["actionType"] == "block"
    assert "earlyLaunchAntimalwareDriverEnabled" not in cleaned_compliance
    assert "edgeSearchEngine" not in cleaned_configuration
    assert "passwordMinimumLength" not in cleaned_configuration
    assert "passwordBlockSimple" not in cleaned_configuration


def test_exchange_command_builder_routes_exchange_cmdlets_through_powershell():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    command = workload._build_exchange_command(
        "New-SafeLinksPolicy -Name DEF-Standard-SafeLinks",
        m365_executable="/usr/local/bin/m365",
        pwsh_executable="/usr/local/bin/pwsh",
    )

    assert command[:3] == ["/usr/local/bin/pwsh", "-NoLogo", "-NoProfile"]
    assert "New-SafeLinksPolicy -Name DEF-Standard-SafeLinks" in command[-1]


def test_exchange_policy_error_classification():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    assert workload._classify_exchange_policy_error(
        return_code=1,
        stdout="",
        stderr="Command \"m365 defender anti-phishing policy list\" was not found.",
        command_type="m365",
    ) == "unsupported-m365-command"

    assert workload._classify_exchange_policy_error(
        return_code=1,
        stdout="",
        stderr="The term 'New-SafeLinksPolicy' is not recognized as the name of a cmdlet, function, script file, or operable program.",
        command_type="powershell",
    ) == "unsupported-powershell-cmdlet"


def test_exchange_policy_runner_marks_supported_failures_as_skipped_and_not_failed(tmp_path, monkeypatch):
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = "Command \"m365 defender anti-phishing policy list\" was not found."

    def fake_run(*args, **kwargs):
        return FakeResult()

    monkeypatch.setattr(workload.shutil, "which", lambda name: "/usr/local/bin/m365" if name == "m365" else "/usr/local/bin/pwsh")
    monkeypatch.setattr(workload.subprocess, "run", fake_run)

    logger = workload.JsonlLogger(tmp_path / "workload.log")
    debug = workload.DebugLogger(tmp_path / "workload-debug.log")
    cfg = {"tenant": {"tenantDomain": "tenant.domain"}}
    policies = [{"name": "unsupported", "commands": ["m365 defender anti-phishing policy list --output json"]}]

    planned, executed, failed, results = workload._run_exchange_policy_commands(
        logger,
        debug,
        cfg,
        policies,
        dry_run=False,
    )

    assert planned == 1
    assert executed == 1
    assert failed == 0
    assert len(results) == 1
    assert results[0]["status"] == "skipped"
    assert results[0]["reason"] == "unsupported-m365-command"
    assert results[0]["returnCode"] == 1


def test_mdm_artifact_includes_managed_targets_and_windows365_plan():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")
    cfg = json.loads((ROOT / "config.enterprise-lab-max.json").read_text(encoding="utf-8"))

    artifact = workload._build_mdm_enrollment_plan(cfg, workload.build_device_inventory(cfg))

    assert artifact["summary"]["plannedDevices"] == 100
    assert artifact["summary"]["managedTargets"]["phase1"] == 1
    assert artifact["summary"]["managedTargets"]["phase2"] >= 10
    assert artifact["windows365"]["enabled"] is True
    assert artifact["windows365"]["pilotUserAlias"] == "daily.user"


def test_windows365_policy_payload_targets_azure_ad_join_region():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")
    cfg = json.loads((ROOT / "config.enterprise-lab-max.json").read_text(encoding="utf-8"))

    plan = workload.build_windows365_plan(cfg)
    payload = workload._build_windows365_policy_payload(plan)

    assert payload["displayName"] == "W365-Enterprise-Pilot"
    assert payload["cloudPcNamingTemplate"] == "CPC-%USERNAME:4%"
    assert payload["imageType"] == "gallery"
    assert payload["provisioningType"] == "dedicated"
    assert payload["domainJoinConfigurations"] == [{"domainJoinType": "azureADJoin", "regionName": "eastus"}]


def test_windows365_assignment_payload_targets_single_group():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    payload = workload._build_windows365_assignment_payload("group-123")

    assert payload == {
        "assignments": [
            {
                "target": {
                    "@odata.type": "microsoft.graph.cloudPcManagementGroupAssignmentTarget",
                    "groupId": "group-123",
                }
            }
        ]
    }


def test_intune_endpoint_resolver_covers_app_protection_and_device_categories():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    assert workload._endpoint_for_intune_policy({"@odata.type": "#microsoft.graph.deviceCategory"}) == "/deviceManagement/deviceCategories"
    assert workload._endpoint_for_intune_policy({"@odata.type": "#microsoft.graph.iosManagedAppProtection"}) == "/deviceAppManagement/iosManagedAppProtections"
    assert workload._endpoint_for_intune_policy({"@odata.type": "#microsoft.graph.androidManagedAppProtection"}) == "/deviceAppManagement/androidManagedAppProtections"


def test_intune_permission_denied_classifier_covers_device_categories_and_app_management():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    assert workload._is_intune_permission_denied("Request returned error: Forbidden", endpoint="/deviceManagement/deviceCategories")
    assert workload._is_intune_permission_denied(
        "Request returned error: Access to this resource is forbidden",
        endpoint="https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections",
    )
    assert not workload._is_intune_permission_denied("DeviceManagementPolicy.ReadWrite.All missing consent", endpoint="/deviceManagement/deviceConfigurations")


def test_intune_sanitizer_strips_read_only_fields_from_app_protection():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    policy = {
        "@odata.type": "#microsoft.graph.iosManagedAppProtection",
        "displayName": "Seed-iOS-AppProtection",
        "id": "abc",
        "version": "3",
        "createdDateTime": "2026-04-16T00:00:00Z",
        "lastModifiedDateTime": "2026-04-16T00:00:00Z",
        "isAssigned": False,
        "deployedAppCount": 0,
    }

    cleaned = workload._sanitize_intune_policy(policy)

    for field in ["id", "version", "createdDateTime", "lastModifiedDateTime", "isAssigned", "deployedAppCount"]:
        assert field not in cleaned
