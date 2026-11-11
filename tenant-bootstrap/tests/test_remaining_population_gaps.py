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


def load_enterprise_cfg() -> dict:
    return json.loads((ROOT / "config.enterprise-lab-max.json").read_text(encoding="utf-8"))


def test_identity_graph_client_prefers_env_token(monkeypatch):
    identity = load_module(ROOT / "scripts" / "identity_seed_az.py")
    logger = identity.JsonlLogger(Path("/tmp/identity-seed-test.jsonl"))

    monkeypatch.setenv("AZURE_ACCESS_TOKEN", "env-token")

    client = identity.GraphClient(logger, dry_run=False)

    assert client.session.headers["Authorization"] == "Bearer env-token"


def test_guest_invitation_payload_targets_external_email():
    identity = load_module(ROOT / "scripts" / "identity_seed_az.py")
    cfg = load_enterprise_cfg()
    guest = identity.UserDef("guest.1.partner", "Partner Guest 1", "External", "Contractor", True)

    payload = identity.build_guest_invitation_payload(cfg, guest)

    assert payload["invitedUserDisplayName"] == "Partner Guest 1"
    assert payload["inviteRedirectUrl"] == "https://myapplications.microsoft.com"
    assert payload["sendInvitationMessage"] is False
    assert payload["invitedUserEmailAddress"].startswith("guest.1.partner@")


def test_security_defaults_toggle_payload_can_disable_defaults():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")

    payload = workload.build_security_defaults_payload(False)

    assert payload == {"isEnabled": False}


def test_lab_populator_permissions_include_team_create():
    permissions = json.loads((ROOT / "configs" / "lab-populator-permissions.json").read_text(encoding="utf-8"))

    assert "Team.Create" in permissions["applicationPermissions"]
    assert "CloudPC.ReadWrite.All" in permissions["delegatedPermissions"]
    assert "DeviceManagementServiceConfig.ReadWrite.All" in permissions["applicationPermissions"]


def test_enterprise_config_defines_windows365_phase1_targets():
    cfg = load_enterprise_cfg()

    assert cfg["devices"]["managedTargetPhase1"] == 1
    assert cfg["devices"]["managedTargetPhase2"] >= 10
    assert cfg["devices"]["managedTargetFinal"] >= cfg["devices"]["managedTargetPhase2"]
    assert cfg["windows365"]["enabled"] is True
    assert cfg["windows365"]["phase1PilotUser"] == "daily.user"
    assert cfg["licenses"]["cloudPcEnterprise"]


def test_windows365_plan_prefers_enterprise_sku_for_phase1():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")
    cfg = load_enterprise_cfg()

    plan = workload.build_windows365_plan(cfg)

    assert plan["enabled"] is True
    assert plan["managedDeviceTarget"] == 1
    assert plan["pilotUserAlias"] == "daily.user"
    assert plan["preferredSkuPattern"] == cfg["licenses"]["cloudPcEnterprise"]
    assert plan["fallbackSkuPattern"] == cfg["licenses"]["cloudPcBusiness"]


def test_windows365_plan_exposes_policy_defaults_for_enterprise_pilot():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")
    cfg = load_enterprise_cfg()

    plan = workload.build_windows365_plan(cfg)

    assert plan["policyDisplayName"] == "W365-Enterprise-Pilot"
    assert plan["pilotGroupName"] == "GG-W365-Enterprise-Pilot"
    assert plan["regionName"] == "eastus"
    assert plan["imageType"] == "gallery"
    assert plan["provisioningType"] == "dedicated"


def test_managed_device_target_defaults_to_phase1():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")
    cfg = load_enterprise_cfg()

    assert workload.resolve_managed_device_target(cfg) == 1
    assert workload.resolve_managed_device_target(cfg, phase="phase2") >= 10


def test_intune_collector_definitions_include_windows365_queries():
    defs = json.loads((ROOT / "configs" / "collector-definitions.json").read_text(encoding="utf-8"))

    assert "cloudPCs" in defs["collectors"]["intune"]["query_plan"]
    assert "provisioningPolicies" in defs["collectors"]["intune"]["query_plan"]
    assert "deviceCategories" in defs["collectors"]["intune"]["query_plan"]
    assert "iosManagedAppProtections" in defs["collectors"]["intune"]["query_plan"]
    assert "deviceEnrollmentConfigurations" in defs["collectors"]["intune"]["query_plan"]


def test_verifier_expected_counts_include_phase1_managed_device_target():
    verify = load_module(ROOT / "scripts" / "verify-population-az.py")
    cfg = load_enterprise_cfg()

    expected = verify._load_expected_definitions(cfg, ROOT / "scripts", ROOT / "policies")

    assert expected["expectedCounts"]["managedDevicesPhase1"] == 1
    assert expected["expectedCounts"]["intuneCompliancePolicies"] == 6
    assert expected["expectedCounts"]["intuneConfigurationPolicies"] == 4


def test_windows365_provisioning_artifact_exposes_managed_device_evidence(tmp_path):
    verify = load_module(ROOT / "scripts" / "verify-population-az.py")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "windows365-provisioning-manifest.json").write_text(
        json.dumps(
            {
                "cloudPc": {
                    "cloudPc": {
                        "id": "cloudpc-123",
                        "status": "provisioned",
                        "managedDeviceId": "managed-device-456",
                    },
                    "pollState": "found",
                }
            }
        ),
        encoding="utf-8",
    )

    evidence = verify._resolve_windows365_managed_device_evidence(run_dir)

    assert evidence["provisioningArtifactPresent"] is True
    assert evidence["cloudPcId"] == "cloudpc-123"
    assert evidence["cloudPcStatus"] == "provisioned"
    assert evidence["managedDeviceId"] == "managed-device-456"


def test_audit_graph_client_get_all_accepts_full_urls():
    sys.path.insert(0, str(ROOT))
    from azure_tenant_audit import config, graph  # type: ignore

    client = graph.GraphClient(config.AuthConfig(tenant_id="tenant", client_id=None, access_token="token"))
    calls = []

    def fake_get_json(path, params=None, full_url=False):
        calls.append({"path": path, "full_url": full_url})
        return {"value": []}

    client.get_json = fake_get_json  # type: ignore[method-assign]

    client.get_all("https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs")

    assert calls[0]["path"] == "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs"
    assert calls[0]["full_url"] is True
