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


def test_enterprise_lab_max_identity_shape_is_large_and_deterministic():
    identity = load_module(ROOT / "scripts" / "identity_seed_az.py")
    cfg = load_enterprise_cfg()

    users = identity.build_users(cfg)
    groups = identity.build_groups(cfg)
    dynamic_groups = identity.build_dynamic_groups(cfg)

    assert len([user for user in users if not user.is_guest]) == 96
    assert len([user for user in users if user.is_guest]) == 12
    assert len(groups) >= 600
    assert len(dynamic_groups) >= 60
    assert users[0].alias == "daily.user"
    assert groups[0].display_name == "GG-L0-AllUsers"


def test_enterprise_lab_max_workload_shape_plans_dense_policies_and_devices():
    workload = load_module(ROOT / "scripts" / "seed-workload-az.py")
    cfg = load_enterprise_cfg()

    devices = workload.build_device_inventory(cfg)
    scenarios = workload.build_scenario_plan(cfg)
    policy_plan = workload.build_policy_artifact_plan(ROOT)

    assert len(devices) == 100
    assert sum(1 for device in devices if device["platform"] == "windows11") == 72
    assert sum(1 for device in devices if device["platform"] == "macos") == 10
    assert sum(1 for device in devices if device["platform"] == "ios") == 12
    assert sum(1 for device in devices if device["platform"] == "android") == 6
    assert len(scenarios["plannedEvents"]) >= 500
    assert policy_plan["counts"]["exchange"] >= 25
    assert policy_plan["counts"]["entra"] >= 25
    assert policy_plan["counts"]["intune"] >= 20
