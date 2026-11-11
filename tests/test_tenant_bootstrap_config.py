from __future__ import annotations

import json
from pathlib import Path

CONFIG_PATH = Path("tenant-bootstrap/config.example.json")


def _load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _generated_internal_aliases(cfg: dict) -> set[str]:
    aliases = {
        cfg["actors"]["dailyUser"],
        cfg["actors"]["namedAdmin"],
        *cfg["actors"]["breakGlassUsers"],
    }
    for department, count in cfg["departmentDistribution"].items():
        prefix = department.lower()
        for index in range(1, count + 1):
            aliases.add(f"{prefix}.{index:02d}.staff")
    return aliases


def _enterprise_static_group_count(cfg: dict) -> int:
    profile = cfg["enterpriseScale"]["profile"]
    department_count = len(cfg["departments"])
    function_count = len(cfg["enterpriseScale"]["functionFamilies"])
    core_group_count = len(cfg["groupNames"])
    return (
        core_group_count
        + profile["departmentSecurityGroupsPerDepartment"] * department_count
        + profile["departmentM365GroupsPerDepartment"] * department_count
        + profile["departmentServiceGroupsPerDepartment"] * department_count
        + profile["functionGroupsPerFunction"] * function_count
        + profile["resourceOwnerGroups"]
        + profile["policyAndProgramGroups"]
        + profile["overshareSignalGroups"]
        + profile["geoRegionGroups"]
    )


def test_bootstrap_actor_aliases_match_generated_users() -> None:
    cfg = _load_config()
    aliases = _generated_internal_aliases(cfg)

    for alias in cfg["actors"]["copilotPilotUsers"] + cfg["actors"]["reportingUsers"]:
        assert alias in aliases


def test_bootstrap_counts_match_user_distribution() -> None:
    cfg = _load_config()
    expected_internal = (
        2
        + len(cfg["actors"]["breakGlassUsers"])
        + sum(cfg["departmentDistribution"].values())
    )

    assert cfg["counts"]["targetEmployeeUsers"] == expected_internal
    assert cfg["counts"]["targetGuests"] >= 4


def test_bootstrap_enterprise_group_model_exceeds_200_groups() -> None:
    cfg = _load_config()
    dynamic_count = 4 + len(cfg["departments"]) + 9

    assert cfg["enterpriseScale"]["enabled"] is True
    assert _enterprise_static_group_count(cfg) >= 200
    assert dynamic_count >= 20
