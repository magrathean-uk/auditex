from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .collectors import REGISTRY
from .config import CollectorConfig, CollectorDefinition
from .presets import load_collector_presets
from .profiles import PROFILES, AuditProfile
from .resources import load_json_resource


@dataclass(frozen=True)
class AuditCatalog:
    collectors: dict[str, CollectorDefinition]
    default_order: list[str]
    registry: dict[str, Any]
    permissions: dict[str, dict[str, Any]]
    presets: dict[str, Any]
    profiles: dict[str, AuditProfile]

    def validate(self) -> list[str]:
        issues: list[str] = []
        registry_names = set(self.registry)
        config_names = set(self.collectors)
        permission_names = set(self.permissions)
        order_names = set(self.default_order)

        for name in sorted(registry_names - config_names):
            issues.append(f"collector_missing_definition:{name}")
        for name in sorted(config_names - registry_names):
            issues.append(f"definition_missing_collector:{name}")
        for name in sorted(registry_names - permission_names):
            issues.append(f"collector_missing_permission_hints:{name}")
        for name in sorted(permission_names - registry_names):
            issues.append(f"permission_hints_missing_collector:{name}")
        for name in sorted(registry_names - order_names):
            issues.append(f"collector_missing_default_order:{name}")
        for name in sorted(order_names - registry_names):
            issues.append(f"default_order_missing_collector:{name}")

        for profile_name, profile in self.profiles.items():
            for collector_name in profile.default_collectors:
                if collector_name not in registry_names:
                    issues.append(f"profile_unknown_collector:{profile_name}:{collector_name}")

        for preset_name, preset in self.presets.items():
            collectors = []
            if isinstance(preset, dict):
                collectors = list(preset.get("include") or []) + list(preset.get("exclude") or [])
            for collector_name in collectors:
                if str(collector_name) not in registry_names:
                    issues.append(f"preset_unknown_collector:{preset_name}:{collector_name}")

        return issues


def _load_permissions() -> dict[str, dict[str, Any]]:
    payload = load_json_resource("configs/collector-permissions.json", default={})
    raw = payload.get("collector_permissions") if isinstance(payload, dict) else {}
    if not isinstance(raw, dict):
        return {}
    return {str(name): dict(value) if isinstance(value, dict) else {} for name, value in raw.items()}


def load_catalog() -> AuditCatalog:
    config = CollectorConfig.from_path("configs/collector-definitions.json")
    return AuditCatalog(
        collectors=config.collectors,
        default_order=config.default_order,
        registry=dict(REGISTRY),
        permissions=_load_permissions(),
        presets=load_collector_presets(),
        profiles=dict(PROFILES),
    )
