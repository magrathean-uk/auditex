from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .resources import resolve_resource_path

DEFAULT_PRESETS_PATH = Path("configs/collector-presets.json")


def load_collector_presets(path: Path | None = None) -> dict[str, dict[str, Any]]:
    target = resolve_resource_path(path or DEFAULT_PRESETS_PATH)
    payload = json.loads(target.read_text(encoding="utf-8"))
    presets = payload.get("presets", {})
    if not isinstance(presets, dict):
        return {}
    normalized: dict[str, dict[str, Any]] = {}
    for name, value in sorted(presets.items()):
        if not isinstance(value, dict):
            continue
        normalized[str(name)] = {
            "description": value.get("description", ""),
            "include": _normalize_names(value.get("include")),
            "exclude": _normalize_names(value.get("exclude")),
            "plane": value.get("plane"),
        }
    return normalized


def resolve_collector_selection(
    *,
    available: list[str],
    profile_default_collectors: tuple[str, ...],
    preset_name: str | None = None,
    presets: dict[str, dict[str, Any]] | None = None,
    explicit_collectors: list[str] | None = None,
    excluded_collectors: list[str] | None = None,
) -> list[str]:
    presets = presets or {}
    explicit_collectors = _normalize_names(explicit_collectors)
    excluded_collectors = _normalize_names(excluded_collectors)

    if explicit_collectors:
        base = explicit_collectors
    elif preset_name:
        preset = presets.get(preset_name)
        if preset is None:
            raise ValueError(f"Unknown collector preset '{preset_name}'.")
        include = _normalize_names(preset.get("include"))
        preset_exclude = set(_normalize_names(preset.get("exclude")))
        base = [name for name in include if name not in preset_exclude]
    else:
        base = _normalize_names(profile_default_collectors)

    available_set = set(available)
    resolved = [name for name in base if name in available_set and name not in set(excluded_collectors)]
    resolved = list(dict.fromkeys(resolved))
    if not resolved:
        if preset_name:
            raise ValueError(f"Collector preset '{preset_name}' resolved to no runnable collectors.")
        raise ValueError("No collectors selected.")
    return resolved


def _normalize_names(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return []
    normalized: list[str] = []
    for item in values:
        if item is None:
            continue
        value = str(item).strip()
        if value:
            normalized.append(value)
    return normalized
