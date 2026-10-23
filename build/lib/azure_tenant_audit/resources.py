from __future__ import annotations

import json
import os
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .shipped_content import SHIPPED_CONTENT_AREAS, shipped_directories


RESOURCE_ROOT_ENV = "AUDITEX_RESOURCE_ROOT"


@dataclass(frozen=True)
class ResourceAdapter:
    name: str
    root: Path

    def resolve(self, path: str | Path) -> Path | None:
        candidate = self.root / Path(path)
        if candidate.exists():
            return candidate
        return None

    def list_files(self, directory: str | Path, pattern: str = "*") -> list[Path]:
        root = self.resolve(directory)
        if root is None or not root.is_dir():
            return []
        return sorted(path for path in root.glob(pattern) if path.is_file())


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _looks_like_dev_root(root: Path) -> bool:
    return (root / "pyproject.toml").exists() and any((root / directory).exists() for directory in shipped_directories())


def _looks_like_installed_root(root: Path) -> bool:
    return any((root / directory).exists() for directory in shipped_directories())


def _unique_paths(paths: list[Path]) -> list[Path]:
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        expanded = path.expanduser()
        key = str(expanded.resolve() if expanded.exists() else expanded)
        if key not in seen:
            seen.add(key)
            unique.append(expanded)
    return unique


def _resource_adapters() -> list[ResourceAdapter]:
    adapters: list[ResourceAdapter] = []
    configured = os.environ.get(RESOURCE_ROOT_ENV)
    if configured:
        adapters.append(ResourceAdapter("env", Path(configured).expanduser()))

    cwd = Path.cwd()
    dev_candidates = _unique_paths([cwd, *cwd.parents, _repo_root()])
    adapters.extend(ResourceAdapter("dev", root) for root in dev_candidates if _looks_like_dev_root(root))

    installed_candidates: list[Path] = []
    data_path = sysconfig.get_paths().get("data")
    if data_path:
        installed_candidates.append(Path(data_path) / "auditex")
    installed_candidates.extend([Path(sys.prefix) / "auditex", Path(sys.base_prefix) / "auditex"])
    adapters.extend(
        ResourceAdapter("installed", root)
        for root in _unique_paths(installed_candidates)
        if _looks_like_installed_root(root)
    )
    return adapters


def _candidate_roots() -> list[Path]:
    return [adapter.root for adapter in _resource_adapters()]


def resolve_resource_path(path: str | Path) -> Path:
    target = Path(path).expanduser()
    if target.is_absolute():
        return target

    for adapter in _resource_adapters():
        candidate = adapter.resolve(target)
        if candidate is not None:
            return candidate

    return _repo_root() / target


def open_text_resource(path: str | Path) -> str:
    return resolve_resource_path(path).read_text(encoding="utf-8")


def load_json_resource(path: str | Path, *, default: Any) -> Any:
    target = resolve_resource_path(path)
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, ValueError):
        return default


def list_resource_files(directory: str | Path, pattern: str = "*") -> list[Path]:
    for adapter in _resource_adapters():
        files = adapter.list_files(directory, pattern)
        if files:
            return files
    root = resolve_resource_path(directory)
    if root.exists() and root.is_dir():
        return sorted(path for path in root.glob(pattern) if path.is_file())
    return []


def shipped_resource_manifest() -> dict[str, Any]:
    resources: list[str] = []
    for area in SHIPPED_CONTENT_AREAS:
        for pattern in area.package_patterns:
            directory, _, file_pattern = pattern.rpartition("/")
            for path in list_resource_files(directory or ".", file_pattern or "*"):
                resources.append(f"{directory}/{path.name}" if directory else path.name)
    return {
        "areas": [area.directory for area in SHIPPED_CONTENT_AREAS],
        "resources": sorted(dict.fromkeys(resources)),
    }
