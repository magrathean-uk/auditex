from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .resources import resolve_resource_path
from .selection import select_collectors


@dataclass
class AuthConfig:
    tenant_id: str
    client_id: str | None
    auth_mode: str = "app"
    client_secret: Optional[str] = None
    access_token: Optional[str] = None
    authority: str = "https://login.microsoftonline.com/"
    graph_scope: str = "https://graph.microsoft.com/.default"
    interactive_scopes: Optional[list[str]] = None
    timeout_seconds: int = 60
    throttle_mode: str = "safe"


@dataclass
class RunConfig:
    tenant_name: str
    output_dir: Path
    collectors: Optional[list[str]] = None
    excluded_collectors: Optional[list[str]] = None
    include_exchange: bool = False
    offline: bool = False
    sample_path: Optional[Path] = None
    run_name: Optional[str] = None
    top_items: Optional[int] = None
    page_size: int = 100
    auditor_profile: str = "auto"
    default_collectors: tuple[str, ...] = ()
    plane: str = "inventory"
    since: Optional[str] = None
    until: Optional[str] = None

    def selected_collectors(self, available: Iterable[str]) -> list[str]:
        return select_collectors(
            available=available,
            profile_default_collectors=self.default_collectors,
            explicit_collectors=self.collectors,
            excluded_collectors=self.excluded_collectors,
            include_exchange=self.include_exchange,
        )


@dataclass
class CollectorDefinition:
    collector_id: str
    description: str
    enabled: bool
    required_permissions: list[str]
    query_plan: list[str]
    command_collectors: Optional[list[dict]] = None


@dataclass
class CollectorConfig:
    collectors: dict[str, CollectorDefinition]
    default_order: list[str]

    @classmethod
    def from_path(cls, path: str | Path) -> "CollectorConfig":
        target = resolve_resource_path(path)
        payload = json.loads(target.read_text(encoding="utf-8"))
        collectors = {
            key: CollectorDefinition(
                collector_id=key,
                description=value.get("description", ""),
                enabled=bool(value.get("enabled", False)),
                required_permissions=value.get("required_permissions", []),
                query_plan=value.get("query_plan", []),
                command_collectors=value.get("command_collectors"),
            )
            for key, value in payload.get("collectors", {}).items()
        }
        return cls(collectors=collectors, default_order=payload.get("default_order", list(collectors.keys())))
