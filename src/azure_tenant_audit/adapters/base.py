from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AdapterMetadata:
    name: str
    auth_requirements: tuple[str, ...]
    tool_dependencies: tuple[str, ...]


class Adapter:
    metadata: AdapterMetadata

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def auth_requirements(self) -> tuple[str, ...]:
        return self.metadata.auth_requirements

    @property
    def tool_dependencies(self) -> tuple[str, ...]:
        return self.metadata.tool_dependencies

    def dependency_check(self) -> bool:
        raise NotImplementedError

    def run(self, command: str, log_event: Callable[[str, str, dict[str, Any] | None], None] | None = None) -> dict[str, Any]:
        raise NotImplementedError
