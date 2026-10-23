from __future__ import annotations

from .base import Adapter
from .m365_cli import M365CLIAdapter
from .m365dsc import M365DSCAdapter
from .powershell_graph import PowerShellGraphAdapter
from .capabilities import capability_for_adapter

ADAPTERS: dict[str, Adapter] = {
    "m365_cli": M365CLIAdapter(),
    "m365dsc": M365DSCAdapter(),
    "powershell_graph": PowerShellGraphAdapter(),
}


def get_adapter(name: str) -> Adapter:
    return ADAPTERS[name]


def list_adapters() -> list[dict[str, object]]:
    """Return lightweight metadata for all configured adapters."""

    return [
        {
            "name": adapter.name,
            "class": adapter.__class__.__name__,
            "auth_requirements": list(adapter.auth_requirements),
            "tool_dependencies": list(adapter.tool_dependencies),
            "dependency_available": bool(adapter.dependency_check()),
            **capability_for_adapter(adapter.name),
        }
        for adapter in ADAPTERS.values()
    ]
