from __future__ import annotations

from typing import Any

ADAPTER_CAPABILITY_REGISTRY: dict[str, dict[str, Any]] = {
    "m365_cli": {
        "supported_auth_modes": ["delegated", "saved_context"],
        "required_tools": ["m365"],
        "supported_profiles": ["exchange-reader", "global-reader", "security-reader", "auto"],
        "supported_actions": ["probe", "exchange_inventory", "response_readiness"],
        "write_risk": "read_verb_allowlist",
        "expected_commands": ["m365 status --output json", "m365 connection list --output json"],
    },
    "m365dsc": {
        "supported_auth_modes": ["delegated", "app"],
        "required_tools": ["pwsh", "Microsoft365DSC"],
        "supported_profiles": ["app-readonly-full", "global-reader", "auto"],
        "supported_actions": ["configuration_export"],
        "write_risk": "read_verb_allowlist_export_only",
        "expected_commands": ["Export-M365DSCConfiguration"],
    },
    "powershell_graph": {
        "supported_auth_modes": ["delegated", "app", "saved_context"],
        "required_tools": ["pwsh", "Microsoft.Graph"],
        "supported_profiles": ["security-reader", "global-reader", "app-readonly-full", "auto"],
        "supported_actions": ["graph_command", "exchange_probe"],
        "write_risk": "read_verb_allowlist",
        "expected_commands": ["Get-*", "Search-UnifiedAuditLog"],
    },
}


def capability_for_adapter(name: str) -> dict[str, Any]:
    return dict(ADAPTER_CAPABILITY_REGISTRY.get(name, {}))
