from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .features import response_enabled


Handler = Callable[..., dict[str, Any]]


@dataclass(frozen=True)
class McpToolEntry:
    name: str
    description: str
    read_only_hint: bool

    @property
    def annotations(self) -> dict[str, bool]:
        return {"readOnlyHint": self.read_only_hint}

    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "readOnlyHint": self.read_only_hint,
        }


TOOL_REGISTRY: tuple[McpToolEntry, ...] = (
    McpToolEntry(
        name="auditex_list_collectors",
        description="List Microsoft 365 or Google Workspace collector IDs, required permissions, and query plans.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_adapters",
        description="List configured adapters and their dependency requirements.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_response_actions",
        description="List guarded response actions exposed by the response plane.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_profiles",
        description="List built-in delegated and app-readonly audit profiles.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_status",
        description="Show local Auditex auth state, including Azure CLI and saved m365 connections.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_list",
        description="List saved m365 connections for the local Auditex operator environment.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_use",
        description="Switch the active saved m365 connection.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_auth_import_token",
        description="Store a customer-provided Graph bearer token as a local auth context.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_auth_inspect_token",
        description="Decode a Graph bearer token locally and return its claims summary.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_auth_capability",
        description="Map a saved auth context to collector capability and missing read permissions.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_setup_guide",
        description="Build provider setup scopes, roles, admin steps, and verification commands before tenant access.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_contract_schema_manifest",
        description="List versioned output contract schemas shipped with this Auditex build.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_run_offline_validation",
        description="Run the offline sample audit to validate local packaging without tenant access.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_run_delegated_audit",
        description="Run the Azure CLI token or supplied-token audit path against a tenant and return the run manifest path.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_google_doctor",
        description="Check Google Workspace audit dependencies and target auth configuration.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_google_probe",
        description="Run a low-volume Google Workspace capability probe and return command output.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_run_google_workspace_audit",
        description="Run the Google Workspace audit path with domain delegation or OAuth.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_summarize_run",
        description="Read a completed run directory and return summary, manifest, and diagnostics paths.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_diff_runs",
        description="Compare normalized snapshots between two completed run directories.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_compare_runs",
        description="Compare multiple completed runs with same-tenant gating and timeline output.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_probe_live",
        description="Run a live capability probe against a tenant and emit capability/toolchain/blocker artifacts.",
        read_only_hint=False,
    ),
    McpToolEntry(
        name="auditex_probe_summarize",
        description="Read a completed probe run and return capability, toolchain, and blocker artifact paths.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_list_blockers",
        description="Read blocker artifacts from a completed audit or probe run.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_report_preview",
        description="Build an in-memory report preview for a completed run without writing files.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_report_analyze",
        description="Analyze a completed run into auditor score, attack paths, dry-run control simulator, and QA without tenant access.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_api_inventory",
        description="Read the enterprise API call inventory from a completed run bundle.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_permissions_ledger",
        description="Read required, observed, and missing permissions from a completed run bundle.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_proof_table",
        description="Read finding-to-evidence proof rows from a completed run bundle.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_enterprise_handoff",
        description="Read the enterprise customer handoff index for a completed run bundle.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_verify_customer_pack",
        description="Verify a customer handoff pack manifest, required files, and SHA-256 checksums.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_export_list",
        description="List available report exporters.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_notify_preview",
        description="Build the dry-run notification payload for a completed run.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_rules_inventory",
        description="List built-in rule inventory rows with optional routing filters.",
        read_only_hint=True,
    ),
    McpToolEntry(
        name="auditex_run_response_action",
        description="Run a guarded response action in a separate response bundle.",
        read_only_hint=False,
    ),
)


def iter_tool_specs(*, include_response: bool | None = None) -> tuple[dict[str, Any], ...]:
    enabled = response_enabled() if include_response is None else include_response
    return tuple(
        entry.spec()
        for entry in TOOL_REGISTRY
        if enabled or entry.name not in {"auditex_list_response_actions", "auditex_run_response_action"}
    )


def register_fastmcp_tools(server: Any, handlers: Mapping[str, Handler]) -> None:
    enabled_names = {item["name"] for item in iter_tool_specs()}
    for entry in TOOL_REGISTRY:
        if entry.name not in enabled_names:
            continue
        if entry.name not in handlers:
            continue
        handler = handlers[entry.name]
        handler.__name__ = entry.name
        _tool_decorator(server, entry)(handler)


def _tool_decorator(server: Any, entry: McpToolEntry) -> Callable[[Handler], Handler]:
    metadata = {
        "name": entry.name,
        "description": entry.description,
        "annotations": entry.annotations,
    }
    try:
        return server.tool(**metadata)
    except TypeError:
        return server.tool()
