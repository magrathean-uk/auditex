from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from azure_tenant_audit.config import CollectorConfig

from . import auth as auditex_auth
from .features import response_disabled_message, response_enabled
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.profiles import PROFILES
from azure_tenant_audit.adapters import ADAPTERS, list_adapters as _list_adapters
from azure_tenant_audit.citations import build_citation_summary
from azure_tenant_audit.response import response_actions
from azure_tenant_audit.contracts import contract_schema_manifest
from .rules import list_rule_inventory
from .command_runner import run_cli_command
from .command_builders import (
    AuditRunCommandSpec,
    GoogleRunCommandSpec,
    ProbeCommandSpec,
    ResponseCommandSpec,
    build_audit_run_command,
    build_google_run_command,
    build_probe_command as build_probe_tool_command,
    build_response_command as build_response_tool_command,
)
from .mcp_registry import iter_tool_specs, register_fastmcp_tools
from .run_bundle import RunBundle
from .setup_guide import build_setup_guide
from azure_tenant_audit.scope_catalog import build_google_scope_catalog, build_m365_scope_catalog
from azure_tenant_audit.versioning import package_version_line
SUPPORTED_PLANES = ("inventory", "full", "export")
SUPPORTED_PROBE_MODES = ("delegated", "app", "response")

_SUMMARY_ARTIFACT_REASONS = {
    "run-manifest.json": "Run identity and bundle metadata.",
    "summary.json": "Top-level run summary.",
    "summary.md": "Human-readable summary for this run.",
    "diagnostics.json": "Collector diagnostics and runtime notes.",
    "capability-matrix.json": "Capability and permission probe results.",
    "toolchain-readiness.json": "Local toolchain readiness for this run.",
    "live-readiness.json": "Collector trust, blockers, and evidence gates.",
    "audit-plan.json": "Audit plan and collector execution truth.",
    "api-inventory.json": "Observed and declared API inventory for this run.",
    "data-handling.json": "Read-only and content-boundary assertions for this run.",
    "auth-context.json": "Saved auth context metadata used for this run.",
    "coverage.json": "Collector coverage ledger for this run.",
    "ai_context.json": "AI-safe context and redaction guidance.",
    "validation.json": "Contract validation result for this run.",
    "blockers/blockers.json": "Recorded collector and runtime blockers for this run.",
    "findings/findings.json": "Normalized findings generated from bundle evidence.",
    "reports/report-pack.json": "Structured report pack and citation summary.",
    "reports/action-plan.json": "Recommended action plan derived from current findings.",
    "index/evidence.sqlite": "Local evidence index for bundle records and artifact lookup.",
}


def _with_static_citations(
    payload: dict[str, Any],
    citations: list[dict[str, Any]],
    *,
    evidence_missing: list[str] | None = None,
) -> dict[str, Any]:
    result = dict(payload)
    result["citations"] = citations
    result["citation_summary"] = build_citation_summary(citations)
    result["evidence_missing"] = list(evidence_missing or [])
    return result


def _relative_source(path: Path, run_path: Path) -> str:
    try:
        return str(path.relative_to(run_path))
    except ValueError:
        return str(path)


def list_collectors(config_path: str = "configs/collector-definitions.json", provider: str = "m365") -> dict[str, Any]:
    if provider in {"google", "google_workspace"}:
        from .google_workspace.collectors import DEFAULT_ORDER, REGISTRY

        catalog = build_google_scope_catalog(registry=REGISTRY)
        collectors = [
            {
                "name": name,
                "description": getattr(collector, "description", ""),
                "enabled": True,
                "required_permissions": list(catalog.get(name, {}).get("required_permissions") or []),
                "minimum_role_hints": list(catalog.get(name, {}).get("minimum_role_hints") or []),
                "tool_requirements": list(catalog.get(name, {}).get("tool_requirements") or []),
                "query_plan": [],
                "command_collectors": [],
                "position": position,
            }
            for position, (name, collector) in enumerate(REGISTRY.items())
        ]
        return _with_static_citations(
            {
            "provider": "google",
            "collectors": collectors,
            "default_order": list(DEFAULT_ORDER),
            },
            [
                {"artifact_path": "src/auditex/google_workspace/collectors.py", "reason": "Google Workspace collector registry and required scopes."},
                {"artifact_path": "src/azure_tenant_audit/scope_catalog.py", "reason": "Shared scope catalog aggregation used to derive collector requirements."},
            ],
        )

    path = Path(config_path)
    if not path.exists():
        return _with_static_citations(
            {"error": "collector definitions file not found", "path": str(path)},
            [{"artifact_path": str(path), "reason": "Collector definition source requested by this MCP helper."}],
            evidence_missing=[str(path)],
        )
    try:
        config = CollectorConfig.from_path(path)
    except Exception as exc:  # noqa: BLE001
        return _with_static_citations(
            {"error": str(exc), "path": str(path)},
            [{"artifact_path": str(path), "reason": "Collector definition source requested by this MCP helper."}],
        )
    from azure_tenant_audit.diagnostics import load_permission_hints

    catalog = build_m365_scope_catalog(
        collector_config=config,
        permission_hints=load_permission_hints(Path("configs/collector-permissions.json")),
    )

    collectors = [
        {
            "name": name,
            "description": definition.description,
            "enabled": definition.enabled,
            "required_permissions": list(catalog.get(name, {}).get("required_permissions") or definition.required_permissions),
            "minimum_role_hints": list(catalog.get(name, {}).get("minimum_role_hints") or []),
            "tool_requirements": list(catalog.get(name, {}).get("tool_requirements") or []),
            "query_plan": list(definition.query_plan),
            "command_collectors": list(definition.command_collectors or []),
            "position": position,
        }
        for position, (name, definition) in enumerate(config.collectors.items())
    ]
    return _with_static_citations(
        {
            "provider": "m365",
            "path": str(path),
            "collectors": collectors,
            "default_order": config.default_order,
        },
        [
            {"artifact_path": str(path), "reason": "Microsoft 365 collector definitions and query plans."},
            {"artifact_path": "configs/collector-permissions.json", "reason": "Permission hints and role guidance for Microsoft 365 collectors."},
            {"artifact_path": "src/azure_tenant_audit/scope_catalog.py", "reason": "Shared scope catalog aggregation used to derive collector requirements."},
        ],
    )


def list_adapters() -> dict[str, Any]:
    adapters = _list_adapters()
    return _with_static_citations(
        {
            "adapters": adapters,
            "count": len(adapters),
        },
        [{"artifact_path": "src/azure_tenant_audit/adapters/__init__.py", "reason": "Configured adapter registry and capability metadata."}],
    )


def list_profiles() -> dict[str, Any]:
    return _with_static_citations(
        {"profiles": [profile.__dict__ for profile in PROFILES.values()]},
        [{"artifact_path": "src/azure_tenant_audit/profiles.py", "reason": "Shipped auditor profile catalog and default collector presets."}],
    )


def list_response_actions() -> dict[str, Any]:
    citations = [
        {"artifact_path": "src/auditex/features.py", "reason": "Response-plane feature flag and disable message for this helper."},
        {"artifact_path": "src/azure_tenant_audit/response.py", "reason": "Shipped lab response-action catalog used for this helper."},
    ]
    if not response_enabled():
        return _with_static_citations(
            {"enabled": False, "error": "response_disabled", "message": response_disabled_message(), "actions": [], "count": 0},
            citations,
        )
    actions = response_actions()
    return _with_static_citations(
        {
            "enabled": True,
            "actions": actions,
            "count": len(actions),
        },
        citations,
    )


def tool_specs() -> list[dict[str, Any]]:
    return list(iter_tool_specs())


def setup_guide(
    *,
    provider: str,
    collector_preset: str = "",
    collectors: str = "",
    exclude: str = "",
    auth: str = "domain-delegation",
    tenant_name: str = "CLIENT",
    tenant_id: str = "<tenant-id-or-domain>",
    domain: str = "example.com",
    customer_id: str = "my_customer",
    subject: str = "admin@example.com",
    service_account_key: str = "/path/to/service-account.json",
    oauth_client: str = "/path/to/oauth-client.json",
    token_cache: str = ".secrets/google-token.json",
    auditor_profile: str = "global-reader",
    plane: str = "full",
    mode: str = "delegated",
    include_exchange: bool = False,
) -> dict[str, Any]:
    payload = build_setup_guide(
        provider=provider,
        collector_preset=collector_preset or None,
        collectors=collectors or None,
        exclude=exclude or None,
        auth=auth,
        tenant_name=tenant_name,
        tenant_id=tenant_id,
        domain=domain,
        customer_id=customer_id,
        subject=subject,
        service_account_key=service_account_key,
        oauth_client=oauth_client,
        token_cache=token_cache,
        auditor_profile=auditor_profile,
        plane=plane,
        mode=mode,
        include_exchange=include_exchange,
    )
    citations = [
        {"artifact_path": "src/auditex/setup_guide.py", "reason": "Setup-guide rendering and provider setup logic."},
        {"artifact_path": "src/azure_tenant_audit/scope_catalog.py", "reason": "Shared scope catalog used to derive setup requirements."},
    ]
    normalized_provider = str(payload.get("provider") or provider).lower()
    if normalized_provider == "m365":
        citations.extend(
            [
                {"artifact_path": "configs/collector-definitions.json", "reason": "Microsoft 365 collector scope and query definitions."},
                {"artifact_path": "configs/collector-permissions.json", "reason": "Microsoft 365 permission hints and role guidance."},
            ]
        )
    else:
        citations.append({"artifact_path": "src/auditex/google_workspace/collectors.py", "reason": "Google Workspace collector registry and required scopes."})
    return _with_static_citations(payload, citations)


def auth_capability(name: str = "", collectors: str = "", auditor_profile: str = "auto") -> dict[str, Any]:
    selected_collectors = [item.strip() for item in collectors.split(",") if item.strip()]
    payload = auditex_auth.capability_for_context(
        name=name or None,
        collectors=selected_collectors,
        auditor_profile=auditor_profile,
    )
    citations = [
        {"artifact_path": "src/auditex/auth.py", "reason": "Saved auth-context path resolution and product auth capability entrypoint."},
        {"artifact_path": "src/auditex/auth_runtime.py", "reason": "Auth-context capability evaluation against collected token claims."},
        {"artifact_path": "configs/collector-definitions.json", "reason": "Collector definitions used to derive required permissions for capability checks."},
        {"artifact_path": "configs/collector-permissions.json", "reason": "Permission hints and role guidance used in capability evaluation."},
        {"artifact_path": "src/azure_tenant_audit/scope_catalog.py", "reason": "Shared scope catalog used to map collectors to required permissions."},
    ]
    evidence_missing: list[str] = []
    auth_context_name = str(payload.get("auth_context", {}).get("name") or "").strip()
    store_path = auditex_auth.default_auth_contexts_path()
    citations.append({"artifact_path": str(store_path), "reason": "Saved local auth context store used to resolve the selected context."})
    if auth_context_name and not store_path.exists():
        evidence_missing.append(str(store_path))
    return _with_static_citations(payload, citations, evidence_missing=evidence_missing)


def auth_status() -> dict[str, Any]:
    payload = auditex_auth.get_auth_status()
    local_auth_path = auditex_auth.default_local_auth_env_path()
    contexts_path = auditex_auth.default_auth_contexts_path()
    citations = [
        {"artifact_path": "src/auditex/auth.py", "reason": "Product auth status entrypoint and local auth path resolution."},
        {"artifact_path": "src/auditex/auth_runtime.py", "reason": "Local auth status command probes and context summary logic."},
        {"artifact_path": str(local_auth_path), "reason": "Local masked auth-env location used for this status view."},
        {"artifact_path": str(contexts_path), "reason": "Saved local auth-context store used for this status view."},
        {"artifact_path": "command:az account show --output json", "reason": "Azure CLI status probe used for this status view."},
        {"artifact_path": "command:m365 status --output json", "reason": "Microsoft 365 CLI status probe used for this status view."},
        {"artifact_path": "command:m365 connection list --output json", "reason": "Saved Microsoft 365 connection listing used for this status view."},
        {"artifact_path": "command:pwsh exchange-module-check", "reason": "Exchange Online PowerShell module readiness probe used for this status view."},
        {"artifact_path": "src/azure_tenant_audit/adapters/__init__.py", "reason": "Adapter capability catalog surfaced in auth status."},
    ]
    evidence_missing: list[str] = []
    if not local_auth_path.exists():
        evidence_missing.append(str(local_auth_path))
    if not contexts_path.exists():
        evidence_missing.append(str(contexts_path))
    return _with_static_citations(payload, citations, evidence_missing=evidence_missing)


def auth_list() -> dict[str, Any]:
    local_auth_path = auditex_auth.default_local_auth_env_path()
    try:
        payload = auditex_auth.list_connections()
        evidence_missing: list[str] = [] if local_auth_path.exists() else [str(local_auth_path)]
    except RuntimeError as exc:
        payload = {"connections": [], "error": str(exc), "status": "blocked"}
        evidence_missing = [str(local_auth_path)] if not local_auth_path.exists() else ["command:m365 connection list --output json"]
    return _with_static_citations(
        payload,
        [
            {"artifact_path": "src/auditex/auth.py", "reason": "Product auth connection-list entrypoint and local auth path resolution."},
            {"artifact_path": "src/auditex/auth_runtime.py", "reason": "Microsoft 365 connection-list command handling for this helper."},
            {"artifact_path": str(local_auth_path), "reason": "Local auth env used before listing saved Microsoft 365 connections."},
            {"artifact_path": "command:m365 connection list --output json", "reason": "Saved Microsoft 365 connection listing returned by this helper."},
        ],
        evidence_missing=evidence_missing,
    )


def auth_inspect_token(token: str) -> dict[str, Any]:
    payload = auditex_auth.inspect_token_claims(token)
    return _with_static_citations(
        payload,
        [
            {"artifact_path": "src/auditex/auth.py", "reason": "Product token-inspection entrypoint and token-input resolution path."},
            {"artifact_path": "src/auditex/auth_runtime.py", "reason": "JWT claim decoding and safe token-claim shaping used for this helper."},
            {"artifact_path": "token_input", "reason": "Caller-supplied JWT decoded for this inspection result."},
        ],
    )


def contract_schema_inventory(schema_dir: str = "schemas") -> dict[str, Any]:
    payload = contract_schema_manifest(schema_dir=schema_dir)
    path = Path(schema_dir)
    citations = [
        {"artifact_path": "src/azure_tenant_audit/contracts.py", "reason": "Contract schema manifest builder and bundle validation rules."},
        {"artifact_path": str(path), "reason": "Shipped schema directory requested by this MCP helper."},
    ]
    evidence_missing = [] if path.exists() else [str(path)]
    return _with_static_citations(payload, citations, evidence_missing=evidence_missing)


def build_cli_command(
    *,
    tenant_name: str,
    out_dir: str,
    tenant_id: str | None = None,
    auditor_profile: str = "global-reader",
    plane: str = "inventory",
    use_azure_cli_token: bool = True,
    access_token: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    include_exchange: bool = False,
    collectors: str | list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
    offline: bool = False,
    sample_path: str = "examples/sample_audit_bundle/sample_result.json",
) -> list[str]:
    return build_audit_run_command(
        AuditRunCommandSpec(
            tenant_name=tenant_name,
            out_dir=out_dir,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            plane=plane,
            use_azure_cli_token=use_azure_cli_token,
            access_token=access_token,
            client_id=client_id,
            client_secret=client_secret,
            include_exchange=include_exchange,
            collectors=collectors,
            since=since,
            until=until,
            offline=offline,
            sample_path=sample_path,
            python_executable=sys.executable,
        )
    )


def build_google_command(
    *,
    tenant_name: str = "google-workspace",
    out_dir: str = "outputs/google",
    google_command: str = "run",
    auth: str = "domain-delegation",
    domain: str = "",
    customer_id: str = "",
    subject: str = "",
    service_account_key: str = "",
    oauth_client: str = "",
    token_cache: str = "",
    collector_preset: str = "core-security",
    collectors: str | list[str] | None = None,
    exclude: str | list[str] | None = None,
    top: int | None = None,
    page_size: int | None = None,
    since: str = "",
    until: str = "",
    run_name: str = "",
    offline: bool = False,
    sample_path: str = "examples/google_workspace_sample.json",
    json_output: bool = False,
) -> list[str]:
    return build_google_run_command(
        GoogleRunCommandSpec(
            tenant_name=tenant_name,
            out_dir=out_dir,
            google_command=google_command,
            auth=auth,
            domain=domain or None,
            customer_id=customer_id or None,
            subject=subject or None,
            service_account_key=service_account_key or None,
            oauth_client=oauth_client or None,
            token_cache=token_cache or None,
            collector_preset=collector_preset or None,
            collectors=collectors,
            exclude=exclude,
            top=top,
            page_size=page_size,
            since=since or None,
            until=until or None,
            run_name=run_name or None,
            offline=offline,
            sample_path=sample_path,
            json_output=json_output,
            python_executable=sys.executable,
        )
    )


def build_probe_command(
    *,
    tenant_name: str,
    out_dir: str,
    tenant_id: str | None = None,
    auditor_profile: str = "global-reader",
    mode: str = "delegated",
    surface: str = "all",
    since: str | None = None,
    until: str | None = None,
    allow_lab_response: bool = False,
    use_azure_cli_token: bool = True,
    access_token: str | None = None,
    auth_context: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> list[str]:
    return build_probe_tool_command(
        ProbeCommandSpec(
            tenant_name=tenant_name,
            out_dir=out_dir,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            mode=mode,
            surface=surface,
            since=since,
            until=until,
            allow_lab_response=allow_lab_response,
            use_azure_cli_token=use_azure_cli_token,
            access_token=access_token,
            auth_context=auth_context,
            client_id=client_id,
            client_secret=client_secret,
            python_executable=sys.executable,
        )
    )


def build_response_command(
    *,
    tenant_name: str,
    out_dir: str,
    action: str,
    tenant_id: str | None = None,
    auditor_profile: str = "exchange-reader",
    target: str | None = None,
    intent: str = "",
    since: str | None = None,
    until: str | None = None,
    run_name: str | None = None,
    execute: bool = False,
    allow_write: bool = False,
    allow_lab_response: bool = False,
    auth_context: str | None = None,
    adapter_override: str | None = None,
    command_override: str | None = None,
    allow_adapter_override: bool = False,
    allow_command_override: bool = False,
) -> list[str]:
    if not response_enabled():
        raise ValueError(response_disabled_message())
    return build_response_tool_command(
        ResponseCommandSpec(
            tenant_name=tenant_name,
            out_dir=out_dir,
            action=action,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            target=target,
            intent=intent,
            since=since,
            until=until,
            run_name=run_name,
            execute=execute,
            allow_write=allow_write,
            allow_lab_response=allow_lab_response,
            auth_context=auth_context,
            adapter_override=adapter_override,
            command_override=command_override,
            allow_adapter_override=allow_adapter_override,
            allow_command_override=allow_command_override,
            python_executable=sys.executable,
        ),
        supported_actions=response_actions(),
    )


def summarize_run(run_dir: str) -> dict[str, Any]:
    bundle = RunBundle(run_dir).read()
    citations: list[dict[str, Any]] = []
    evidence_missing: list[str] = []
    seen_paths: set[str] = set()
    for path_key, artifact_path, payload_key in (
        ("manifest_path", "run-manifest.json", "manifest"),
        ("summary_path", "summary.json", "summary"),
        ("summary_md_path", "summary.md", "summary_md"),
        ("diagnostics_path", "diagnostics.json", "diagnostics"),
        ("capability_matrix_path", "capability-matrix.json", "capability_matrix"),
        ("toolchain_readiness_path", "toolchain-readiness.json", "toolchain_readiness"),
        ("live_readiness_path", "live-readiness.json", "live_readiness"),
        ("audit_plan_path", "audit-plan.json", "audit_plan"),
        ("api_inventory_path", "api-inventory.json", "api_inventory"),
        ("data_handling_path", "data-handling.json", "data_handling"),
        ("auth_context_path", "auth-context.json", "auth_context"),
        ("coverage_ledger_path", "coverage.json", "coverage_ledger"),
        ("ai_context_path", "ai_context.json", "ai_context"),
        ("validation_path", "validation.json", "validation"),
        ("blockers_path", "blockers/blockers.json", "blockers"),
        ("findings_path", "findings/findings.json", "findings"),
        ("report_pack_path", "reports/report-pack.json", "report_pack"),
        ("action_plan_path", "reports/action-plan.json", "action_plan"),
        ("evidence_db_path", "index/evidence.sqlite", "evidence_db_path"),
    ):
        path_value = bundle.get(path_key)
        if payload_key not in bundle:
            continue
        if isinstance(path_value, str) and path_value and artifact_path not in seen_paths:
            citations.append({"artifact_path": artifact_path, "reason": _SUMMARY_ARTIFACT_REASONS[artifact_path]})
            seen_paths.add(artifact_path)
    for required_artifact in ("run-manifest.json", "summary.json"):
        if required_artifact not in seen_paths:
            evidence_missing.append(required_artifact)
    bundle["citations"] = citations
    bundle["citation_summary"] = build_citation_summary(citations)
    report_pack = bundle.get("report_pack")
    if isinstance(report_pack, dict) and isinstance(report_pack.get("citation_summary"), dict):
        bundle["report_pack_citation_summary"] = dict(report_pack.get("citation_summary") or {})
    bundle["evidence_missing"] = evidence_missing
    return bundle


def diff_runs(run_a: str, run_b: str, classic: bool = False) -> dict[str, Any]:
    return diff_run_directories(run_a, run_b, classic=classic)


def list_blockers(run_dir: str) -> dict[str, Any]:
    bundle = RunBundle(run_dir)
    path, blockers = bundle.blockers()
    citations = (
        [{"artifact_path": _relative_source(path, Path(run_dir)), "reason": "Recorded collector and runtime blockers for this run."}]
        if path is not None
        else []
    )
    result = {
        "run_dir": run_dir,
        "blockers_path": str(path or bundle.path("blockers/blockers.json")),
        "evidence_missing": path is None,
        "citations": citations,
        "citation_summary": build_citation_summary(citations),
    }
    if path is not None:
        result["blockers"] = blockers
    return result


def compare_many_runs(run_dirs: list[str], allow_cross_tenant: bool = False, classic: bool = False) -> dict[str, Any]:
    from .compare import compare_runs

    return compare_runs(run_dirs, allow_cross_tenant=allow_cross_tenant, classic=classic)


def preview_report(
    run_dir: str,
    format_name: str = "json",
    include_sections: str = "",
    exclude_sections: str = "",
) -> dict[str, Any]:
    from .reporting import preview_report as _preview_report

    include = [item.strip() for item in include_sections.split(",") if item.strip()]
    exclude = [item.strip() for item in exclude_sections.split(",") if item.strip()]
    return _preview_report(
        run_dir=run_dir,
        format_name=format_name,
        include_sections=include or None,
        exclude_sections=exclude or None,
    )


def analyze_report(run_dir: str) -> dict[str, Any]:
    from .reporting import analyze_report as _analyze_report

    return _analyze_report(run_dir)


def api_inventory(run_dir: str) -> dict[str, Any]:
    from .reporting import api_call_inventory as _api_call_inventory

    return _api_call_inventory(run_dir)


def permissions_ledger(run_dir: str) -> dict[str, Any]:
    from .reporting import permissions_ledger as _permissions_ledger

    return _permissions_ledger(run_dir)


def proof_table(run_dir: str) -> dict[str, Any]:
    from .reporting import proof_table as _proof_table

    return _proof_table(run_dir)


def enterprise_handoff(run_dir: str) -> dict[str, Any]:
    from .reporting import enterprise_handoff as _enterprise_handoff

    return _enterprise_handoff(run_dir)


def verify_customer_pack(pack_dir: str) -> dict[str, Any]:
    from .reporting import verify_enterprise_handoff_pack

    return verify_enterprise_handoff_pack(pack_dir)


def list_available_exporters() -> dict[str, Any]:
    from .exporters import list_exporters

    return _with_static_citations(
        {"exporters": list_exporters()},
        [{"artifact_path": "src/auditex/exporters.py", "reason": "Built-in exporter registry and plugin discovery path."}],
    )


def preview_notification(run_dir: str, sink: str = "teams") -> dict[str, Any]:
    from .notify import send_notification

    return send_notification(run_dir=run_dir, sink=sink, dry_run=True)


def rules_inventory(
    tag: str = "",
    path_prefix: str = "",
    platform: str = "",
    product_family: str = "",
    license_tier: str = "",
    audit_level: str = "",
) -> dict[str, Any]:
    rows = list_rule_inventory(
        tag=tag or None,
        path_prefix=path_prefix or None,
        platform=platform or None,
        product_family=product_family or None,
        license_tier=license_tier or None,
        audit_level=audit_level or None,
    )
    return _with_static_citations(
        {"count": len(rows), "rules": rows},
        [
            {"artifact_path": "src/auditex/rules.py", "reason": "Rule inventory filtering and row shaping."},
            {"artifact_path": "configs/rule-packs.json", "reason": "Shipped rule pack source for MCP inventory results."},
        ],
    )


def _build_mcp_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditex-mcp", description="Auditex MCP server.")
    parser.add_argument("--version", action="version", version=package_version_line("auditex-mcp"))
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        if argv[0] in {"-h", "--help", "help"}:
            _build_mcp_parser().print_help()
            return 0
        if argv[0] == "--version":
            print(package_version_line("auditex-mcp"))
            return 0
        _build_mcp_parser().parse_args(argv)

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install Auditex with the MCP extra: pip install -e '.[mcp]'", file=sys.stderr)
        return 2

    server = FastMCP("auditex")

    def auditex_list_profiles() -> dict[str, Any]:
        return list_profiles()

    def auditex_list_collectors(config_path: str = "configs/collector-definitions.json", provider: str = "m365") -> dict[str, Any]:
        return list_collectors(config_path=config_path, provider=provider)

    def auditex_list_adapters() -> dict[str, Any]:
        return list_adapters()

    def auditex_list_response_actions() -> dict[str, Any]:
        return list_response_actions()

    def auditex_auth_status() -> dict[str, Any]:
        return auth_status()

    def auditex_auth_list() -> dict[str, Any]:
        return auth_list()

    def auditex_auth_use(connection_name: str) -> dict[str, Any]:
        return auditex_auth.use_connection(connection_name)

    def auditex_auth_import_token(name: str, token: str, tenant_id: str = "") -> dict[str, Any]:
        return auditex_auth.import_token_context(name=name, token=token, tenant_id=tenant_id or None)

    def auditex_auth_inspect_token(token: str) -> dict[str, Any]:
        return auth_inspect_token(token)

    def auditex_auth_capability(name: str = "", collectors: str = "", auditor_profile: str = "auto") -> dict[str, Any]:
        return auth_capability(name=name, collectors=collectors, auditor_profile=auditor_profile)

    def auditex_setup_guide(
        provider: str,
        collector_preset: str = "",
        collectors: str = "",
        exclude: str = "",
        auth: str = "domain-delegation",
        tenant_name: str = "CLIENT",
        tenant_id: str = "<tenant-id-or-domain>",
        domain: str = "example.com",
        customer_id: str = "my_customer",
        subject: str = "admin@example.com",
        service_account_key: str = "/path/to/service-account.json",
        oauth_client: str = "/path/to/oauth-client.json",
        token_cache: str = ".secrets/google-token.json",
        auditor_profile: str = "global-reader",
        plane: str = "full",
        mode: str = "delegated",
        include_exchange: bool = False,
    ) -> dict[str, Any]:
        return setup_guide(
            provider=provider,
            collector_preset=collector_preset,
            collectors=collectors,
            exclude=exclude,
            auth=auth,
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            domain=domain,
            customer_id=customer_id,
            subject=subject,
            service_account_key=service_account_key,
            oauth_client=oauth_client,
            token_cache=token_cache,
            auditor_profile=auditor_profile,
            plane=plane,
            mode=mode,
            include_exchange=include_exchange,
        )

    def auditex_contract_schema_manifest(schema_dir: str = "schemas") -> dict[str, Any]:
        return contract_schema_inventory(schema_dir=schema_dir)

    def auditex_run_offline_validation(
        tenant_name: str,
        out_dir: str = "outputs/offline",
        sample_path: str = "examples/sample_audit_bundle/sample_result.json",
    ) -> dict[str, Any]:
        command = build_cli_command(
            tenant_name=tenant_name,
            out_dir=out_dir,
            auditor_profile="auto",
            offline=True,
            sample_path=sample_path,
        )
        return run_cli_command(command)

    def auditex_run_delegated_audit(
        tenant_name: str,
        tenant_id: str = "organizations",
        out_dir: str = "outputs/live",
        auditor_profile: str = "global-reader",
        plane: str = "inventory",
        include_exchange: bool = False,
        collectors: str = "",
        since: str = "",
        until: str = "",
    ) -> dict[str, Any]:
        command = build_cli_command(
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            out_dir=out_dir,
            auditor_profile=auditor_profile,
            plane=plane,
            use_azure_cli_token=True,
            include_exchange=include_exchange,
            collectors=collectors or None,
            since=since or None,
            until=until or None,
        )
        return run_cli_command(command)

    def auditex_google_doctor(
        auth: str = "domain-delegation",
        domain: str = "",
        customer_id: str = "",
        subject: str = "",
        service_account_key: str = "",
        oauth_client: str = "",
        token_cache: str = "",
    ) -> dict[str, Any]:
        command = build_google_command(
            google_command="doctor",
            auth=auth,
            domain=domain,
            customer_id=customer_id,
            subject=subject,
            service_account_key=service_account_key,
            oauth_client=oauth_client,
            token_cache=token_cache,
            json_output=True,
        )
        return run_cli_command(command)

    def auditex_google_probe(
        tenant_name: str = "google-workspace",
        out_dir: str = "outputs/google-probes",
        auth: str = "domain-delegation",
        domain: str = "",
        customer_id: str = "",
        subject: str = "",
        service_account_key: str = "",
        oauth_client: str = "",
        token_cache: str = "",
        collector_preset: str = "core-security",
        collectors: str = "",
        exclude: str = "",
        top: int = 1,
        page_size: int = 1,
    ) -> dict[str, Any]:
        command = build_google_command(
            tenant_name=tenant_name,
            out_dir=out_dir,
            google_command="probe",
            auth=auth,
            domain=domain,
            customer_id=customer_id,
            subject=subject,
            service_account_key=service_account_key,
            oauth_client=oauth_client,
            token_cache=token_cache,
            collector_preset=collector_preset,
            collectors=collectors or None,
            exclude=exclude or None,
            top=top,
            page_size=page_size,
        )
        return run_cli_command(command)

    def auditex_run_google_workspace_audit(
        tenant_name: str = "google-workspace",
        out_dir: str = "outputs/google",
        auth: str = "domain-delegation",
        domain: str = "",
        customer_id: str = "",
        subject: str = "",
        service_account_key: str = "",
        oauth_client: str = "",
        token_cache: str = "",
        collector_preset: str = "core-security",
        collectors: str = "",
        exclude: str = "",
        top: int = 100,
        page_size: int = 100,
        since: str = "",
        until: str = "",
        run_name: str = "",
    ) -> dict[str, Any]:
        command = build_google_command(
            tenant_name=tenant_name,
            out_dir=out_dir,
            google_command="run",
            auth=auth,
            domain=domain,
            customer_id=customer_id,
            subject=subject,
            service_account_key=service_account_key,
            oauth_client=oauth_client,
            token_cache=token_cache,
            collector_preset=collector_preset,
            collectors=collectors or None,
            exclude=exclude or None,
            top=top,
            page_size=page_size,
            since=since,
            until=until,
            run_name=run_name,
        )
        return run_cli_command(command)

    def auditex_summarize_run(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    def auditex_diff_runs(run_a: str, run_b: str, classic: bool = False) -> dict[str, Any]:
        return diff_runs(run_a, run_b, classic=classic)

    def auditex_compare_runs(run_dirs: list[str], allow_cross_tenant: bool = False, classic: bool = False) -> dict[str, Any]:
        return compare_many_runs(run_dirs, allow_cross_tenant=allow_cross_tenant, classic=classic)

    def auditex_probe_live(
        tenant_name: str,
        tenant_id: str = "organizations",
        out_dir: str = "outputs/probes",
        auditor_profile: str = "global-reader",
        mode: str = "delegated",
        surface: str = "all",
        since: str = "",
        until: str = "",
        allow_lab_response: bool = False,
        auth_context: str = "",
        client_id: str = "",
        client_secret: str = "",
    ) -> dict[str, Any]:
        command = build_probe_command(
            tenant_name=tenant_name,
            tenant_id=tenant_id,
            out_dir=out_dir,
            auditor_profile=auditor_profile,
            mode=mode,
            surface=surface,
            since=since or None,
            until=until or None,
            allow_lab_response=allow_lab_response,
            auth_context=auth_context or None,
            client_id=client_id or None,
            client_secret=client_secret or None,
        )
        return run_cli_command(command)

    def auditex_probe_summarize(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    def auditex_list_blockers(run_dir: str) -> dict[str, Any]:
        return list_blockers(run_dir)

    def auditex_report_preview(
        run_dir: str,
        format_name: str = "json",
        include_sections: str = "",
        exclude_sections: str = "",
    ) -> dict[str, Any]:
        return preview_report(
            run_dir=run_dir,
            format_name=format_name,
            include_sections=include_sections,
            exclude_sections=exclude_sections,
        )

    def auditex_report_analyze(run_dir: str) -> dict[str, Any]:
        return analyze_report(run_dir)

    def auditex_api_inventory(run_dir: str) -> dict[str, Any]:
        return api_inventory(run_dir)

    def auditex_permissions_ledger(run_dir: str) -> dict[str, Any]:
        return permissions_ledger(run_dir)

    def auditex_proof_table(run_dir: str) -> dict[str, Any]:
        return proof_table(run_dir)

    def auditex_enterprise_handoff(run_dir: str) -> dict[str, Any]:
        return enterprise_handoff(run_dir)

    def auditex_verify_customer_pack(pack_dir: str) -> dict[str, Any]:
        return verify_customer_pack(pack_dir)

    def auditex_export_list() -> dict[str, Any]:
        return list_available_exporters()

    def auditex_notify_preview(run_dir: str, sink: str = "teams") -> dict[str, Any]:
        return preview_notification(run_dir=run_dir, sink=sink)

    def auditex_rules_inventory(
        tag: str = "",
        path_prefix: str = "",
        product_family: str = "",
        license_tier: str = "",
        audit_level: str = "",
    ) -> dict[str, Any]:
        return rules_inventory(
            tag=tag,
            path_prefix=path_prefix,
            product_family=product_family,
            license_tier=license_tier,
            audit_level=audit_level,
        )

    def auditex_run_response_action(
        tenant_name: str,
        action: str,
        tenant_id: str = "organizations",
        out_dir: str = "outputs/response",
        auditor_profile: str = "exchange-reader",
        target: str = "",
        intent: str = "",
        since: str = "",
        until: str = "",
        run_name: str = "",
        execute: bool = False,
        allow_write: bool = False,
        allow_lab_response: bool = False,
        auth_context: str = "",
        adapter_override: str = "",
        command_override: str = "",
        allow_adapter_override: bool = False,
        allow_command_override: bool = False,
    ) -> dict[str, Any]:
        command = build_response_command(
            tenant_name=tenant_name,
            out_dir=out_dir,
            action=action,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            target=target or None,
            intent=intent,
            since=since or None,
            until=until or None,
            run_name=run_name or None,
            execute=execute,
            allow_write=allow_write,
            allow_lab_response=allow_lab_response,
            auth_context=auth_context or None,
            adapter_override=adapter_override or None,
            command_override=command_override or None,
            allow_adapter_override=allow_adapter_override,
            allow_command_override=allow_command_override,
        )
        return run_cli_command(command)

    handlers = {name: value for name, value in locals().items() if name.startswith("auditex_") and callable(value)}
    register_fastmcp_tools(server, handlers)
    server.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
