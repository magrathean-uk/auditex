from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from azure_tenant_audit.config import CollectorConfig

from . import auth as auditex_auth
from azure_tenant_audit.diffing import diff_run_directories
from azure_tenant_audit.profiles import PROFILES
from azure_tenant_audit.adapters import ADAPTERS, list_adapters as _list_adapters
from azure_tenant_audit.response import response_actions
from azure_tenant_audit.contracts import contract_schema_manifest
from .rules import list_rule_inventory
from .command_runner import run_cli_command
from .command_builders import (
    AuditRunCommandSpec,
    ProbeCommandSpec,
    ResponseCommandSpec,
    build_audit_run_command,
    build_probe_command as build_probe_tool_command,
    build_response_command as build_response_tool_command,
)
from .mcp_registry import iter_tool_specs, register_fastmcp_tools
from .run_bundle import RunBundle
SUPPORTED_PLANES = ("inventory", "full", "export")
SUPPORTED_PROBE_MODES = ("delegated", "app", "response")


def list_collectors(config_path: str = "configs/collector-definitions.json") -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        return {"error": "collector definitions file not found", "path": str(path)}
    try:
        config = CollectorConfig.from_path(path)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "path": str(path)}

    collectors = [
        {
            "name": name,
            "description": definition.description,
            "enabled": definition.enabled,
            "required_permissions": list(definition.required_permissions),
            "query_plan": list(definition.query_plan),
            "command_collectors": list(definition.command_collectors or []),
            "position": position,
        }
        for position, (name, definition) in enumerate(config.collectors.items())
    ]
    return {
        "path": str(path),
        "collectors": collectors,
        "default_order": config.default_order,
    }


def list_adapters() -> dict[str, Any]:
    adapters = _list_adapters()
    return {
        "adapters": adapters,
        "count": len(adapters),
    }


def list_response_actions() -> dict[str, Any]:
    actions = response_actions()
    return {
        "actions": actions,
        "count": len(actions),
    }


def tool_specs() -> list[dict[str, Any]]:
    return list(iter_tool_specs())


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
    return RunBundle(run_dir).read()


def diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
    return diff_run_directories(run_a, run_b)


def list_blockers(run_dir: str) -> dict[str, Any]:
    bundle = RunBundle(run_dir)
    path, blockers = bundle.blockers()
    result = {"run_dir": run_dir, "blockers_path": str(path or bundle.path("blockers/blockers.json"))}
    if path is not None:
        result["blockers"] = blockers
    return result


def compare_many_runs(run_dirs: list[str], allow_cross_tenant: bool = False) -> dict[str, Any]:
    from .compare import compare_runs

    return compare_runs(run_dirs, allow_cross_tenant=allow_cross_tenant)


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


def list_available_exporters() -> dict[str, Any]:
    from .exporters import list_exporters

    return {"exporters": list_exporters()}


def preview_notification(run_dir: str, sink: str = "teams") -> dict[str, Any]:
    from .notify import send_notification

    return send_notification(run_dir=run_dir, sink=sink, dry_run=True)


def rules_inventory(
    tag: str = "",
    path_prefix: str = "",
    product_family: str = "",
    license_tier: str = "",
    audit_level: str = "",
) -> dict[str, Any]:
    rows = list_rule_inventory(
        tag=tag or None,
        path_prefix=path_prefix or None,
        product_family=product_family or None,
        license_tier=license_tier or None,
        audit_level=audit_level or None,
    )
    return {"count": len(rows), "rules": rows}


def main() -> int:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install Auditex with the MCP extra: pip install -e '.[mcp]'", file=sys.stderr)
        return 2

    server = FastMCP("auditex")

    def auditex_list_profiles() -> dict[str, Any]:
        return {"profiles": [profile.__dict__ for profile in PROFILES.values()]}

    def auditex_list_collectors(config_path: str = "configs/collector-definitions.json") -> dict[str, Any]:
        return list_collectors(config_path=config_path)

    def auditex_list_adapters() -> dict[str, Any]:
        return list_adapters()

    def auditex_list_response_actions() -> dict[str, Any]:
        return list_response_actions()

    def auditex_auth_status() -> dict[str, Any]:
        return auditex_auth.get_auth_status()

    def auditex_auth_list() -> dict[str, Any]:
        return auditex_auth.list_connections()

    def auditex_auth_use(connection_name: str) -> dict[str, Any]:
        return auditex_auth.use_connection(connection_name)

    def auditex_auth_import_token(name: str, token: str, tenant_id: str = "") -> dict[str, Any]:
        return auditex_auth.import_token_context(name=name, token=token, tenant_id=tenant_id or None)

    def auditex_auth_inspect_token(token: str) -> dict[str, Any]:
        return auditex_auth.inspect_token_claims(token)

    def auditex_auth_capability(name: str = "", collectors: str = "", auditor_profile: str = "auto") -> dict[str, Any]:
        selected_collectors = [item.strip() for item in collectors.split(",") if item.strip()]
        return auditex_auth.capability_for_context(
            name=name or None,
            collectors=selected_collectors,
            auditor_profile=auditor_profile,
        )

    def auditex_contract_schema_manifest(schema_dir: str = "schemas") -> dict[str, Any]:
        return contract_schema_manifest(schema_dir=schema_dir)

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

    def auditex_summarize_run(run_dir: str) -> dict[str, Any]:
        return summarize_run(run_dir)

    def auditex_diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
        return diff_runs(run_a, run_b)

    def auditex_compare_runs(run_dirs: list[str], allow_cross_tenant: bool = False) -> dict[str, Any]:
        return compare_many_runs(run_dirs, allow_cross_tenant=allow_cross_tenant)

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
