from __future__ import annotations

import argparse
import inspect
import json
import sys
from functools import wraps
from pathlib import Path
from typing import Any

from azure_tenant_audit.adapters import list_adapters as _list_adapters
from azure_tenant_audit.citations import build_citation_summary
from azure_tenant_audit.config import CollectorConfig
from azure_tenant_audit.contracts import contract_schema_manifest
from azure_tenant_audit.guarded_io import (
    current_context,
    guard_session,
    guarded_operation,
    open_pinned_binary,
)
from azure_tenant_audit.output_redaction import (
    PROFILE_SHAREABLE,
    assert_snapshot_stable,
    redact_payload,
    snapshot_run,
)
from azure_tenant_audit.profiles import PROFILES
from azure_tenant_audit.resources import resolve_resource_path
from azure_tenant_audit.response import response_actions
from azure_tenant_audit.scope_catalog import (
    build_google_scope_catalog,
    build_m365_scope_catalog,
)
from azure_tenant_audit.secret_hygiene import build_argument_parser
from azure_tenant_audit.versioning import package_version_line

from .command_builders import (
    AuditRunCommandSpec,
    GoogleRunCommandSpec,
    ProbeCommandSpec,
    ResponseCommandSpec,
    build_audit_run_command,
    build_google_run_command,
)
from .command_builders import (
    build_probe_command as build_probe_tool_command,
)
from .command_builders import (
    build_response_command as build_response_tool_command,
)
from .command_runner import run_cli_command
from .features import response_disabled_message, response_enabled
from .mcp_paths import McpPathError, mcp_root
from .mcp_registry import iter_tool_specs, register_fastmcp_tools
from .rules import list_rule_inventory
from .run_bundle import RunBundle
from .setup_guide import build_setup_guide

SUPPORTED_PLANES = ("inventory", "full", "export")
SUPPORTED_PROBE_MODES = ("app", "response")

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
        # R024: the default names a shipped resource; an installed server or another working directory finds it there.
        path = resolve_resource_path(config_path)
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
        permission_hints=load_permission_hints(resolve_resource_path("configs/collector-permissions.json")),
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


def contract_schema_inventory(schema_dir: str = "schemas") -> dict[str, Any]:
    payload = contract_schema_manifest(schema_dir=schema_dir)
    path = Path(schema_dir)
    resolved = path if path.exists() else resolve_resource_path(schema_dir)
    citations = [
        {"artifact_path": "src/azure_tenant_audit/contracts.py", "reason": "Contract schema manifest builder and bundle validation rules."},
        {"artifact_path": str(path), "reason": "Shipped schema directory requested by this MCP helper."},
    ]
    evidence_missing = [] if resolved.exists() else [str(path)]
    return _with_static_citations(payload, citations, evidence_missing=evidence_missing)


def build_cli_command(
    *,
    tenant_name: str,
    out_dir: str,
    tenant_id: str | None = None,
    auditor_profile: str = "global-reader",
    plane: str = "inventory",
    client_id: str | None = None,
    certificate_path: str | None = None,
    certificate_thumbprint: str | None = None,
    certificate_password_env: str | None = None,
    certificate_password_file: str | None = None,
    collectors: str | list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
    offline: bool = False,
    sample_path: str = "examples/sample_audit_bundle/sample_result.json",
) -> list[str]:
    """Audit command for the MCP tools: the reader app's certificate options, never a secret, token or auth context."""
    return build_audit_run_command(
        AuditRunCommandSpec(
            tenant_name=tenant_name,
            out_dir=out_dir,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            plane=plane,
            client_id=client_id,
            certificate_path=certificate_path,
            certificate_thumbprint=certificate_thumbprint,
            certificate_password_env=certificate_password_env,
            certificate_password_file=certificate_password_file,
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
    surface: str = "all",
    since: str | None = None,
    until: str | None = None,
    allow_lab_response: bool = False,
    client_id: str | None = None,
    certificate_path: str | None = None,
    certificate_thumbprint: str | None = None,
    certificate_password_env: str | None = None,
    certificate_password_file: str | None = None,
) -> list[str]:
    """Probe command for the MCP tools: the reader app with its certificate, never a secret, token or auth context."""
    return build_probe_tool_command(
        ProbeCommandSpec(
            tenant_name=tenant_name,
            out_dir=out_dir,
            tenant_id=tenant_id,
            auditor_profile=auditor_profile,
            mode="app",
            surface=surface,
            since=since,
            until=until,
            allow_lab_response=allow_lab_response,
            client_id=client_id,
            certificate_path=certificate_path,
            certificate_thumbprint=certificate_thumbprint,
            certificate_password_env=certificate_password_env,
            certificate_password_file=certificate_password_file,
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
            adapter_override=adapter_override,
            command_override=command_override,
            allow_adapter_override=allow_adapter_override,
            allow_command_override=allow_command_override,
            python_executable=sys.executable,
        ),
        supported_actions=response_actions(),
    )


# MCP clients cap a tool result at tens of kilobytes; a summary over this size drops its heaviest sections (R025).
SUMMARY_RESPONSE_BUDGET_BYTES = 48_000
# Sections a size-capped summary may drop, and the tool that reads each one in full.
_SUMMARY_DROPPABLE_SECTIONS = {
    "report_pack": "auditex_report_analyze",
    "findings": "auditex_proof_table",
    "action_plan": "auditex_report_analyze",
    "api_inventory": "auditex_api_inventory",
    "ai_context": "auditex_report_preview",
    "audit_plan": "auditex_enterprise_handoff",
    "coverage_ledger": "auditex_enterprise_handoff",
    "capability_matrix": "auditex_permissions_ledger",
    "blockers": "auditex_list_blockers",
    "diagnostics": "auditex_list_blockers",
    "validation": "auditex_enterprise_handoff",
    "data_handling": "auditex_enterprise_handoff",
    "live_readiness": "auditex_enterprise_handoff",
    "toolchain_readiness": "auditex_enterprise_handoff",
    "auth_context": "auditex_enterprise_handoff",
    "summary_md": "auditex_report_preview",
    "report_pack_citation_summary": "auditex_report_analyze",
}


_MANIFEST_ARTIFACTS = "manifest.artifacts"


def _json_size(value: Any) -> int:
    return len(json.dumps(value, default=str))


def _cap_summary(result: dict[str, Any], budget: int = SUMMARY_RESPONSE_BUDGET_BYTES) -> dict[str, Any]:
    """Drop the largest droppable sections until the summary fits ``budget``; each is listed in ``omitted_sections``.

    Identity, the summary, validation status, coverage gaps, the scorecard and citations always stay. A section that
    is dropped keeps its path, its size and item count, and the tool that reads it in full.
    """
    if _json_size(result) <= budget:
        return result
    capped = dict(result)
    omitted: dict[str, Any] = {}
    sizes = sorted(
        ((_json_size(capped[key]), key) for key in _SUMMARY_DROPPABLE_SECTIONS if key in capped), reverse=True
    )
    manifest = capped.get("manifest")
    if isinstance(manifest, dict) and isinstance(manifest.get("artifacts"), list):
        # The manifest stays, but its artifact list grows with every raw page and chunk of a large run.
        sizes = sorted([*sizes, (_json_size(manifest["artifacts"]), _MANIFEST_ARTIFACTS)], reverse=True)
    for size, key in sizes:
        if key == _MANIFEST_ARTIFACTS:
            capped["manifest"] = {name: item for name, item in capped["manifest"].items() if name != "artifacts"}
            value: Any = manifest["artifacts"]
            entry: dict[str, Any] = {"bytes": size}
            path = capped.get("manifest_path")
        else:
            value = capped.pop(key)
            entry = {"bytes": size, "read_with": _SUMMARY_DROPPABLE_SECTIONS[key]}
            path = capped.get(f"{key}_path")
        if isinstance(value, list):
            entry["items"] = len(value)
        elif isinstance(value, dict) and isinstance(value.get("findings"), list):
            entry["findings"] = len(value["findings"])
        if isinstance(path, str) and path:
            entry["path"] = path
        omitted[key] = entry
        capped["omitted_sections"] = omitted
        capped["summary_truncated"] = True
        if _json_size(capped) <= budget:
            return capped
    return _cap_kept_sections(capped, omitted, budget)


# Keys the capped summary never drops: what the client needs to know the answer was cut and where to read the rest.
_SUMMARY_CORE_KEYS = frozenset({"omitted_sections", "summary_truncated", "citations", "citation_summary", "evidence_missing"})


def _cap_kept_sections(capped: dict[str, Any], omitted: dict[str, Any], budget: int) -> dict[str, Any]:
    """Second stage of ``_cap_summary`` (R025): the kept sections alone are over ``budget`` (hundreds of coverage gaps
    repeated in the manifest, the summary and the run metadata). Drop their nested lists and mappings, largest first,
    keeping each section's scalar fields (tenant, run id, status); then, if still over, whole sections.
    """
    capped["omitted_sections"] = omitted
    capped["summary_truncated"] = True
    nested: list[tuple[int, str, str | None]] = []
    for key, value in capped.items():
        if key in _SUMMARY_CORE_KEYS:
            continue
        if isinstance(value, dict):
            nested.extend(
                (_json_size(item), key, name) for name, item in value.items() if isinstance(item, (dict, list)) and item
            )
        elif isinstance(value, list) and value:
            nested.append((_json_size(value), key, None))
    for size, key, name in sorted(nested, key=lambda row: row[0], reverse=True):
        if _json_size(capped) <= budget:
            return capped
        if name is None:
            value = capped.pop(key)
            label = key
        else:
            section = dict(capped[key])
            value = section.pop(name)
            capped[key] = section
            label = f"{key}.{name}"
        omitted[label] = _omitted_entry(capped, key, value, size)
    for key in sorted(
        (key for key in capped if key not in _SUMMARY_CORE_KEYS), key=lambda item: _json_size(capped[item]), reverse=True
    ):
        if _json_size(capped) <= budget:
            break
        value = capped.pop(key)
        omitted[key] = _omitted_entry(capped, key, value, _json_size(value))
    return capped


def _omitted_entry(capped: dict[str, Any], key: str, value: Any, size: int) -> dict[str, Any]:
    entry: dict[str, Any] = {"bytes": size}
    if isinstance(value, list):
        entry["items"] = len(value)
    path = capped.get(f"{key}_path")
    if isinstance(path, str) and path:
        entry["path"] = path
    return entry


@guarded_operation
def summarize_run(run_dir: str) -> dict[str, Any]:
    """The run summary an MCP client receives: the shareable redaction over the complete payload (its citation
    summary re-derived), capped at ``SUMMARY_RESPONSE_BUDGET_BYTES`` by dropping its heaviest sections. The
    operator's own terminal reads ``summarize_run_raw``."""
    current_context().bind_run(run_dir)
    before = snapshot_run(run_dir)
    result = redact_payload(summarize_run_raw(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    # Dropping keys after redaction cannot reveal anything the redaction removed.
    return _cap_summary(result)


def summarize_run_raw(run_dir: str) -> dict[str, Any]:
    """Operator-only: the whole run summary, unredacted (``auditex summarize`` and ``auditex probe summarize``)."""
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


def diff_run_directories(run_a: str, run_b: str, *, classic: bool = False) -> dict[str, Any]:
    """The gated two-run diff: the same tenant gate, bundle verification and reassessment check as compare (R054)."""
    from .compare import diff_two_runs

    return diff_two_runs(run_a, run_b, classic=classic)


def diff_runs(run_a: str, run_b: str, classic: bool = False) -> dict[str, Any]:
    # Discover normalised evidence before the diff reader visits it and retain both snapshots until after redaction.
    before = [(run_dir, snapshot_run(run_dir)) for run_dir in (run_a, run_b)]
    redact_payload({}, run_dirs=[run_a, run_b], profile=PROFILE_SHAREABLE)
    result = redact_payload(diff_run_directories(run_a, run_b, classic=classic), run_dirs=[run_a, run_b], profile=PROFILE_SHAREABLE)
    for run_dir, snapshot in before:
        assert_snapshot_stable(run_dir, snapshot)
    return result


def list_blockers(run_dir: str) -> dict[str, Any]:
    """The blockers an MCP client receives (shareable redaction); the operator's terminal reads ``list_blockers_raw``."""
    before = snapshot_run(run_dir)
    result = redact_payload(list_blockers_raw(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def list_blockers_raw(run_dir: str) -> dict[str, Any]:
    """Operator-only: the blockers, unredacted (``auditex blockers``)."""
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

    before = [(run_dir, snapshot_run(run_dir)) for run_dir in run_dirs]
    redact_payload({}, run_dirs=run_dirs, profile=PROFILE_SHAREABLE)
    result = redact_payload(
        compare_runs(run_dirs, allow_cross_tenant=allow_cross_tenant, classic=classic), run_dirs=list(run_dirs), profile=PROFILE_SHAREABLE
    )
    for run_dir, snapshot in before:
        assert_snapshot_stable(run_dir, snapshot)
    return result


def normalize_external_assessment(source: str, input_path: str, tenant_id: str | None = None) -> dict[str, Any]:
    from .external_assessments import import_assessment

    return redact_payload(import_assessment(source, input_path, tenant_id=tenant_id), profile=PROFILE_SHAREABLE)


def compare_external_assessment_files(
    assessment_paths: list[str], expected_tenant_id: str | None = None, run_dir: str | None = None,
) -> dict[str, Any]:
    from .assessment_review import compare_external_assessments

    before = snapshot_run(run_dir) if run_dir else None
    if run_dir:
        redact_payload({}, run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    result = redact_payload(
        compare_external_assessments(assessment_paths, expected_tenant_id=expected_tenant_id, run_dir=run_dir),
        run_dirs=[run_dir] if run_dir else [],
        profile=PROFILE_SHAREABLE,
    )
    if run_dir and before is not None:
        assert_snapshot_stable(run_dir, before)
    return result


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
        profile=PROFILE_SHAREABLE,
    )


def analyze_report(run_dir: str) -> dict[str, Any]:
    from .reporting import analyze_report as _analyze_report

    before = snapshot_run(run_dir)
    result = redact_payload(_analyze_report(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def read_local_answer(run_dir: str) -> dict[str, Any]:
    """The run's local answer re-checked against its rule assessment (``local_answer.load_answer``), shareable
    redaction applied; runs no model and writes nothing. ``status: unavailable`` with the reason when the run has no
    answer or it does not check."""
    from .local_answer import LocalAnswerError, load_answer

    before = snapshot_run(run_dir)
    try:
        answer = load_answer(run_dir)
    except LocalAnswerError as exc:
        answer = {"status": "unavailable", "detail": str(exc)}
    result = redact_payload(answer, run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def api_inventory(run_dir: str) -> dict[str, Any]:
    from .reporting import api_call_inventory as _api_call_inventory

    before = snapshot_run(run_dir)
    result = redact_payload(_api_call_inventory(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def permissions_ledger(run_dir: str) -> dict[str, Any]:
    from .reporting import permissions_ledger as _permissions_ledger

    before = snapshot_run(run_dir)
    result = redact_payload(_permissions_ledger(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def proof_table(run_dir: str) -> dict[str, Any]:
    from .reporting import proof_table as _proof_table

    before = snapshot_run(run_dir)
    result = redact_payload(_proof_table(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def enterprise_handoff(run_dir: str) -> dict[str, Any]:
    from .reporting import enterprise_handoff as _enterprise_handoff

    before = snapshot_run(run_dir)
    redact_payload({}, run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    result = redact_payload(_enterprise_handoff(run_dir), run_dirs=[run_dir], profile=PROFILE_SHAREABLE)
    assert_snapshot_stable(run_dir, before)
    return result


def verify_customer_pack(
    pack_dir: str,
    expect_manifest_sha256: str | None = None,
    expect_checksums_sha256: str | None = None,
) -> dict[str, Any]:
    from .reporting import verify_enterprise_handoff_pack

    return redact_payload(
        verify_enterprise_handoff_pack(
            pack_dir,
            expect_manifest_sha256=expect_manifest_sha256,
            expect_checksums_sha256=expect_checksums_sha256,
        ),
        paths=[pack_dir],
        profile=PROFILE_SHAREABLE,
    )


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
    parser = build_argument_parser(allow_abbrev=False, prog="auditex-mcp", description="Auditex MCP server.")
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
        from azure_tenant_audit.cli_guard import parse_guarded
        parse_guarded(_build_mcp_parser(), argv)

    try:
        mcp_root()
    except McpPathError as exc:
        print(f"auditex-mcp: {exc}", file=sys.stderr)
        return 2

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install Auditex with the MCP extra: pip install -e '.[mcp]'", file=sys.stderr)
        return 2

    server = FastMCP("auditex")
    register_fastmcp_tools(server, tool_handlers())
    server.run()
    return 0


def _guard_tool(handler):
    signature = inspect.signature(handler)

    @wraps(handler)
    def guarded(*args, **kwargs):
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        with guard_session() as context:
            for name in ("run_dir", "run_dirs", "run_a", "run_b", "baseline_run_dir", "current_run_dir"):
                value = bound.arguments.get(name)
                paths = value if isinstance(value, (list, tuple)) else [value]
                for path in paths:
                    if isinstance(path, str) and path:
                        context.bind_run(path)
            for name, field in (("input_path", "input"), ("assessment_paths", "assessment"),
                                ("sample_path", "sample"), ("config_path", "config")):
                if name not in bound.arguments:
                    continue
                value = bound.arguments[name]
                parameter = signature.parameters[name]
                if parameter.default is not inspect.Parameter.empty and value == parameter.default:
                    continue  # shipped resource default
                paths = value if isinstance(value, (list, tuple)) else [value]
                for path in paths:
                    if isinstance(path, str) and path:
                        with open_pinned_binary(path, field=field, context=context):
                            pass
            return handler(*bound.args, **bound.kwargs)
    return guarded


def tool_handlers() -> dict[str, Any]:
    """The MCP tool handlers by name.

    Tools take no bearer token, client secret or auth context: Microsoft 365 tools take the reader app's client ID
    and confined paths to its certificate key and password file. Filesystem arguments are confined to the MCP root
    by ``register_fastmcp_tools`` (see ``mcp_registry`` and ``mcp_paths``).
    """
    def auditex_list_profiles() -> dict[str, Any]:
        return list_profiles()

    def auditex_list_collectors(config_path: str = "configs/collector-definitions.json", provider: str = "m365") -> dict[str, Any]:
        return list_collectors(config_path=config_path, provider=provider)

    def auditex_list_adapters() -> dict[str, Any]:
        return list_adapters()

    def auditex_list_response_actions() -> dict[str, Any]:
        return list_response_actions()

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
        return run_cli_command(command, scrub_operator_inputs=True)

    def auditex_run_certificate_audit(
        tenant_name: str,
        certificate_path: str,
        certificate_thumbprint: str,
        tenant_id: str = "",
        client_id: str = "",
        certificate_password_env: str = "",
        certificate_password_file: str = "",
        out_dir: str = "outputs/live",
        auditor_profile: str = "global-reader",
        plane: str = "full",
        collectors: str = "",
        since: str = "",
        until: str = "",
    ) -> dict[str, Any]:
        try:
            command = build_cli_command(
                tenant_name=tenant_name,
                tenant_id=tenant_id or None,
                out_dir=out_dir,
                auditor_profile=auditor_profile,
                plane=plane,
                client_id=client_id or None,
                certificate_path=certificate_path,
                certificate_thumbprint=certificate_thumbprint,
                certificate_password_env=certificate_password_env or None,
                certificate_password_file=certificate_password_file or None,
                collectors=collectors or None,
                since=since or None,
                until=until or None,
            )
        except ValueError as exc:
            return {"status": "blocked", "error": str(exc)}
        return run_cli_command(command, resumable=True)

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
        top: int | None = None,
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

    def auditex_normalize_external_assessment(
        source: str, input_path: str, tenant_id: str | None = None,
    ) -> dict[str, Any]:
        return normalize_external_assessment(source, input_path, tenant_id=tenant_id)

    def auditex_compare_external_assessments(
        assessment_paths: list[str], expected_tenant_id: str | None = None, run_dir: str | None = None,
    ) -> dict[str, Any]:
        return compare_external_assessment_files(assessment_paths, expected_tenant_id=expected_tenant_id, run_dir=run_dir)

    def auditex_probe_live(
        tenant_name: str,
        certificate_path: str,
        certificate_thumbprint: str,
        tenant_id: str = "",
        client_id: str = "",
        certificate_password_env: str = "",
        certificate_password_file: str = "",
        out_dir: str = "outputs/probes",
        auditor_profile: str = "global-reader",
        surface: str = "all",
        since: str = "",
        until: str = "",
        allow_lab_response: bool = False,
    ) -> dict[str, Any]:
        try:
            command = build_probe_command(
                tenant_name=tenant_name,
                tenant_id=tenant_id or None,
                out_dir=out_dir,
                auditor_profile=auditor_profile,
                surface=surface,
                since=since or None,
                until=until or None,
                allow_lab_response=allow_lab_response,
                client_id=client_id or None,
                certificate_path=certificate_path,
                certificate_thumbprint=certificate_thumbprint,
                certificate_password_env=certificate_password_env or None,
                certificate_password_file=certificate_password_file or None,
            )
        except ValueError as exc:
            return {"status": "blocked", "error": str(exc)}
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

    def auditex_local_answer(run_dir: str) -> dict[str, Any]:
        return read_local_answer(run_dir)

    def auditex_api_inventory(run_dir: str) -> dict[str, Any]:
        return api_inventory(run_dir)

    def auditex_permissions_ledger(run_dir: str) -> dict[str, Any]:
        return permissions_ledger(run_dir)

    def auditex_proof_table(run_dir: str) -> dict[str, Any]:
        return proof_table(run_dir)

    def auditex_enterprise_handoff(run_dir: str) -> dict[str, Any]:
        return enterprise_handoff(run_dir)

    def auditex_verify_customer_pack(
        pack_dir: str,
        expect_manifest_sha256: str | None = None,
        expect_checksums_sha256: str | None = None,
    ) -> dict[str, Any]:
        return verify_customer_pack(pack_dir, expect_manifest_sha256, expect_checksums_sha256)

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
            adapter_override=adapter_override or None,
            command_override=command_override or None,
            allow_adapter_override=allow_adapter_override,
            allow_command_override=allow_command_override,
        )
        return run_cli_command(command)

    return {name: _guard_tool(value) for name, value in locals().items() if name.startswith("auditex_") and callable(value)}


if __name__ == "__main__":
    raise SystemExit(main())
