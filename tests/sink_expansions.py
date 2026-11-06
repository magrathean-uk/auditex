"""Frozen expansion of every wildcard in ``SINK_INVENTORY``: the functions each pattern matched when it was last reviewed.

A new function that a wildcard now matches fails ``tests/test_writer_sinks_d3.py`` until its author reviews it and
adds it here (it writes, prints or sends: confirm that it is private, or route it through the redaction) or gives
it its own explicit inventory entry. Keep each tuple sorted.
"""
from __future__ import annotations

WILDCARD_EXPANSIONS: dict[str, tuple[str, ...]] = {
    'auditex.auth:*': (
        'auditex.auth:_product_auth_runtime',
        'auditex.auth:_save_json',
        'auditex.auth:save_local_auth_values',
    ),
    'auditex.auth_runtime:*': (
        'auditex.auth_runtime:_save_json',
    ),
    'auditex.demo:*': (
        'auditex.demo:_Console.line',
        'auditex.demo:_step_handoff',
    ),
    'auditex.google_workspace.run:run_google_*': (
        'auditex.google_workspace.run:run_google_live',
        'auditex.google_workspace.run:run_google_probe',
    ),
    'auditex.guided:*': (
        'auditex.guided:ProgressRenderer.__call__',
        'auditex.guided:_offer_m365_setup',
        'auditex.guided:_prompt_choice',
        'auditex.guided:run_guided',
    ),
    'auditex.model_serving:ModelClient.*': (
        'auditex.model_serving:ModelClient.__init__',
        'auditex.model_serving:ModelClient._request',
    ),
    'auditex.model_training:*': (
        'auditex.model_training:_write_json',
        'auditex.model_training:_write_jsonl',
        'auditex.model_training:prepare_training_pack',
    ),
    'azure_tenant_audit.adapters.powershell_graph:*': (
        'azure_tenant_audit.adapters.powershell_graph:PowerShellGraphAdapter._session_prelude',
    ),
    'azure_tenant_audit.adapters.teams_admin_rest:*': (
        'azure_tenant_audit.adapters.teams_admin_rest:_read_attempt.read',
    ),
    'azure_tenant_audit.collectors.*': (
        'azure_tenant_audit.collectors.power_bi:PowerBICollector.run',
        'azure_tenant_audit.collectors.power_platform:PowerPlatformCollector._safe_get',
    ),
    'azure_tenant_audit.dns_lookup:*': (
        'azure_tenant_audit.dns_lookup:DohClient.query_detailed',
    ),
    'azure_tenant_audit.evidence_db:*': (
        'azure_tenant_audit.evidence_db:build_run_evidence_index',
    ),
    'azure_tenant_audit.exposure_lookup:*': (
        'azure_tenant_audit.exposure_lookup:RequestsHttpsFetcher.get_text',
    ),
    'azure_tenant_audit.graph:*': (
        'azure_tenant_audit.graph:GraphClient._app_token',
        'azure_tenant_audit.graph:GraphClient._follow_redirects',
        'azure_tenant_audit.graph:GraphClient._request',
        'azure_tenant_audit.graph:GraphClient.app_token_for',
    ),
    'azure_tenant_audit.output:*': (
        'azure_tenant_audit.output:AuditLogger.log',
        'azure_tenant_audit.output:AuditWriter._write_text_atomic',
        'azure_tenant_audit.output:AuditWriter.write_chunk_records',
        'azure_tenant_audit.output:AuditWriter.write_export_records',
        'azure_tenant_audit.output:AuditWriter.write_index_records',
        'azure_tenant_audit.output:AuditWriter.write_partner_domains',
        'azure_tenant_audit.output:AuditWriter.write_sensitive_users',
        'azure_tenant_audit.output:_open_private',
    ),
    'azure_tenant_audit.perf_runtime:*': (
        'azure_tenant_audit.perf_runtime:write_metric_snapshot',
    ),
    'azure_tenant_audit.power_bi:*': (
        'azure_tenant_audit.power_bi:PowerBIClient.get',
    ),
    'azure_tenant_audit.power_platform:*': (
        'azure_tenant_audit.power_platform:PowerPlatformClient.request',
    ),
    'azure_tenant_audit.private_io:*': (
        'azure_tenant_audit.private_io:copy_private_file',
        'azure_tenant_audit.private_io:write_private_bytes',
        'azure_tenant_audit.private_io:write_private_text',
    ),
    'azure_tenant_audit.secret_hygiene:secure_write_*': (
        'azure_tenant_audit.secret_hygiene:secure_write_json',
        'azure_tenant_audit.secret_hygiene:secure_write_text',
    ),
}
