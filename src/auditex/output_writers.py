"""The inventory of output writers and how the output redaction boundary treats each.

Three tables, all checked by ``tests/test_writer_sinks_d3.py``:

* ``WRITER_INVENTORY``: the writers that produce shareable output (or are expressly private working files), with
  profile and audience; every ``shareable`` one must reach the redaction.
* ``SINK_INVENTORY``: every function under ``src/`` that an AST scan finds writing a file, printing a
  non-literal value or sending over the network, classified ``routed`` (reaches the redaction, directly or through the
  named function), ``profiled`` (local by default) or ``private`` (with the reason). A hit with no entry fails the test; an entry that matches
  nothing fails it too.
* ``MCP_TOOL_INVENTORY``: every MCP tool, classified by what its response carries.

The scan is by name and by shape (see ``SCAN_LIMITS``): it finds the usual ways of writing, printing and sending,
not every way. Add a writer, classify it, and (if routed) redact it. The decided boundary is in
``docs/reference/security-privacy.md`` ("Output redaction boundary"); the function is
``azure_tenant_audit.output_redaction.redact_output``.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase

from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_LOCAL,
    PROFILE_SHAREABLE,
)


@dataclass(frozen=True)
class WriterEntry:
    """One output writer and how it is treated; checked against the source by the structural test."""

    module: str
    qualname: str
    kind: str  # "shareable", "profiled" (local default), or "private"
    profile: str | None
    audience: str


WRITER_INVENTORY: tuple[WriterEntry, ...] = (
    WriterEntry("auditex.reporting", "preview_report", "profiled", PROFILE_LOCAL, "local by default; MCP and customer pack pass their profiles"),
    WriterEntry("auditex.reporting", "render_report", "profiled", PROFILE_LOCAL, "local by default; built-in exporters pass shareable"),
    WriterEntry("auditex.exporters", "_run_builtin", "shareable", PROFILE_SHAREABLE, "built-in report exporters"),
    WriterEntry("auditex.reporting", "_write_text_artifact", "shareable", PROFILE_CUSTOMER_PACK, "every generated customer-pack file"),
    WriterEntry("auditex.reporting", "_copy_source_artifact", "shareable", PROFILE_CUSTOMER_PACK, "redacted customer-pack source derivatives"),
    WriterEntry("auditex.reporting", "write_enterprise_handoff_pack", "shareable", PROFILE_CUSTOMER_PACK, "customer pack manifest and payloads"),
    WriterEntry("auditex.cli", "_emit_report_payload", "shareable", PROFILE_SHAREABLE, "report api-calls, permissions, proof-table and handoff files and stdout"),
    WriterEntry("auditex.cli", "_emit_assessment", "private", None, "operator-supplied assessment re-emitted outside bundles; not run evidence"),
    WriterEntry("auditex.notify", "send_notification", "shareable", PROFILE_CUSTOMER_PACK, "webhook, SMTP, Jira and GitHub sinks"),
    WriterEntry("auditex.explorer", "write_explorer", "private", None, "operator's local interactive run explorer"),
    WriterEntry("auditex.model_serving", "assess_run", "private", None, "assessment file; the model view is redacted by the projection"),
    WriterEntry("auditex.model_serving", "assess_scubagear_export", "private", None, "model assessment file for an imported export; as assess_run"),
    WriterEntry("auditex.rule_assessment", "assess_run", "private", None, "assessment file; the model view is redacted by the projection"),
    WriterEntry("auditex.rule_assessment", "assess_scubagear_export", "private", None, "model assessment file for an imported export; as assess_run"),
    WriterEntry("azure_tenant_audit.output", "AuditWriter.write_report_pack", "private", None, "unmodified working report pack inside the run bundle"),
    WriterEntry("azure_tenant_audit.output", "AuditWriter.*", "private", None, "run bundle working files (raw, normalized, summaries, manifests)"),
    WriterEntry("azure_tenant_audit.output", "AuditLogger.*", "private", None, "audit-log.jsonl: private run log, diagnostics masked by the command-output boundary"),
    WriterEntry("azure_tenant_audit.cli", "run_offline", "private", None, "offline replay copy inside the run's raw directory"),
)


SCAN_LIMITS = (
    "The scan reads source text only. It sees: open()/os.fdopen() with a write mode, os.open() with write flags, "
    "Path.write_text/write_bytes, write_private_*, copy_private_file, secure_write_*, shutil copies, .write(), "
    "json/pickle/yaml dump, print() of a non-literal value, and HTTP/SMTP sends through requests, a session, an "
    "opener, smtplib or urlopen (by call name and receiver name). It does not see: a write reached through an "
    "alias or a callable stored in a variable, os.write on a raw descriptor, sqlite writes, subprocess commands that "
    "write, logging handlers, writes in non-Python files, or third-party code. It does not follow data: a "
    "'routed' function is checked to call the redaction (or be reached only from a function that does), not to "
    "redact every value it writes."
)


@dataclass(frozen=True)
class SinkEntry:
    """How the boundary treats one function (or a fnmatch pattern of functions) that the scan finds sinking data.

    ``pattern`` is ``"module:qualname"`` with ``*`` wildcards. ``via`` (routed entries) names the function that
    performs the redaction: either the entry's own function calls a redaction helper, or ``via`` is
    ``"module:qualname"`` of a function that calls the sink function and a redaction helper.
    """

    pattern: str
    classification: str  # "routed", "profiled" or "private"
    reason: str
    via: str | None = None

    def matches(self, module: str, qualname: str) -> bool:
        return fnmatchcase(f"{module}:{qualname}", self.pattern)


_NOTIFY_VIA = "auditex.notify:send_notification"
SINK_INVENTORY: tuple[SinkEntry, ...] = (
    # -- routed through the redaction ---------------------------------------------------------------------------
    SinkEntry("auditex.reporting:render_report", "profiled", "local report by default; built-in exporters select shareable", "auditex.reporting:preview_report"),
    SinkEntry("auditex.reporting:_write_text_artifact", "routed", "every generated customer-pack file", "auditex.reporting:_write_text_artifact"),
    SinkEntry("auditex.reporting:_copy_source_artifact", "routed", "every source artifact is a redacted derivative (run-manifest.json made pack-relative, the other JSON files under customer_pack with the run salt); the hash manifest is copied only when redaction leaves it unchanged; operator-inputs/ is never copied", "auditex.reporting:_copy_source_artifact"),
    SinkEntry("auditex.reporting:write_enterprise_handoff_pack", "routed", "pack manifest", "auditex.reporting:write_enterprise_handoff_pack"),
    SinkEntry("auditex.cli:_emit_report_payload", "routed", "report payload files and stdout", "auditex.cli:_emit_report_payload"),
    SinkEntry("auditex.notify:_send_webhook", "routed", "webhook body: the payload is the redacted envelope", _NOTIFY_VIA),
    SinkEntry("auditex.notify:_send_smtp", "routed", "e-mail body: the payload is the redacted envelope", _NOTIFY_VIA),
    SinkEntry("auditex.notify:_send_jira", "routed", "Jira issue: the payload is the redacted envelope", _NOTIFY_VIA),
    SinkEntry("auditex.notify:_send_github", "routed", "GitHub issue: the payload is the redacted envelope", _NOTIFY_VIA),
    # -- private: operator-only files, terminal output, configuration, collection --------------------------------
    SinkEntry("auditex.notify:_jira_search_existing", "private", "GET carrying the project key and the fingerprint digest only"),
    SinkEntry("auditex.notify:_github_search_existing_issue", "private", "GET carrying the repository and the fingerprint digest only"),
    SinkEntry("auditex.auth:*", "private", "operator's credential and connection files (0600), never report content"),
    SinkEntry("auditex.auth_runtime:*", "private", "operator's auth-context store (0600)"),
    SinkEntry("auditex.google_workspace.auth:build_google_credentials", "private", "operator's Google credential file (0600)"),
    SinkEntry("auditex.bootstrap:print_doctor_report", "private", "operator terminal: toolchain status; diagnostics masked by the command-output boundary"),
    SinkEntry("auditex.cli:_emit_assessment", "private", "operator-supplied assessment re-emitted to the operator; not run evidence"),
    SinkEntry("auditex.cli:_emit_gate_result", "private", "operator terminal and the operator's own CI log: gate verdict and ids (open item for product)"),
    SinkEntry("auditex.cli:_gate_run_refusal", "private", "operator terminal and CI: fixed blocked gate JSON, with no refused paths or values"),
    SinkEntry("auditex.cli:main", "private", "operator terminal: summarize, blockers, diff, compare, probe, auth, models, rules, verify-pack and customer-pack results (pack path); report commands go through _emit_report_payload, notifications through send_notification"),
    SinkEntry("auditex.demo:*", "private", "demo tenant script output (synthetic data)"),
    SinkEntry("auditex.explorer:write_explorer", "private", "operator's local interactive run explorer"),
    SinkEntry("auditex.google_workspace.run:run_google_*", "private", "operator terminal output of live Google runs"),
    SinkEntry("auditex.guided:*", "private", "operator terminal prompts and the operator's own setup file"),
    SinkEntry("auditex.mcp_server:main", "private", "server start-up text on the operator's terminal; tool responses are inventoried in MCP_TOOL_INVENTORY"),
    SinkEntry("auditex.model_serving:ModelClient.*", "private", "model endpoint call (loopback unless the operator says otherwise); input is the redacted projection"),
    SinkEntry("auditex.model_serving:assess_run", "private", "model assessment file; model view is redacted by the projection input gate"),
    SinkEntry("auditex.model_serving:assess_scubagear_export", "private", "model assessment file for an imported export; as assess_run"),
    SinkEntry("auditex.model_training:*", "private", "training-pack toolchain output"),
    SinkEntry("auditex.rule_assessment:assess_run", "private", "model assessment file; model view is redacted by the projection input gate"),
    SinkEntry("auditex.rule_assessment:assess_scubagear_export", "private", "model assessment file for an imported export; as assess_run"),
    SinkEntry("azure_tenant_audit.adapters.powershell_graph:*", "private", "builds PowerShell text for a local command; no I/O of its own"),
    SinkEntry("azure_tenant_audit.cli:run_live", "private", "operator terminal: partial-workload notice contains only fixed collector names and status text"),
    SinkEntry("azure_tenant_audit.cli:run_offline", "private", "offline replay copy inside the run's raw directory"),
    SinkEntry("azure_tenant_audit.cli_guard:guarded_cli.wrapped", "private", "operator terminal: fixed path-free unsafe-input refusal"),
    SinkEntry("azure_tenant_audit.adapters.teams_admin_rest:*", "private", "read-only Teams admin API GET with the app token (collection)"),
    SinkEntry("azure_tenant_audit.collectors.*", "private", "collection: read-only request to the audited tenant's own API"),
    SinkEntry("azure_tenant_audit.dns_lookup:*", "private", "public DNS-over-HTTPS query for a domain the operator audits"),
    SinkEntry("azure_tenant_audit.evidence_db:*", "private", "private index snapshots and the run's fixed debug notice"),
    SinkEntry("azure_tenant_audit.exposure_lookup:*", "private", "public HTTPS fetch of the audited domain's own policy files"),
    SinkEntry("azure_tenant_audit.graph:*", "private", "read-only Microsoft Graph requests and token exchange (credentials stay in the request)"),
    SinkEntry("azure_tenant_audit.guarded_io:_stdin_text_buffer_is_empty", "private", "local pipe containing only a fixed buffer-probe value"),
    SinkEntry("azure_tenant_audit.guarded_io:open_private_output", "private", "admitted private output descriptors; producer notice appends preserve an existing log mode"),
    SinkEntry("azure_tenant_audit.output:*", "private", "run bundle working files and the private audit log"),
    SinkEntry("azure_tenant_audit.perf_runtime:*", "private", "local timing metrics, no tenant evidence"),
    SinkEntry("azure_tenant_audit.power_bi:*", "private", "read-only Power BI requests"),
    SinkEntry("azure_tenant_audit.power_platform:*", "private", "read-only Power Platform requests"),
    SinkEntry("azure_tenant_audit.private_io:*", "private", "unredacted 0600 file primitives; protection is the caller's"),
    SinkEntry("azure_tenant_audit.probe:run_live_probe", "private", "operator terminal: fixed collection notices, including the default DNS endpoint; no tenant data"),
    SinkEntry("azure_tenant_audit.run_files:copy_run_file", "private", "guarded unredacted copies to a caller-selected destination"),
    SinkEntry("azure_tenant_audit.run_files:open_run_file", "private", "read-only guarded descriptor; the scanner treats its flags as a write"),
    SinkEntry("azure_tenant_audit.secret_hygiene:secure_write_*", "private", "unredacted 0600 file primitives for credentials"),
    SinkEntry("azure_tenant_audit.waivers:load_waivers", "private", "warning on the operator's terminal about a waiver file"),
)


def sink_entry(module: str, qualname: str) -> SinkEntry | None:
    """The inventory entry covering ``module:qualname``, if any."""
    for entry in SINK_INVENTORY:
        if entry.matches(module, qualname):
            return entry
    return None


@dataclass(frozen=True)
class McpToolEntry:
    """What one MCP tool's response carries and how the boundary treats it.

    ``routed``: the function in ``auditex.mcp_server`` named ``function`` calls ``redact_payload`` (or, with
    ``via``, delegates to the routed writer named there). ``no_evidence``: the response holds shipped catalogue or
    configuration data, no run evidence. ``operator_config``: saved connection metadata of the operator.
    ``diagnostic``: runs a command; its output passes the separate command-output boundary.
    """

    tool: str
    classification: str
    function: str | None = None
    via: str | None = None
    reason: str = ""


MCP_TOOL_INVENTORY: tuple[McpToolEntry, ...] = (
    McpToolEntry("auditex_summarize_run", "routed", "summarize_run"),
    McpToolEntry("auditex_probe_summarize", "routed", "summarize_run"),
    McpToolEntry("auditex_diff_runs", "routed", "diff_runs"),
    McpToolEntry("auditex_compare_runs", "routed", "compare_many_runs"),
    McpToolEntry("auditex_normalize_external_assessment", "routed", "normalize_external_assessment"),
    McpToolEntry("auditex_compare_external_assessments", "routed", "compare_external_assessment_files"),
    McpToolEntry("auditex_list_blockers", "routed", "list_blockers"),
    McpToolEntry("auditex_report_analyze", "routed", "analyze_report"),
    McpToolEntry("auditex_api_inventory", "routed", "api_inventory"),
    McpToolEntry("auditex_permissions_ledger", "routed", "permissions_ledger"),
    McpToolEntry("auditex_proof_table", "routed", "proof_table"),
    McpToolEntry("auditex_enterprise_handoff", "routed", "enterprise_handoff"),
    McpToolEntry("auditex_verify_customer_pack", "routed", "verify_customer_pack"),
    McpToolEntry("auditex_report_preview", "routed", "preview_report", via="auditex.reporting:preview_report"),
    McpToolEntry("auditex_notify_preview", "routed", "preview_notification", via=_NOTIFY_VIA),
    McpToolEntry("auditex_list_profiles", "no_evidence", reason="shipped profile catalogue"),
    McpToolEntry("auditex_list_collectors", "no_evidence", reason="shipped collector catalogue"),
    McpToolEntry("auditex_list_adapters", "no_evidence", reason="adapter catalogue"),
    McpToolEntry("auditex_list_response_actions", "no_evidence", reason="response action catalogue"),
    McpToolEntry("auditex_rules_inventory", "no_evidence", reason="shipped rule catalogue"),
    McpToolEntry("auditex_export_list", "no_evidence", reason="exporter registry"),
    McpToolEntry("auditex_contract_schema_manifest", "no_evidence", reason="shipped schema catalogue"),
    McpToolEntry("auditex_setup_guide", "no_evidence", reason="the caller's own parameters echoed back; no tenant evidence"),
    McpToolEntry("auditex_auth_status", "operator_config", reason="saved connection and tenant metadata of the operator (open item for product)"),
    McpToolEntry("auditex_auth_list", "operator_config", reason="saved connection names of the operator (open item for product)"),
    McpToolEntry("auditex_auth_use", "operator_config", reason="switches the operator's saved connection"),
    McpToolEntry("auditex_auth_capability", "operator_config", reason="capability of the operator's saved connection"),
    McpToolEntry("auditex_run_offline_validation", "diagnostic", reason="command output through the command-output boundary"),
    McpToolEntry("auditex_run_delegated_audit", "diagnostic", reason="command output through the command-output boundary"),
    McpToolEntry("auditex_google_doctor", "diagnostic", reason="command output through the command-output boundary"),
    McpToolEntry("auditex_google_probe", "diagnostic", reason="command output through the command-output boundary"),
    McpToolEntry("auditex_run_google_workspace_audit", "diagnostic", reason="command output through the command-output boundary"),
    McpToolEntry("auditex_probe_live", "diagnostic", reason="command output through the command-output boundary"),
    McpToolEntry("auditex_run_response_action", "diagnostic", reason="lab-only response command; command output through the command-output boundary"),
)
