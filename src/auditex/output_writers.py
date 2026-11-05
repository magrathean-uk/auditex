"""The inventory of output writers and how the output redaction boundary treats each.

``tests/test_output_redaction.py`` reads this against the source: every writer listed must exist, every
``shareable`` writer must reach ``redact_output``, and no function in the scanned modules may write a file
without an entry here. Add a writer, classify it, and (if shareable) redact it. The decided boundary is in
``docs/reference/security-privacy.md`` ("Output redaction boundary"); the function is
``azure_tenant_audit.output_redaction.redact_output``.
"""
from __future__ import annotations

from dataclasses import dataclass

from azure_tenant_audit.output_redaction import (
    PROFILE_CUSTOMER_PACK,
    PROFILE_REPORT_PACK,
    PROFILE_SHAREABLE,
)


@dataclass(frozen=True)
class WriterEntry:
    """One output writer and how it is treated; checked against the source by the structural test."""

    module: str
    qualname: str
    kind: str  # "shareable" (must call redact_output / redact_for_run) or "private" (operator-only, not redacted)
    profile: str | None
    audience: str


WRITER_INVENTORY: tuple[WriterEntry, ...] = (
    WriterEntry("auditex.reporting", "preview_report", "shareable", PROFILE_SHAREABLE, "report content returned to CLI, MCP and render"),
    WriterEntry("auditex.reporting", "render_report", "shareable", PROFILE_SHAREABLE, "HTML, Markdown, JSON, CSV, SARIF and OSCAL files; exporters"),
    WriterEntry("auditex.reporting", "_write_text_artifact", "shareable", PROFILE_CUSTOMER_PACK, "every generated customer-pack file"),
    WriterEntry("auditex.reporting", "_copy_source_artifact", "shareable", PROFILE_CUSTOMER_PACK, "the customer pack's run-manifest copy (other source artifacts are integrity-bound verbatim copies)"),
    WriterEntry("auditex.reporting", "write_enterprise_handoff_pack", "shareable", PROFILE_CUSTOMER_PACK, "customer pack manifest and payloads"),
    WriterEntry("auditex.cli", "_emit_report_payload", "shareable", PROFILE_SHAREABLE, "report api-calls, permissions, proof-table and handoff files and stdout"),
    WriterEntry("auditex.cli", "_emit_assessment", "private", None, "operator-supplied assessment re-emitted outside bundles; not run evidence"),
    WriterEntry("auditex.notify", "send_notification", "shareable", PROFILE_SHAREABLE, "webhook, SMTP, Jira and GitHub sinks"),
    WriterEntry("auditex.explorer", "write_explorer", "private", None, "operator's interactive run explorer (decision pending product)"),
    WriterEntry("auditex.model_serving", "assess_run", "private", None, "model assessment file; model view is redacted by the projection; explainer text is wired by the explainer job"),
    WriterEntry("auditex.model_serving", "assess_scubagear_export", "private", None, "model assessment file for an imported export; as assess_run"),
    WriterEntry("azure_tenant_audit.output", "AuditWriter.write_report_pack", "shareable", PROFILE_REPORT_PACK, "reports/report-pack.json and action-plan.json in the run bundle"),
    WriterEntry("azure_tenant_audit.output", "AuditWriter.*", "private", None, "run bundle working files (raw, normalized, summaries, manifests)"),
    WriterEntry("azure_tenant_audit.output", "AuditLogger.*", "private", None, "audit-log.jsonl: private run log, diagnostics masked by the command-output boundary"),
    WriterEntry("azure_tenant_audit.cli", "run_offline", "private", None, "offline replay copy inside the run's raw directory"),
)
