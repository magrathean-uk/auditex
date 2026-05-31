# Auditex Documentation

Start here when operating or reviewing Auditex.

## Repository Agent Starting Points

- [Agent Notes](../AGENTS.md) - repo map, command matrix, edit guardrails, generated-file rules, and done criteria for future Codex sessions.
- [Runbook](../RUNBOOK.md) - local setup, live operator flows, tenant bootstrap, and verification commands.
- [Repository Overview](../README.md) - public overview, quickstart, CLI examples, and output contract summary.

## Operator Docs

- [Product Manual](PRODUCT_MANUAL.md) - install, run, verify, report, export, and MCP workflows.
- [Setup Guide](SETUP_GUIDE.md) - pre-audit scopes, roles, admin steps, and setup-guide CLI usage.
- [Administrator Permission Guide](ADMIN_PERMISSION_GUIDE.md) - Microsoft 365 and Google Workspace access setup.
- [Customer Handoff Guide](CUSTOMER_HANDOFF_GUIDE.md) - evidence pack contents, integrity checks, and reviewer flow.
- [Troubleshooting Guide](TROUBLESHOOTING.md) - common auth, scope, license, report, and pack failures.

## Product Assurance

- [Security and Privacy Model](SECURITY_PRIVACY.md) - read-only guarantees, no-content-read policy, local evidence handling, and secret rules.
- [Output Contract](OUTPUT_CONTRACT.md) - stable bundle contract and evidence rules.
- [API Call Catalog](API_CALL_CATALOG.md) - API inventory, permission ledger, and customer API review process.

## Planning and Provenance

- [Next 5 Release Roadmap](AUDITEX_NEXT_5_RELEASE_ROADMAP.md) - planning context and backlog; not live operator truth.
- [Provenance Notes](provenance/provenance.md) - shipped third-party and provenance context.

Auditex 1.0 is audit-only. Audit, probe, report, export, MCP audit tools, and customer-pack verification must not write to a production tenant or read mail/file body content.
