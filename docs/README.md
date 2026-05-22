# Auditex Documentation

Start here when shipping, operating, or reviewing Auditex.

## Operator Docs

- [Repository Overview](../README.md) - public overview and quickstart.
- [Runbook](../RUNBOOK.md) - live operator setup, bootstrap, and release commands.
- [Product Manual](PRODUCT_MANUAL.md) - install, run, verify, report, export, and MCP workflows.
- [Setup Guide](SETUP_GUIDE.md) - pre-audit scopes, roles, admin steps, and setup-guide CLI usage.
- [Administrator Permission Guide](ADMIN_PERMISSION_GUIDE.md) - Microsoft 365 and Google Workspace access setup.
- [Customer Handoff Guide](CUSTOMER_HANDOFF_GUIDE.md) - evidence pack contents, integrity checks, and reviewer flow.
- [Troubleshooting Guide](TROUBLESHOOTING.md) - common auth, scope, license, report, and pack failures.
- [AI Operator Guide](AI_OPERATOR_GUIDE.md) - AI-safe setup, probe, run, and evidence-answer workflow.
- [GitHub Operator Guide](GITHUB_OPERATOR_GUIDE.md) - issue, PR, and CI guidance without raw tenant evidence.

## Product Assurance

- [Security and Privacy Model](SECURITY_PRIVACY.md) - read-only guarantees, no-content-read policy, local evidence handling, and secret rules.
- [Ship Readiness Guide](SHIP_READINESS.md) - product acceptance gates before a release is shipped.
- [Release Checklist](RELEASE_CHECKLIST.md) - command-level verification gates.
- [Release Notes](../RELEASE_NOTES.md) - v1 shipping notes.
- [Changelog](../CHANGELOG.md) - release history.
- [Output Contract](OUTPUT_CONTRACT.md) - stable bundle contract and evidence rules.
- [API Call Catalog](API_CALL_CATALOG.md) - API inventory, permission ledger, and customer API review process.

## Planning and Provenance

- [Auditex 1.0 Ultimate Audit Plan](improvement/auditex-1.0-ultimate-plan.md) - architecture and 1.0 acceptance criteria.
- [Provenance Notes](provenance/provenance.md) - shipped third-party and provenance context.

Auditex 1.0 is audit-only. Audit, probe, report, export, MCP audit tools, and customer-pack verification must not write to a production tenant or read mail/file body content.
