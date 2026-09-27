# Auditex documentation

This index separates operator guidance, product assurance, and provenance material. Start
with the [repository README](../README.md) for a short overview and the
[runbook](development/runbook.md) for commands and local checks.

For repository changes, see [CONTRIBUTING.md](../.github/CONTRIBUTING.md). For product
questions and issue reports, see [SUPPORT.md](../.github/SUPPORT.md).

## Operator docs

- [Product Manual](guides/product-manual.md): install, audit, probe, report, export, compare, customer packs, and MCP.
- [Setup Guide](guides/setup-guide.md): provider scopes, roles, admin steps, and generated setup plans.
- [Administrator Permission Guide](guides/admin-permission-guide.md): Microsoft 365 and Google Workspace access models.
- [Customer Handoff Guide](guides/customer-handoff-guide.md): pack contents, integrity checks, evidence review, and partial runs.
- [Troubleshooting Guide](guides/troubleshooting.md): local runtime, authentication, provider scope, report, and pack failures.

## Assurance and contracts

- [Security and Privacy Model](reference/security-privacy.md): authorization boundary, read-only rules, no-content-read policy, local evidence, auth material, and telemetry.
- [Output Contract](reference/output-contract.md): finalized bundle artifacts, validation, evidence references, and MCP contract surfaces.
- [API Call Catalog](reference/api-call-catalog.md): the API inventory and permission ledger used for customer review.

## Legal

- [Trademarks](legal/trademarks.md)
- [Third-party notices](legal/third-party-notices.md): dependency and vendored-component notices.
- [NOTICE](../NOTICE) and [License](../LICENSE): Apache License 2.0 text.

## Provenance

- [Provenance Notes](provenance/provenance.md): retained third-party and research provenance.

## Product boundary

Auditex's public audit, probe, report, export, MCP audit, and customer-pack verification surfaces are read-only with respect to production tenants and do not read mail or file body content. The `tenant-bootstrap/` directory is a separate lab helper for seeding and rehearsing test environments; follow its own scripts and keep its credentials and generated runs local.
