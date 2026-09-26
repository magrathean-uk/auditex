# Auditex documentation

This index separates operator guidance, product assurance, and provenance material. Start with the [repository README](../README.md) for a short overview and the [runbook](../RUNBOOK.md) for commands and local checks.

For repository changes, see [CONTRIBUTING.md](../CONTRIBUTING.md). For product questions and issue reports, see [SUPPORT.md](../SUPPORT.md).

## Operator docs

- [Product Manual](PRODUCT_MANUAL.md): install, audit, probe, report, export, compare, customer packs, and MCP.
- [Setup Guide](SETUP_GUIDE.md): provider scopes, roles, admin steps, and generated setup plans.
- [Administrator Permission Guide](ADMIN_PERMISSION_GUIDE.md): Microsoft 365 and Google Workspace access models.
- [Customer Handoff Guide](CUSTOMER_HANDOFF_GUIDE.md): pack contents, integrity checks, evidence review, and partial runs.
- [Troubleshooting Guide](TROUBLESHOOTING.md): local runtime, authentication, provider scope, report, and pack failures.

## Assurance and contracts

- [Security and Privacy Model](SECURITY_PRIVACY.md): authorization boundary, read-only rules, no-content-read policy, local evidence, auth material, and telemetry.
- [Output Contract](OUTPUT_CONTRACT.md): finalized bundle artifacts, validation, evidence references, and MCP contract surfaces.
- [API Call Catalog](API_CALL_CATALOG.md): the API inventory and permission ledger used for customer review.

## Provenance

- [Provenance Notes](provenance/provenance.md): retained third-party and research provenance.
- [Third-Party Notices](../THIRD_PARTY_NOTICES.md): dependency and vendored-component notices.
- [License](../LICENSE): Apache License 2.0 text.

## Product boundary

Auditex's public audit, probe, report, export, MCP audit, and customer-pack verification surfaces are read-only with respect to production tenants and do not read mail or file body content. The `tenant-bootstrap/` directory is a separate lab helper for seeding and rehearsing test environments; follow its own scripts and keep its credentials and generated runs local.
