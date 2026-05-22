# Auditex Security and Privacy Model

Auditex is designed for authorized tenant auditing. The default public product surface is audit-only.

## Authorization Boundary

Use Auditex only against tenants you own or where the tenant owner has given explicit written authorization. The operator is responsible for Microsoft, Google, legal, regulatory, and data-protection obligations.

## Read-Only Policy

The audit plane must not write to production tenants. This applies to:

- Microsoft 365 audit runs,
- Google Workspace audit runs,
- probes,
- report rendering,
- exports,
- MCP audit tools,
- customer-pack creation,
- customer-pack verification.

Any response or remediation experiment must stay outside the public 1.0 audit flow and behind explicit local development gating.

## No-Content-Read Policy

Auditex audit collectors must not read:

- Gmail message bodies,
- Google Drive file content,
- Exchange mailbox body content,
- SharePoint file content,
- OneDrive file content.

Metadata and settings may still contain personal data, such as user names, email addresses, group membership, device metadata, OAuth grant metadata, sharing metadata, and audit event metadata. Treat every bundle as confidential.

## Local Evidence Handling

Evidence is written locally under the selected output directory. Raw evidence is not sent to an external service by Auditex. Customer handoff packs copy selected customer-safe artifacts and include checksums.

Store output folders according to customer retention rules. Delete stale bundles when retention expires.

## Auth Material Handling

Auditex must not commit or ship:

- Azure app auth values,
- Google service-account files,
- OAuth client files,
- OAuth cache files,
- bearer material,
- refresh material,
- raw credential dumps,
- customer signing keys.

Use local paths such as `.secrets/` or a dedicated auth folder excluded from git. Do not put auth paths into repo defaults.

## API Inventory And Auditability

Every finalized audit bundle should include `api-inventory.json`. This records:

- declared collectors,
- observed calls,
- required permissions,
- observed and missing permissions,
- read/write classification,
- content-read classification,
- mutating and content-read counts,
- scope risk.

Validation fails audit-plane bundles that report tenant writes or body/file content reads.

## Customer Pack Integrity

Customer packs include:

- `pack-manifest.json`,
- `checksums.sha256`,
- generated-file hashes,
- source-artifact hashes.

Verify before handoff:

```bash
auditex report verify-pack customer-pack
```

If verification fails, regenerate from the original run directory.

## AI And MCP Use

Use AI and MCP only against bundle artifacts intended for reasoning:

- `summary.json`,
- `summary.md`,
- `data-handling.json`,
- `audit-plan.json`,
- `api-inventory.json`,
- `reports/report-pack.json`,
- `proof-table` rows,
- `ai_context.json`,
- `validation.json`.

Do not ask MCP clients to infer facts without evidence. If evidence is missing, the answer should say so.

## No Telemetry Rule

Do not add external crash telemetry or analytics. Diagnostics stay local unless a customer-approved runbook says otherwise.

## Incident Handling

If sensitive auth material is found in a bundle or pack:

1. Stop handoff.
2. Remove the pack from the transfer channel.
3. Rotate the exposed auth material.
4. Regenerate the run or pack after fixing the source.
5. Run pack verification again.
6. Record the incident according to the customer's process.
