# Auditex Security and Privacy Model

Auditex is for authorized tenant auditing. The public product surface is
audit-only.

## Authorization and audit boundaries

Use Auditex only against tenants you own or for which the tenant owner has
given explicit written authorization. The operator remains responsible for the
applicable Microsoft, Google, legal, regulatory, and data-protection
requirements.

The audit plane must not write to production tenants. This covers Microsoft
365 and Google Workspace audit runs, probes, reports, exports, MCP audit tools,
customer-pack creation, and customer-pack verification. Lab-only response
features require `AUDITEX_ENABLE_RESPONSE` to have a truthy value (`1`,
`true`, `yes`, or `on`) and are outside the public audit flow.

## Data collected

Audit collectors must not read Gmail or Exchange message bodies, or Drive,
SharePoint, or OneDrive file content. Metadata and settings can still contain
personal data, including user names, email addresses, group membership, device
metadata, OAuth grant metadata, sharing metadata, and audit-event metadata.
Treat every bundle as confidential.

`data-handling.json` describes a run's declared plane, scope risk, read-only
status, content-read status, and write actions. `api-inventory.json` records
declared collectors, observed calls, permissions, call classification, and
safety counts. Final audit-plane validation rejects bundles that report tenant
writes or body or file content reads. These artifacts support review of a run;
they do not authorize access or replace an operator's obligations.

## External lookups

Live Microsoft 365 runs with the `dns_posture` collector make unauthenticated,
read-only requests about the audited tenant's own verified domains:

- DNS-over-HTTPS queries (default resolver `cloudflare-dns.com`) for SPF,
  DMARC, DKIM, MTA-STS, TLS-RPT, and BIMI records.
- An HTTPS GET of `https://mta-sts.<domain>/.well-known/mta-sts.txt`, only when
  the `_mta-sts` TXT record exists. Redirects are not followed.
- An HTTPS GET of the public Entra OpenID discovery document,
  `https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration`.
  Only tenant-level facts (tenant ID, region scope, cloud instance) are kept,
  as the informational `public_footprint` report section.

These requests reveal the audited domain names to the DNS resolver, the
domain's web host, and Microsoft. No usernames, mailboxes, or accounts are
probed, and no user enumeration endpoint is called. Unverified domains and
domains outside the tenant are never looked up. Offline runs make no external
lookups; embedded callers can pass `public_lookups: False` in the collector
context to skip the HTTPS reads.

The opt-in `identity_protection` collector stores only aggregate risky-user
counts, never user names or UPNs. The `exchange_policy` mailbox audit bypass
check stores only a count of bypassed accounts.

## Evidence and customer packs

Evidence is written locally under the selected output directory. Auditex does
not send raw evidence to an external service. Customer handoff packs copy
selected artifacts and include checksums. Selected artifacts can still contain
customer-sensitive metadata. Create each pack in a fresh review directory,
inspect its contents and intended recipients before transfer, then store it
under the customer's retention rules and delete stale bundles when that period
ends.

Before handoff, verify the pack:

```sh
auditex report verify-pack <customer-pack-dir>
```

If verification fails, regenerate the pack from the original run directory.

Notification preview is local by default. `auditex notify send --execute`
sends the chosen notification to an external sink. Review the recipient and
payload separately from pack verification before using `--execute`.

## Credentials and local files

Never commit or ship Azure app authentication values, Google service-account
files, OAuth client files, OAuth caches, bearer or refresh material, raw
credential dumps, or customer signing keys. Keep them in `.secrets/` or another
local Git-excluded path. Do not place those paths in repository defaults.

Use AI and MCP only with bundle artifacts intended for reasoning, such as
`summary.json`, `summary.md`, `data-handling.json`, `audit-plan.json`,
`api-inventory.json`, report-pack data, proof-table rows, `ai_context.json`,
and `validation.json`. If evidence is missing, say so rather than inferring a
fact. Do not add external crash telemetry or analytics.

## Suspected exposure

If sensitive auth material is found in a bundle or pack, stop handoff, remove
the pack from its transfer channel, rotate the exposed material, regenerate the
run or pack after correcting the source, verify the pack again, and record the
incident through the customer's process.
